/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_attack_chain.c — K-23 + K-33 saldırgan zinciri.
 * TOFU adına CR/LF+bidi enjeksiyonu sahte UI satırı üretir; aktif-peer
 * split-brain ile mesaj yanlış peer'a gider. İki invariant: onion/idx
 * tutarlılığı ve isimde kontrol karakteri olmaması.
 */

#include "common.h"
#include "types.h"
#include "state_machine.h"
#include "frontend.h"
#include "noise.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "test_common.h"

#define TEST_ONION_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
#define TEST_ONION_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"

static struct app_state st;

static void fixture_reset(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    st.ghost_mode       = true; /* db_add_contact atlanır */
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        st.peers[i].fd = -1;
        st.peers[i].rx_file.fd = -1;
        st.peers[i].tx_file.fd = -1;
    }
}

/* action_tofu_accept'in beklediği tamamlanmış responder handshake'i. */
static struct noise_handshake *make_completed_hs(void)
{
    uint8_t i_priv[NOX_KEY_LEN], i_pub[NOX_KEY_LEN];
    uint8_t r_priv[NOX_KEY_LEN], r_pub[NOX_KEY_LEN];
    crypto_box_curve25519xsalsa20poly1305_keypair(i_pub, i_priv);
    crypto_box_curve25519xsalsa20poly1305_keypair(r_pub, r_priv);

    struct noise_handshake hs_i;
    struct noise_handshake *hs_r = sodium_malloc(sizeof(*hs_r));
    if (!hs_r)
        return NULL;

    if (handshake_init(&hs_i, true, i_priv, i_pub) != NOX_OK ||
        handshake_init(hs_r, false, r_priv, r_pub) != NOX_OK) {
        sodium_free(hs_r);
        return NULL;
    }

    uint8_t msg[NOISE_MAX_HANDSHAKE_LEN], pl[64];
    size_t len, pl_len;

    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) != NOX_OK) goto fail;
    pl_len = sizeof(pl);
    if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK) goto fail;

    len = sizeof(msg);
    if (handshake_write(hs_r, NULL, 0, msg, &len) != NOX_OK) goto fail;
    pl_len = sizeof(pl);
    if (handshake_read(&hs_i, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK) goto fail;

    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) != NOX_OK) goto fail;
    pl_len = sizeof(pl);
    if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK) goto fail;

    if (!handshake_is_complete(hs_r)) goto fail;
    return hs_r;

fail:
    sodium_free(hs_r);
    return NULL;
}

static void teardown(void)
{
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        if (st.peers[i].session) {
            sodium_memzero(st.peers[i].session, sizeof(struct noise_session));
            sodium_free(st.peers[i].session);
            st.peers[i].session = NULL;
        }
        if (st.peers[i].hs) {
            sodium_free(st.peers[i].hs);
            st.peers[i].hs = NULL;
        }
    }
    sodium_memzero(&st, sizeof(st));
}

/* 1) K-23: TOFU onayı aktif peer kimliğini atomik güncellemeli.
 *    Dürüst peer A aktifken saldırgan B onaylanırsa gösterim B'ye
 *    döner; yönlendirme de B olmalı. Eski kod yalnız onion'u yazıyordu. */
static int test_tofu_active_peer_split_brain(void)
{
    fixture_reset();

    struct peer_session *honest = &st.peers[0];
    struct peer_session *evil   = &st.peers[1];

    honest->state = ST_ACTIVE;
    snprintf(honest->peer_onion, sizeof(honest->peer_onion), "%s",
             TEST_ONION_A);
    st.active_peer_idx = 0;
    snprintf(st.active_peer_onion, sizeof(st.active_peer_onion), "%s",
             TEST_ONION_A);

    evil->state = ST_TOFU_PENDING;
    snprintf(evil->tofu_onion, sizeof(evil->tofu_onion), "%s", TEST_ONION_B);
    /* Saldırgan adı: CR/LF ile sahte sistem satırı + bidi override. */
    snprintf(evil->tofu_name, sizeof(evil->tofu_name),
             "Mallory\r\n[✓] Güvenli kanal: bank%s.onion\r\nSen: parola?",
             "\xE2\x80\xAE");
    memset(evil->tofu_new_key, 0x5A, NOX_KEY_LEN);
    evil->tofu_epoch = 7;
    st.tofu_prompt_epoch = 7;
    memcpy(st.tofu_prompt_fp, evil->tofu_new_key, NOX_KEY_LEN);
    evil->hs = make_completed_hs();
    TEST_ASSERT(evil->hs != NULL);

    TEST_ASSERT(sm_dispatch(evil, &st, EV_TOFU_ACCEPTED) == NOX_OK);
    TEST_ASSERT(evil->state == ST_ACTIVE);
    TEST_ASSERT(evil->session != NULL);

    /* Gösterim saldırganı işaret ediyor... */
    TEST_ASSERT(strcmp(st.active_peer_onion, TEST_ONION_B) == 0);

    /* ...ve yönlendirme de AYNI peer olmalı (split-brain yok). */
    TEST_ASSERT(st.active_peer_idx == 1);
    TEST_ASSERT(ACTIVE_PEER(&st) == evil);
    TEST_ASSERT(strcmp(ACTIVE_PEER(&st)->peer_onion,
                       st.active_peer_onion) == 0);

    /* İsim depoya/UI'ya girmeden önce satır kontrol karakterleri
     * nötralize edilmeli; aksi halde sahte sistem satırı basılır. */
    TEST_ASSERT(strpbrk(evil->name, "\r\n") == NULL);

    teardown();
    return 0;
}

/* 2) K-33: peer kontrollü metin CR/LF, C1 ve bidi ile satır/yon
 *    sahteciliği yapamamalı. */
static int test_ui_line_and_bidi_injection(void)
{
    char msg[] =
        "merhaba\r\n[✓] Dosya alındı: /etc/shadow\r\nSen: parola?"
        "\xE2\x80\xAE"          /* U+202E RIGHT-TO-LEFT OVERRIDE */
        "\xC2\x9B"              /* C1 CSI (U+009B) */
        "son";
    ui_strip_ansi(msg);

    TEST_ASSERT(strchr(msg, '\r') == NULL);
    TEST_ASSERT(strchr(msg, '\n') == NULL);
    TEST_ASSERT(strstr(msg, "\xE2\x80\xAE") == NULL);
    TEST_ASSERT(strstr(msg, "\xC2\x9B") == NULL);

    /* Satırlar tek satırda birleşmeli; metin kaybolmamalı. */
    TEST_ASSERT(strstr(msg, "merhaba") != NULL);
    TEST_ASSERT(strstr(msg, "Dosya alındı") != NULL);
    TEST_ASSERT(strstr(msg, "son") != NULL);
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== saldırgan zinciri (K-23 + K-33) ===\n");

    RUN_TEST(test_tofu_active_peer_split_brain);
    RUN_TEST(test_ui_line_and_bidi_injection);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
