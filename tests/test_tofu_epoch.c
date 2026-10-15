/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_tofu_epoch.c — C2 TOFU slot-recycling token birim testi
 *
 * C2 (audit §1): "y" prompt'taki slot instance'ına bağlanmalı. Slot
 * recycle'ı (drop → aynı slota yeni anahtar → yeni prompt) esnasında
 * kullanıcı eski fp'ye verdiği "y" ile YENİ anahtarı rehbere
 * kaydedememeli.
 *
 * Testler:
 *   1. İlk prompt: epoch=1, snapshot (tofu_prompt_epoch + fp) kurulur
 *   2. Supersede (çekirdek): çözülmemiş prompt varken yeni prompt
 *      snapshot'ı EZMEZ — recycle korumasının çekirdeği
 *   3. "n" ile çözüm → snapshot sıfırlanır; sonraki prompt taze kurulur
 *   4. Bayat "y" (recycle) → reddedilir + yeniden arm edilir
 *   5. Negatif: epoch eşit ama fp farklı → RET (token fp boyutu)
 *   6. Negatif: fp eşit ama epoch farklı → RET (token epoch boyutu)
 *   7. Token tutuyor ama hs ölü → accept fail-closed + cleanup
 *   8. GERÇEK accept yolu: loopback Noise XX handshake + test db ile
 *      tam onay → ST_ACTIVE, session kuruldu, rehberde kayıtlı,
 *      snapshot sıfırlandı
 *
 * Kapsam notu: 1-7 db'ye dokunmaz (accept hs guard'ı öncesinden döner).
 * 8'de db_add_contact gerçekten çağrılır ve db_get_contact ile okunur.
 */

#include "common.h"
#include "types.h"
#include "state_machine.h"
#include "stdin_handler.h"
#include "noise.h"
#include "database.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>
#include "test_common.h"


/* ================================================================
 * FIXTURE
 * ================================================================ */
static struct app_state st;

static struct peer_session *slot0(void) { return &st.peers[0]; }

static void fixture_reset(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    st.peers[0].fd      = -1; /* cleanup'ta close(0) olmasın */
}

/* Aynı slotta prompt'a sokar (event_loop EV_HANDSHAKE_DONE yolunun karşılığı) */
static nox_err_t prompt_with(uint8_t fill)
{
    slot0()->state = ST_HANDSHAKE_INIT;
    memset(slot0()->tofu_new_key, fill, NOX_KEY_LEN);
    return sm_dispatch(slot0(), &st, EV_HANDSHAKE_DONE);
}

/* ================================================================
 * GERÇEK ACCEPT İÇİN YARDIMCILAR
 *
 * action_tofu_accept, tamamlanmış bir Noise XX hs + geçerli db ister.
 * Şablon: tests/test_noise.c loopback dansı (prologue yok).
 * ================================================================ */
static const char *TEST_ONION =
    "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst.onion";
static const char *TEST_NAME = "C2 Test";

static const char *TEST_DB_DIR = "tests/.tmp_db_tofu";
static uint8_t g_db_key[NOX_KEY_LEN];

/* Tamamlanmış responder hs üretir. ps->hs sodium_malloc OLMALI:
 * action_tofu_accept başarıda sodium_free(ps->hs) çağırır. */
static struct noise_handshake *make_completed_hs(void)
{
    uint8_t i_priv[NOX_KEY_LEN], i_pub[NOX_KEY_LEN];
    uint8_t r_priv[NOX_KEY_LEN], r_pub[NOX_KEY_LEN];
    crypto_box_curve25519xsalsa20poly1305_keypair(i_pub, i_priv);
    crypto_box_curve25519xsalsa20poly1305_keypair(r_pub, r_priv);

    struct noise_handshake hs_i; /* peer tarafı — stack yeter */
    struct noise_handshake *hs_r = sodium_malloc(sizeof(*hs_r));
    if (!hs_r) return NULL;
    if (handshake_init(&hs_i, true, i_priv, i_pub) != NOX_OK ||
        handshake_init(hs_r, false, r_priv, r_pub) != NOX_OK) {
        sodium_free(hs_r);
        return NULL;
    }

    uint8_t msg[NOISE_MAX_HANDSHAKE_LEN], pl[64];
    size_t len, pl_len;

    /* msg0: I → R (→ e) */
    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) != NOX_OK) {
        sodium_free(hs_r); return NULL;
    }
    pl_len = sizeof(pl);
    if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK) {
        sodium_free(hs_r); return NULL;
    }
    /* msg1: R → I (← e, ee, s, es) */
    len = sizeof(msg);
    if (handshake_write(hs_r, NULL, 0, msg, &len) != NOX_OK) {
        sodium_free(hs_r); return NULL;
    }
    pl_len = sizeof(pl);
    if (handshake_read(&hs_i, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK) {
        sodium_free(hs_r); return NULL;
    }
    /* msg2: I → R (→ s, se) */
    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) != NOX_OK) {
        sodium_free(hs_r); return NULL;
    }
    pl_len = sizeof(pl);
    if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK) {
        sodium_free(hs_r); return NULL;
    }

    if (!handshake_is_complete(hs_r)) {
        sodium_free(hs_r);
        return NULL;
    }
    return hs_r;
}

static nox_err_t db_init_tofu_test(void)
{
    int fd = open(TEST_DB_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NOX_ERR_CONFIG;
    nox_err_t r = db_init(TEST_DB_DIR, fd, g_db_key);
    close(fd);
    return r;
}

static void cleanup_db_dir(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/contacts.db", TEST_DB_DIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/contacts.db-wal", TEST_DB_DIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/contacts.db-shm", TEST_DB_DIR);
    unlink(path);
    rmdir(TEST_DB_DIR);
}

/* accept sonrası kalan kaynaklar (LSAN temizliği) */
static void teardown_accept(void)
{
    if (slot0()->session) {
        sodium_memzero(slot0()->session, sizeof(struct noise_session));
        sodium_free(slot0()->session);
        slot0()->session = NULL;
    }
    if (slot0()->hs) {
        sodium_free(slot0()->hs);
        slot0()->hs = NULL;
    }
    db_close();
    cleanup_db_dir();
}

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 1) İlk prompt: epoch + snapshot + fp kopyalanır, state geçişi olur */
static int test_prompt_snapshot(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);
    TEST_ASSERT(slot0()->state == ST_TOFU_PENDING);
    TEST_ASSERT(slot0()->tofu_epoch == 1);
    TEST_ASSERT(st.tofu_prompt_epoch == 1);
    TEST_ASSERT(memcmp(st.tofu_prompt_fp, slot0()->tofu_new_key,
                       NOX_KEY_LEN) == 0);
    return 0;
}

/* 2) Çekirdek: çözülmemiş prompt varken ikinci prompt snapshot'ı EZMEZ */
static int test_supersede_keeps_snapshot(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);      /* prompt #1 */
    TEST_ASSERT(prompt_with(0xB2) == NOX_OK);      /* recycle: yeni anahtar */

    TEST_ASSERT(slot0()->tofu_epoch == 2);         /* sayaç ilerledi */
    TEST_ASSERT(st.tofu_prompt_epoch == 1);        /* snapshot EZİLMEDİ */
    TEST_ASSERT(st.tofu_prompt_fp[0] == 0xA1);     /* hâlâ eski fp */
    return 0;
}

/* 3) "n" çözümü snapshot'ı sıfırlar; sonraki prompt taze kurulur */
static int test_resolve_then_reprompt(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);

    process_line(&st, "n");
    TEST_ASSERT(slot0()->state == ST_IDLE);
    TEST_ASSERT(st.tofu_prompt_epoch == 0);

    TEST_ASSERT(prompt_with(0xC3) == NOX_OK);      /* taze prompt */
    TEST_ASSERT(st.tofu_prompt_epoch == 2);        /* sayaç süreklilik */
    TEST_ASSERT(st.tofu_prompt_fp[0] == 0xC3);     /* fp tazelendi */
    return 0;
}

/* 4) Bayat "y": recycle sonrası uyuşmazlık → ret + re-arm */
static int test_stale_yes_rejected(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);      /* snapshot: 0xA1 */
    TEST_ASSERT(prompt_with(0xB2) == NOX_OK);      /* recycle: epoch 2, snap 1 */

    process_line(&st, "y");

    TEST_ASSERT(slot0()->state == ST_TOFU_PENDING); /* RET — hâlâ pending */
    TEST_ASSERT(st.tofu_prompt_epoch == 2);         /* yeniden arm */
    TEST_ASSERT(st.tofu_prompt_fp[0] == 0xB2);      /* güncel fp kuruldu */
    return 0;
}

/* 5) NEGATİF: epoch'lar eşit ama fp snapshot farklı → RET
 *    (token'ın fp boyutu tek başına yakalar) */
static int test_epoch_match_fp_mismatch_rejected(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);      /* epoch1, snap1, fp A */
    memset(st.tofu_prompt_fp, 0xEE, NOX_KEY_LEN);  /* fp'yi boz */
    TEST_ASSERT(slot0()->tofu_epoch == st.tofu_prompt_epoch); /* epoch eşit! */

    process_line(&st, "y");

    TEST_ASSERT(slot0()->state == ST_TOFU_PENDING); /* RET */
    TEST_ASSERT(st.tofu_prompt_epoch == 1);         /* re-arm: aynı örnek */
    TEST_ASSERT(memcmp(st.tofu_prompt_fp, slot0()->tofu_new_key,
                       NOX_KEY_LEN) == 0);          /* fp gerçek fp'ye döndü */
    return 0;
}

/* 6) NEGATİF: fp eşit ama epoch uyuşmaz → RET
 *    (token'ın epoch boyutu tek başına yakalar) */
static int test_fp_match_epoch_mismatch_rejected(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);
    st.tofu_prompt_epoch = 7;                      /* bayat epoch */
    TEST_ASSERT(memcmp(st.tofu_prompt_fp, slot0()->tofu_new_key,
                       NOX_KEY_LEN) == 0);         /* fp eşit! */

    process_line(&st, "y");

    TEST_ASSERT(slot0()->state == ST_TOFU_PENDING); /* RET */
    TEST_ASSERT(st.tofu_prompt_epoch == 1);         /* re-arm: güncel epoch */
    return 0;
}

/* 7) Token tutuyor ama hs ölü → accept fail-closed, cleanup, pencere kapandı */
static int test_yes_without_hs_cleans_up(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);
    /* ps->hs bilinçli NULL: db yoluna bile girmeden döner */

    process_line(&st, "y");

    TEST_ASSERT(slot0()->state == ST_IDLE);         /* örnek temizlendi */
    TEST_ASSERT(st.tofu_prompt_epoch == 0);         /* pencere kapandı */
    return 0;
}

/* 8) GERÇEK accept yolu: tam onay akışı — ST_ACTIVE + session + rehber */
static int test_real_accept_path(void)
{
    fixture_reset();
    mkdir(TEST_DB_DIR, 0700);                       /* EEXIST göz ardı */
    TEST_ASSERT(db_init_tofu_test() == NOX_OK);

    TEST_ASSERT(prompt_with(0xA1) == NOX_OK);
    snprintf(slot0()->tofu_onion, sizeof(slot0()->tofu_onion),
             "%s", TEST_ONION);
    snprintf(slot0()->tofu_name, sizeof(slot0()->tofu_name),
             "%s", TEST_NAME);
    slot0()->hs = make_completed_hs();
    TEST_ASSERT(slot0()->hs != NULL);

    process_line(&st, "y");

    /* Onay akışı: token ✓ → hs ✓ → db_add_contact → split → ST_ACTIVE */
    TEST_ASSERT(slot0()->state == ST_ACTIVE);
    TEST_ASSERT(slot0()->session != NULL);
    TEST_ASSERT(slot0()->hs == NULL);               /* hs tüketildi */
    TEST_ASSERT(!slot0()->tofu_pending);
    TEST_ASSERT(st.tofu_prompt_epoch == 0);         /* onay penceresi kapandı */
    TEST_ASSERT(strcmp(slot0()->peer_onion, TEST_ONION) == 0);
    TEST_ASSERT(strcmp(slot0()->name, TEST_NAME) == 0);
    TEST_ASSERT(st.active_peer_onion[0] != '\0');
    TEST_ASSERT(!slot0()->peer_verified);           /* H-1: TOFU = doğrulanmamış */

    /* db_add_contact gerçekten yazdı mı — geri okuma ile doğrula */
    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];
    TEST_ASSERT(db_get_contact(TEST_ONION, name_out,
                               sizeof(name_out), key_out) == NOX_OK);
    TEST_ASSERT(strcmp(name_out, TEST_NAME) == 0);
    TEST_ASSERT(memcmp(key_out, slot0()->tofu_new_key, NOX_KEY_LEN) == 0);

    teardown_accept();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }
    randombytes_buf(g_db_key, NOX_KEY_LEN);

    fprintf(stderr, "=== TOFU epoch (C2) token testleri ===\n");

    RUN_TEST(test_prompt_snapshot);
    RUN_TEST(test_supersede_keeps_snapshot);
    RUN_TEST(test_resolve_then_reprompt);
    RUN_TEST(test_stale_yes_rejected);
    RUN_TEST(test_epoch_match_fp_mismatch_rejected);
    RUN_TEST(test_fp_match_epoch_mismatch_rejected);
    RUN_TEST(test_yes_without_hs_cleans_up);
    RUN_TEST(test_real_accept_path);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
