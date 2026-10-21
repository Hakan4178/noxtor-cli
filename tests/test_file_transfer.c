/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_file_transfer.c — file_transfer_handle_rx birim testi
 *
 * Kapsam:
 *   1. M-F3 REGRESYON: aktif RX sırasında decrypt fail → rx_abort →
 *      yarım dosya unlinkat ile silinir (orphan kalmaz). Eski inline
 *      temizlik close+memzero yapıp unlinkat atlıyordu.
 *   2. Transfer dış decrypt fail → sessiz ret (abort yok, crash yok)
 *   3. Başarılı DATA chunk: loopback Noise session ile şifrelenmiş chunk
 *      yazılır + hash ilerler + tamamlanma → dosya diskte kalır, struct
 *      sıfırlanır (hash eşleşmezse unlink olurdu — dosyanın varlığı
 *      hash doğruluğunun kanıtı)
 *
 * Kurulum şablonu: tests/test_tofu_epoch.c loopback dansı + iki taraf
 * handshake_split (state_machine.c:418 kalıbı): g_sess_i sender (encrypt),
 * ps->session receiver (decrypt).
 */

#include "common.h"
#include "types.h"
#include "noise.h"
#include "state_machine.h"
#include "file_transfer.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>
#include "test_common.h"


/* ================================================================
 * FIXTURE
 * ================================================================ */
static struct app_state st;
static const char *TEST_DL_DIR = "tests/.tmp_dl_ftx";
static struct noise_session *g_sess_i = NULL; /* sender (encrypt) */

/* Loopback Noise XX: initiator stack, responder sodium_malloc. Split
 * her hs'yi tüketir (zeroize) — çağrı iki complete hs ister. */
static int make_split_pair(struct noise_session *sess_i,
                           struct noise_session *sess_r)
{
    uint8_t i_priv[NOX_KEY_LEN], i_pub[NOX_KEY_LEN];
    uint8_t r_priv[NOX_KEY_LEN], r_pub[NOX_KEY_LEN];
    crypto_box_curve25519xsalsa20poly1305_keypair(i_pub, i_priv);
    crypto_box_curve25519xsalsa20poly1305_keypair(r_pub, r_priv);

    struct noise_handshake hs_i;
    struct noise_handshake *hs_r = sodium_malloc(sizeof(*hs_r));
    if (!hs_r) return -1;

    if (handshake_init(&hs_i, true, i_priv, i_pub) != NOX_OK ||
        handshake_init(hs_r, false, r_priv, r_pub) != NOX_OK) {
        sodium_free(hs_r);
        return -1;
    }

    uint8_t msg[NOISE_MAX_HANDSHAKE_LEN], pl[64];
    size_t len, pl_len;
    nox_err_t err = NOX_OK;

    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) == NOX_OK) {
        pl_len = sizeof(pl);
        if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) == NOX_OK) {
            len = sizeof(msg);
            if (handshake_write(hs_r, NULL, 0, msg, &len) == NOX_OK) {
                pl_len = sizeof(pl);
                if (handshake_read(&hs_i, msg, len, pl, sizeof(pl), &pl_len) == NOX_OK) {
                    len = sizeof(msg);
                    if (handshake_write(&hs_i, NULL, 0, msg, &len) == NOX_OK) {
                        pl_len = sizeof(pl);
                        if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK)
                            err = NOX_ERR_CRYPTO;
                    } else err = NOX_ERR_CRYPTO;
                } else err = NOX_ERR_CRYPTO;
            } else err = NOX_ERR_CRYPTO;
        } else err = NOX_ERR_CRYPTO;
    } else err = NOX_ERR_CRYPTO;

    if (err == NOX_OK &&
        (!handshake_is_complete(&hs_i) || !handshake_is_complete(hs_r)))
        err = NOX_ERR_CRYPTO;

    if (err == NOX_OK)
        err = handshake_split(&hs_i, sess_i);   /* initiator → sender */
    if (err == NOX_OK)
        err = handshake_split(hs_r, sess_r);    /* responder → receiver */

    sodium_free(hs_r);
    return err == NOX_OK ? 0 : -1;
}

/* state + downloads dir + slot0 session (receiver) + sender session */
static int fixture_rx(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;
    st.epoll_fd         = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++)
        st.peers[i].fd = -1;

    mkdir(TEST_DL_DIR, 0700); /* EEXIST göz ardı */
    st.downloads_dir_fd = open(TEST_DL_DIR,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (st.downloads_dir_fd < 0) return -1;

    st.peers[0].session = sodium_malloc(sizeof(struct noise_session));
    g_sess_i = sodium_malloc(sizeof(struct noise_session));
    if (!st.peers[0].session || !g_sess_i) return -1;

    if (make_split_pair(g_sess_i, st.peers[0].session) != 0) return -1;

    st.peers[0].state = ST_ACTIVE;
    /* main.c açılış karşılığı: rx fd geçersiz işaretle (memset → 0 olurdu) */
    st.peers[0].rx_file.fd = -1;
    return 0;
}

static void fixture_teardown(void)
{
    if (g_sess_i) {
        sodium_memzero(g_sess_i, sizeof(struct noise_session));
        sodium_free(g_sess_i);
        g_sess_i = NULL;
    }
    if (st.peers[0].session) {
        sodium_memzero(st.peers[0].session, sizeof(struct noise_session));
        sodium_free(st.peers[0].session);
        st.peers[0].session = NULL;
    }
    if (st.downloads_dir_fd >= 0) {
        close(st.downloads_dir_fd);
        st.downloads_dir_fd = -1;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/orphan.bin", TEST_DL_DIR); unlink(path);
    snprintf(path, sizeof(path), "%s/chunk.bin", TEST_DL_DIR);  unlink(path);
    rmdir(TEST_DL_DIR);
}

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 1) M-F3 REGRESYON: aktif RX + decrypt fail → rx_abort → orphan silinir */
static int test_rx_abort_unlinks_orphan(void)
{
    if (fixture_rx() != 0) { TEST_ASSERT(!"fixture"); }
    struct peer_session *ps = &st.peers[0];

    /* yarım alınmış dosya taklidi */
    int fd = openat(st.downloads_dir_fd, "orphan.bin",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    TEST_ASSERT(fd >= 0);
    ps->rx_file.active = true;
    ps->rx_file.fd = fd;
    ps->rx_file.expected_size = 64;
    ps->rx_file.received_bytes = 0;
    snprintf(ps->rx_file.local_name, sizeof(ps->rx_file.local_name),
             "orphan.bin");

    /* H3: decrypt event_loop'ta; pt_len=0 = AEAD fail sinyali → rx_abort */
    uint8_t garbage[64];
    randombytes_buf(garbage, sizeof(garbage));
    TEST_ASSERT(file_transfer_handle_rx(&st, ps, garbage, 0));

    /* M-F3 sözleşmesi: dosya SİLİNDİ, struct sıfır, fd geçersiz */
    TEST_ASSERT(faccessat(st.downloads_dir_fd, "orphan.bin", F_OK, 0) == -1);
    TEST_ASSERT(ps->rx_file.fd == -1);
    TEST_ASSERT(ps->rx_file.active == false);
    TEST_ASSERT(ps->rx_file.local_name[0] == '\0');

    fixture_teardown();
    return 0;
}

/* 2) Transfer DIŞI decrypt fail → sessiz ret, abort tetiklenmez */
static int test_rx_decrypt_fail_inactive(void)
{
    if (fixture_rx() != 0) { TEST_ASSERT(!"fixture"); }
    struct peer_session *ps = &st.peers[0];

    /* H3: decrypt event_loop'ta; pt_len=0 = AEAD fail sinyali */
    uint8_t garbage[48];
    randombytes_buf(garbage, sizeof(garbage));
    TEST_ASSERT(file_transfer_handle_rx(&st, ps, garbage, 0));

    TEST_ASSERT(ps->rx_file.active == false);   /* abort yok */
    TEST_ASSERT(ps->rx_file.fd == -1);

    fixture_teardown();
    return 0;
}

/* 3) Başarılı DATA chunk: yaz + hash ilerlet + tamamla — dosya diskte */
static int test_rx_data_chunk_success(void)
{
    if (fixture_rx() != 0) { TEST_ASSERT(!"fixture"); }
    struct peer_session *ps = &st.peers[0];

    int fd = openat(st.downloads_dir_fd, "chunk.bin",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    TEST_ASSERT(fd >= 0);
    ps->rx_file.active = true;
    ps->rx_file.fd = fd;
    ps->rx_file.expected_size = 4;
    ps->rx_file.received_bytes = 0;
    snprintf(ps->rx_file.local_name, sizeof(ps->rx_file.local_name),
             "chunk.bin");
    snprintf(ps->rx_file.filename, sizeof(ps->rx_file.filename),
             "chunk.bin");

    /* beklenen hash = generichash(size_hdr_BE(4) || "test") — C-6 kalıbı;
     * sonra hash_state'i gerçek akış gibi yeniden başlat (init+size_hdr) */
    uint8_t size_hdr[8] = {0, 0, 0, 0, 0, 0, 0, 4};
    TEST_ASSERT(crypto_generichash_init(&ps->rx_file.hash_state,
                                        NULL, 0, 32) == 0);
    TEST_ASSERT(crypto_generichash_update(&ps->rx_file.hash_state,
                                          size_hdr, 8) == 0);
    TEST_ASSERT(crypto_generichash_update(&ps->rx_file.hash_state,
                                          (const uint8_t *)"test", 4) == 0);
    TEST_ASSERT(crypto_generichash_final(&ps->rx_file.hash_state,
                                         ps->rx_file.expected_hash, 32) == 0);
    TEST_ASSERT(crypto_generichash_init(&ps->rx_file.hash_state,
                                        NULL, 0, 32) == 0);
    TEST_ASSERT(crypto_generichash_update(&ps->rx_file.hash_state,
                                          size_hdr, 8) == 0);

    /* H3: handle_rx artık düz metin alır (decrypt event_loop'ta) */
    uint8_t chunk[] = "test";
    TEST_ASSERT(file_transfer_handle_rx(&st, ps, chunk, 4));

    /* tamamlandı: struct sıfır, dosya diskte ve içerik doğru */
    TEST_ASSERT(ps->rx_file.active == false);
    TEST_ASSERT(ps->rx_file.fd == -1);

    int rfd = openat(st.downloads_dir_fd, "chunk.bin", O_RDONLY | O_CLOEXEC);
    TEST_ASSERT(rfd >= 0);
    char buf[8] = {0};
    TEST_ASSERT(read(rfd, buf, 4) == 4);
    close(rfd);
    TEST_ASSERT(memcmp(buf, "test", 4) == 0);

    fixture_teardown();
    return 0;
}

/* 4) F9 REGRESYON: chunk-timeout FILE_RX hayaletini bırakmamalı.
 * event_loop.c timeout bloğu unlink+close+memzero yapıp EV_FILE_DONE
 * dispatch etmiyordu (rx_abort ediyordu) → ST_FILE_RX + active=false,
 * /switch 3600sn bloklu. Patch: FILE_RX ise EV_FILE_DONE dispatch.
 * Bu test patch sözleşmesini kilitler: expired predikat + timeout
 * temizliği sonrası state ACTIVE'a dönmeli, yarım dosya silinmeli. */
static int test_rx_chunk_timeout_returns_to_active(void)
{
    if (fixture_rx() != 0) { TEST_ASSERT(!"fixture"); }
    struct peer_session *ps = &st.peers[0];

    /* RX başlamış gibi: state FILE_RX, yarım dosya diskte */
    ps->state = ST_FILE_RX;
    int fd = openat(st.downloads_dir_fd, "timeout.bin",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    TEST_ASSERT(fd >= 0);
    ps->rx_file.active = true;
    ps->rx_file.fd = fd;
    ps->rx_file.expected_size = 64;
    ps->rx_file.received_bytes = 16;
    snprintf(ps->rx_file.local_name, sizeof(ps->rx_file.local_name),
             "timeout.bin");
    clock_gettime(CLOCK_MONOTONIC, &ps->rx_file.last_chunk_ts);
    ps->rx_file.last_chunk_ts.tv_sec -= (NOX_FILE_CHUNK_TIMEOUT_SEC + 5);

    /* predikat: bayat timestamp expired, taze değil */
    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    TEST_ASSERT(file_transfer_chunk_expired(&ps->rx_file.last_chunk_ts,
                                            &now_ts,
                                            NOX_FILE_CHUNK_TIMEOUT_SEC));
    TEST_ASSERT(!file_transfer_chunk_expired(&now_ts, &now_ts,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    TEST_ASSERT(!file_transfer_chunk_expired(NULL, &now_ts,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));

    /* event_loop.c timeout bloğuyla aynı temizlik (patch sonrası) */
    if (st.downloads_dir_fd >= 0 && ps->rx_file.local_name[0] != '\0') {
        unlinkat(st.downloads_dir_fd, ps->rx_file.local_name, 0);
    }
    if (ps->rx_file.fd >= 0) {
        close(ps->rx_file.fd);
    }
    sodium_memzero(&ps->rx_file, sizeof(ps->rx_file));
    ps->rx_file.fd = -1;
    if (ps->state == ST_FILE_RX) {
        sm_dispatch(ps, &st, EV_FILE_DONE);
    }

    /* sözleşme: hayalet yok — ACTIVE + temiz struct + dosya silindi */
    TEST_ASSERT(ps->rx_file.active == false);
    TEST_ASSERT(ps->rx_file.fd == -1);
    TEST_ASSERT(ps->state == ST_ACTIVE);
    TEST_ASSERT(faccessat(st.downloads_dir_fd, "timeout.bin", F_OK, 0) == -1);

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== file_transfer RX testleri (M-F3 dahil) ===\n");

    RUN_TEST(test_rx_abort_unlinks_orphan);
    RUN_TEST(test_rx_decrypt_fail_inactive);
    RUN_TEST(test_rx_data_chunk_success);
    RUN_TEST(test_rx_chunk_timeout_returns_to_active);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
