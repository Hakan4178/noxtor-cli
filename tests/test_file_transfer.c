/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_file_transfer.c — file_transfer RX/TX birim testleri
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
 *   4. Adım 5 — TX metadata EAGAIN/kısa yazım: C2 kuyruğu gelene kadar
 *      eski "kop" sözleşmesi KIRMIZI; nihai sözleşme queue olacak.
 *   5. Adım 5 — TX chunk fatal write: zero-byte veya kısmi frame → teardown;
 *      tüketilen nonce geri alınamaz.
 *   6. TX sırasında gelen METADATA: ortak TX+RX durumu yok; muhafazakâr
 *      sözleşme: yerel hata + reddet, yarım dosya açma, oturumu koru.
 *   7. TX başlangıç/bitiş: ACTIVE → FILE_TX → ACTIVE; aksi halde sonraki
 *      transfer/RX kabulü kilitlenir.
 *   8. TX şifreleme hatası nonce tüketmeden: transfer abort, oturum kalır.
 *   9. TX nonce tükenmesi: fail-closed, transfer + oturum teardown.
 *  10. İki chunk'lık başarılı TX: tx_seq ve nonce sırayla ilerler.
 *
 * Kurulum şablonu: tests/test_tofu_epoch.c loopback dansı + iki taraf
 * handshake_split (state_machine.c:418 kalıbı): g_sess_i sender (encrypt),
 * ps->session receiver (decrypt).
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "noise.h"
#include "state_machine.h"
#include "file_transfer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
static int g_tx_peer_fd = -1;
static char g_tx_src_path[256];

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
    st.downloads_dir_fd = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        st.peers[i].fd = -1;
        st.peers[i].rx_file.fd = -1;
        st.peers[i].tx_file.fd = -1;
    }

    if (mkdir(TEST_DL_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    /* Kalıntı dizin yanlış izinle kalmışsa H-3 doğrulaması reddeder. */
    if (chmod(TEST_DL_DIR, 0700) != 0)
        return -1;
    st.downloads_dir_fd = open(TEST_DL_DIR,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (st.downloads_dir_fd < 0) return -1;

    st.peers[0].session = sodium_malloc(sizeof(struct noise_session));
    g_sess_i = sodium_malloc(sizeof(struct noise_session));
    if (!st.peers[0].session || !g_sess_i) return -1;

    if (make_split_pair(g_sess_i, st.peers[0].session) != 0) return -1;

    st.peers[0].state = ST_ACTIVE;
    return 0;
}

/* Adım 5 TX fixture'ı: gerçek kaynak dosya + gerçek socket + AEAD anahtarı.
 * `fill_socket` true ise alıcı hiç okumaz; soket EAGAIN'e kadar doldurulur. */
static void init_cipher_session(struct noise_session *s, uint64_t n)
{
    memset(s, 0, sizeof(*s));
    memset(s->tx.k, 0x42, NOX_KEY_LEN);
    memset(s->rx.k, 0x42, NOX_KEY_LEN);
    s->tx.n = n;
    s->rx.n = n;
    s->tx.has_key = true;
    s->rx.has_key = true;
}

#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
#define FTX_WOULD_BLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define FTX_WOULD_BLOCK(e) ((e) == EAGAIN)
#endif

/* Gerçek bir FILE chunk'ını tx_buf'a şifrele: write hatası testinde
 * nonce'ın gerçekten tüketildiğini (tx.n=1) ve tx_seq'in ilerlemediğini
 * (0) göstermek için. */
static int stage_one_byte_chunk(struct peer_session *ps)
{
    uint8_t one = 'Z';
    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_FILE,
        .seq = ps->tx_seq,
        .len = 1 + NOX_MAC_LEN,
    };
    frame_ad(&fh, ps->tx_file.tx_buf);
    ssize_t ct_len = noise_encrypt(ps->session, ps->tx_file.tx_buf,
                                   FRAME_HEADER_WIRE_SIZE, &one, 1,
                                   ps->tx_file.tx_buf + FRAME_HEADER_WIRE_SIZE);
    if (ct_len != (ssize_t)fh.len)
        return -1;
    ps->tx_file.tx_len = FRAME_HEADER_WIRE_SIZE + (size_t)ct_len;
    ps->tx_file.tx_offset = 0;
    ps->tx_file.current_chunk_size = 1;
    return 0;
}

/* Kaynak dosyayı istenen boyuta getir (sparse okuma; içerik önemsiz). */
static int fill_tx_source(size_t total_size)
{
    int fd = open(g_tx_src_path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int rc = ftruncate(fd, (off_t)total_size);
    if (close(fd) != 0)
        rc = -1;
    return rc;
}

/* file_transfer_start'ın yaptığı TX state kurulumunu, metadata yazmadan
 * yap: gerçek kaynak fd + plain_buf + aktif transfer. */
static int arm_tx_file(struct peer_session *ps, size_t total_size)
{
    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;
    ps->tx_file.fd = open(g_tx_src_path, O_RDONLY | O_CLOEXEC);
    if (ps->tx_file.fd < 0)
        return -1;

    ps->tx_file.plain_buf = sodium_malloc(4096);
    if (!ps->tx_file.plain_buf) {
        close(ps->tx_file.fd);
        ps->tx_file.fd = -1;
        ps->tx_file.active = false;
        return -1;
    }

    ps->tx_file.total_size = total_size;
    ps->tx_file.sent_bytes = 0;
    ps->tx_file.tx_len = 0;
    ps->tx_file.tx_offset = 0;
    ps->tx_file.current_chunk_size = 0;
    return 0;
}

static int fill_socket_to_eagain(int fd)
{
    int sndbuf = 4096;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0)
        return -1;

    uint8_t filler[4096];
    memset(filler, 0xA5, sizeof(filler));

    /* Büyük yazımlarla dol; son boşluğu 1 byte'lık yazımlarla kapat.
     * Böylece writev(334) için kesin EAGAIN üretilir. */
    for (;;) {
        ssize_t w = write(fd, filler, sizeof(filler));
        if (w < 0) {
            if (errno == EINTR) continue;
            if (FTX_WOULD_BLOCK(errno)) break;
            return -1;
        }
        if (w == 0) return -1;
    }
    for (;;) {
        ssize_t w = write(fd, filler, 1);
        if (w < 0) {
            if (errno == EINTR) continue;
            return FTX_WOULD_BLOCK(errno) ? 0 : -1;
        }
        if (w == 0) return -1;
    }
}

static int fixture_tx(bool fill_socket)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = 0;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    g_tx_src_path[0] = '\0';
    g_tx_peer_fd = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        st.peers[i].fd = -1;
        st.peers[i].rx_file.fd = -1;
        st.peers[i].tx_file.fd = -1;
    }

    snprintf(g_tx_src_path, sizeof(g_tx_src_path),
             "tests/.tmp_ftx_src_XXXXXX");
    int src_fd = mkstemp(g_tx_src_path);
    if (src_fd < 0) return -1;
    if (write(src_fd, "A", 1) != 1) {
        close(src_fd);
        return -1;
    }
    close(src_fd);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;

    struct peer_session *ps = &st.peers[0];
    ps->fd = sv[0];
    g_tx_peer_fd = sv[1];
    int flags = fcntl(ps->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(ps->fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;

    ps->state = ST_ACTIVE;
    ps->session = sodium_malloc(sizeof(*ps->session));
    if (!ps->session) return -1;
    init_cipher_session(ps->session, 0);

    if (fill_socket && fill_socket_to_eagain(ps->fd) != 0)
        return -1;
    return 0;
}

static void fixture_tx_teardown(void)
{
    struct peer_session *ps = &st.peers[0];

    if (ps->tx_file.plain_buf) {
        sodium_free(ps->tx_file.plain_buf);
        ps->tx_file.plain_buf = NULL;
    }
    if (ps->tx_file.fd >= 0) {
        close(ps->tx_file.fd);
        ps->tx_file.fd = -1;
    }
    if (ps->session) {
        sodium_memzero(ps->session, sizeof(*ps->session));
        sodium_free(ps->session);
        ps->session = NULL;
    }
    if (ps->fd >= 0) {
        close(ps->fd);
        ps->fd = -1;
    }
    if (g_tx_peer_fd >= 0) {
        close(g_tx_peer_fd);
        g_tx_peer_fd = -1;
    }
    if (g_tx_src_path[0] != '\0') {
        unlink(g_tx_src_path);
        g_tx_src_path[0] = '\0';
    }
    sodium_memzero(&st, sizeof(st));
}

static void fixture_teardown(void)
{
    struct peer_session *ps = &st.peers[0];

    /* Erken FAIL yolunda da yarım RX dosyasını kapat/sil. */
    if (ps->rx_file.fd >= 0) {
        close(ps->rx_file.fd);
        ps->rx_file.fd = -1;
    }
    if (st.downloads_dir_fd >= 0 && ps->rx_file.local_name[0] != '\0') {
        unlinkat(st.downloads_dir_fd, ps->rx_file.local_name, 0);
    }
    sodium_memzero(&ps->rx_file, sizeof(ps->rx_file));
    ps->rx_file.fd = -1;

    if (ps->tx_file.plain_buf) {
        sodium_free(ps->tx_file.plain_buf);
        ps->tx_file.plain_buf = NULL;
    }
    if (ps->tx_file.active && ps->tx_file.fd >= 0) {
        close(ps->tx_file.fd);
    }
    sodium_memzero(&ps->tx_file, sizeof(ps->tx_file));
    ps->tx_file.fd = -1;

    if (g_sess_i) {
        sodium_memzero(g_sess_i, sizeof(struct noise_session));
        sodium_free(g_sess_i);
        g_sess_i = NULL;
    }
    if (ps->session) {
        sodium_memzero(ps->session, sizeof(struct noise_session));
        sodium_free(ps->session);
        ps->session = NULL;
    }
    if (ps->fd >= 0) {
        close(ps->fd);
        ps->fd = -1;
    }
    if (st.downloads_dir_fd >= 0) {
        close(st.downloads_dir_fd);
        st.downloads_dir_fd = -1;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/orphan.bin", TEST_DL_DIR); unlink(path);
    snprintf(path, sizeof(path), "%s/chunk.bin", TEST_DL_DIR);  unlink(path);
    snprintf(path, sizeof(path), "%s/received_evil.bin", TEST_DL_DIR); unlink(path);
    rmdir(TEST_DL_DIR);
}

#define FT_TX_ASSERT(cond) do {                                        \
    if (!(cond)) {                                                     \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        fixture_tx_teardown();                                         \
        return 1;                                                      \
    }                                                                  \
} while (0)

#define FT_RX_ASSERT(cond) do {                                        \
    if (!(cond)) {                                                     \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        fixture_teardown();                                            \
        return 1;                                                      \
    }                                                                  \
} while (0)

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 0) K-26 kotası: 100 GiB tavanı NOX_ERR_QUOTA'ya bağlanıyor */
static int test_quota_bounds(void)
{
    TEST_ASSERT(file_transfer_check_quota(0) == NOX_OK);
    TEST_ASSERT(file_transfer_check_quota(NOX_MAX_FILE_SIZE) == NOX_OK);
    TEST_ASSERT(file_transfer_check_quota(NOX_MAX_FILE_SIZE + 1) ==
                NOX_ERR_QUOTA);
    return 0;
}

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

/* 6) [ADIM 5 — C2 BEKLİYOR, KIRMIZI] Metadata EAGAIN: nonce tüketildi,
 * tx_seq ilerlemedi, soket açık kaldı. Bu eski "kop" sözleşmesi artık
 * geçerli değil; §15 C2 kuyruğu gelince test "kısmi yazımda kopma yok,
 * sonraki frame doğru" sözleşmesine yeniden yazılacak.
 *
 * Bu testin bugünkü kırmızısı bilinçli: fix disconnect değil, queue.
 */
static int test_tx_metadata_short_write_disconnects(void)
{
    FT_TX_ASSERT(fixture_tx(true) == 0);
    struct peer_session *ps = &st.peers[0];

    /* Ön koşul: soket gerçekten dolu (writev EAGAIN üretecek). */
    uint8_t probe = 0;
    ssize_t p = write(ps->fd, &probe, 1);
    FT_TX_ASSERT(p < 0 && FTX_WOULD_BLOCK(errno));

    file_transfer_start(&st, g_tx_src_path);

    /* Transfer iptal edildi... */
    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_seq == 0);

    /* Kanıt: metadata AEAD nonce'u tüketti (tx.n=1), tx_seq hâlâ 0.
     * Kopma olursa session NULL olur; o durumda bu kanıt aranmaz. */
    if (ps->session != NULL) {
        FT_TX_ASSERT(ps->session->tx.n == 1);
        FT_TX_ASSERT(ps->tx_seq == 0);
    }

    /* ...ama H3 fail-closed kopma yok: nonce harcanmış kanal canlı. */
    FT_TX_ASSERT(ps->fd == -1);
    FT_TX_ASSERT(ps->state == ST_IDLE);
    FT_TX_ASSERT(ps->session == NULL);

    fixture_tx_teardown();
    return 0;
}

/* 7) [ADIM 5] FILE TX chunk write fatal (EBADF/EPIPE), HİÇ byte yazılmadı:
 * başarılı şifreleme nonce'u tüketmiştir; rollback yasak. Frame
 * düşürülemez, bu yüzden zero-byte fatal write da kısmi frame gibi
 * teardown'dır.
 */
static int test_tx_chunk_zero_byte_write_disconnects(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    /* Yazma yönü kapalı bir fd: write() kesin EBADF döndürür. */
    close(ps->fd);
    ps->fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    FT_TX_ASSERT(ps->fd >= 0);

    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;
    ps->tx_file.fd = -1;
    ps->tx_file.plain_buf = NULL;
    ps->tx_file.total_size = 1;
    ps->tx_file.sent_bytes = 0;

    /* Gerçek AEAD: nonce tüketilir (tx.n=1), tx_seq 0'da kalır. */
    FT_TX_ASSERT(stage_one_byte_chunk(ps) == 0);
    FT_TX_ASSERT(ps->session->tx.n == 1);
    FT_TX_ASSERT(ps->tx_seq == 0);

    file_transfer_handle_tx(&st, ps);

    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_file.fd == -1);

    /* Zero-byte fatal: nonce tüketildi ve geri alınamaz; frame
     * düşürülemez. Kısmi frame ile aynı teardown sözleşmesi. */
    FT_TX_ASSERT(ps->session == NULL);
    FT_TX_ASSERT(ps->tx_seq == 0);
    FT_TX_ASSERT(ps->fd == -1);
    FT_TX_ASSERT(ps->state == ST_IDLE);

    fixture_tx_teardown();
    return 0;
}

/* 8) [ADIM 5] FILE TX chunk write fatal, KISMİ frame kabloda:
 * stream yeniden senkronize edilemez; transferle birlikte oturum kapanır.
 */
static int test_tx_chunk_partial_write_disconnects(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    close(ps->fd);
    ps->fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    FT_TX_ASSERT(ps->fd >= 0);

    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;
    ps->tx_file.fd = -1;
    ps->tx_file.plain_buf = NULL;
    ps->tx_file.total_size = 1;
    ps->tx_file.sent_bytes = 0;

    FT_TX_ASSERT(stage_one_byte_chunk(ps) == 0);
    FT_TX_ASSERT(ps->session->tx.n == 1);
    FT_TX_ASSERT(ps->tx_seq == 0);
    /* Bir byte'ın daha önce kabloya yazıldığını simüle et. */
    ps->tx_file.tx_offset = 1;

    file_transfer_handle_tx(&st, ps);

    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->fd == -1);
    FT_TX_ASSERT(ps->state == ST_IDLE);
    FT_TX_ASSERT(ps->session == NULL);
    FT_TX_ASSERT(ps->tx_seq == 0);

    fixture_tx_teardown();
    return 0;
}

/* 9) [ADIM 5 — MUHAFAZAKÂR SÖZLEŞME] TX sırasında METADATA.
 *
 * Peer, biz dosya gönderirken geçerli bir METADATA frame'i yollar.
 * Mevcut state machine TX+RX'i birlikte temsil etmiyor. Handler state
 * geçişini reddeder, yerel hata gösterir, hiç dosya açmaz ve oturumu
 * korur. Full-duplex tasarımı seçilirse bu test bilinçli değiştirilir.
 */
static int test_rx_metadata_during_tx_rejected(void)
{
    FT_RX_ASSERT(fixture_rx() == 0);
    struct peer_session *ps = &st.peers[0];

    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;
    ps->tx_file.fd = -1;

    uint8_t meta[305];
    memset(meta, 0, sizeof(meta));
    memcpy(meta, "METADATA", 9);
    memcpy(meta + 9, "evil.bin", 9); /* NUL dahil, name_len=8 */
    meta[265] = 0; meta[266] = 0; meta[267] = 0; meta[268] = 0;
    meta[269] = 0; meta[270] = 0; meta[271] = 0; meta[272] = 4; /* 4 byte */
    memset(meta + 273, 0x42, 32); /* sıfır olmayan hash */

    FT_RX_ASSERT(file_transfer_handle_rx(&st, ps, meta, sizeof(meta)));

    /* Hedef sözleşme: geçiş reddedildiyse yan etki de olmamalı; TX
     * oturumu ve durumu korunmalı. */
    FT_RX_ASSERT(ps->rx_file.active == false);
    FT_RX_ASSERT(ps->rx_file.fd == -1);
    FT_RX_ASSERT(ps->session != NULL);
    FT_RX_ASSERT(ps->state == ST_FILE_TX);
    FT_RX_ASSERT(faccessat(st.downloads_dir_fd, "received_evil.bin",
                           F_OK, 0) == -1);

    fixture_teardown();
    return 0;
}

/* 10) [ADIM 5] TX başlangıç/bitiş durum geçişleri:
 * file_transfer_start ACTIVE → FILE_TX yapar; son chunk bitince
 * FILE_TX → ACTIVE döner. Aksi halde peer bir sonraki transferi
 * başlatamaz veya RX kabul edemez.
 */
static int test_start_and_complete_file_tx(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    file_transfer_start(&st, g_tx_src_path);
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->state == ST_FILE_TX);
    FT_TX_ASSERT(ps->tx_seq == 1); /* metadata frame */
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 1);

    /* İlk çağrı dosyayı okuyup frame'i tx_buf'a şifreler; ikincisi
     * EPOLLOUT yazımını yapar ve transferi tamamlar. */
    file_transfer_handle_tx(&st, ps);
    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->tx_seq == 2); /* tek chunk */
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 2);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->fd >= 0);

    fixture_tx_teardown();
    return 0;
}

/* 11) [ADIM 5] Şifreleme nonce tüketmeden fail ederse yalnız transfer
 * iptal edilir; peer oturumu, fd ve nonce sayacı korunur.
 * Keyless session bu dalı gerçek noise_encrypt guard'ı üzerinden tetikler.
 */
static int test_tx_encrypt_without_nonce_keeps_session(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    ps->session->tx.has_key = false;
    atomic_store(&ps->session->tx.n, 7);
    FT_TX_ASSERT(arm_tx_file(ps, 1) == 0);

    file_transfer_handle_tx(&st, ps);

    /* Nonce tüketilmedi: teardown değil, yalnız transfer abort. */
    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_file.fd == -1);
    FT_TX_ASSERT(ps->tx_file.plain_buf == NULL);
    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 7);
    FT_TX_ASSERT(ps->tx_seq == 0);
    FT_TX_ASSERT(ps->fd >= 0);

    fixture_tx_teardown();
    return 0;
}

/* 12) [ADIM 5] Nonce tükenmişse şifreleme fail-closed olur; tüketilmiş
 * sayaç geri alınamaz. Transferle birlikte oturum da kapanır.
 */
static int test_tx_encrypt_exhausted_nonce_tears_down(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    atomic_store(&ps->session->tx.n, UINT64_MAX);
    FT_TX_ASSERT(arm_tx_file(ps, 1) == 0);

    file_transfer_handle_tx(&st, ps);

    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_file.fd == -1);
    FT_TX_ASSERT(ps->tx_file.plain_buf == NULL);
    FT_TX_ASSERT(ps->tx_seq == 0);
    FT_TX_ASSERT(ps->session == NULL);
    FT_TX_ASSERT(ps->fd == -1);
    FT_TX_ASSERT(ps->state == ST_IDLE);

    fixture_tx_teardown();
    return 0;
}

/* 13) [ADIM 5] İki chunk'lık başarılı TX: nonce ve tx_seq sırayla
 * ilerler; son parça bitince transfer kapanır, oturum ACTIVE kalır.
 */
static int test_tx_multi_chunk_success(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    /* 4096 + 904 = iki FILE chunk (metadata ayrı frame). */
    FT_TX_ASSERT(fill_tx_source(5000) == 0);

    file_transfer_start(&st, g_tx_src_path);
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->state == ST_FILE_TX);
    FT_TX_ASSERT(ps->tx_seq == 1); /* metadata */
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 1);

    for (int i = 0; i < 12 && ps->tx_file.active; i++)
        file_transfer_handle_tx(&st, ps);

    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_file.fd == -1);
    FT_TX_ASSERT(ps->tx_file.plain_buf == NULL);
    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->tx_seq == 3); /* metadata + 2 chunk */
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 3);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->fd >= 0);

    fixture_tx_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== file_transfer RX/TX testleri (M-F3 + Adım 5) ===\n");

    RUN_TEST(test_quota_bounds);
    RUN_TEST(test_rx_abort_unlinks_orphan);
    RUN_TEST(test_rx_decrypt_fail_inactive);
    RUN_TEST(test_rx_data_chunk_success);
    RUN_TEST(test_rx_chunk_timeout_returns_to_active);
    RUN_TEST(test_tx_metadata_short_write_disconnects);
    RUN_TEST(test_tx_chunk_zero_byte_write_disconnects);
    RUN_TEST(test_tx_chunk_partial_write_disconnects);
    RUN_TEST(test_rx_metadata_during_tx_rejected);
    RUN_TEST(test_start_and_complete_file_tx);
    RUN_TEST(test_tx_encrypt_without_nonce_keeps_session);
    RUN_TEST(test_tx_encrypt_exhausted_nonce_tears_down);
    RUN_TEST(test_tx_multi_chunk_success);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
