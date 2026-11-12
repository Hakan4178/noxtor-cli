/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_file_transfer.c — file_transfer RX/TX birim testleri (C2)
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
 *   4. T-03: METADATA kısmi yazım/EAGAIN → kopma YOK; frame kuyrukta
 *      offset ile bekler, tx_seq yalnız commit'te artar, sonraki frame
 *      (FILE chunk) doğru sırayla ve doğru içerikle parse edilir.
 *   5. C2 fatal TX: zero-byte/kalıcı hata ve kısmi frame sonrası kalıcı
 *      hata → teardown; tüketilen nonce geri alınamaz.
 *   6. TX sırasında gelen METADATA: ortak TX+RX durumu yok; muhafazakâr
 *      sözleşme: yerel hata + reddet, yarım dosya açma, oturumu koru.
 *   7. TX başlangıç/bitiş: ACTIVE → FILE_TX → ACTIVE; kuyruk boşalınca
 *      tamamlanır. Aksi halde sonraki transfer/RX kabulü kilitlenir.
 *   8. TX şifreleme hatası nonce tüketmeden: transfer abort, oturum kalır.
 *   9. TX nonce tükenmesi: fail-closed, transfer + oturum teardown.
 *  10. İki chunk'lık başarılı TX: tx_seq ve nonce commit'te sırayla artar.
 *  11. 100 chunk'lık akış: küçük SO_SNDBUF + kısmi yazım; alıcı tüm
 *      frame'leri sırayla çözer ve içerik hash'i eşleşir.
 *
 * Kurulum şablonu: tests/test_tofu_epoch.c loopback dansı + iki taraf
 * handshake_split (state_machine.c:418 kalıbı): g_sess_i sender (encrypt),
 * ps->session receiver (decrypt).
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "noise.h"
#include "frame_queue.h"
#include "state_machine.h"
#include "file_transfer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
static size_t g_tx_prefill_len = 0;

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

/* Gerçek bir FILE chunk'ını ortak TX kuyruğuna şifreleyip commit eder.
 * Fatal flush testlerinde nonce'ın gerçekten tüketildiğini ve tx_seq'in
 * commit'te arttığını göstermek için kullanılır. */
static int stage_file_chunk(struct peer_session *ps, const uint8_t *data,
                            size_t len)
{
    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_FILE,
        .seq = ps->tx_seq,
        .len = (uint32_t)(len + NOX_MAC_LEN),
    };

    uint8_t *slot = frame_queue_reserve(ps);
    if (!slot)
        return -1;

    frame_ad(&fh, slot);
    ssize_t ct_len = noise_encrypt(ps->session, slot, FRAME_HEADER_WIRE_SIZE,
                                   data, len, slot + FRAME_HEADER_WIRE_SIZE);
    if (ct_len != (ssize_t)fh.len)
        return -1;

    return frame_queue_commit(ps, FRAME_HEADER_WIRE_SIZE + (size_t)ct_len) ==
                   NOX_OK
               ? 0
               : -1;
}

static int stage_one_byte_chunk(struct peer_session *ps)
{
    static const uint8_t one = 'Z';
    return stage_file_chunk(ps, &one, 1);
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
    return 0;
}

/* Soketi EAGAIN'e kadar doldur; yazılan byte sayısını döndür. */
static int fill_socket_to_eagain(int fd, size_t *filled_out)
{
    int sndbuf = 4096;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0)
        return -1;

    uint8_t filler[4096];
    memset(filler, 0xA5, sizeof(filler));
    size_t filled = 0;

    /* Büyük yazımlarla dol; son boşluğu 1 byte'lık yazımlarla kapat.
     * Böylece tek bir frame için bile kesin EAGAIN üretilir. */
    for (;;) {
        ssize_t w = write(fd, filler, sizeof(filler));
        if (w < 0) {
            if (errno == EINTR) continue;
            if (FTX_WOULD_BLOCK(errno)) break;
            return -1;
        }
        if (w == 0) return -1;
        filled += (size_t)w;
    }
    for (;;) {
        ssize_t w = write(fd, filler, 1);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (!FTX_WOULD_BLOCK(errno)) return -1;
            break;
        }
        if (w == 0) return -1;
        filled += 1;
    }

    *filled_out = filled;
    return 0;
}

/* Tam `len` byte oku (engelleyici olmayan sokette EAGAIN'e kadar dener). */
static int drain_exact(int fd, uint8_t *out, size_t len)
{
    size_t got = 0;
    int idle = 0;
    while (got < len) {
        ssize_t r = recv(fd, out + got, len - got, MSG_DONTWAIT);
        if (r > 0) {
            got += (size_t)r;
            idle = 0;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0 && FTX_WOULD_BLOCK(errno) && ++idle < 1000)
            continue;
        return -1;
    }
    return 0;
}

/* Alıcı taraftan en çok `cap` byte oku; EAGAIN'de dur. */
static size_t drain_avail(int fd, uint8_t *out, size_t cap)
{
    size_t got = 0;
    while (got < cap) {
        ssize_t r = recv(fd, out + got, cap - got, MSG_DONTWAIT);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        break;
    }
    return got;
}

/* Alıcıdan `len` byte oku ve at (önek/kirlilik temizliği). */
static int drain_discard(int fd, size_t len)
{
    uint8_t scratch[4096];
    while (len > 0) {
        size_t n = len < sizeof(scratch) ? len : sizeof(scratch);
        if (drain_exact(fd, scratch, n) != 0)
            return -1;
        len -= n;
    }
    return 0;
}

static int fixture_tx(bool fill_socket)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = 0;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    g_tx_src_path[0] = '\0';
    g_tx_peer_fd = -1;
    g_tx_prefill_len = 0;
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

    if (fill_socket && fill_socket_to_eagain(ps->fd, &g_tx_prefill_len) != 0)
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
    g_tx_prefill_len = 0;
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

/* 6) T-03 REGRESYON (C2): METADATA kısmi yazım/EAGAIN → kopma YOK.
 *
 * Soket dolu; METADATA commit edilir (tx_seq=1, nonce=1) ve kuyrukta
 * offset ile bekler. Kısmi flush NOX_ERR_AGAIN döner, oturum açık kalır.
 * Soket boşalınca aynı frame kaldığı yerden tamamlanır; ardından gelen
 * FILE chunk doğru sırada ve doğru içerikle parse edilir.
 */
static int test_tx_metadata_partial_no_disconnect(void)
{
    FT_TX_ASSERT(fixture_tx(true) == 0);
    struct peer_session *ps = &st.peers[0];

    /* Ön koşul: soket gerçekten dolu. */
    uint8_t probe = 0;
    ssize_t p = write(ps->fd, &probe, 1);
    FT_TX_ASSERT(p < 0 && FTX_WOULD_BLOCK(errno));

    const size_t prefill_len = g_tx_prefill_len;
    FT_TX_ASSERT(prefill_len > 128U);

    file_transfer_start(&st, g_tx_src_path);

    /* C2: METADATA doğrudan yazılmaz; commit edilip kuyruğa girer. */
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->state == ST_FILE_TX);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->tx_seq == 1U);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 1U);
    FT_TX_ASSERT(frame_queue_count(ps) == 1U);

    /* Dolu sokette flush: EAGAIN → kopma yok, nonce/tx_seq değişmez. */
    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_AGAIN);
    FT_TX_ASSERT(ps->fd >= 0);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->state == ST_FILE_TX);
    FT_TX_ASSERT(ps->tx_seq == 1U);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 1U);
    FT_TX_ASSERT(frame_queue_count(ps) == 1U);

    struct frame_queue_slot *slot = &ps->tx_frames.slots[ps->tx_frames.head];
    const uint16_t frame_len = slot->len;
    FT_TX_ASSERT(slot->off == 0U);
    FT_TX_ASSERT(frame_len == FRAME_HEADER_WIRE_SIZE + 305U + NOX_MAC_LEN);

    /* Kirlilik önekini (prefill) tamamen boşalt. */
    FT_TX_ASSERT(drain_discard(g_tx_peer_fd, prefill_len) == 0);

    /* Kısmi yazımı deterministik mod: AF_UNIX tampon muhasebesi 318 B'lik
     * frame'i tek seferde ya hiç ya tam yazar; gerçek kısmi durumu,
     * frame'in ilk 100 byte'ını sokete yazıp kuyruk offset'ini aynı
     * noktaya kurarak modelliyoruz. Kalan gerçek flush ile gider. */
    const uint16_t off_seed = 100U;
    FT_TX_ASSERT(frame_len > off_seed);
    ssize_t seeded = send(ps->fd, slot->buf, off_seed,
                          MSG_DONTWAIT | MSG_NOSIGNAL);
    FT_TX_ASSERT(seeded == (ssize_t)off_seed);
    slot->off = off_seed;

    /* Kalan METADATA byte'larını flush et; tx_seq yalnız commit'te artar. */
    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FT_TX_ASSERT(frame_queue_empty(ps));
    FT_TX_ASSERT(ps->tx_seq == 1U);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 1U);

    static uint8_t wire[8192];
    size_t got = drain_avail(g_tx_peer_fd, wire, sizeof(wire));
    FT_TX_ASSERT(got == frame_len);

    /* METADATA frame'ini parse et ve alıcı gibi çöz. */
    const uint8_t *frame = wire;
    struct frame_header fh;
    FT_TX_ASSERT(frame_header_decode(frame, &fh) == NOX_OK);
    FT_TX_ASSERT(fh.type == NOX_MSG_FILE);
    FT_TX_ASSERT(fh.seq == 0U);
    FT_TX_ASSERT(fh.len == 305U + NOX_MAC_LEN);

    struct noise_session rx;
    init_cipher_session(&rx, 0);
    uint8_t pt[NOX_MAX_MSG_LEN + 1];
    ssize_t n = noise_decrypt(&rx, frame, FRAME_HEADER_WIRE_SIZE,
                              frame + FRAME_HEADER_WIRE_SIZE, fh.len, pt);
    FT_TX_ASSERT(n == 305);
    FT_TX_ASSERT(memcmp(pt, "METADATA", 9) == 0);

    uint64_t declared = 0;
    for (size_t i = 0; i < 8U; i++)
        declared = (declared << 8) | pt[265U + i];
    FT_TX_ASSERT(declared == 1U); /* kaynak dosya: "A" */

    /* Sonraki frame (FILE chunk) doğru sırada ve içerikte olmalı. */
    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->tx_seq == 2U);
    FT_TX_ASSERT(frame_queue_count(ps) == 1U);
    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FT_TX_ASSERT(frame_queue_empty(ps));

    uint8_t file_wire[4096];
    size_t file_got = drain_avail(g_tx_peer_fd, file_wire, sizeof(file_wire));
    FT_TX_ASSERT(frame_header_decode(file_wire, &fh) == NOX_OK);
    FT_TX_ASSERT(fh.type == NOX_MSG_FILE && fh.seq == 1U);
    FT_TX_ASSERT(fh.len == 1U + NOX_MAC_LEN);
    FT_TX_ASSERT(file_got == FRAME_HEADER_WIRE_SIZE + (size_t)fh.len);
    n = noise_decrypt(&rx, file_wire, FRAME_HEADER_WIRE_SIZE,
                      file_wire + FRAME_HEADER_WIRE_SIZE, fh.len, pt);
    FT_TX_ASSERT(n == 1);
    FT_TX_ASSERT(pt[0] == 'A');

    /* Kuyruk boşaldı: transfer tamamlanır, oturum canlı kalır. */
    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->fd >= 0);
    FT_TX_ASSERT(ps->tx_seq == 2U);

    fixture_tx_teardown();
    return 0;
}

/* 7) C2 fatal TX: kalıcı yazma hatası (EBADF/EPIPE), HİÇ byte yazılmadı.
 * Başarılı şifreleme nonce'u tüketmiştir; rollback yasak. Frame
 * düşürülemez, bu yüzden zero-byte/kalıcı hata teardown'dır.
 */
static int test_tx_chunk_zero_byte_write_disconnects(void)
{
    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    /* Yazma yönü kapalı bir fd: send() kesin EBADF döndürür. */
    close(ps->fd);
    ps->fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    FT_TX_ASSERT(ps->fd >= 0);

    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;

    /* Gerçek AEAD: nonce tüketilir (tx.n=1), commit tx_seq'i artırır. */
    FT_TX_ASSERT(stage_one_byte_chunk(ps) == 0);
    FT_TX_ASSERT(ps->session->tx.n == 1);
    FT_TX_ASSERT(ps->tx_seq == 1);
    FT_TX_ASSERT(frame_queue_count(ps) == 1);

    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_IO);

    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_file.fd == -1);

    /* Kalıcı hata: nonce tüketildi ve geri alınamaz; frame
     * düşürülemez. Teardown sözleşmesi. */
    FT_TX_ASSERT(ps->session == NULL);
    FT_TX_ASSERT(ps->tx_seq == 0);
    FT_TX_ASSERT(ps->fd == -1);
    FT_TX_ASSERT(ps->state == ST_IDLE);

    fixture_tx_teardown();
    return 0;
}

/* 8) C2 fatal TX: KISMİ frame kabloda kaldıktan sonra kalıcı hata.
 * Stream yeniden senkronize edilemez; transferle birlikte oturum kapanır.
 * (Kısmi yazım + EAGAIN teardown DEĞİLDİR; bu test kalıcı hatayı kurar.)
 */
static int test_tx_chunk_partial_write_disconnects(void)
{
    FT_TX_ASSERT(fixture_tx(true) == 0);
    struct peer_session *ps = &st.peers[0];

    FT_TX_ASSERT(g_tx_prefill_len > 4096U);

    /* 4096 byte boşluk aç: 4125 B'lik FILE frame'in ilk 4096 byte'ı
     * gerçekten yazılsın, son 29 byte EAGAIN'de kuyrukta kalsın. */
    FT_TX_ASSERT(drain_discard(g_tx_peer_fd, 4096) == 0);

    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;

    uint8_t chunk[4096];
    memset(chunk, 0x5A, sizeof(chunk));
    FT_TX_ASSERT(stage_file_chunk(ps, chunk, sizeof(chunk)) == 0);
    FT_TX_ASSERT(ps->session->tx.n == 1);
    FT_TX_ASSERT(ps->tx_seq == 1);

    struct frame_queue_slot *slot = &ps->tx_frames.slots[ps->tx_frames.head];

    /* Kısmi yazım + EAGAIN: kopma YOK, offset korunur. */
    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_AGAIN);
    FT_TX_ASSERT(ps->fd >= 0);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->state == ST_FILE_TX);
    FT_TX_ASSERT(slot->off > 0U);
    FT_TX_ASSERT(slot->off < slot->len);

    /* Alıcıyı kapat: kalan yazım kalıcı hataya döner. */
    close(g_tx_peer_fd);
    g_tx_peer_fd = -1;

    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_IO);

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
    FT_TX_ASSERT(ps->tx_seq == 1); /* metadata commit */
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 1);
    FT_TX_ASSERT(frame_queue_count(ps) == 1);

    /* C2 kuyruk doldurucu: metadata kuyrukta olsa da chunk girer. */
    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->tx_file.sent_bytes == 1);
    FT_TX_ASSERT(ps->tx_seq == 2);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 2);
    FT_TX_ASSERT(frame_queue_count(ps) == 2);

    /* Tüm byte'lar commit edildi ama kuyruk dolu: bitiş flush sonrası. */
    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FT_TX_ASSERT(frame_queue_empty(ps));
    FT_TX_ASSERT(ps->tx_file.active == true);

    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->tx_seq == 2);
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

    /* Kuyruk doldurucu 2 chunk'ı da commit eder; tx_seq/nonce birlikte
     * ilerler, bitiş kuyruk boşalınca gelir. */
    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.sent_bytes == 5000);
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->tx_seq == 3); /* metadata + 2 chunk */
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 3);
    FT_TX_ASSERT(frame_queue_count(ps) == 3);

    FT_TX_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FT_TX_ASSERT(frame_queue_empty(ps));

    file_transfer_handle_tx(&st, ps);
    FT_TX_ASSERT(ps->tx_file.active == false);
    FT_TX_ASSERT(ps->tx_file.fd == -1);
    FT_TX_ASSERT(ps->tx_file.plain_buf == NULL);
    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->tx_seq == 3);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == 3);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->fd >= 0);

    fixture_tx_teardown();
    return 0;
}

/* 14) 100 chunk'lık dosya akışı: küçük SO_SNDBUF + kısmi yazımlar.
 * Alıcı tüm frame'leri sırayla çözer; METADATA boyut/hash alanları ve
 * birleşik içerik BLAKE2b hash'i kaynak dosyayla birebir eşleşir. */
static int test_tx_file_stream(void)
{
    enum { TOTAL = 409600, CHUNK = 4096, FRAMES = TOTAL / CHUNK };

    FT_TX_ASSERT(fixture_tx(false) == 0);
    struct peer_session *ps = &st.peers[0];

    /* Deterministik içerik. */
    uint8_t *content = malloc(TOTAL);
    FT_TX_ASSERT(content != NULL);
    for (size_t i = 0; i < (size_t)TOTAL; i++)
        content[i] = (uint8_t)((i * 31U + 7U) & 0xFFU);

    int fd = open(g_tx_src_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    FT_TX_ASSERT(fd >= 0);
    size_t wrote = 0;
    while (wrote < (size_t)TOTAL) {
        ssize_t w = write(fd, content + wrote, (size_t)TOTAL - wrote);
        if (w < 0 && errno == EINTR)
            continue;
        FT_TX_ASSERT(w > 0);
        wrote += (size_t)w;
    }
    FT_TX_ASSERT(close(fd) == 0);

    /* Beklenen: BLAKE2b(size_be64 || içerik) — üretim TX/RX kalıbı. */
    uint8_t size_be[8];
    uint64_t total_u = (uint64_t)TOTAL;
    for (size_t i = 0; i < 8U; i++)
        size_be[i] = (uint8_t)(total_u >> (56U - 8U * i));

    uint8_t expect_hash[32];
    crypto_generichash_state hs;
    FT_TX_ASSERT(crypto_generichash_init(&hs, NULL, 0, 32) == 0);
    FT_TX_ASSERT(crypto_generichash_update(&hs, size_be, 8) == 0);
    FT_TX_ASSERT(crypto_generichash_update(&hs, content, TOTAL) == 0);
    FT_TX_ASSERT(crypto_generichash_final(&hs, expect_hash, 32) == 0);

    /* Küçük tampon: flush'lar kısmi yazsın. */
    int sndbuf = 4096;
    FT_TX_ASSERT(setsockopt(ps->fd, SOL_SOCKET, SO_SNDBUF,
                            &sndbuf, sizeof(sndbuf)) == 0);

    file_transfer_start(&st, g_tx_src_path);
    FT_TX_ASSERT(ps->tx_file.active == true);
    FT_TX_ASSERT(ps->tx_seq == 1U); /* METADATA */

    const size_t wire_cap = 1U << 20;
    uint8_t *wire = malloc(wire_cap);
    FT_TX_ASSERT(wire != NULL);
    size_t wire_len = 0;

    struct noise_session rx;
    init_cipher_session(&rx, 0);

    crypto_generichash_state got_hs;
    FT_TX_ASSERT(crypto_generichash_init(&got_hs, NULL, 0, 32) == 0);
    FT_TX_ASSERT(crypto_generichash_update(&got_hs, size_be, 8) == 0);

    uint8_t pt[NOX_MAX_MSG_LEN + 1];
    size_t frames_seen = 0;
    uint64_t payload_bytes = 0;
    bool saw_partial = false;
    int rounds = 0;

    for (;;) {
        nox_err_t err = frame_queue_flush(&st, ps);
        FT_TX_ASSERT(err == NOX_OK || err == NOX_ERR_AGAIN);

        if (err == NOX_ERR_AGAIN && frame_queue_count(ps) > 0) {
            struct frame_queue_slot *s =
                &ps->tx_frames.slots[ps->tx_frames.head];
            if (s->off > 0U && s->off < s->len)
                saw_partial = true;
        }

        if (ps->tx_file.active && frame_queue_free(ps) > 0)
            file_transfer_handle_tx(&st, ps);

        if (wire_len < wire_cap) {
            wire_len += drain_avail(g_tx_peer_fd, wire + wire_len,
                                    wire_cap - wire_len);
        }

        /* Tamamlanan frame'leri sırayla çöz. */
        size_t pos = 0;
        while (wire_len - pos >= FRAME_HEADER_WIRE_SIZE) {
            struct frame_header fh;
            FT_TX_ASSERT(frame_header_decode(wire + pos, &fh) == NOX_OK);
            size_t flen = FRAME_HEADER_WIRE_SIZE + (size_t)fh.len;
            if (wire_len - pos < flen)
                break;

            FT_TX_ASSERT(fh.seq == (uint32_t)frames_seen);
            ssize_t d = noise_decrypt(&rx, wire + pos,
                                      FRAME_HEADER_WIRE_SIZE,
                                      wire + pos + FRAME_HEADER_WIRE_SIZE,
                                      fh.len, pt);
            FT_TX_ASSERT(d > 0);
            FT_TX_ASSERT(fh.type == NOX_MSG_FILE);

            if (frames_seen == 0) {
                FT_TX_ASSERT(d == 305);
                FT_TX_ASSERT(memcmp(pt, "METADATA", 9) == 0);

                uint64_t declared = 0;
                for (size_t i = 0; i < 8U; i++)
                    declared = (declared << 8) | pt[265U + i];
                FT_TX_ASSERT(declared == total_u);
                FT_TX_ASSERT(memcmp(pt + 273, expect_hash, 32) == 0);
            } else {
                FT_TX_ASSERT((uint64_t)d <= (uint64_t)CHUNK);
                FT_TX_ASSERT(payload_bytes + (uint64_t)d <= total_u);
                FT_TX_ASSERT(memcmp(pt, content + payload_bytes,
                                    (size_t)d) == 0);
                FT_TX_ASSERT(crypto_generichash_update(&got_hs, pt,
                                                       (size_t)d) == 0);
                payload_bytes += (uint64_t)d;
            }

            frames_seen++;
            pos += flen;
        }
        if (pos > 0) {
            memmove(wire, wire + pos, wire_len - pos);
            wire_len -= pos;
        }

        if (!ps->tx_file.active && frame_queue_empty(ps) && wire_len == 0)
            break;
        FT_TX_ASSERT(++rounds < 200000);
    }

    FT_TX_ASSERT(frames_seen == (size_t)FRAMES + 1U);
    FT_TX_ASSERT(payload_bytes == total_u);
    FT_TX_ASSERT(saw_partial);

    uint8_t got_hash[32];
    FT_TX_ASSERT(crypto_generichash_final(&got_hs, got_hash, 32) == 0);
    FT_TX_ASSERT(sodium_memcmp(got_hash, expect_hash, 32) == 0);

    FT_TX_ASSERT(ps->state == ST_ACTIVE);
    FT_TX_ASSERT(ps->tx_seq == (uint32_t)FRAMES + 1U);
    FT_TX_ASSERT(atomic_load(&ps->session->tx.n) == (uint64_t)FRAMES + 1U);
    FT_TX_ASSERT(ps->session != NULL);
    FT_TX_ASSERT(ps->fd >= 0);
    FT_TX_ASSERT(frame_queue_empty(ps));

    free(wire);
    free(content);
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
    RUN_TEST(test_tx_metadata_partial_no_disconnect);
    RUN_TEST(test_tx_chunk_zero_byte_write_disconnects);
    RUN_TEST(test_tx_chunk_partial_write_disconnects);
    RUN_TEST(test_rx_metadata_during_tx_rejected);
    RUN_TEST(test_start_and_complete_file_tx);
    RUN_TEST(test_tx_encrypt_without_nonce_keeps_session);
    RUN_TEST(test_tx_encrypt_exhausted_nonce_tears_down);
    RUN_TEST(test_tx_multi_chunk_success);
    RUN_TEST(test_tx_file_stream);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
