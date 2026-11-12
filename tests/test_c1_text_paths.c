/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_c1_text_paths.c — C1/C2: TEXT gönderim yolları entegrasyon testleri
 *
 * Kapsam:
 *   1. Çok parçalı TEXT: nonce sırası = şifreleme sırası = wire sırası;
 *      alıcı gerçek AEAD ile çözer.
 *   2. DB kuyruğu callback'i: slot dolu → AGAIN + db_retry_pending;
 *      kuyruk boşalınca aynı callback başarıyla yazar.
 *   3. Kuyruk dolu → yeni TEXT AGAIN; hiçbir frame şifrelenmez,
 *      nonce tüketilmez, kuyruk değişmez.
 *   4. Preflight: mesaj kalan boş slotlara sığmıyorsa tamamen reddedilir;
 *      kuyruk boşalınca aynı mesaj tek seferde girer.
 *   5. C2/Q3: FILE başlangıcı kuyrukta TEXT varken de yapılabilir;
 *      METADATA sıranın sonuna girer.
 *   6. Kuyrukta boş slot yoksa FILE başlangıcı reddedilir; nonce tüketilmez.
 *   7. Disconnect cleanup: frame kuyruğu, session ve tx_seq zeroize edilir.
 *   8. C2/Q1: >16 KB mesaj (5 frame) 4 slotlu kuyruğa sığmaz → AGAIN;
 *      hiçbir frame şifrelenmez, kuyruk boş kalır.
 *   9. Küçük SO_SNDBUF + kuyruk dolu: EAGAIN altında offset'li ilerleme;
 *      hiçbir frame kaybolmaz, duplike olmaz.
 *  10. FILE başlangıcı EPOLLOUT ilgisini kendisi kurar (liveness).
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "noise.h"
#include "frame_queue.h"
#include "state_machine.h"
#include "stdin_handler.h"
#include "file_transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include "test_common.h"

static struct app_state st;
static int g_rx_fd = -1;
static int g_epfd = -1;
static char *g_msg = NULL;
static char *g_aux = NULL;
static char g_tmp_path[64];
static bool g_tmp_created = false;

static void fixture_teardown(void)
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
    if (ps->hs) {
        sodium_memzero(ps->hs, sizeof(*ps->hs));
        sodium_free(ps->hs);
        ps->hs = NULL;
    }
    if (ps->fd >= 0) {
        close(ps->fd);
        ps->fd = -1;
    }
    if (g_rx_fd >= 0) {
        close(g_rx_fd);
        g_rx_fd = -1;
    }
    if (g_epfd >= 0) {
        close(g_epfd);
        g_epfd = -1;
    }

    free(g_msg);
    g_msg = NULL;
    free(g_aux);
    g_aux = NULL;

    if (g_tmp_created) {
        (void)unlink(g_tmp_path);
        g_tmp_created = false;
    }
    g_tmp_path[0] = '\0';

    sodium_memzero(&st, sizeof(st));
}

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

static int fixture_setup(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx = 0;
    st.epoll_fd = -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;

    struct peer_session *ps = &st.peers[0];
    ps->fd = sv[0];
    ps->tx_file.fd = -1;
    ps->rx_file.fd = -1;
    ps->state = ST_ACTIVE;
    g_rx_fd = sv[1];

    ps->session = sodium_malloc(sizeof(*ps->session));
    if (!ps->session)
        return -1;
    init_cipher_session(ps->session, 5);
    ps->tx_seq = 5;

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0)
        return -1;
    st.epoll_fd = g_epfd;

    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLOUT,
        .data.fd = ps->fd,
    };
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, ps->fd, &ev) != 0)
        return -1;

    return 0;
}

/* Production enqueue_frame() ile aynı sıra: header → AD → noise_encrypt
 * → frame_queue_commit. Frames sokete YAZILMAZ; kuyrukta biriktirilir. */
static int stage_text_frame(struct peer_session *ps, const char *text)
{
    size_t pt_len = strlen(text) + 1;
    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_TEXT,
        .seq = ps->tx_seq,
        .len = (uint32_t)(pt_len + NOX_MAC_LEN),
    };

    uint8_t *slot = frame_queue_reserve(ps);
    if (!slot)
        return -1;

    frame_ad(&fh, slot);
    ssize_t ct_len = noise_encrypt(ps->session, slot, FRAME_HEADER_WIRE_SIZE,
                                   (const uint8_t *)text, pt_len,
                                   slot + FRAME_HEADER_WIRE_SIZE);
    if (ct_len != (ssize_t)fh.len)
        return -1;

    if (frame_queue_commit(ps, FRAME_HEADER_WIRE_SIZE + (size_t)ct_len) !=
        NOX_OK)
        return -1;

    return 0;
}

static int alloc_msg(char **slot, size_t len, char fill)
{
    *slot = malloc(len + 1U);
    if (!*slot)
        return -1;
    memset(*slot, (unsigned char)fill, len);
    (*slot)[len] = '\0';
    return 0;
}

static int make_tmp_file(void)
{
    static const char tmpl[] = "/tmp/opencode/c1_text_XXXXXX";
    static const char payload[] = "c1-text-test";

    memcpy(g_tmp_path, tmpl, sizeof(tmpl));
    int fd = mkstemp(g_tmp_path);
    if (fd < 0)
        return -1;
    g_tmp_created = true;

    ssize_t w = write(fd, payload, sizeof(payload) - 1U);
    if (w != (ssize_t)(sizeof(payload) - 1U)) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0)
        return -1;

    return 0;
}

static int read_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

static int read_frame(int fd, struct frame_header *fh, uint8_t *wire,
                      uint8_t *ct)
{
    if (read_exact(fd, wire, FRAME_HEADER_WIRE_SIZE) != 0)
        return -1;
    if (frame_header_decode(wire, fh) != NOX_OK)
        return -1;
    if (fh->len > NOX_MAX_MSG_LEN + NOX_MAC_LEN)
        return -1;
    return read_exact(fd, ct, fh->len);
}

static int no_pending_wire_bytes(void)
{
    uint8_t b;
    ssize_t n = recv(g_rx_fd, &b, sizeof(b), MSG_DONTWAIT);
    if (n >= 0)
        return 0;
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
    return errno == EAGAIN || errno == EWOULDBLOCK;
#else
    return errno == EAGAIN;
#endif
}

/* Bir TEXT frame'ini oku, gerçek AEAD ile çöz ve beklenen içerikle
 * karşılaştır. text_len NUL hariç uzunluktur; wire'da NUL de taşınır. */
static int expect_text_frame(int fd, struct noise_session *rx, uint32_t seq,
                             const char *text, size_t text_len)
{
    struct frame_header fh;
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    uint8_t ct[NOX_MAX_MSG_LEN + NOX_MAC_LEN];
    uint8_t pt[NOX_MAX_MSG_LEN + 1];

    if (read_frame(fd, &fh, wire, ct) != 0)
        return -1;
    if (fh.type != NOX_MSG_TEXT || fh.seq != seq)
        return -1;

    ssize_t n = noise_decrypt(rx, wire, sizeof(wire), ct, fh.len, pt);
    if (n != (ssize_t)(text_len + 1U))
        return -1;
    if (memcmp(pt, text, text_len) != 0)
        return -1;
    if (pt[text_len] != '\0')
        return -1;

    return 0;
}

static bool mem_is_zero(const void *ptr, size_t len)
{
    const uint8_t *p = ptr;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

/* Başarısızlıkta fixture'ı da kapat: ASan/leak raporu testin kendi
 * FAIL satırını gölgelemesin. */
#define C1_ASSERT(cond) do {                                           \
    if (!(cond)) {                                                     \
        fixture_teardown();                                            \
        TEST_ASSERT(cond);                                             \
    }                                                                  \
} while (0)

/* 1) 9000 B → 4000 + 4000 + 1000 = 3 frame; AEAD/nonce sırası birebir. */
static int test_segmented_aead_roundtrip(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    C1_ASSERT(alloc_msg(&g_aux, 9000U, 'a') == 0);
    for (size_t i = 0; i < 9000U; i++)
        g_aux[i] = (char)('a' + (int)(i % 26U));

    C1_ASSERT(send_segmented_message_to(&st, ps, g_aux) == NOX_OK);
    C1_ASSERT(frame_queue_empty(ps));
    C1_ASSERT(ps->tx_seq == 8U); /* 5 + 3 */

    struct noise_session rx;
    init_cipher_session(&rx, 5);

    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 5U, g_aux, 4000U) == 0);
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 6U, g_aux + 4000U, 4000U) == 0);
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 7U, g_aux + 8000U, 1000U) == 0);
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 2) Kuyruk dolu → callback AGAIN + retry bayrağı; boşalınca başarı. */
static int test_send_queued_callback_queue_full(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];
    static const char *const staged[FRAME_QUEUE_SLOTS] = {
        "q0", "q1", "q2", "q3"
    };
    struct queue_flush_ctx ctx = {
        .state = &st,
        .ps = ps,
    };

    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++)
        C1_ASSERT(stage_text_frame(ps, staged[i]) == 0);

    C1_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    C1_ASSERT(ps->tx_seq == 5U + (uint32_t)FRAME_QUEUE_SLOTS);
    uint32_t seq_before = ps->tx_seq;
    uint64_t nonce_before = atomic_load(&ps->session->tx.n);
    C1_ASSERT(no_pending_wire_bytes());

    /* Kuyruk dolu → şifreleme YOK, nonce tüketilmez, satır silinmez. */
    C1_ASSERT(send_queued_callback("db-msg", &ctx) == NOX_ERR_AGAIN);
    C1_ASSERT(ps->db_retry_pending);
    C1_ASSERT(ps->tx_seq == seq_before);
    C1_ASSERT(atomic_load(&ps->session->tx.n) == nonce_before);
    C1_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    C1_ASSERT(no_pending_wire_bytes());

    /* Kuyruğu boşalt; aynı callback bu kez yazar. */
    C1_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    C1_ASSERT(frame_queue_empty(ps));
    C1_ASSERT(send_queued_callback("db-msg", &ctx) == NOX_OK);
    C1_ASSERT(ps->tx_seq == seq_before + 1U);

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++) {
        C1_ASSERT(expect_text_frame(g_rx_fd, &rx, (uint32_t)(5U + i),
                                    staged[i], strlen(staged[i])) == 0);
    }
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, seq_before, "db-msg", 6U) == 0);
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 3) Kuyruk dolu → yeni TEXT AGAIN; nonce/kuyruk/seq değişmez. */
static int test_queue_full_returns_again(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];
    static const char *const staged[FRAME_QUEUE_SLOTS] = {
        "q0", "q1", "q2", "q3"
    };

    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++)
        C1_ASSERT(stage_text_frame(ps, staged[i]) == 0);

    C1_ASSERT(ps->tx_seq == 9U);
    uint64_t nonce_before = atomic_load(&ps->session->tx.n);

    /* Kuyruk dolu → mesaj kabul edilmez; hiçbir frame şifrelenmez. */
    C1_ASSERT(send_segmented_message_to(&st, ps, "ilk") == NOX_ERR_AGAIN);
    C1_ASSERT(send_segmented_message_to(&st, ps, "ikinci") == NOX_ERR_AGAIN);
    C1_ASSERT(ps->tx_seq == 9U);
    C1_ASSERT(atomic_load(&ps->session->tx.n) == nonce_before);
    C1_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    C1_ASSERT(no_pending_wire_bytes());

    /* Kuyruk boşalınca mesaj tek seferde ve tam olarak çıkar. */
    C1_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    C1_ASSERT(send_segmented_message_to(&st, ps, "ilk") == NOX_OK);
    C1_ASSERT(ps->tx_seq == 10U);

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++) {
        C1_ASSERT(expect_text_frame(g_rx_fd, &rx, (uint32_t)(5U + i),
                                    staged[i], strlen(staged[i])) == 0);
    }
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 9U, "ilk", 3U) == 0);
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 4) Preflight: kalan slotlara sığmayan mesaj tamamen reddedilir;
 * kuyruk boşalınca aynı mesaj iki frame olarak girer. */
static int test_partial_fit_returns_again(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];
    static const char *const staged[3] = {"s0", "s1", "s2"};

    for (size_t i = 0; i < 3U; i++)
        C1_ASSERT(stage_text_frame(ps, staged[i]) == 0);
    C1_ASSERT(ps->tx_seq == 8U);

    /* 4500 B → 2 frame; yalnız 1 boş slot var → preflight AGAIN. */
    C1_ASSERT(alloc_msg(&g_aux, 4500U, 'M') == 0);
    uint64_t nonce_before = atomic_load(&ps->session->tx.n);
    C1_ASSERT(send_segmented_message_to(&st, ps, g_aux) == NOX_ERR_AGAIN);
    C1_ASSERT(ps->tx_seq == 8U);
    C1_ASSERT(atomic_load(&ps->session->tx.n) == nonce_before);
    C1_ASSERT(frame_queue_count(ps) == 3U);
    C1_ASSERT(no_pending_wire_bytes());

    /* Kuyruk boşaltılınca aynı mesaj eksiksiz kuyruğa girer. */
    C1_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    C1_ASSERT(send_segmented_message_to(&st, ps, g_aux) == NOX_OK);
    C1_ASSERT(frame_queue_empty(ps));
    C1_ASSERT(ps->tx_seq == 10U); /* 8 + 2 */

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    for (size_t i = 0; i < 3U; i++) {
        C1_ASSERT(expect_text_frame(g_rx_fd, &rx, (uint32_t)(5U + i),
                                    staged[i], strlen(staged[i])) == 0);
    }
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 8U, g_aux, 4000U) == 0);
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 9U, g_aux + 4000U, 500U) == 0);
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 5) C2/Q3: kuyrukta TEXT varken FILE başlangıcı kabul edilir;
 * METADATA kuyruk sırasına (TEXT'in arkasına) girer. */
static int test_file_start_queues_behind_text(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    C1_ASSERT(make_tmp_file() == 0);
    C1_ASSERT(stage_text_frame(ps, "bekleyen") == 0);
    C1_ASSERT(ps->tx_seq == 6U);

    file_transfer_start(&st, g_tmp_path);

    C1_ASSERT(ps->tx_file.active);
    C1_ASSERT(ps->state == ST_FILE_TX);
    C1_ASSERT(ps->tx_seq == 7U); /* TEXT + METADATA */
    C1_ASSERT(frame_queue_count(ps) == 2U);
    C1_ASSERT(ps->tx_file.sent_bytes == 0U);
    C1_ASSERT(atomic_load(&ps->session->tx.n) == 7U);

    /* Wire sırası: önce TEXT, sonra METADATA. */
    C1_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 5U, "bekleyen", 8U) == 0);

    struct frame_header fh;
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    uint8_t ct[NOX_MAX_MSG_LEN + NOX_MAC_LEN];
    uint8_t pt[NOX_MAX_MSG_LEN + 1];
    C1_ASSERT(read_frame(g_rx_fd, &fh, wire, ct) == 0);
    C1_ASSERT(fh.type == NOX_MSG_FILE && fh.seq == 6U);
    ssize_t n = noise_decrypt(&rx, wire, sizeof(wire), ct, fh.len, pt);
    C1_ASSERT(n == 305);
    C1_ASSERT(memcmp(pt, "METADATA", 9) == 0);
    C1_ASSERT(no_pending_wire_bytes());

    /* İlk chunk'ı kuyruğa al ve flush et; sonra drained bitişi. */
    file_transfer_handle_tx(&st, ps);
    C1_ASSERT(ps->tx_file.active);
    C1_ASSERT(ps->tx_seq == 8U); /* + FILE chunk */
    C1_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    C1_ASSERT(read_frame(g_rx_fd, &fh, wire, ct) == 0);
    C1_ASSERT(fh.type == NOX_MSG_FILE && fh.seq == 7U);
    n = noise_decrypt(&rx, wire, sizeof(wire), ct, fh.len, pt);
    C1_ASSERT(n == (ssize_t)(sizeof("c1-text-test") - 1U));

    file_transfer_handle_tx(&st, ps);
    C1_ASSERT(!ps->tx_file.active);
    C1_ASSERT(ps->state == ST_ACTIVE);
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 6) Boş slot yoksa FILE başlangıcı reddedilir; nonce tüketilmez.
 * Kuyruk boşalınca aynı dosya başlatılabilir. */
static int test_file_start_rejected_when_no_free_slot(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];
    static const char *const staged[FRAME_QUEUE_SLOTS] = {
        "q0", "q1", "q2", "q3"
    };

    C1_ASSERT(make_tmp_file() == 0);
    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++)
        C1_ASSERT(stage_text_frame(ps, staged[i]) == 0);

    uint32_t seq_before = ps->tx_seq;
    uint64_t nonce_before = atomic_load(&ps->session->tx.n);
    C1_ASSERT(seq_before == 9U);

    file_transfer_start(&st, g_tmp_path);

    C1_ASSERT(!ps->tx_file.active);
    C1_ASSERT(ps->tx_file.fd == -1);
    C1_ASSERT(ps->tx_file.plain_buf == NULL);
    C1_ASSERT(ps->tx_seq == seq_before);
    C1_ASSERT(atomic_load(&ps->session->tx.n) == nonce_before);
    C1_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    C1_ASSERT(no_pending_wire_bytes());

    /* Red sonrası normal akış: kuyruk boşalınca dosya başlar. */
    C1_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    file_transfer_start(&st, g_tmp_path);
    C1_ASSERT(ps->tx_file.active);
    C1_ASSERT(ps->state == ST_FILE_TX);
    C1_ASSERT(ps->tx_seq == seq_before + 1U); /* yalnız METADATA */

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++) {
        C1_ASSERT(expect_text_frame(g_rx_fd, &rx, (uint32_t)(5U + i),
                                    staged[i], strlen(staged[i])) == 0);
    }
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 7) Disconnect cleanup: TX kuyruğu/session/seq zeroize. */
static int test_disconnect_cleanup_zeroes_tx_state(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];
    static const char *const staged[FRAME_QUEUE_SLOTS] = {
        "q0", "q1", "q2", "q3"
    };

    for (size_t i = 0; i < (size_t)FRAME_QUEUE_SLOTS; i++)
        C1_ASSERT(stage_text_frame(ps, staged[i]) == 0);

    ps->db_retry_pending = true;

    C1_ASSERT(ps->tx_seq == 9U);
    C1_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    C1_ASSERT(!mem_is_zero(&ps->tx_frames, sizeof(ps->tx_frames)));

    C1_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    C1_ASSERT(ps->state == ST_IDLE);
    C1_ASSERT(ps->fd == -1);
    C1_ASSERT(ps->session == NULL);
    C1_ASSERT(ps->tx_seq == 0U);
    C1_ASSERT(ps->rx_seq == 0U);
    C1_ASSERT(!ps->db_retry_pending);
    C1_ASSERT(frame_queue_count(ps) == 0U);
    C1_ASSERT(frame_queue_empty(ps));
    C1_ASSERT(mem_is_zero(&ps->tx_frames, sizeof(ps->tx_frames)));
    C1_ASSERT(!ps->tx_file.active);
    C1_ASSERT(ps->tx_file.fd == -1);
    C1_ASSERT(st.active_peer_idx == -1);

    fixture_teardown();
    return 0;
}

/* 8) C2/Q1: 20000 B = 5 frame > 4 slot → AGAIN; hiçbir nonce tüketilmez,
 * kuyruk boş kalır. Sonraki küçük mesaj normal gönderilir. */
static int test_oversized_segmented_message(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    C1_ASSERT(alloc_msg(&g_msg, 20000U, 'X') == 0);

    uint64_t nonce_before = atomic_load(&ps->session->tx.n);
    C1_ASSERT(send_segmented_message_to(&st, ps, g_msg) == NOX_ERR_AGAIN);
    C1_ASSERT(frame_queue_empty(ps));
    C1_ASSERT(ps->tx_seq == 5U);
    C1_ASSERT(atomic_load(&ps->session->tx.n) == nonce_before);
    C1_ASSERT(no_pending_wire_bytes());

    /* Kuyruk kilitlenmedi: sonraki mesaj normal akışta gider. */
    C1_ASSERT(send_segmented_message_to(&st, ps, "sonraki") == NOX_OK);
    C1_ASSERT(ps->tx_seq == 6U);
    C1_ASSERT(frame_queue_empty(ps));

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    C1_ASSERT(expect_text_frame(g_rx_fd, &rx, 5U, "sonraki", 7U) == 0);
    C1_ASSERT(no_pending_wire_bytes());

    fixture_teardown();
    return 0;
}

/* 9) Küçük SO_SNDBUF + 4 frame'lik mesaj: EAGAIN altında kuyruk
 * offset'li ilerler; hiçbir frame kaybolmaz, duplike olmaz. */
static int test_queue_backpressure_resumes_after_eagain(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    int sndbuf = 4096;
    C1_ASSERT(setsockopt(ps->fd, SOL_SOCKET, SO_SNDBUF,
                         &sndbuf, sizeof(sndbuf)) == 0);

    /* Soket tamponunu doldur: flush'lar EAGAIN alacak. */
    uint8_t prefill[1024];
    memset(prefill, 0xEE, sizeof(prefill));
    size_t prefill_len = 0;
    for (;;) {
        ssize_t w = send(ps->fd, prefill, sizeof(prefill),
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w > 0) {
            prefill_len += (size_t)w;
            C1_ASSERT(prefill_len <= 16384U);
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        C1_ASSERT(w < 0 &&
                  (errno == EAGAIN || errno == EWOULDBLOCK));
        break;
    }
    C1_ASSERT(prefill_len > 0U);

    /* 16000 B = tam 4 frame; kuyruk kapasitesine sığar. */
    C1_ASSERT(alloc_msg(&g_msg, 16000U, 'R') == 0);
    C1_ASSERT(send_segmented_message_to(&st, ps, g_msg) == NOX_OK);
    C1_ASSERT(ps->tx_seq == 9U);
    C1_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);

    uint8_t *raw = malloc(65536U);
    C1_ASSERT(raw != NULL);
    C1_ASSERT(prefill_len + 4U * TX_BUF_CAPACITY <= 65536U);
    size_t raw_len = 0;
    int rounds = 0;

    while (!frame_queue_empty(ps)) {
        nox_err_t err = frame_queue_flush(&st, ps);
        C1_ASSERT(err == NOX_OK || err == NOX_ERR_AGAIN);

        for (;;) {
            uint8_t tmp[4096];
            ssize_t r = recv(g_rx_fd, tmp, sizeof(tmp), MSG_DONTWAIT);
            if (r > 0) {
                C1_ASSERT(raw_len + (size_t)r <= 65536U);
                memcpy(raw + raw_len, tmp, (size_t)r);
                raw_len += (size_t)r;
                continue;
            }
            if (r < 0 && errno == EINTR)
                continue;
            break;
        }
        C1_ASSERT(++rounds < 128);
    }

    C1_ASSERT(ps->tx_seq == 9U);
    C1_ASSERT(raw_len > prefill_len);

    /* Wire'ı baştan çöz: 4 frame, sıra ve içerik birebir. */
    const uint8_t *p = raw + prefill_len;
    size_t left = raw_len - prefill_len;
    struct noise_session rx;
    init_cipher_session(&rx, 5);
    for (size_t i = 0; i < 4U; i++) {
        C1_ASSERT(left >= FRAME_HEADER_WIRE_SIZE);
        struct frame_header fh;
        C1_ASSERT(frame_header_decode(p, &fh) == NOX_OK);
        C1_ASSERT(fh.type == NOX_MSG_TEXT);
        C1_ASSERT(fh.seq == 5U + (uint32_t)i);
        size_t flen = FRAME_HEADER_WIRE_SIZE + (size_t)fh.len;
        C1_ASSERT(left >= flen);

        uint8_t pt[NOX_MAX_MSG_LEN + 1];
        ssize_t n = noise_decrypt(&rx, p, FRAME_HEADER_WIRE_SIZE,
                                  p + FRAME_HEADER_WIRE_SIZE, fh.len, pt);
        C1_ASSERT(n == (ssize_t)(4000U + 1U));
        C1_ASSERT(memcmp(pt, g_msg + i * 4000U, 4000U) == 0);
        C1_ASSERT(pt[4000] == '\0');

        p += flen;
        left -= flen;
    }
    C1_ASSERT(left == 0U);

    free(raw);
    fixture_teardown();
    return 0;
}

/* 10) FILE başlangıcı EPOLLOUT ilgisini kendisi kurar; aksi halde
 * METADATA/chunk akışı uyanmaz (liveness). */
static int test_file_start_arms_epollout(void)
{
    C1_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    C1_ASSERT(make_tmp_file() == 0);
    C1_ASSERT(epoll_modify_fd(st.epoll_fd, ps->fd, EPOLLIN) == NOX_OK);

    file_transfer_start(&st, g_tmp_path);
    C1_ASSERT(ps->tx_file.active);
    C1_ASSERT(ps->state == ST_FILE_TX);
    C1_ASSERT(frame_queue_count(ps) == 1U); /* METADATA kuyrukta */

    struct epoll_event out[4];
    int n = epoll_wait(st.epoll_fd, out, 4, 0);
    C1_ASSERT(n == 1);
    C1_ASSERT(out[0].events & EPOLLOUT);

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== C1/C2 — TEXT gönderim yolları ===\n");
    RUN_TEST(test_segmented_aead_roundtrip);
    RUN_TEST(test_send_queued_callback_queue_full);
    RUN_TEST(test_queue_full_returns_again);
    RUN_TEST(test_partial_fit_returns_again);
    RUN_TEST(test_file_start_queues_behind_text);
    RUN_TEST(test_file_start_rejected_when_no_free_slot);
    RUN_TEST(test_disconnect_cleanup_zeroes_tx_state);
    RUN_TEST(test_oversized_segmented_message);
    RUN_TEST(test_queue_backpressure_resumes_after_eagain);
    RUN_TEST(test_file_start_arms_epollout);
    fprintf(stderr, "=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
