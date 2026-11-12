/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_tx_order.c — C2: FILE/TEXT ortak TX kuyruğu sıra sözleşmesi
 *
 * Kapsam:
 *   1. FILE chunk kuyrukta beklerken gelen TEXT aynı kuyruğa girer;
 *      wire sırası birebir: chunk k → TEXT k+1. Transfer, kuyruk
 *      boşalınca tamamlanır (nonce sırası = wire sırası).
 *   2. Kuyrukta TEXT varken FILE başlatılabilir (Q3); METADATA ve ilk
 *      chunk sıranın sonuna girer: TEXT k → METADATA k+1 → chunk k+2.
 *   3. Disconnect cleanup kuyruğu ve transfer state'ini zeroize eder.
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "noise.h"
#include "frame_queue.h"
#include "state_machine.h"
#include "stdin_handler.h"
#include "file_transfer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>

#include "test_common.h"

static struct app_state st;
static int g_rx_fd = -1;
static int g_epfd = -1;
static FILE *g_tmp_file = NULL;
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
    if (g_tmp_file) {
        fclose(g_tmp_file);
        g_tmp_file = NULL;
    }
    if (g_tmp_created) {
        unlink(g_tmp_path);
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

static int make_tmp_file(const void *payload, size_t len)
{
    static const char tmpl[] = "/tmp/opencode/c2_tx_order_XXXXXX";
    memcpy(g_tmp_path, tmpl, sizeof(tmpl));
    int fd = mkstemp(g_tmp_path);
    if (fd < 0)
        return -1;
    g_tmp_created = true;
    if (write(fd, payload, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0)
        return -1;
    return 0;
}

static int fixture_setup(const void *payload, size_t len)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx = 0;
    st.epoll_fd = -1;

    if (make_tmp_file(payload, len) != 0)
        return -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;

    struct peer_session *ps = &st.peers[0];
    ps->fd = sv[0];
    g_rx_fd = sv[1];
    ps->state = ST_ACTIVE;
    ps->tx_file.fd = -1;

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

/* Transferi metadata yazmadan hazırla: gerçek dosya fd + plain_buf. */
static int arm_tx_file(struct peer_session *ps)
{
    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;
    ps->tx_file.fd = open(g_tmp_path, O_RDONLY | O_CLOEXEC);
    if (ps->tx_file.fd < 0)
        return -1;
    ps->tx_file.plain_buf = sodium_malloc(4096);
    if (!ps->tx_file.plain_buf)
        return -1;
    ps->tx_file.total_size = 2;
    ps->tx_file.sent_bytes = 0;
    memcpy(ps->tx_file.filename, "ab.bin", sizeof("ab.bin"));
    return 0;
}

/* Production enqueue ile aynı sıra; frame kuyrukta biriktirilir. */
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

    return frame_queue_commit(ps, FRAME_HEADER_WIRE_SIZE + (size_t)ct_len) ==
                   NOX_OK
               ? 0
               : -1;
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

static int expect_text(int fd, struct noise_session *rx, uint32_t seq,
                       const char *text)
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
    size_t len = strlen(text);
    if (n != (ssize_t)(len + 1U) || memcmp(pt, text, len) != 0 ||
        pt[len] != '\0')
        return -1;
    return 0;
}

static int expect_file(int fd, struct noise_session *rx, uint32_t seq,
                       const void *data, size_t len)
{
    struct frame_header fh;
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    uint8_t ct[NOX_MAX_MSG_LEN + NOX_MAC_LEN];
    uint8_t pt[NOX_MAX_MSG_LEN + 1];

    if (read_frame(fd, &fh, wire, ct) != 0)
        return -1;
    if (fh.type != NOX_MSG_FILE || fh.seq != seq)
        return -1;

    ssize_t n = noise_decrypt(rx, wire, sizeof(wire), ct, fh.len, pt);
    if (n != (ssize_t)len || memcmp(pt, data, len) != 0)
        return -1;
    return 0;
}

#define TX_ASSERT(cond) do {                                           \
    if (!(cond)) {                                                     \
        fixture_teardown();                                            \
        TEST_ASSERT(cond);                                             \
    }                                                                  \
} while (0)

/* 1) FILE chunk beklerken TEXT aynı kuyruğa girer; sıra korunur. */
static int test_file_chunk_then_text(void)
{
    TX_ASSERT(fixture_setup("AB", 2) == 0);
    struct peer_session *ps = &st.peers[0];
    TX_ASSERT(arm_tx_file(ps) == 0);

    /* FILE chunk kuyruğa girer; henüz sokete yazılmadı. */
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(ps->tx_file.active);
    TX_ASSERT(ps->tx_file.sent_bytes == 2U);
    TX_ASSERT(ps->tx_seq == 6U);
    TX_ASSERT(frame_queue_count(ps) == 1U);

    /* TEXT aynı kuyruğa girer ve kuyruk sırayla flush edilir. */
    TX_ASSERT(send_segmented_message_to(&st, ps, "hello") == NOX_OK);
    TX_ASSERT(ps->tx_seq == 7U);
    TX_ASSERT(frame_queue_empty(ps));

    /* Transfer, kuyruk boşaldıktan sonra tamamlanır. */
    TX_ASSERT(ps->tx_file.active);
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(!ps->tx_file.active);
    TX_ASSERT(ps->state == ST_ACTIVE);

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    TX_ASSERT(expect_file(g_rx_fd, &rx, 5U, "AB", 2U) == 0);
    TX_ASSERT(expect_text(g_rx_fd, &rx, 6U, "hello") == 0);

    fixture_teardown();
    return 0;
}

/* 2) Q3: kuyrukta TEXT varken FILE başlar; METADATA sıranın sonuna girer. */
static int test_text_then_file_start(void)
{
    TX_ASSERT(fixture_setup("C", 1) == 0);
    struct peer_session *ps = &st.peers[0];

    TX_ASSERT(stage_text_frame(ps, "wait") == 0);
    TX_ASSERT(ps->tx_seq == 6U);
    TX_ASSERT(frame_queue_count(ps) == 1U);

    file_transfer_start(&st, g_tmp_path);
    TX_ASSERT(ps->tx_file.active);
    TX_ASSERT(ps->state == ST_FILE_TX);
    TX_ASSERT(ps->tx_seq == 7U); /* TEXT + METADATA */
    TX_ASSERT(frame_queue_count(ps) == 2U);

    /* İlk chunk da sıranın sonuna girer (free slot var). */
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(ps->tx_file.sent_bytes == 1U);
    TX_ASSERT(ps->tx_seq == 8U);
    TX_ASSERT(frame_queue_count(ps) == 3U);

    TX_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    TX_ASSERT(frame_queue_empty(ps));

    /* Kuyruk boşaldı: transfer tamamlanır. */
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(!ps->tx_file.active);
    TX_ASSERT(ps->state == ST_ACTIVE);

    struct noise_session rx;
    init_cipher_session(&rx, 5);
    TX_ASSERT(expect_text(g_rx_fd, &rx, 5U, "wait") == 0);

    struct frame_header fh;
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    uint8_t ct[NOX_MAX_MSG_LEN + NOX_MAC_LEN];
    uint8_t pt[NOX_MAX_MSG_LEN + 1];
    TX_ASSERT(read_frame(g_rx_fd, &fh, wire, ct) == 0);
    TX_ASSERT(fh.type == NOX_MSG_FILE && fh.seq == 6U);
    ssize_t n = noise_decrypt(&rx, wire, sizeof(wire), ct, fh.len, pt);
    TX_ASSERT(n == 305 && memcmp(pt, "METADATA", 9) == 0);

    TX_ASSERT(expect_file(g_rx_fd, &rx, 7U, "C", 1U) == 0);

    fixture_teardown();
    return 0;
}

/* 3) Disconnect cleanup kuyruğu ve transfer state'ini zeroize eder. */
static int test_cleanup_zeroes_queue(void)
{
    TX_ASSERT(fixture_setup("C", 1) == 0);
    struct peer_session *ps = &st.peers[0];

    for (unsigned i = 0; i < FRAME_QUEUE_SLOTS; i++)
        TX_ASSERT(stage_text_frame(ps, "q") == 0);
    TX_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);

    TX_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);
    TX_ASSERT(ps->fd == -1);
    TX_ASSERT(ps->session == NULL);
    TX_ASSERT(ps->tx_seq == 0U);
    TX_ASSERT(frame_queue_count(ps) == 0U);
    TX_ASSERT(!ps->tx_file.active);
    TX_ASSERT(ps->tx_file.fd == -1);

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }
    fprintf(stderr, "\n=== C2 — FILE/TEXT kuyruk sırası ===\n");
    RUN_TEST(test_file_chunk_then_text);
    RUN_TEST(test_text_then_file_start);
    RUN_TEST(test_cleanup_zeroes_queue);
    fprintf(stderr, "=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
