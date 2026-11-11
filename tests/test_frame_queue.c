/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_frame_queue.c — C1: TX frame kuyruğu sözleşmesi
 *
 * Kapsam:
 *   - FIFO sırası: enqueue sırası = soket yazma sırası = tx_seq sırası
 *   - Kuyruk dolu → rezervasyon yok (nonce tüketilmeden AGAIN)
 *   - Kısmi yazım → offset ilerler, AGAIN; drain sonrası devam
 *   - Zero-byte/kalıcı yazma hatası → oturum teardown
 *   - reset/cleanup ciphertext'i zeroize eder
 */

#include "common.h"
#include "types.h"
#include "frame_queue.h"
#include "state_machine.h"

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

static void fixture_teardown(void)
{
    struct peer_session *ps = &st.peers[0];

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
    sodium_memzero(&st, sizeof(st));
}

static int fixture_setup(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx = 0;
    st.epoll_fd = -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0)
        return -1;

    struct peer_session *ps = &st.peers[0];
    ps->fd = sv[0];
    ps->tx_file.fd = -1;
    ps->state = ST_ACTIVE;
    g_rx_fd = sv[1];

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0)
        return -1;
    st.epoll_fd = g_epfd;

    struct epoll_event ev = {.events = EPOLLIN, .data.fd = ps->fd};
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, ps->fd, &ev) != 0)
        return -1;

    /* Alıcı tarafı blocking: read_exact deterministik olsun. */
    int flags = fcntl(g_rx_fd, F_GETFL);
    if (flags < 0 || fcntl(g_rx_fd, F_SETFL, flags & ~O_NONBLOCK) != 0)
        return -1;

    return 0;
}

static int commit_pattern(struct peer_session *ps, uint8_t tag, size_t len)
{
    uint8_t *slot = frame_queue_reserve(ps);
    if (!slot)
        return -1;
    memset(slot, tag, len);
    return frame_queue_commit(ps, len) == NOX_OK ? 0 : -1;
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

static size_t drain_available(int fd, uint8_t *buf, size_t cap)
{
    size_t got = 0;
    while (got < cap) {
        ssize_t n = recv(fd, buf + got, cap - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    return got;
}

#define FQ_ASSERT(cond) do {                                            \
    if (!(cond)) {                                                      \
        fixture_teardown();                                             \
        TEST_ASSERT(cond);                                              \
    }                                                                   \
} while (0)

/* 1) FIFO sırası ve tx_seq commit'te ilerler. */
static int test_order_and_seq(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);

    FQ_ASSERT(commit_pattern(ps, 'A', 100) == 0);
    FQ_ASSERT(commit_pattern(ps, 'B', 200) == 0);
    FQ_ASSERT(commit_pattern(ps, 'C', 300) == 0);

    FQ_ASSERT(frame_queue_count(ps) == 3);
    FQ_ASSERT(frame_queue_free(ps) == 1);
    FQ_ASSERT(ps->tx_seq == 3);
    FQ_ASSERT(!frame_queue_empty(ps));

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT(frame_queue_free(ps) == FRAME_QUEUE_SLOTS);

    uint8_t got[600];
    FQ_ASSERT(read_exact(g_rx_fd, got, sizeof(got)) == 0);
    for (size_t i = 0; i < 100; i++)
        FQ_ASSERT(got[i] == 'A');
    for (size_t i = 100; i < 300; i++)
        FQ_ASSERT(got[i] == 'B');
    for (size_t i = 300; i < 600; i++)
        FQ_ASSERT(got[i] == 'C');

    fixture_teardown();
    return 0;
}

/* 2) Dolu kuyruk: rezervasyon yok, commit sınırları korunur. */
static int test_full_queue_rejects(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    for (int i = 0; i < (int)FRAME_QUEUE_SLOTS; i++)
        FQ_ASSERT(commit_pattern(ps, (uint8_t)('a' + i), 16) == 0);

    FQ_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(frame_queue_free(ps) == 0);
    FQ_ASSERT(frame_queue_reserve(ps) == NULL);
    FQ_ASSERT(frame_queue_commit(ps, 16) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(ps->tx_seq == FRAME_QUEUE_SLOTS);

    fixture_teardown();
    return 0;
}

/* 3) Kısmi yazım: offset ilerler, AGAIN; drain sonrası kaldığı yerden. */
static int test_partial_write_resumes(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* Küçük SO_SNDBUF + 1024 byte ön dolgu: 4125 byte'lık frame
     * tam sığmaz → ilk send kısmi olur. */
    int sndbuf = 1024;
    FQ_ASSERT(setsockopt(ps->fd, SOL_SOCKET, SO_SNDBUF,
                         &sndbuf, sizeof(sndbuf)) == 0);
    uint8_t prefill[1024];
    memset(prefill, 0xEE, sizeof(prefill));
    FQ_ASSERT(send(ps->fd, prefill, sizeof(prefill),
                   MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)sizeof(prefill));

    FQ_ASSERT(commit_pattern(ps, 'X', TX_BUF_CAPACITY) == 0);

    nox_err_t err = frame_queue_flush(&st, ps);
    FQ_ASSERT(err == NOX_ERR_AGAIN);
    FQ_ASSERT(frame_queue_count(ps) == 1);

    struct frame_queue *q = &ps->tx_frames;
    struct frame_queue_slot *head = &q->slots[q->head];
    FQ_ASSERT(head->off > 0);
    FQ_ASSERT(head->off < head->len);

    /* Ön dolguyu tüket; kalan baytlar frame'in yazılmış kısmıdır. */
    uint8_t skip[1024];
    FQ_ASSERT(read_exact(g_rx_fd, skip, sizeof(skip)) == 0);

    uint8_t got[TX_BUF_CAPACITY];
    size_t got_len = drain_available(g_rx_fd, got, sizeof(got));

    for (int i = 0; i < 10000 && !frame_queue_empty(ps); i++) {
        err = frame_queue_flush(&st, ps);
        FQ_ASSERT(err == NOX_OK || err == NOX_ERR_AGAIN);
        got_len += drain_available(g_rx_fd, got + got_len,
                                   sizeof(got) - got_len);
    }
    got_len += drain_available(g_rx_fd, got + got_len,
                               sizeof(got) - got_len);

    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT(got_len == sizeof(got));
    for (size_t i = 0; i < sizeof(got); i++)
        FQ_ASSERT(got[i] == 'X');

    fixture_teardown();
    return 0;
}

/* 4) Kalıcı yazma hatası: frame düşürülemez → oturum kapanır. */
static int test_fatal_write_teardown(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(commit_pattern(ps, 'Z', 128) == 0);
    close(g_rx_fd);
    g_rx_fd = -1;

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_IO);
    FQ_ASSERT(ps->fd == -1);
    FQ_ASSERT(ps->state == ST_IDLE);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT(ps->tx_seq == 0);
    TEST_ASSERT_MEM_ZERO(&ps->tx_frames, sizeof(ps->tx_frames));

    fixture_teardown();
    return 0;
}

/* 5) reset tüm ciphertext'i ve sayaçları zeroize eder. */
static int test_reset_zeroizes(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(commit_pattern(ps, 'Q', 64) == 0);
    FQ_ASSERT(commit_pattern(ps, 'R', 64) == 0);
    FQ_ASSERT(frame_queue_count(ps) == 2);

    frame_queue_reset(ps);
    FQ_ASSERT(frame_queue_count(ps) == 0);
    FQ_ASSERT(frame_queue_free(ps) == FRAME_QUEUE_SLOTS);
    TEST_ASSERT_MEM_ZERO(&ps->tx_frames, sizeof(ps->tx_frames));

    fixture_teardown();
    return 0;
}

/* 6) NULL peer ve geçersiz commit uzunluğu güvenli. */
static int test_null_and_bounds(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(frame_queue_count(NULL) == 0);
    FQ_ASSERT(frame_queue_free(NULL) == 0);
    FQ_ASSERT(frame_queue_empty(NULL));
    FQ_ASSERT(frame_queue_reserve(NULL) == NULL);
    FQ_ASSERT(frame_queue_commit(NULL, 16) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(frame_queue_flush(&st, NULL) == NOX_ERR_NET);

    FQ_ASSERT(frame_queue_commit(ps, 0) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(frame_queue_commit(ps, TX_BUF_CAPACITY + 1) ==
              NOX_ERR_OVERFLOW);
    FQ_ASSERT(frame_queue_count(ps) == 0);
    FQ_ASSERT(ps->tx_seq == 0);

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "=== C1 frame_queue testleri ===\n");
    RUN_TEST(test_order_and_seq);
    RUN_TEST(test_full_queue_rejects);
    RUN_TEST(test_partial_write_resumes);
    RUN_TEST(test_fatal_write_teardown);
    RUN_TEST(test_reset_zeroizes);
    RUN_TEST(test_null_and_bounds);

    fprintf(stderr, "%d/%d test başarılı\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
