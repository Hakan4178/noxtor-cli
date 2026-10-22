/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_tx_order.c — Adım 4.5: gönderim sırası (T1) sözleşmesi
 *
 * Kapsam:
 *   1. FILE chunk'ı tx_buf'ta beklerken TEXT hemen yazılmaz; tek slotta
 *      ertelenir. Drain sonrası wire sırası birebir:
 *          chunk k → TEXT k+1 → chunk k+2
 *      (nonce sırası = wire sırası; alıcı gerçek AEAD ile doğrular.)
 *   2. Slot dolu → net ret (sessiz düşürme yok); cleanup pending_msg'i
 *      zeroize edip serbest bırakır.
 *
 * Not: İlk chunk test tarafından doğrudan tx_buf'a yerleştirilir; bu,
 * "yarım yazılmış/kısmi write sonrası tx_buf dolu" durumunun deterministik
 * modelidir. Sonraki chunk gerçek file_transfer_handle_tx okuma/şifreleme
 * yolundan geçer.
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "noise.h"
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

static void fixture_teardown(void)
{
    struct peer_session *ps = &st.peers[0];

    if (ps->pending_msg) {
        sodium_free(ps->pending_msg);
        ps->pending_msg = NULL;
    }
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

/* İlk FILE chunk'ını şifreleyip tx_buf'a yerleştir (seq = tx_seq). */
static int stage_first_chunk(struct peer_session *ps, const void *pt,
                             size_t pt_len)
{
    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_FILE,
        .seq = ps->tx_seq,
        .len = (uint32_t)(pt_len + NOX_MAC_LEN),
    };
    uint8_t ad[FRAME_HEADER_WIRE_SIZE];
    frame_ad(&fh, ad);
    memcpy(ps->tx_file.tx_buf, ad, sizeof(ad));

    ssize_t ct_len = noise_encrypt(ps->session, ad, sizeof(ad), pt, pt_len,
                                   ps->tx_file.tx_buf + sizeof(ad));
    if (ct_len != (ssize_t)fh.len)
        return -1;

    ps->tx_file.tx_len = FRAME_HEADER_WIRE_SIZE + (size_t)ct_len;
    ps->tx_file.tx_offset = 0;
    ps->tx_file.current_chunk_size = pt_len;
    return 0;
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
    g_rx_fd = sv[1];
    ps->state = ST_FILE_TX;

    ps->session = sodium_malloc(sizeof(*ps->session));
    if (!ps->session)
        return -1;
    init_cipher_session(ps->session, 5);
    ps->tx_seq = 5;

    ps->tx_file.active = true;
    ps->tx_file.plain_buf = sodium_malloc(4096);
    if (!ps->tx_file.plain_buf)
        return -1;
    ps->tx_file.total_size = 3;
    ps->tx_file.sent_bytes = 0;

    g_tmp_file = tmpfile();
    if (!g_tmp_file)
        return -1;
    if (fputc('C', g_tmp_file) == EOF || fflush(g_tmp_file) != 0)
        return -1;
    if (fseek(g_tmp_file, 0, SEEK_SET) != 0)
        return -1;
    /* FILE* sahipliği testte kalsın; transfer yalnız dup fd'yi kapatsın. */
    ps->tx_file.fd = dup(fileno(g_tmp_file));
    if (ps->tx_file.fd < 0)
        return -1;

    if (stage_first_chunk(ps, "AB", 2) != 0)
        return -1;

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

#define TX_ASSERT(cond) do {                                           \
    if (!(cond)) {                                                     \
        fixture_teardown();                                            \
        TEST_ASSERT(cond);                                             \
    }                                                                  \
} while (0)

/* 1) Sıra: chunk k → TEXT k+1 → chunk k+2; slot dolu net ret. */
static int test_tx_order_defer_and_flush(void)
{
    TX_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* tx_buf dolu → TEXT hemen yazılmaz, tek slotta bekler. */
    TX_ASSERT(send_segmented_message_to(&st, ps, "hello") == NOX_OK);
    TX_ASSERT(ps->pending_msg != NULL);
    TX_ASSERT(strcmp(ps->pending_msg, "hello") == 0);
    TX_ASSERT(ps->tx_seq == 5);
    TX_ASSERT(no_pending_wire_bytes());

    /* Slot dolu → ikinci mesaj net ret; ilk mesaj korunur. */
    TX_ASSERT(send_segmented_message_to(&st, ps, "second") == NOX_ERR_STATE);
    TX_ASSERT(ps->pending_msg != NULL);
    TX_ASSERT(strcmp(ps->pending_msg, "hello") == 0);

    /* İlk chunk'ı drain et: tx_seq 5→6, ardından pending TEXT 6→7. */
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(ps->pending_msg == NULL);
    TX_ASSERT(ps->tx_seq == 7);

    /* Alıcı tarafı: gerçek AEAD ile nonce sırasını doğrula. */
    struct noise_session rx;
    init_cipher_session(&rx, 5);
    struct frame_header fh;
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    uint8_t ct[NOX_MAX_MSG_LEN + NOX_MAC_LEN];
    uint8_t pt[NOX_MAX_MSG_LEN + 1];

    TX_ASSERT(read_frame(g_rx_fd, &fh, wire, ct) == 0);
    TX_ASSERT(fh.type == NOX_MSG_FILE && fh.seq == 5);
    ssize_t n = noise_decrypt(&rx, wire, sizeof(wire), ct, fh.len, pt);
    TX_ASSERT(n == 2 && memcmp(pt, "AB", 2) == 0);

    TX_ASSERT(read_frame(g_rx_fd, &fh, wire, ct) == 0);
    TX_ASSERT(fh.type == NOX_MSG_TEXT && fh.seq == 6);
    n = noise_decrypt(&rx, wire, sizeof(wire), ct, fh.len, pt);
    TX_ASSERT(n == 6 && memcmp(pt, "hello", 6) == 0);

    /* Henüz üçüncü frame yazılmadı. */
    TX_ASSERT(no_pending_wire_bytes());

    /* İkinci chunk: read+encrypt, sonra write (seq 7). */
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(ps->tx_seq == 7);
    file_transfer_handle_tx(&st, ps);
    TX_ASSERT(ps->tx_seq == 8);
    TX_ASSERT(!ps->tx_file.active);

    TX_ASSERT(read_frame(g_rx_fd, &fh, wire, ct) == 0);
    TX_ASSERT(fh.type == NOX_MSG_FILE && fh.seq == 7);
    n = noise_decrypt(&rx, wire, sizeof(wire), ct, fh.len, pt);
    TX_ASSERT(n == 1 && pt[0] == 'C');

    TX_ASSERT(no_pending_wire_bytes());
    fixture_teardown();
    return 0;
}

/* 2) Slot dolu net ret + cleanup pending_msg'i serbest bırakır. */
static int test_pending_slot_full_and_cleanup(void)
{
    TX_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    TX_ASSERT(send_segmented_message_to(&st, ps, "one") == NOX_OK);
    TX_ASSERT(send_segmented_message_to(&st, ps, "two") == NOX_ERR_STATE);
    TX_ASSERT(ps->pending_msg != NULL && strcmp(ps->pending_msg, "one") == 0);

    /* Chunk hâlâ bekliyor → flush no-op, mesaj kaybolmaz. */
    TX_ASSERT(peer_tx_flush_pending(&st, ps) == NOX_OK);
    TX_ASSERT(ps->pending_msg != NULL);

    ps->state = ST_FILE_TX;
    TX_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);
    TX_ASSERT(ps->pending_msg == NULL);
    TX_ASSERT(ps->fd == -1);
    TX_ASSERT(ps->session == NULL);
    TX_ASSERT(ps->tx_file.plain_buf == NULL);

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }
    fprintf(stderr, "\n=== Adım 4.5 — gönderim sırası (T1) ===\n");
    RUN_TEST(test_tx_order_defer_and_flush);
    RUN_TEST(test_pending_slot_full_and_cleanup);
    fprintf(stderr, "=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
