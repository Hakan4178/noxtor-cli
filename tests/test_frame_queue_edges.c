/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_frame_queue_edges.c — C1: TX frame kuyruğu sınır/uç durumları
 *
 * test_frame_queue.c temel sözleşmeyi doğrular; bu dosya halka (ring)
 * taşması, state'siz reserve, başarısız commit'lerin atomikliği, çoklu
 * frame kısmi yazımı ve EAGAIN sonrası epoll interest'ini kilitler.
 *
 * Kapsam:
 *   1. 4 slot dolup bir kısmı drain edildikten sonra yeni frame ekleme:
 *      head/tail wrap sırasında FIFO ve bayt içeriği birebir korunur.
 *   2. reserve yalnızca pointer döndürür; tx_seq/count/head/tail değişmez.
 *   3. len=0, len>TX_BUF_CAPACITY ve dolu kuyruk commit'leri tx_seq'i
 *      artırmaz, kuyruğu (slot len/off dahil) bozmaz.
 *   4. Çoklu frame + küçük SO_SNDBUF + ön dolgu: birden fazla flush
 *      turunda kısmi yazım olsa da wire akışı bozulmaz.
 *   5. Kalıcı yazma hatası: NOX_ERR_IO + tam teardown + zeroize
 *      (hem hiç yazılmamış hem de kısmi yazılmış frame için).
 *   6. NULL peer yolları, reset(NULL), reset idempotentliği ve fd<0.
 *   7. EAGAIN sonrası epoll interest EPOLLIN|EPOLLOUT olur; bunu
 *      epoll_wait ile gözlemlenebilir biçimde doğrula.
 */

#include "common.h"
#include "types.h"
#include "frame_queue.h"
#include "state_machine.h"

#include <errno.h>
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

/* Beklenen wire akışı ve alıcıdan toplanan baytlar. */
static uint8_t g_expected[65536];
static size_t g_expected_len;
static uint8_t g_received[65536];
static size_t g_received_len;
static size_t g_prefill_len;

/* Kuyruk anlık görüntüsü — büyük struct'ı stack'e kopyalamamak için. */
static struct frame_queue g_snapshot;

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

    struct peer_session *ps = &st.peers[0];
    ps->fd = -1;
    ps->tx_file.fd = -1;

    g_rx_fd = -1;
    g_epfd = -1;
    g_expected_len = 0;
    g_received_len = 0;
    g_prefill_len = 0;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0)
        return -1;

    ps->fd = sv[0];
    ps->state = ST_ACTIVE;
    g_rx_fd = sv[1];

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0)
        return -1;
    st.epoll_fd = g_epfd;

    /* Üretimdeki ilk kayıt: yalnızca EPOLLIN. */
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = ps->fd};
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, ps->fd, &ev) != 0)
        return -1;

    return 0;
}

#define FQ_ASSERT(cond) do {                                            \
    if (!(cond)) {                                                      \
        fixture_teardown();                                             \
        TEST_ASSERT(cond);                                              \
    }                                                                   \
} while (0)

static int errno_would_block(void)
{
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
    return errno == EAGAIN || errno == EWOULDBLOCK;
#else
    return errno == EAGAIN;
#endif
}

/* Konuma ve seed'e bağlı, tekrar etmeyen içerik üret. */
static void fill_pattern(uint8_t *buf, uint8_t seed, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)((unsigned)seed + (unsigned)i * 37U +
                           (unsigned)(i >> 8U));
}

static int record_expected(const uint8_t *buf, size_t len)
{
    if (g_expected_len + len > sizeof(g_expected))
        return -1;
    memcpy(g_expected + g_expected_len, buf, len);
    g_expected_len += len;
    return 0;
}

/* Reserve et, desenle doldur, commit et ve beklenen akışa ekle. */
static int enqueue_pattern(struct peer_session *ps, uint8_t seed, size_t len)
{
    if (len == 0 || len > TX_BUF_CAPACITY)
        return -1;

    uint8_t *slot = frame_queue_reserve(ps);
    if (!slot)
        return -1;

    fill_pattern(slot, seed, len);
    if (frame_queue_commit(ps, len) != NOX_OK)
        return -1;

    return record_expected(slot, len);
}

/* Alıcı soketinde biriken tüm baytları g_received'a ekle. */
static int drain_receiver(void)
{
    for (;;) {
        uint8_t tmp[4096];
        ssize_t n = recv(g_rx_fd, tmp, sizeof(tmp), MSG_DONTWAIT);

        if (n > 0) {
            if (g_received_len + (size_t)n > sizeof(g_received))
                return -1;
            memcpy(g_received + g_received_len, tmp, (size_t)n);
            g_received_len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && errno_would_block())
            return 0;
        return -1; /* gerçek hata veya karşı taraf kapandı */
    }
}

static int verify_stream(void)
{
    if (g_received_len != g_prefill_len + g_expected_len)
        return -1;
    for (size_t i = 0; i < g_prefill_len; i++) {
        if (g_received[i] != 0xEE)
            return -1;
    }
    return memcmp(g_received + g_prefill_len, g_expected,
                  g_expected_len) == 0 ? 0 : -1;
}

/* Küçük SO_SNDBUF + sabit ön dolgu: kısmi yazımı deterministik kılar. */
static int setup_small_sndbuf_and_prefill(size_t len)
{
    if (len > 1024U)
        return -1;

    int sndbuf = 1024;
    if (setsockopt(st.peers[0].fd, SOL_SOCKET, SO_SNDBUF,
                   &sndbuf, sizeof(sndbuf)) != 0)
        return -1;

    uint8_t prefill[1024];
    memset(prefill, 0xEE, sizeof(prefill));

    size_t off = 0;
    while (off < len) {
        ssize_t w = send(st.peers[0].fd, prefill + off, len - off,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return -1;
    }

    g_prefill_len = len;
    return 0;
}

/*
 * Kuyruk iç tutarlılığı: tail = (head + count) % SLOTS, dolu her slotta
 * 0 < len <= TX_BUF_CAPACITY ve off <= len.
 */
static int queue_invariant(const struct peer_session *ps)
{
    if (!ps)
        return 0;

    const struct frame_queue *q = &ps->tx_frames;

    if ((unsigned)q->count > FRAME_QUEUE_SLOTS)
        return 0;
    if ((unsigned)q->head >= FRAME_QUEUE_SLOTS ||
        (unsigned)q->tail >= FRAME_QUEUE_SLOTS)
        return 0;
    if ((unsigned)q->tail !=
        ((unsigned)q->head + (unsigned)q->count) % FRAME_QUEUE_SLOTS)
        return 0;
    if (frame_queue_count(ps) != q->count)
        return 0;
    if (frame_queue_free(ps) != (uint8_t)(FRAME_QUEUE_SLOTS - q->count))
        return 0;
    if (frame_queue_empty(ps) != (q->count == 0))
        return 0;

    for (unsigned i = 0; i < (unsigned)q->count; i++) {
        const struct frame_queue_slot *s =
            &q->slots[((unsigned)q->head + i) % FRAME_QUEUE_SLOTS];
        if (s->len == 0 || (unsigned)s->len > TX_BUF_CAPACITY)
            return 0;
        if (s->off > s->len)
            return 0;
    }
    return 1;
}

/*
 * 1) Ring wrap-around: 4 slot doldur, bir kısmını flush/drain et,
 *    boşalan slotlara yeni frame ekle. Halka tam doluyken (head == tail,
 *    tail 0'a sarmış) head'den başlayan FIFO sırası korunmalı.
 */
static int test_ring_wrap_preserves_fifo(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(setup_small_sndbuf_and_prefill(1024) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x11, TX_BUF_CAPACITY) == 0); /* A */
    FQ_ASSERT(enqueue_pattern(ps, 0x22, 777) == 0);             /* B */
    FQ_ASSERT(enqueue_pattern(ps, 0x33, TX_BUF_CAPACITY) == 0); /* C */
    FQ_ASSERT(enqueue_pattern(ps, 0x44, 333) == 0);             /* D */

    FQ_ASSERT((unsigned)frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(ps->tx_frames.tail == 0); /* 4 commit sonrası tail 0'a sardı */
    FQ_ASSERT(ps->tx_seq == 4U);
    FQ_ASSERT(queue_invariant(ps));

    /* En az iki frame tamamen drain edilene kadar flush + drain et.
     * Böylece head ilerler; tail hâlâ 0'dadır. */
    int guard = 0;
    while ((unsigned)frame_queue_count(ps) > 2U && guard++ < 200) {
        nox_err_t err = frame_queue_flush(&st, ps);
        FQ_ASSERT(err == NOX_OK || err == NOX_ERR_AGAIN);
        FQ_ASSERT(drain_receiver() == 0);
    }
    FQ_ASSERT(guard < 200);
    FQ_ASSERT((unsigned)frame_queue_count(ps) >= 1U);
    FQ_ASSERT((unsigned)frame_queue_count(ps) <= 2U);
    FQ_ASSERT(ps->tx_frames.head >= 2U); /* en az 2 frame tamamlandı */
    FQ_ASSERT(ps->tx_frames.tail == 0);
    FQ_ASSERT(queue_invariant(ps));

    /* Boşalan slotlara yeni frame'ler: tail 0'dan ilerleyerek head'in
     * önüne sarılır; kuyruk yeniden tam dolar. */
    uint8_t room = frame_queue_free(ps);
    FQ_ASSERT(room >= 1U);
    for (unsigned i = 0; i < (unsigned)room; i++) {
        size_t len = 512U + (size_t)i * 111U;
        uint8_t seed = (uint8_t)(0x55U + i * 0x10U);
        FQ_ASSERT(enqueue_pattern(ps, seed, len) == 0);
    }

    FQ_ASSERT((unsigned)frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(ps->tx_frames.head == ps->tx_frames.tail); /* dolu halka */
    FQ_ASSERT(ps->tx_frames.head >= 2U);
    FQ_ASSERT(ps->tx_seq == 4U + (uint32_t)room);
    FQ_ASSERT(queue_invariant(ps));

    /* Kalan her şeyi boşalt; wire akışı A,B,C,D,E... olmalı. */
    guard = 0;
    while (!frame_queue_empty(ps) && guard++ < 1000) {
        nox_err_t err = frame_queue_flush(&st, ps);
        FQ_ASSERT(err == NOX_OK || err == NOX_ERR_AGAIN);
        FQ_ASSERT(drain_receiver() == 0);
        FQ_ASSERT(queue_invariant(ps));
    }
    FQ_ASSERT(guard < 1000);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(verify_stream() == 0);

    fixture_teardown();
    return 0;
}

/*
 * 2) reserve state değiştirmez: aynı tail slotunu döndürür, tx_seq,
 *    count, head, tail ve slot len/off alanları aynı kalır.
 */
static int test_reserve_does_not_mutate(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(enqueue_pattern(ps, 0x0A, 100) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x0B, 200) == 0);

    memcpy(&g_snapshot, &ps->tx_frames, sizeof(g_snapshot));
    uint32_t seq_before = ps->tx_seq;
    uint8_t *slot = frame_queue_reserve(ps);

    FQ_ASSERT(slot != NULL);
    FQ_ASSERT(slot == ps->tx_frames.slots[ps->tx_frames.tail].buf);
    FQ_ASSERT(ps->tx_seq == seq_before);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 2U);
    FQ_ASSERT(memcmp(&g_snapshot, &ps->tx_frames, sizeof(g_snapshot)) == 0);

    /* İkinci reserve de aynı slotu döndürmeli ve hâlâ state'siz olmalı. */
    FQ_ASSERT(frame_queue_reserve(ps) == slot);
    FQ_ASSERT(memcmp(&g_snapshot, &ps->tx_frames, sizeof(g_snapshot)) == 0);

    /* Rezerve edilen alan gerçekten yazılabilir; commit sonrası içerik
     * wire'a aynen çıkmalı. */
    fill_pattern(slot, 0x7A, 321);
    FQ_ASSERT(frame_queue_commit(ps, 321) == NOX_OK);
    FQ_ASSERT(record_expected(slot, 321) == 0);
    FQ_ASSERT(ps->tx_seq == seq_before + 1U);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 3U);
    FQ_ASSERT(queue_invariant(ps));

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(verify_stream() == 0);

    fixture_teardown();
    return 0;
}

/*
 * 3) Başarısız commit atomiktir: len 0, len > kapasite ve dolu kuyruk
 *    yollarında tx_seq artmaz; kuyruk bayt bayt aynı kalır.
 *    Ayrıca len == TX_BUF_CAPACITY sınırı kabul edilir.
 */
static int test_failed_commit_leaves_queue_intact(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];
    struct frame_queue *q = &ps->tx_frames;

    FQ_ASSERT(enqueue_pattern(ps, 0x21, 100) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x22, 200) == 0);
    uint32_t seq_before = ps->tx_seq;

    uint8_t *slot = frame_queue_reserve(ps);
    FQ_ASSERT(slot != NULL);
    FQ_ASSERT(slot == q->slots[q->tail].buf);

    /* Çağıran rezerve alanı doldurmuş olabilir; başarısız commit bunu
     * bile değiştirmemeli (len/off yazılmadan dönüş). */
    fill_pattern(slot, 0xC0, 128);
    memcpy(&g_snapshot, q, sizeof(g_snapshot));

    FQ_ASSERT(frame_queue_commit(ps, 0) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(memcmp(&g_snapshot, q, sizeof(g_snapshot)) == 0);

    FQ_ASSERT(frame_queue_commit(ps, TX_BUF_CAPACITY + 1U) ==
              NOX_ERR_OVERFLOW);
    FQ_ASSERT(memcmp(&g_snapshot, q, sizeof(g_snapshot)) == 0);
    FQ_ASSERT(ps->tx_seq == seq_before);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 2U);
    FQ_ASSERT(q->slots[q->tail].len == 0);
    FQ_ASSERT(q->slots[q->tail].off == 0);
    FQ_ASSERT(queue_invariant(ps));

    /* Tam kapasite sınırı başarılı olmalı. */
    fill_pattern(slot, 0xD0, TX_BUF_CAPACITY);
    FQ_ASSERT(frame_queue_commit(ps, TX_BUF_CAPACITY) == NOX_OK);
    FQ_ASSERT(record_expected(slot, TX_BUF_CAPACITY) == 0);
    FQ_ASSERT(ps->tx_seq == seq_before + 1U);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 3U);
    FQ_ASSERT(queue_invariant(ps));

    /* Kuyruğu doldur; dolu kuyrukta commit de hiçbir şeyi değiştirmemeli. */
    FQ_ASSERT(enqueue_pattern(ps, 0x44, 64) == 0);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(frame_queue_reserve(ps) == NULL);
    memcpy(&g_snapshot, q, sizeof(g_snapshot));
    uint32_t full_seq = ps->tx_seq;

    FQ_ASSERT(frame_queue_commit(ps, 64) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(memcmp(&g_snapshot, q, sizeof(g_snapshot)) == 0);
    FQ_ASSERT(ps->tx_seq == full_seq);
    FQ_ASSERT(queue_invariant(ps));

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(verify_stream() == 0);

    fixture_teardown();
    return 0;
}

/*
 * 4) Çoklu frame + küçük SO_SNDBUF + ön dolgu: birçok flush turunda
 *    kısmi yazım gerçekleşir; bayt sırası ve içeriği bozulmadan tamamlanır.
 */
static int test_multiframe_partial_write_order(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(setup_small_sndbuf_and_prefill(1024) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x61, TX_BUF_CAPACITY) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x62, 2048) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x63, 512) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x64, TX_BUF_CAPACITY) == 0);

    int again_rounds = 0;
    int saw_partial = 0;
    int guard = 0;
    while (!frame_queue_empty(ps) && guard++ < 1000) {
        nox_err_t err = frame_queue_flush(&st, ps);
        FQ_ASSERT(err == NOX_OK || err == NOX_ERR_AGAIN);
        if (err == NOX_ERR_AGAIN)
            again_rounds++;
        if (!frame_queue_empty(ps)) {
            struct frame_queue_slot *head =
                &ps->tx_frames.slots[ps->tx_frames.head];
            if (head->off > 0 && head->off < head->len)
                saw_partial = 1;
        }
        FQ_ASSERT(drain_receiver() == 0);
        FQ_ASSERT(queue_invariant(ps));
    }

    FQ_ASSERT(guard < 1000);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT(again_rounds >= 2); /* gerçekten çoklu kısmi yazım turu */
    FQ_ASSERT(saw_partial);       /* en az bir frame yarım kaldı */
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(verify_stream() == 0);
    FQ_ASSERT(ps->tx_seq == 4U);

    /* Tamamlanan her slot ciphertext'i zeroize edilmiş olmalı. */
    for (unsigned i = 0; i < FRAME_QUEUE_SLOTS; i++) {
        TEST_ASSERT_MEM_ZERO(ps->tx_frames.slots[i].buf, TX_BUF_CAPACITY);
    }

    fixture_teardown();
    return 0;
}

/*
 * 5) Kalıcı yazma hatası (alıcı kapandı): NOX_ERR_IO, fd=-1, ST_IDLE,
 *    kuyruk boş, tx_seq=0 ve tüm tx_frames zeroize edilmiş olmalı.
 */
static int test_fatal_write_teardown(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(enqueue_pattern(ps, 0x71, 128) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x72, 64) == 0);

    close(g_rx_fd);
    g_rx_fd = -1;

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_IO);
    FQ_ASSERT(ps->fd == -1);
    FQ_ASSERT(ps->state == ST_IDLE);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 0U);
    FQ_ASSERT((unsigned)frame_queue_free(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(ps->tx_seq == 0U);
    TEST_ASSERT_MEM_ZERO(&ps->tx_frames, sizeof(ps->tx_frames));

    fixture_teardown();
    return 0;
}

/*
 * 5b) Kısmi frame yazıldıktan sonra alıcı kapanırsa da oturum kapanır:
 *     yarım frame resync edilemez; kuyruk tamamen zeroize edilir.
 */
static int test_fatal_write_after_partial(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(setup_small_sndbuf_and_prefill(1024) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x95, TX_BUF_CAPACITY) == 0);

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_AGAIN);
    struct frame_queue_slot *head = &ps->tx_frames.slots[ps->tx_frames.head];
    FQ_ASSERT(head->off > 0);
    FQ_ASSERT(head->off < head->len);

    close(g_rx_fd);
    g_rx_fd = -1;

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_IO);
    FQ_ASSERT(ps->fd == -1);
    FQ_ASSERT(ps->state == ST_IDLE);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 0U);
    FQ_ASSERT((unsigned)frame_queue_free(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(ps->tx_seq == 0U);
    TEST_ASSERT_MEM_ZERO(&ps->tx_frames, sizeof(ps->tx_frames));

    fixture_teardown();
    return 0;
}

/*
 * 6) NULL peer güvenliği, reset(NULL), reset idempotentliği ve fd<0.
 *    Reset sonrası kuyruk yeniden kullanılabilir olmalı.
 */
static int test_null_reset_and_bounds(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* NULL peer: hiçbir yol çökmemeli, güvenli tarafa dönmeli. */
    FQ_ASSERT(frame_queue_count(NULL) == 0);
    FQ_ASSERT(frame_queue_free(NULL) == 0);
    FQ_ASSERT(frame_queue_empty(NULL));
    FQ_ASSERT(frame_queue_reserve(NULL) == NULL);
    FQ_ASSERT(frame_queue_commit(NULL, 16) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(frame_queue_commit(NULL, 0) == NOX_ERR_OVERFLOW);
    FQ_ASSERT(frame_queue_flush(&st, NULL) == NOX_ERR_NET);
    FQ_ASSERT(frame_queue_flush(NULL, NULL) == NOX_ERR_NET);

    frame_queue_reset(NULL);
    frame_queue_reset(NULL); /* idempotent, çökme yok */

    /* reset iki kez: ilkinden sonra tüm kuyruk sıfır, ikincisi aynı. */
    FQ_ASSERT(enqueue_pattern(ps, 0x81, 64) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x82, 128) == 0);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 2U);

    frame_queue_reset(ps);
    FQ_ASSERT(frame_queue_empty(ps));
    FQ_ASSERT((unsigned)frame_queue_free(ps) == FRAME_QUEUE_SLOTS);
    FQ_ASSERT(queue_invariant(ps));
    TEST_ASSERT_MEM_ZERO(&ps->tx_frames, sizeof(ps->tx_frames));

    /* Kuyruk sıfırlandı; testin beklenen wire akışı da sıfırlanmalı. */
    g_expected_len = 0;
    g_received_len = 0;

    frame_queue_reset(ps);
    TEST_ASSERT_MEM_ZERO(&ps->tx_frames, sizeof(ps->tx_frames));

    /* Reset sonrası kuyruk yeniden çalışmalı. */
    FQ_ASSERT(enqueue_pattern(ps, 0x83, 256) == 0);
    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(verify_stream() == 0);

    /* fd < 0: kuyruk korunur, NOX_ERR_NET döner; fd geri gelince akar. */
    FQ_ASSERT(enqueue_pattern(ps, 0x84, 32) == 0);
    int saved_fd = ps->fd;
    ps->fd = -1;
    nox_err_t err = frame_queue_flush(&st, ps);
    ps->fd = saved_fd;
    FQ_ASSERT(err == NOX_ERR_NET);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 1U);
    FQ_ASSERT(queue_invariant(ps));

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(verify_stream() == 0);

    fixture_teardown();
    return 0;
}

/*
 * 7) EAGAIN sonrası epoll interest'i EPOLLIN|EPOLLOUT olur. Interest
 *    maskesini /proc'tan okumak yerine davranışla doğrula:
 *      - kısmi yazım + EAGAIN (flush NOX_ERR_AGAIN),
 *      - alıcıyı boşalt → soket yazılabilir hâle gelir,
 *      - alıcıdan 1 byte gönder → soket okunabilir hâle gelir,
 *      - epoll_wait her iki biti de raporlamalı.
 *    EPOLL_CTL_MOD yapılmasaydı yalnızca EPOLLIN gelir, test düşer.
 */
static int test_eagain_sets_epollout_interest(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    FQ_ASSERT(setup_small_sndbuf_and_prefill(1024) == 0);
    FQ_ASSERT(enqueue_pattern(ps, 0x91, TX_BUF_CAPACITY) == 0);

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_ERR_AGAIN);
    FQ_ASSERT((unsigned)frame_queue_count(ps) == 1U);

    struct frame_queue_slot *head = &ps->tx_frames.slots[ps->tx_frames.head];
    FQ_ASSERT(head->off > 0);
    FQ_ASSERT(head->off < head->len);
    size_t partial = (size_t)head->off;

    /* Ön dolgu + kısmi frame baytlarını boşalt: soket yazılabilir olur. */
    FQ_ASSERT(drain_receiver() == 0);
    FQ_ASSERT(g_received_len == g_prefill_len + partial);

    /* Alıcıdan 1 byte: soket okunabilir olur. */
    uint8_t probe = 0x5A;
    FQ_ASSERT(send(g_rx_fd, &probe, sizeof(probe),
                   MSG_DONTWAIT | MSG_NOSIGNAL) == 1);

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    int n = epoll_wait(g_epfd, &ev, 1, 500);
    FQ_ASSERT(n == 1);
    FQ_ASSERT(ev.data.fd == ps->fd);
    FQ_ASSERT((ev.events & (uint32_t)(EPOLLIN | EPOLLOUT)) ==
              (uint32_t)(EPOLLIN | EPOLLOUT));

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== C1 frame_queue uç durum testleri ===\n");
    RUN_TEST(test_ring_wrap_preserves_fifo);
    RUN_TEST(test_reserve_does_not_mutate);
    RUN_TEST(test_failed_commit_leaves_queue_intact);
    RUN_TEST(test_multiframe_partial_write_order);
    RUN_TEST(test_fatal_write_teardown);
    RUN_TEST(test_fatal_write_after_partial);
    RUN_TEST(test_null_reset_and_bounds);
    RUN_TEST(test_eagain_sets_epollout_interest);

    fprintf(stderr, "=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
