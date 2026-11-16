/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_frame_queue_contract.c — C1: TX frame kuyruğu SÖZLEŞME + güvenlik
 *                                değişmezleri + frame_queue_arm_tx
 *
 * test_frame_queue.c temel akışı, test_frame_queue_edges.c halka taşması /
 * kısmi yazım / EAGAIN yollarını kilitler. Bu dosya **kalan boşlukları**
 * kapatır:
 *
 *   1. frame_queue_arm_tx() — C2'nin "FILE transferi METADATA commit'inden
 *      sonra EPOLLOUT'a uyandır" yolu. HİÇ test edilmemişti:
 *        - NULL peer / fd<0 → NOX_ERR_NET
 *        - epoll yok (birim testi) → NOX_OK (no-op)
 *        - epoll kurulamaz → NOX_ERR_IO + **fail-closed** (oturum kapanır)
 *        - başarılı → EPOLLIN|EPOLLOOUT ilgisi (epoll_wait ile gözlem)
 *   2. **Zeroize'in sızıntı önleyici etkisi**: tamamlanan frame'in slot'u
 *      sıfırlanır; sonraki frame "len > yazılan byte" hatasıyla
 *      commit edilse bile ESKİ CIPHERTEXT sızmaz (sıfır gider).
 *   3. reset tx_seq'i **sıfırlamaz** — wire sıra numarası monoton kalır
 *      (rewind → peer'de replay hatası).
 *   4. Peer izolasyonu: iki peer'ın kuyrukları/seq'leri birbirinden
 *      bağımsız.
 *   5. reserve'siz commit: sözleşme ihlali ama kuyruk tutarlılığı bozulmaz
 *      (frame düşmez — nonce tüketilir ama kaybolmaz).
 *   6. EINTR stresi: sinyal (SA_RESTART'sız) ile flush sırasında EINTR
 *      oluşabilir; oluşsa bile kuyruk ve byte akışı tutarlı kalmalı.
 *
 * Kapsam: yalnız frame_queue API'si + arm_tx. Network/Noise katmanı
 * test_tx_order.c ve test_c1_text_paths.c'de.
 */

#include "common.h"
#include "types.h"
#include "frame_queue.h"
#include "state_machine.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <sodium.h>

#include "test_common.h"

static struct app_state st;
static int g_rx_fd = -1;
static int g_epfd = -1;

/* Kuyruk tutarlılık invariantı: count/head/tail birbirini tutmalı. */
static bool queue_invariant(const struct peer_session *ps)
{
    const struct frame_queue *q = &ps->tx_frames;
    if (q->count > FRAME_QUEUE_SLOTS)
        return false;
    if (q->head >= FRAME_QUEUE_SLOTS || q->tail >= FRAME_QUEUE_SLOTS)
        return false;
    if (q->count == 0)
        return q->head == q->tail;
    return q->head != q->tail;
}

static void fixture_teardown(void)
{
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        if (st.peers[i].fd >= 0) {
            close(st.peers[i].fd);
            st.peers[i].fd = -1;
        }
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

    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        st.peers[i].fd = -1;
        st.peers[i].tofu_peer_fd = -1;
        st.peers[i].rx_file.fd = -1;
        st.peers[i].tx_file.fd = -1;
    }

    g_rx_fd = -1;
    g_epfd = -1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0)
        return -1;

    struct peer_session *ps = &st.peers[0];
    ps->fd = sv[0];
    ps->state = ST_ACTIVE;
    g_rx_fd = sv[1];

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0)
        return -1;
    st.epoll_fd = g_epfd;

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

/* Alıcı taraftan n byte oku (EINTR dayanıklı). */
static ssize_t rx_read(uint8_t *buf, size_t n)
{
    ssize_t total = 0;
    while (total < (ssize_t)n) {
        ssize_t r = read(g_rx_fd, buf + total, n - (size_t)total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return total > 0 ? total : -1;
        total += r;
    }
    return total;
}

/* ================================================================
 * 1) frame_queue_arm_tx — C2 uyandırma yolu
 * ================================================================ */
static int test_arm_tx_guards(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* NULL peer / geçersiz fd → NOX_ERR_NET */
    FQ_ASSERT(frame_queue_arm_tx(&st, NULL) == NOX_ERR_NET);
    int saved_fd = ps->fd;
    ps->fd = -1;
    FQ_ASSERT(frame_queue_arm_tx(&st, ps) == NOX_ERR_NET);
    ps->fd = saved_fd;

    /* epoll yok → no-op NOX_OK (birim testi ortamı) */
    FQ_ASSERT(frame_queue_arm_tx(NULL, ps) == NOX_OK);
    st.epoll_fd = -1;
    FQ_ASSERT(frame_queue_arm_tx(&st, ps) == NOX_OK);
    st.epoll_fd = g_epfd;

    fixture_teardown();
    return 0;
}

/* arm_tx: epoll kurulamazsa fail-closed — oturum kapanır (state → IDLE) */
static int test_arm_tx_fail_closed(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* epoll fd'si geçersiz (epoll olmayan bir fd) → epoll_ctl hata verir */
    int pipefd[2];
    FQ_ASSERT(pipe(pipefd) == 0);
    st.epoll_fd = pipefd[0];

    nox_err_t rc = frame_queue_arm_tx(&st, ps);
    FQ_ASSERT(rc == NOX_ERR_IO);
    /* Fail-closed: peer oturumu kapatıldı → ST_IDLE */
    FQ_ASSERT(ps->state == ST_IDLE);

    close(pipefd[0]);
    close(pipefd[1]);
    st.epoll_fd = g_epfd;

    fixture_teardown();
    return 0;
}

/* arm_tx: başarılı → EPOLLIN|EPOLLOUT ilgisi (davranışla gözlem) */
static int test_arm_tx_sets_epollout_interest(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* Üretimdeki ilk kayıt yalnız EPOLLIN ile yapılır */
    FQ_ASSERT(frame_queue_arm_tx(&st, ps) == NOX_OK);

    /* Alıcıdan 1 byte → soket okunabilir olur; EPOLLOUT da istenmiş olmalı */
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

/* ================================================================
 * 2) Zeroize → eski ciphertext SIZMAZ
 *
 * Tamamlanan frame'in slot'u sodium_memzero ile sıfırlanır. Çağıran
 * "len > yazılan byte" hatası yapsa bile (commit len kadar gönderir) eski
 * frame'in baytları sızmaz — sıfır gider.
 * ================================================================ */
static int test_no_stale_ciphertext_leak(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    /* 1) "Şifreli" veri içeren ilk frame + halkayı DOLDURAN 3 dolgu frame
     *    (doldurmazsak sonraki frame FARKLI slota düşer ve aynı slotun
     *     yeniden kullanımını test edemeyiz). */
    uint8_t *b = frame_queue_reserve(ps);
    FQ_ASSERT(b != NULL);
    memset(b, 0x5A, 32);
    FQ_ASSERT(frame_queue_commit(ps, 32) == NOX_OK);

    for (int i = 0; i < 3; i++) {
        b = frame_queue_reserve(ps);
        FQ_ASSERT(b != NULL);
        memset(b, 0x33, 16);
        FQ_ASSERT(frame_queue_commit(ps, 16) == NOX_OK);
    }
    FQ_ASSERT(frame_queue_count(ps) == FRAME_QUEUE_SLOTS);

    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    FQ_ASSERT(frame_queue_empty(ps));

    /* Alıcı tarafı: 4 frame sırayla ulaştı (32 + 3×16 bayt) */
    uint8_t got[64];
    FQ_ASSERT(rx_read(got, 32) == 32);
    for (size_t i = 0; i < 32; i++)
        FQ_ASSERT(got[i] == 0x5A);
    for (int f = 0; f < 3; f++) {
        FQ_ASSERT(rx_read(got, 16) == 16);
        for (size_t i = 0; i < 16; i++)
            FQ_ASSERT(got[i] == 0x33);
    }

    /* 2) ZEROIZE KANITI: tamamlanan frame'in slot'u sıfırlanmış olmalı.
     *    Tüm slotlar taranır (hangi slotun yazıldığından bağımsız). */
    for (size_t sl = 0; sl < FRAME_QUEUE_SLOTS; sl++) {
        for (size_t i = 0; i < sizeof(ps->tx_frames.slots[sl].buf); i++) {
            if (ps->tx_frames.slots[sl].buf[i] == 0x5A) {
                fprintf(stderr,
                        "\n  SIZINTI: slot %zu içinde 0x5A kaldı (offset %zu) — "
                        "zeroize yapılmamış\n", sl, i);
                return 1;
            }
        }
    }

    /* 3) HALKA SARMASI: kuyruk boşaldıktan sonra head/tail aynı slota
     *    döner → ilk frame'in slotu YENİDEN kullanılacak. */
    FQ_ASSERT(ps->tx_frames.head == ps->tx_frames.tail);

    b = frame_queue_reserve(ps);
    FQ_ASSERT(b != NULL);
    FQ_ASSERT(b == ps->tx_frames.slots[0].buf);  /* ilk framein slotu */

    /* Çağıran hatası: 1 byte yazıp 64 byte commit et → frame 64 bayt
     * gönderilir; eski 0x5A baytları SIFIR olmalı (sızmamalı). */
    b[0] = 0x11;
    FQ_ASSERT(frame_queue_commit(ps, 64) == NOX_OK);
    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);

    uint8_t got2[64];
    FQ_ASSERT(rx_read(got2, sizeof(got2)) == (ssize_t)sizeof(got2));
    FQ_ASSERT(got2[0] == 0x11);
    for (size_t i = 1; i < sizeof(got2); i++)
        FQ_ASSERT(got2[i] == 0x00);

    fixture_teardown();
    return 0;
}

/* ================================================================
 * 3) reset tx_seq'i sıfırlamaz (monoton kalmalı)
 * ================================================================ */
static int test_reset_keeps_tx_seq(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    uint32_t seq0 = ps->tx_seq;

    uint8_t *b = frame_queue_reserve(ps);
    FQ_ASSERT(b != NULL);
    memset(b, 0x01, 16);
    FQ_ASSERT(frame_queue_commit(ps, 16) == NOX_OK);
    FQ_ASSERT(ps->tx_seq == seq0 + 1);

    frame_queue_reset(ps);
    FQ_ASSERT(frame_queue_empty(ps));
    /* Seq GERİ SARILMAZ — peer'de replay tespiti bozulurdu */
    FQ_ASSERT(ps->tx_seq == seq0 + 1);

    /* Reset sonrası yeni frame seq'i monoton devam ettirir */
    b = frame_queue_reserve(ps);
    FQ_ASSERT(b != NULL);
    memset(b, 0x02, 16);
    FQ_ASSERT(frame_queue_commit(ps, 16) == NOX_OK);
    FQ_ASSERT(ps->tx_seq == seq0 + 2);
    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);

    fixture_teardown();
    return 0;
}

/* ================================================================
 * 4) Peer izolasyonu — kuyruklar ve seq'ler bağımsız
 * ================================================================ */
static int test_peer_isolation(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps0 = &st.peers[0];
    struct peer_session *ps1 = &st.peers[1];

    /* ps1'e ayrı bir soket çifti */
    int sv[2];
    FQ_ASSERT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
    ps1->fd = sv[0];
    ps1->state = ST_ACTIVE;
    int rx1 = sv[1];

    /* ps0'a iki frame, ps1'e bir frame */
    uint8_t *b = frame_queue_reserve(ps0);
    FQ_ASSERT(b != NULL);
    memset(b, 0xA0, 8);
    FQ_ASSERT(frame_queue_commit(ps0, 8) == NOX_OK);

    b = frame_queue_reserve(ps1);
    FQ_ASSERT(b != NULL);
    memset(b, 0xB0, 8);
    FQ_ASSERT(frame_queue_commit(ps1, 8) == NOX_OK);

    FQ_ASSERT(frame_queue_count(ps0) == 1);
    FQ_ASSERT(frame_queue_count(ps1) == 1);
    FQ_ASSERT(ps0->tx_seq == 1);
    FQ_ASSERT(ps1->tx_seq == 1);   /* bağımsız sayaç */

    /* ps0 flush → yalnız ps0'ın soketine yazılır */
    FQ_ASSERT(frame_queue_flush(&st, ps0) == NOX_OK);
    uint8_t g0[8];
    FQ_ASSERT(rx_read(g0, sizeof(g0)) == (ssize_t)sizeof(g0));
    for (size_t i = 0; i < sizeof(g0); i++)
        FQ_ASSERT(g0[i] == 0xA0);

    /* ps1'in kuyruğu bozulmamış olmalı */
    FQ_ASSERT(frame_queue_count(ps1) == 1);
    FQ_ASSERT(queue_invariant(ps1));

    /* ps1 de flush edilir → kendi alıcısına gider */
    FQ_ASSERT(frame_queue_flush(&st, ps1) == NOX_OK);
    uint8_t g1[8];
    FQ_ASSERT(read(rx1, g1, sizeof(g1)) == (ssize_t)sizeof(g1));
    for (size_t i = 0; i < sizeof(g1); i++)
        FQ_ASSERT(g1[i] == 0xB0);

    close(rx1);
    fixture_teardown();
    return 0;
}

/* ================================================================
 * 5) reserve'siz commit — sözleşme ihlali ama tutarlılık korunur
 * ================================================================ */
static int test_commit_without_reserve(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    uint32_t seq_before = ps->tx_seq;

    /* Sözleşme: reserve → yaz → commit. Reserve edilmeden commit
     * çağrılırsa kuyruk yine de tail slotunu alır; frame DÜŞMEZ
     * (nonce tüketilir ama kaybolmaz → akış desync olmaz). */
    FQ_ASSERT(frame_queue_commit(ps, 16) == NOX_OK);
    FQ_ASSERT(frame_queue_count(ps) == 1);
    FQ_ASSERT(ps->tx_seq == seq_before + 1);
    FQ_ASSERT(queue_invariant(ps));

    /* Slot içeriği sıfır (hiç yazılmadı) → wire'da 16 sıfır gider */
    FQ_ASSERT(frame_queue_flush(&st, ps) == NOX_OK);
    uint8_t got[16];
    FQ_ASSERT(rx_read(got, sizeof(got)) == (ssize_t)sizeof(got));
    for (size_t i = 0; i < sizeof(got); i++)
        FQ_ASSERT(got[i] == 0x00);

    fixture_teardown();
    return 0;
}

/* ================================================================
 * 6) EINTR stresi — flush sırasında sinyal kesintisi
 *
 * SA_RESTART'sız handler + kısa aralıklı timer → send() EINTR
 * dönebilir. EINTR oluşmasa da test geçer (kırılganlık yok); oluşursa
 * kuyruk/byte tutarlılığı korunmalıdır (flush EINTR'da retry eder).
 * ================================================================ */
static volatile sig_atomic_t g_alarm_hits;

static void alarm_handler(int sig)
{
    (void)sig;
    g_alarm_hits++;
}

static int test_eintr_stress(void)
{
    FQ_ASSERT(fixture_setup() == 0);
    struct peer_session *ps = &st.peers[0];

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;              /* SA_RESTART YOK → EINTR mümkün */
    FQ_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0);

    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_interval.tv_usec = 200;      /* 200 µs */
    it.it_value.tv_usec = 200;
    FQ_ASSERT(setitimer(ITIMER_REAL, &it, NULL) == 0);

    const int rounds = 200;
    const size_t payload = 64;
    uint8_t rxbuf[256];
    size_t total_rx = 0;

    for (int i = 0; i < rounds; i++) {
        uint8_t *b = frame_queue_reserve(ps);
        FQ_ASSERT(b != NULL);
        memset(b, (uint8_t)i, payload);
        FQ_ASSERT(frame_queue_commit(ps, payload) == NOX_OK);

        nox_err_t rc = frame_queue_flush(&st, ps);
        FQ_ASSERT(rc == NOX_OK || rc == NOX_ERR_AGAIN);

        /* Alıcı tarafı: EINTR dayanıklı oku */
        ssize_t r = 0;
        while (r < (ssize_t)payload) {
            ssize_t got = read(g_rx_fd, rxbuf + r, payload - (size_t)r);
            if (got < 0 && errno == EINTR)
                continue;
            FQ_ASSERT(got > 0);
            r += got;
        }
        for (size_t k = 0; k < payload; k++)
            FQ_ASSERT(rxbuf[k] == (uint8_t)i);
        total_rx += payload;

        if (rc == NOX_ERR_AGAIN) {
            /* Kısmi yazım → kuyruk boşalana kadar tekrar dene */
            while (frame_queue_flush(&st, ps) == NOX_ERR_AGAIN)
                ;
            /* Kalan baytlar bir sonraki read'da gelecek */
        }
        FQ_ASSERT(queue_invariant(ps));
    }

    memset(&it, 0, sizeof(it));
    (void)setitimer(ITIMER_REAL, &it, NULL);

    FQ_ASSERT(total_rx == (size_t)rounds * payload);
    FQ_ASSERT(frame_queue_empty(ps));
    fprintf(stderr, "        (EINTR kesintisi sayısı: %d)\n",
            (int)g_alarm_hits);

    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== C1 frame_queue sözleşme + arm_tx testleri ===\n");

    RUN_TEST(test_arm_tx_guards);
    RUN_TEST(test_arm_tx_fail_closed);
    RUN_TEST(test_arm_tx_sets_epollout_interest);
    RUN_TEST(test_no_stale_ciphertext_leak);
    RUN_TEST(test_reset_keeps_tx_seq);
    RUN_TEST(test_peer_isolation);
    RUN_TEST(test_commit_without_reserve);
    RUN_TEST(test_eintr_stress);

    fprintf(stderr, "\nSonuç: %d/%d test başarılı\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
