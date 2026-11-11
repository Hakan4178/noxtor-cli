/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_net_io.c — network.c I/O sözleşmeleri (socketpair fixtür'ü)
 *
 * Kapsam:
 *   read_full        — tam okuma, EOF ortada, len=0, bad fd, parçalı
 *                      teslimat, sinyalle EINTR, kısmi veri + timeout
 *   write_full       — EPIPE, kısa yazma döngüsü, toplam deadline
 *   ctrl_read_line   — satır + CRLF, C3 overflow (newline'sız dolan
 *                      buffer), kapalı peer (NOX_ERR_TOR), hızlı timeout
 *                      (NOX_ERR_TIMEOUT, enjekte edilebilir!), kısmi satır
 *                      sonrası timeout, toplam deadline (slow loris)
 *   ctrl_read_response — tek satır, 250- devam birleştirme, 4xx/5xx hata
 *                      (NOX_ERR_TOR), H-2 64-satır limiti (off-by-one
 *                      sınırı dahil), buffer tavanı, hızlı timeout,
 *                      yarım yanıt ve satırlar arası toplam deadline
 *   ctrl_send_command — write_full zarfı, kapalı peer (EPIPE)
 *   epoll_add/remove  — ekle/sil, double-remove (H-13 ENOENT→OK),
 *                      -1 epoll fd'de çökme yok
 *
 * Not: read_full/write_full üretimde NOX_READ_TIMEOUT_MS=10000 kullanır.
 * Testler, aynı kod yolunu küçük timeout ile sınamak için _timeout
 * varyantlarını kullanır; SIGPIPE main.c ile aynı şekilde ignore edilir.
 */

#include "common.h"
#include "network.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond) do {                                      \
    if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL %s:%d: %s\n",                        \
                __FILE__, __LINE__, #cond);                         \
        return 1;                                                   \
    }                                                               \
} while (0)

#define RUN_TEST(test_fn) do {                                      \
    tests_run++;                                                    \
    fprintf(stderr, "  [%d] %-45s ", tests_run, #test_fn);          \
    if (test_fn() == 0) {                                           \
        tests_passed++;                                             \
        fprintf(stderr, "\033[32mOK\033[0m\n");                     \
    } else {                                                        \
        fprintf(stderr, "\033[31mFAIL\033[0m\n");                   \
    }                                                               \
} while (0)

/* socketpair: sv[0] = test edilen taraf, sv[1] = karşı taraf */
static int make_pair(int sv[2])
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

static long monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Child yardımcıları: EINTR + kısa yazma/okuma döngüsü. */
static int write_all_raw(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

static int read_all_raw(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, p + off, len - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;
        off += (size_t)r;
    }
    return 0;
}

static int wait_child_ok(pid_t pid)
{
    int status = 0;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r < 0 && errno == EINTR);

    if (r != pid)
        return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ================================================================
 * read_full
 * ================================================================ */

static int test_read_full_exact(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "hello!", 6) == 6);

    char buf[16] = {0};
    TEST_ASSERT(read_full(sv[0], buf, 6) == NOX_OK);
    TEST_ASSERT(memcmp(buf, "hello!", 6) == 0);

    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_read_full_eof_midway(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "abc", 3) == 3);
    shutdown(sv[1], SHUT_WR);          /* yarım kapanış → EOF */

    char buf[16] = {0};
    /* 10 isteyecek: 3 geldi, sonra EOF → NOX_ERR_IO, ilk baytlar dolu */
    TEST_ASSERT(read_full(sv[0], buf, 10) == NOX_ERR_IO);
    TEST_ASSERT(memcmp(buf, "abc", 3) == 0);

    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_read_full_zero_len_and_bad_fd(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    /* len=0 → döngü çalışmaz, NULL buf bile güvenli */
    TEST_ASSERT(read_full(sv[0], NULL, 0) == NOX_OK);

    /* bad fd → hata (çökme yok) */
    char buf[4];
    TEST_ASSERT(read_full(-1, buf, 1) == NOX_ERR_IO);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* Parçalı teslimat: tek write() tek read() garantisi vermez.
 * Child 1+2+3 baytı aralıklı yazar; read_full döngüsü tamamlamalı. */
static int test_read_full_fragmented_delivery(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]); close(sv[1]);
        TEST_ASSERT(pid >= 0);
    }
    if (pid == 0) {
        close(sv[0]);
        alarm(5);
        const char *chunks[] = { "a", "bc", "def" };
        for (size_t i = 0; i < 3; i++) {
            if (write_all_raw(sv[1], chunks[i], strlen(chunks[i])) != 0)
                _exit(1);
            if (i < 2)
                usleep(50000);
        }
        _exit(0);
    }

    close(sv[1]);
    char buf[8] = {0};
    nox_err_t err = read_full(sv[0], buf, 6);
    close(sv[0]);
    int child_ok = wait_child_ok(pid);

    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(memcmp(buf, "abcdef", 6) == 0);
    TEST_ASSERT(child_ok == 0);
    return 0;
}

static volatile sig_atomic_t g_alarm_count;
static void alarm_handler(int sig)
{
    (void)sig;
    g_alarm_count++;
}

/* EINTR: SA_RESTART yok; poll/read sinyalle kesilse de okuma tamamlanmalı. */
static int test_read_full_signal_eintr(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    struct sigaction sa = {0}, old;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGALRM, &sa, &old) == 0);

    g_alarm_count = 0;
    struct itimerval it = {
        .it_interval = { .tv_sec = 0, .tv_usec = 10000 },
        .it_value    = { .tv_sec = 0, .tv_usec = 10000 },
    };
    TEST_ASSERT(setitimer(ITIMER_REAL, &it, NULL) == 0);

    pid_t pid = fork();
    if (pid < 0) {
        struct itimerval stop = {0};
        setitimer(ITIMER_REAL, &stop, NULL);
        sigaction(SIGALRM, &old, NULL);
        close(sv[0]); close(sv[1]);
        TEST_ASSERT(pid >= 0);
    }
    if (pid == 0) {
        close(sv[0]);
        usleep(100000);
        if (write_all_raw(sv[1], "abcdef", 6) != 0)
            _exit(1);
        _exit(0);
    }

    close(sv[1]);
    char buf[8] = {0};
    long t0 = monotonic_ms();
    nox_err_t err = read_full_timeout(sv[0], buf, 6, 1000);
    long elapsed = monotonic_ms() - t0;

    struct itimerval stop = {0};
    setitimer(ITIMER_REAL, &stop, NULL);
    sigaction(SIGALRM, &old, NULL);
    close(sv[0]);
    int child_ok = wait_child_ok(pid);

    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(memcmp(buf, "abcdef", 6) == 0);
    TEST_ASSERT(g_alarm_count > 0);
    TEST_ASSERT(t0 >= 0 && elapsed >= 50 && elapsed < 2000);
    TEST_ASSERT(child_ok == 0);
    return 0;
}

/* read_full timeout'u üretimde 10s; test için _timeout varyantı. */
static int test_read_full_timeout_no_data(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    char buf[4];
    long t0 = monotonic_ms();
    nox_err_t err = read_full_timeout(sv[0], buf, sizeof(buf), 150);
    long elapsed = monotonic_ms() - t0;
    close(sv[0]); close(sv[1]);

    TEST_ASSERT(err == NOX_ERR_TIMEOUT);
    TEST_ASSERT(t0 >= 0 && elapsed >= 100 && elapsed < 2000);
    return 0;
}

/* Veri geldikten sonra karşı taraf durursa: kısmi veri korunmalı, timeout. */
static int test_read_full_timeout_after_partial(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "abc", 3) == 3);

    char buf[6] = {0};
    long t0 = monotonic_ms();
    nox_err_t err = read_full_timeout(sv[0], buf, sizeof(buf), 150);
    long elapsed = monotonic_ms() - t0;
    close(sv[0]); close(sv[1]);

    TEST_ASSERT(err == NOX_ERR_TIMEOUT);
    TEST_ASSERT(memcmp(buf, "abc", 3) == 0);
    TEST_ASSERT(t0 >= 0 && elapsed >= 100 && elapsed < 2000);
    return 0;
}

/* ================================================================
 * ctrl_read_line
 * ================================================================ */

static int test_ctrl_read_line_basic_crlf(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "250 OK\r\n", 8) == 8);

    char buf[256] = {0};
    TEST_ASSERT(ctrl_read_line(sv[0], buf, sizeof(buf), 500) == NOX_OK);
    TEST_ASSERT(strcmp(buf, "250 OK\r\n") == 0);   /* satır CRLF dahil */

    close(sv[0]); close(sv[1]);
    return 0;
}

/* C3: newline'sız dolan buffer parçalı parse edilmemeli → OVERFLOW */
static int test_ctrl_read_line_overflow_no_newline(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "abcdefgh", 8) == 8);

    char buf[5];   /* en fazla 4 byte + NUL beklenir; satır sığmaz */
    TEST_ASSERT(ctrl_read_line(sv[0], buf, sizeof(buf), 500) ==
                NOX_ERR_OVERFLOW);

    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_ctrl_read_line_closed_peer(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    close(sv[1]);                       /* peer gitti */

    char buf[64];
    TEST_ASSERT(ctrl_read_line(sv[0], buf, sizeof(buf), 500) ==
                NOX_ERR_TOR);

    close(sv[0]);
    return 0;
}

/* Timeout enjekte edilebilir → 150ms'de hızlı hata (slow loris koruması) */
static int test_ctrl_read_line_fast_timeout(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);    /* hiç veri yok */

    char buf[64];
    TEST_ASSERT(ctrl_read_line(sv[0], buf, sizeof(buf), 150) ==
                NOX_ERR_TIMEOUT);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* Veri gelir, satır tamamlanmaz: timeout veri sonrası da çalışmalı. */
static int test_ctrl_read_line_partial_then_stall(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "250 OK", 6) == 6);  /* CRLF yok */

    char buf[64];
    TEST_ASSERT(ctrl_read_line(sv[0], buf, sizeof(buf), 150) ==
                NOX_ERR_TIMEOUT);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* Slow loris: her baytta timeout resetlenmemeli; toplam deadline bağlayıcı.
 * Child 100ms aralıkla "250 \r\n" yazar. Toplam deadline 120ms ise ilk
 * 1-2 bayttan sonra timeout; per-byte reset olsaydı ~500ms'de OK dönerdi. */
static int test_ctrl_read_line_total_deadline(void)
{
    int sv[2], go[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(pipe(go) == 0);

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]); close(sv[1]);
        close(go[0]); close(go[1]);
        TEST_ASSERT(pid >= 0);
    }
    if (pid == 0) {
        close(sv[0]);
        close(go[1]);
        alarm(5);
        signal(SIGPIPE, SIG_IGN);
        char c;
        while (read(go[0], &c, 1) < 0 && errno == EINTR) { }
        close(go[0]);
        const char *chunks[] = { "2", "5", "0", " ", "\r\n" };
        for (size_t i = 0; i < 5; i++) {
            if (write_all_raw(sv[1], chunks[i], strlen(chunks[i])) != 0)
                _exit(0);  /* parent timeout'ta kapattı */
            if (i < 4)
                usleep(100000);
        }
        _exit(0);
    }

    close(sv[1]);
    close(go[0]);
    TEST_ASSERT(write(go[1], "g", 1) == 1);
    close(go[1]);
    char buf[64];
    long t0 = monotonic_ms();
    nox_err_t err = ctrl_read_line(sv[0], buf, sizeof(buf), 120);
    long elapsed = monotonic_ms() - t0;
    close(sv[0]);
    int child_ok = wait_child_ok(pid);

    TEST_ASSERT(err == NOX_ERR_TIMEOUT);
    TEST_ASSERT(t0 >= 0 && elapsed >= 80 && elapsed < 400);
    TEST_ASSERT(child_ok == 0);
    return 0;
}

static int test_ctrl_read_line_tiny_buffer(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    char buf[1];
    TEST_ASSERT(ctrl_read_line(sv[0], buf, sizeof(buf), 100) ==
                NOX_ERR_CONFIG);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* ================================================================
 * ctrl_read_response
 * ================================================================ */

static int test_ctrl_response_single_line(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(write(sv[1], "250 OK\r\n", 8) == 8);

    char buf[256] = {0};
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 500) == NOX_OK);
    TEST_ASSERT(strcmp(buf, "250 OK\r\n") == 0);

    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_ctrl_response_continuation_joined(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    const char *resp = "250-AUTH=COOKIE\r\n250-B\r\n250 OK\r\n";
    TEST_ASSERT(write(sv[1], resp, strlen(resp)) == (ssize_t)strlen(resp));

    char buf[256] = {0};
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 500) == NOX_OK);
    TEST_ASSERT(strcmp(buf, resp) == 0);   /* devam satırları birleşti */

    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_ctrl_response_error_line(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    const char *resp = "515 Authentication failed\r\n";
    TEST_ASSERT(write(sv[1], resp, strlen(resp)) == (ssize_t)strlen(resp));

    char buf[256];
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 500) ==
                NOX_ERR_TOR);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* H-2 sınırı: 63 devam + 1 final = 64 satır → OK;
 * 64 devam + 1 final = 65 → OVERFLOW (off-by-one avcısı) */
static int test_ctrl_response_line_limit_boundary(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    for (int i = 0; i < 63; i++)
        TEST_ASSERT(write(sv[1], "250-x\r\n", 7) == 7);
    TEST_ASSERT(write(sv[1], "250 OK\r\n", 8) == 8);

    char buf[1024] = {0};
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 1000) == NOX_OK);
    close(sv[0]); close(sv[1]);

    /* 65 satır varyantı */
    int sv2[2];
    TEST_ASSERT(make_pair(sv2) == 0);
    for (int i = 0; i < 64; i++)
        TEST_ASSERT(write(sv2[1], "250-x\r\n", 7) == 7);
    TEST_ASSERT(write(sv2[1], "250 OK\r\n", 8) == 8);

    char buf2[1024];
    TEST_ASSERT(ctrl_read_response(sv2[0], buf2, sizeof(buf2), 1000) ==
                NOX_ERR_OVERFLOW);
    close(sv2[0]); close(sv2[1]);
    return 0;
}

static int test_ctrl_response_buffer_overflow(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    /* 17'şer baytlık devam satırları; 32'lik buffer 2. satırda taşar */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(write(sv[1], "250-xxxxxxxxxxx\r\n", 17) == 17);

    char buf[32];
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 1000) ==
                NOX_ERR_OVERFLOW);

    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_ctrl_response_fast_timeout(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    char buf[256];
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 150) ==
                NOX_ERR_TIMEOUT);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* İlk satır tamam, ikinci satır yarım: yanıt timeout'u ortada çalışmalı. */
static int test_ctrl_response_partial_then_stall(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    const char *partial = "250-AUTH=COOKIE\r\n250";
    TEST_ASSERT(write(sv[1], partial, strlen(partial)) ==
                (ssize_t)strlen(partial));

    char buf[256];
    TEST_ASSERT(ctrl_read_response(sv[0], buf, sizeof(buf), 150) ==
                NOX_ERR_TIMEOUT);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* Toplam deadline satırlar arasında da korunmalı (her satır resetlemez). */
static int test_ctrl_response_total_deadline(void)
{
    int sv[2], go[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(pipe(go) == 0);

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]); close(sv[1]);
        close(go[0]); close(go[1]);
        TEST_ASSERT(pid >= 0);
    }
    if (pid == 0) {
        close(sv[0]);
        close(go[1]);
        alarm(5);
        signal(SIGPIPE, SIG_IGN);
        char c;
        while (read(go[0], &c, 1) < 0 && errno == EINTR) { }
        close(go[0]);
        for (int i = 0; i < 4; i++) {
            if (write_all_raw(sv[1], "250-x\r\n", 7) != 0)
                _exit(0);
            usleep(100000);
        }
        _exit(0);
    }

    close(sv[1]);
    close(go[0]);
    TEST_ASSERT(write(go[1], "g", 1) == 1);
    close(go[1]);
    char buf[256];
    long t0 = monotonic_ms();
    nox_err_t err = ctrl_read_response(sv[0], buf, sizeof(buf), 120);
    long elapsed = monotonic_ms() - t0;
    close(sv[0]);
    int child_ok = wait_child_ok(pid);

    TEST_ASSERT(err == NOX_ERR_TIMEOUT);
    TEST_ASSERT(t0 >= 0 && elapsed >= 80 && elapsed < 400);
    TEST_ASSERT(child_ok == 0);
    return 0;
}

/* ================================================================
 * ctrl_send_command + epoll
 * ================================================================ */

static int test_ctrl_send_command_roundtrip(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    TEST_ASSERT(ctrl_send_command(sv[0], "GETINFO version\r\n") == NOX_OK);

    char buf[64] = {0};
    ssize_t n = read(sv[1], buf, sizeof(buf) - 1);
    TEST_ASSERT(n == 17);
    TEST_ASSERT(strcmp(buf, "GETINFO version\r\n") == 0);

    close(sv[0]); close(sv[1]);
    return 0;
}

/* SIGPIPE ignore (main.c ile aynı) altında EPIPE kontrollü hata olmalı. */
static int test_ctrl_send_command_closed_peer(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    close(sv[1]);  /* peer gitti */

    nox_err_t err = ctrl_send_command(sv[0], "GETINFO version\r\n");
    close(sv[0]);

    TEST_ASSERT(err == NOX_ERR_IO);
    return 0;
}

static int test_write_full_epipe(void)
{
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);
    close(sv[1]);

    nox_err_t err = write_full(sv[0], "x", 1);
    close(sv[0]);

    TEST_ASSERT(err == NOX_ERR_IO);
    return 0;
}

/* Kısa yazma: nonblocking fd + küçük SO_SNDBUF + yavaş okuyucu.
 * 1 MiB tek write'a sığmaz; write_full döngüsü tamamlamalı. */
static int test_write_full_short_writes_complete(void)
{
    enum { PAYLOAD_LEN = 1 << 20 };
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    int sndbuf = 4096;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    TEST_ASSERT(set_nonblocking(sv[0]) == 0);

    unsigned char *payload = malloc(PAYLOAD_LEN);
    if (!payload) {
        close(sv[0]); close(sv[1]);
        TEST_ASSERT(payload != NULL);
    }
    for (size_t i = 0; i < PAYLOAD_LEN; i++)
        payload[i] = (unsigned char)((i * 31u + 7u) & 0xffu);

    pid_t pid = fork();
    if (pid < 0) {
        free(payload);
        close(sv[0]); close(sv[1]);
        TEST_ASSERT(pid >= 0);
    }
    if (pid == 0) {
        close(sv[0]);
        alarm(5);
        unsigned char *rbuf = malloc(PAYLOAD_LEN);
        if (!rbuf)
            _exit(1);
        if (read_all_raw(sv[1], rbuf, PAYLOAD_LEN) != 0)
            _exit(1);
        if (memcmp(rbuf, payload, PAYLOAD_LEN) != 0)
            _exit(1);
        free(rbuf);
        _exit(0);
    }

    close(sv[1]);
    nox_err_t err = write_full_timeout(sv[0], payload, PAYLOAD_LEN, 5000);
    close(sv[0]);
    int child_ok = wait_child_ok(pid);
    free(payload);

    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(child_ok == 0);
    return 0;
}

/* Peer okumuyor: buffer dolunca toplam deadline timeout vermeli. */
static int test_write_full_timeout(void)
{
    enum { PAYLOAD_LEN = 1 << 20 };
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    int sndbuf = 4096;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    TEST_ASSERT(set_nonblocking(sv[0]) == 0);

    unsigned char *payload = malloc(PAYLOAD_LEN);
    if (!payload) {
        close(sv[0]); close(sv[1]);
        TEST_ASSERT(payload != NULL);
    }
    memset(payload, 'A', PAYLOAD_LEN);

    long t0 = monotonic_ms();
    nox_err_t err = write_full_timeout(sv[0], payload, PAYLOAD_LEN, 150);
    long elapsed = monotonic_ms() - t0;
    close(sv[0]); close(sv[1]);
    free(payload);

    TEST_ASSERT(err == NOX_ERR_TIMEOUT);
    TEST_ASSERT(t0 >= 0 && elapsed >= 100 && elapsed < 2000);
    return 0;
}

static int test_epoll_add_remove(void)
{
    int ep = epoll_create1(0);
    TEST_ASSERT(ep >= 0);
    int sv[2];
    TEST_ASSERT(make_pair(sv) == 0);

    TEST_ASSERT(epoll_add_fd(ep, sv[0]) == NOX_OK);
    TEST_ASSERT(epoll_remove_fd(ep, sv[0]) == NOX_OK);
    /* H-13: zaten kaldırılmış → ENOENT → temiz sayılır */
    TEST_ASSERT(epoll_remove_fd(ep, sv[0]) == NOX_OK);
    /* -1 epoll fd → hata, çökme yok */
    TEST_ASSERT(epoll_remove_fd(-1, sv[0]) == NOX_ERR_NET);
    TEST_ASSERT(epoll_add_fd(-1, sv[0]) == NOX_ERR_NET);

    close(sv[0]); close(sv[1]);
    close(ep);
    return 0;
}

int main(void)
{
    /* main.c ile aynı politika: kapalı peer'a yazma süreci öldürmemeli. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "SIGPIPE ignore kurulamadı: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "=== network I/O sözleşmeleri (socketpair) ===\n");

    RUN_TEST(test_read_full_exact);
    RUN_TEST(test_read_full_eof_midway);
    RUN_TEST(test_read_full_zero_len_and_bad_fd);
    RUN_TEST(test_read_full_fragmented_delivery);
    RUN_TEST(test_read_full_signal_eintr);
    RUN_TEST(test_read_full_timeout_no_data);
    RUN_TEST(test_read_full_timeout_after_partial);
    RUN_TEST(test_ctrl_read_line_basic_crlf);
    RUN_TEST(test_ctrl_read_line_overflow_no_newline);
    RUN_TEST(test_ctrl_read_line_closed_peer);
    RUN_TEST(test_ctrl_read_line_fast_timeout);
    RUN_TEST(test_ctrl_read_line_partial_then_stall);
    RUN_TEST(test_ctrl_read_line_total_deadline);
    RUN_TEST(test_ctrl_read_line_tiny_buffer);
    RUN_TEST(test_ctrl_response_single_line);
    RUN_TEST(test_ctrl_response_continuation_joined);
    RUN_TEST(test_ctrl_response_error_line);
    RUN_TEST(test_ctrl_response_line_limit_boundary);
    RUN_TEST(test_ctrl_response_buffer_overflow);
    RUN_TEST(test_ctrl_response_fast_timeout);
    RUN_TEST(test_ctrl_response_partial_then_stall);
    RUN_TEST(test_ctrl_response_total_deadline);
    RUN_TEST(test_ctrl_send_command_roundtrip);
    RUN_TEST(test_ctrl_send_command_closed_peer);
    RUN_TEST(test_write_full_epipe);
    RUN_TEST(test_write_full_short_writes_complete);
    RUN_TEST(test_write_full_timeout);
    RUN_TEST(test_epoll_add_remove);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
