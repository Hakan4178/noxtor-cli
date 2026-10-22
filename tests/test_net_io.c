/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_net_io.c — network.c I/O sözleşmeleri (socketpair fixtür'ü)
 *
 * Kapsam:
 *   read_full        — tam okuma, EOF ortada, len=0, bad fd
 *   ctrl_read_line   — satır + CRLF, C3 overflow (newline'sız dolan
 *                      buffer), kapalı peer (NOX_ERR_TOR), hızlı timeout
 *                      (NOX_ERR_TIMEOUT, enjekte edilebilir!), minik buffer
 *   ctrl_read_response — tek satır, 250- devam birleştirme, 4xx/5xx hata
 *                      (NOX_ERR_TOR), H-2 64-satır limiti (off-by-one
 *                      sınırı dahil), buffer tavanı, hızlı timeout
 *                      (NOX_ERR_TIMEOUT)
 *   ctrl_send_command — write_full zarfı
 *   epoll_add/remove  — ekle/sil, double-remove (H-13 ENOENT→OK),
 *                      -1 epoll fd'de çökme yok
 *
 * Not: read_full timeout'u NOX_READ_TIMEOUT_MS=10000 sabitine bağlı
 * (enjekte edilemez) — timeout testi bilinçli YOK (10s yavaş); poll
 * öncelikli desen ctrl_read_line'da aynı kod yoluyla kapsanıyor.
 */

#include "common.h"
#include "network.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
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
    fprintf(stderr, "=== network I/O sözleşmeleri (socketpair) ===\n");

    RUN_TEST(test_read_full_exact);
    RUN_TEST(test_read_full_eof_midway);
    RUN_TEST(test_read_full_zero_len_and_bad_fd);
    RUN_TEST(test_ctrl_read_line_basic_crlf);
    RUN_TEST(test_ctrl_read_line_overflow_no_newline);
    RUN_TEST(test_ctrl_read_line_closed_peer);
    RUN_TEST(test_ctrl_read_line_fast_timeout);
    RUN_TEST(test_ctrl_read_line_tiny_buffer);
    RUN_TEST(test_ctrl_response_single_line);
    RUN_TEST(test_ctrl_response_continuation_joined);
    RUN_TEST(test_ctrl_response_error_line);
    RUN_TEST(test_ctrl_response_line_limit_boundary);
    RUN_TEST(test_ctrl_response_buffer_overflow);
    RUN_TEST(test_ctrl_response_fast_timeout);
    RUN_TEST(test_ctrl_send_command_roundtrip);
    RUN_TEST(test_epoll_add_remove);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
