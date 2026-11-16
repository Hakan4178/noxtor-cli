/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_support.h — proje bağımlılığı olmayan ortak test yardımcıları
 *
 * Bu header yalnız test binary'lerine dahil edilir. Yardımcılar
 * `static inline` olduğundan her test tek çeviri birimi olarak
 * derlenir; Makefile'da ek nesne/link kuralı gerekmez.
 *
 * Proje tiplerine ihtiyaç duyan helper'lar test_protocol_support.h'de.
 * Seccomp stage süitleri yalnız bu header'ı kullanır; böylece
 * sodium/proje başlıkları stage testlerine sızmaz.
 */
#ifndef NOX_TEST_SUPPORT_H
#define NOX_TEST_SUPPORT_H

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Sabit saniye → timespec; timeout sınırı testlerinde ortak. */
static inline struct timespec nox_test_ts_of(long sec)
{
    struct timespec t = { .tv_sec = sec, .tv_nsec = 0 };
    return t;
}

/* EINTR'de yeniden dene; EOF/kısa okuma → -1. */
static inline int nox_test_read_exact(int fd, void *buf, size_t len)
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

/* Seccomp stage süitleri: senaryoyu ayrı child process'te koşar.
 * should_die=1 → SIGSYS, 0 → normal _exit(0). Dönüş: 1=PASS, 0=FAIL.
 * `name` yalnız çağrı yerindeki okunabilirlik içindir; çıktı `desc`. */
static inline int nox_test_seccomp_run(const char *name, const char *desc,
                                       void (*fn)(void), int should_die)
{
    (void)name;
    printf("  %-38s ", desc);

    pid_t child = fork();
    if (child < 0) {
        printf("[SKIP] fork başarısız\n");
        return 0;
    }

    if (child == 0) {
        fn();  /* asla dönmez — SIGSYS veya _exit */
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);

    if (should_die) {
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
            printf("[PASS] SIGSYS ✓\n");
            return 1;
        }
        if (WIFEXITED(status)) {
            printf("[FAIL] exit=%d (SIGSYS bekleniyordu)\n",
                   WEXITSTATUS(status));
            return 0;
        }
        printf("[FAIL] signal=%d (SIGSYS bekleniyordu)\n", WTERMSIG(status));
        return 0;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[PASS] yaşadı ✓\n");
        return 1;
    }
    if (WIFSIGNALED(status)) {
        printf("[FAIL] signal=%d (yaşaması bekleniyordu)\n",
               WTERMSIG(status));
        return 0;
    }
    printf("[FAIL] exit=%d (yaşaması bekleniyordu)\n", WEXITSTATUS(status));
    return 0;
}

#endif /* NOX_TEST_SUPPORT_H */
