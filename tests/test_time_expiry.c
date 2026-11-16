/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_time_expiry.c — file_transfer_chunk_expired (monotonic saat).
 * delta==timeout canlı, timeout+1 ölü; geri sıçrama/wrap yok; NULL
 * guard fail-safe. A bulgusu: duvar saati transferi öldürmemeli.
 */

#include "common.h"
#include "types.h"
#include "file_transfer.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "test_common.h"
#include "test_support.h"


/* 1) Sınır: delta tam timeout'a eşit → hâlâ canlı (strict >, M-2 kalıbı) */
static int test_boundary_not_expired(void)
{
    struct timespec last = nox_test_ts_of(1000);
    struct timespec now  = nox_test_ts_of(1000 + NOX_FILE_CHUNK_TIMEOUT_SEC);
    TEST_ASSERT(!file_transfer_chunk_expired(&last, &now,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 2) delta timeout+1 → expired (eski chunk gelmedi) */
static int test_expired_one_past(void)
{
    struct timespec last = nox_test_ts_of(1000);
    struct timespec now  = nox_test_ts_of(1000 + NOX_FILE_CHUNK_TIMEOUT_SEC + 1);
    TEST_ASSERT(file_transfer_chunk_expired(&last, &now,
                                            NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 3) delta 0 — chunk az önce geldi */
static int test_fresh_chunk(void)
{
    struct timespec last = nox_test_ts_of(500);
    struct timespec now  = nox_test_ts_of(500);
    TEST_ASSERT(!file_transfer_chunk_expired(&last, &now,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 4) Geri sıçrama: now < last (duvar saati senaryosunun simülü; monotonda
 *    imkânsız ama predikat wraparound/aşırı negatif farka karşı korumalı) */
static int test_backward_jump_safe(void)
{
    struct timespec last = nox_test_ts_of(2000);
    struct timespec now  = nox_test_ts_of(1000);   /* -1000s fark */
    TEST_ASSERT(!file_transfer_chunk_expired(&last, &now,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 5) Suspend: duvar saati +3600s, gerçek süre +5s. Predikat yalnız
 * monotonic farka bakar → transfer yaşar; time(NULL) tabanlı eski kontrol
 * 3600>60 deyip dosyayı sessizce öldürürdü. */
static int test_suspend_scenario_survives(void)
{
    struct timespec last_mono = nox_test_ts_of(5000);
    struct timespec now_mono  = nox_test_ts_of(5000 + 5);   /* monotonic: +5s */

    TEST_ASSERT(!file_transfer_chunk_expired(&last_mono, &now_mono,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 6) NULL guard → fail-safe: timeout mekanizması sahipsiz girdiyle
 *    aktif transferi öldürmesin (kullanıcı verisi kaybı > bir uyarı) */
static int test_null_guard(void)
{
    struct timespec t = nox_test_ts_of(1000);
    TEST_ASSERT(!file_transfer_chunk_expired(NULL, &t,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    TEST_ASSERT(!file_transfer_chunk_expired(&t, NULL,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

int main(void)
{
    fprintf(stderr, "=== chunk timeout sözleşmesi (A: CLOCK_MONOTONIC) ===\n");

    RUN_TEST(test_boundary_not_expired);
    RUN_TEST(test_expired_one_past);
    RUN_TEST(test_fresh_chunk);
    RUN_TEST(test_backward_jump_safe);
    RUN_TEST(test_suspend_scenario_survives);
    RUN_TEST(test_null_guard);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
