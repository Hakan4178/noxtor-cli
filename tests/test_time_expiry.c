/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_time_expiry.c — dosya chunk timeout sözleşmesi (A: saat karışımı)
 *
 * A BULGUSU (audit derinlemesine): ps->rx_file timeout'u hâlâ time(NULL)
 * (duvar saati) ile ölçülüyordu (file_transfer.c set, event_loop.c check)
 * — halbuki tüm diğer timeout'lar M-12 ile CLOCK_MONOTONIC'e taşınmıştı.
 * Senaryo: suspend/resume ya da NTP adımı duvarı ileri fırlatır → aktif
 * transfer anında "timeout" → rx_abort → dosya unlinkat.
 *
 * Sözleşme (yeni API): file_transfer_chunk_expired(last, now, timeout) —
 * saf predikat, saat enjekte edilebilir. Test hem iyi hem kötü yamayı
 * kilitler:
 *   1-2. Sınır: delta==timeout → hâlâ canlı (strict >); timeout+1 → expired
 *   3-4. delta 0 / geri sıçrama (duvar saati simülasyonu) → canlı, wrap yok
 *   5.   Suspend senaryosu: duvar +3600s ama monotonic +5s → canlı
 *        (eski time(NULL) kontrolü bu senaryoda transferi öldürürdü)
 *   6.   NULL guard → fail-safe (sahipsiz girdi transferi öldürmesin)
 */

#include "common.h"
#include "types.h"
#include "file_transfer.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "test_common.h"


static struct timespec ts_of(long sec)
{
    struct timespec t = { .tv_sec = sec, .tv_nsec = 0 };
    return t;
}

/* 1) Sınır: delta tam timeout'a eşit → hâlâ canlı (strict >, M-2 kalıbı) */
static int test_boundary_not_expired(void)
{
    struct timespec last = ts_of(1000);
    struct timespec now  = ts_of(1000 + NOX_FILE_CHUNK_TIMEOUT_SEC);
    TEST_ASSERT(!file_transfer_chunk_expired(&last, &now,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 2) delta timeout+1 → expired (eski chunk gelmedi) */
static int test_expired_one_past(void)
{
    struct timespec last = ts_of(1000);
    struct timespec now  = ts_of(1000 + NOX_FILE_CHUNK_TIMEOUT_SEC + 1);
    TEST_ASSERT(file_transfer_chunk_expired(&last, &now,
                                            NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 3) delta 0 — chunk az önce geldi */
static int test_fresh_chunk(void)
{
    struct timespec last = ts_of(500);
    struct timespec now  = ts_of(500);
    TEST_ASSERT(!file_transfer_chunk_expired(&last, &now,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 4) Geri sıçrama: now < last (duvar saati senaryosunun simülü; monotonda
 *    imkânsız ama predikat wraparound/aşırı negatif farka karşı korumalı) */
static int test_backward_jump_safe(void)
{
    struct timespec last = ts_of(2000);
    struct timespec now  = ts_of(1000);   /* -1000s fark */
    TEST_ASSERT(!file_transfer_chunk_expired(&last, &now,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 5) Suspend senaryosu: duvar saati +3600s fırladı, gerçek süre +5s.
 *    Predikat SADECE monotonik farka bakar → transfer yaşamalı.
 *    (Bad patch kanıtı — yorum: eski time(NULL) tabanlı kontrol
 *     3600 > 60 der ve unlinkat ile download'ı sessizce öldürürdü;
 *     predikata duvar saati hiç girmediğinden burada yalnızca
 *     gerçek süre ölçülür.) */
static int test_suspend_scenario_survives(void)
{
    struct timespec last_mono = ts_of(5000);
    struct timespec now_mono  = ts_of(5000 + 5);   /* monotonic: +5s */

    TEST_ASSERT(!file_transfer_chunk_expired(&last_mono, &now_mono,
                                             NOX_FILE_CHUNK_TIMEOUT_SEC));
    return 0;
}

/* 6) NULL guard → fail-safe: timeout mekanizması sahipsiz girdiyle
 *    aktif transferi öldürmesin (kullanıcı verisi kaybı > bir uyarı) */
static int test_null_guard(void)
{
    struct timespec t = ts_of(1000);
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
