/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_cet_shstk.c — 4b CET-SS mekanizma regresyon testi
 *
 * Doğrulanan:
 *   1. cet_ss_lock_and_verify() BROKEN DÖNDÜRMEZ — sonuç ya UNSUPPORTED
 *      (CPU/kernel shstk'siz), ya ENFORCED (aktif + kilitli + #CP
 *      self-test), ya NOT_ENFORCED (pasif — CET-OFF yolu, child exit
 *      100 ile exercise edilir).
 *   2. Ardışık iki çağrı aynı sonucu verir (LOCK idempotent: zaten
 *      kilitliyken de rc=0 — empirik, bkz. src/cet_shstk.c).
 *   3. cet_ss_state_str() her geçerli değer için tanımlı metin döndürür.
 *
 * NOT: Test shstk'yi BU makinede açmaz (aktifleşme için ortam değişkeni
 *      gerekir) — mevcut durumu bozmadan mekanizmayı çalıştırır.
 */

#include "cet_shstk.h"

#include <stdio.h>
#include <string.h>

/* ================================================================
 * TEST MAKROLARI (şablon: test_onion_bind.c)
 * ================================================================ */
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

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 1) Sonuç BROKEN olmamalı — BROKEN = sahte güvenlik veya bozuk
 *    mekanizma demektir; regresyon tam olarak budur. */
static int test_state_gecerli(void)
{
    cet_ss_state st = cet_ss_lock_and_verify();

    fprintf(stderr, "\n     durum: %s (%d)", cet_ss_state_str(st), (int)st);
    TEST_ASSERT(st == CET_SS_UNSUPPORTED || st == CET_SS_ENFORCED ||
                st == CET_SS_NOT_ENFORCED);
    return 0;
}

/* 2) İdempotent: ikinci çağrı ilk ile aynı (kilit tekrarı bozmaz) */
static int test_idempotent(void)
{
    cet_ss_state a = cet_ss_lock_and_verify();
    cet_ss_state b = cet_ss_lock_and_verify();

    TEST_ASSERT(a == b);
    TEST_ASSERT(b != CET_SS_BROKEN);
    return 0;
}

/* 3) state_str: geçerli değerler tanımlı, birbirinden farklı */
static int test_state_str(void)
{
    TEST_ASSERT(strcmp(cet_ss_state_str(CET_SS_ENFORCED),
                       cet_ss_state_str(CET_SS_NOT_ENFORCED)) != 0);
    TEST_ASSERT(strcmp(cet_ss_state_str(CET_SS_BROKEN), "?") != 0);
    return 0;
}

int main(void)
{
    fprintf(stderr, "=== CET-SS (4b) mekanizma testleri ===\n");

    RUN_TEST(test_state_gecerli);
    RUN_TEST(test_idempotent);
    RUN_TEST(test_state_str);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
