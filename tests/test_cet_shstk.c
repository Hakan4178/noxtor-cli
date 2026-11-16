/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_cet_shstk.c — CET shadow stack: BROKEN dönmez, LOCK idempotent,
 * durum metinleri tanımlı. Makinede shstk açmaz; mevcut durumu bozmaz.
 */

#include "cet_shstk.h"

#include <stdio.h>
#include <string.h>
#include "test_common.h"



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
