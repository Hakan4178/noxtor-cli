/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_pin.c — PIN doğrulama birim testleri
 *
 * validate_pin() fonksiyonunu test eder.
 * Terminal'e bağımlı DEĞİL — saf fonksiyon testi.
 *
 * Testler:
 *   1. Geçerli PIN — tam minimum uzunlukta
 *   2. Geçerli PIN — uzun, UTF-8 karakterlerli
 *   3. Çok kısa PIN → NOX_ERR_PIN
 *   4. Çok uzun PIN → NOX_ERR_PIN
 *   5. Boş string → NOX_ERR_PIN
 *   6. NULL pointer → NOX_ERR_PIN
 *   7. Embedded null byte → NOX_ERR_PIN
 *   8. Kontrol karakteri (newline) → NOX_ERR_PIN
 *   9. DEL karakteri (0x7F) → NOX_ERR_PIN
 *  10. Tab karakteri → kabul edilmeli (tek istisna)
 *  11. Tam sınır — 128 byte PIN → geçerli
 *  12. 129 byte → NOX_ERR_PIN
 */

#include "common.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

/* ================================================================
 * TEST MAKROLARI
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

/* 1. Geçerli PIN — tam 8 byte (minimum) */
static int test_valid_min(void)
{
    TEST_ASSERT(validate_pin("12345678", 8) == NOX_OK);
    return 0;
}

/* 2. Geçerli PIN — uzun, karışık karakterler */
static int test_valid_long(void)
{
    const char *pin = "MyS3cur3P@ssw0rd!#2024";
    TEST_ASSERT(validate_pin(pin, strlen(pin)) == NOX_OK);
    return 0;
}

/* 3. Çok kısa — 7 byte */
static int test_too_short(void)
{
    TEST_ASSERT(validate_pin("1234567", 7) == NOX_ERR_PIN);
    return 0;
}

/* 4. Çok uzun — 129 byte */
static int test_too_long(void)
{
    char pin[130];
    memset(pin, 'A', 129);
    pin[129] = '\0';
    TEST_ASSERT(validate_pin(pin, 129) == NOX_ERR_PIN);
    return 0;
}

/* 5. Boş string */
static int test_empty(void)
{
    TEST_ASSERT(validate_pin("", 0) == NOX_ERR_PIN);
    return 0;
}

/* 6. NULL pointer */
static int test_null(void)
{
    TEST_ASSERT(validate_pin(NULL, 0) == NOX_ERR_PIN);
    return 0;
}

/* 7. Embedded kontrol karakteri — newline ortada */
static int test_control_char(void)
{
    /* "1234\n5678" — newline kontrol karakteri */
    char pin[] = "1234\n5678";
    TEST_ASSERT(validate_pin(pin, strlen(pin)) == NOX_ERR_PIN);
    return 0;
}

/* 8. DEL karakteri (0x7F) */
static int test_del_char(void)
{
    char pin[] = "12345678\x7F";
    TEST_ASSERT(validate_pin(pin, strlen(pin)) == NOX_ERR_PIN);
    return 0;
}

/* 9. Tab karakteri — kabul edilmeli */
static int test_tab_allowed(void)
{
    char pin[] = "pass\tword123";
    TEST_ASSERT(validate_pin(pin, strlen(pin)) == NOX_OK);
    return 0;
}

/* 10. Tam 128 byte — sınır değer, geçerli */
static int test_exact_max(void)
{
    char pin[129];
    memset(pin, 'Z', 128);
    pin[128] = '\0';
    TEST_ASSERT(validate_pin(pin, 128) == NOX_OK);
    return 0;
}

/* 11. UTF-8 multi-byte — Türkçe karakterler geçerli */
static int test_utf8_valid(void)
{
    /* "şifre123" — ş = 0xC5 0x9F (2 byte UTF-8) */
    const char *pin = "şifre123456";
    TEST_ASSERT(validate_pin(pin, strlen(pin)) == NOX_OK);
    return 0;
}

/* 12. Sadece boşluk — geçerli (minimum uzunluk sağlanırsa) */
static int test_spaces_valid(void)
{
    TEST_ASSERT(validate_pin("        ", 8) == NOX_OK); /* 8 space */
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== test_pin ===\n\n");

    RUN_TEST(test_valid_min);
    RUN_TEST(test_valid_long);
    RUN_TEST(test_too_short);
    RUN_TEST(test_too_long);
    RUN_TEST(test_empty);
    RUN_TEST(test_null);
    RUN_TEST(test_control_char);
    RUN_TEST(test_del_char);
    RUN_TEST(test_tab_allowed);
    RUN_TEST(test_exact_max);
    RUN_TEST(test_utf8_valid);
    RUN_TEST(test_spaces_valid);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
