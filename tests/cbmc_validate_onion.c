/* SPDX-License-Identifier: GPL-3.0-or-later
 * cbmc_validate_onion.c — CBMC/ESBMC harness for network.c:validate_onion_address
 *
 * Self-contained: types.h/common.h/network.h kullanılmaz.
 * Sabitler manuel tanımlı.
 *
 * Doğrulanan fonksiyon:
 *   validate_onion_address — V3 onion format doğrulama
 *
 * Komut (CBMC):
 *   cbmc tests/cbmc_validate_onion.c \
 *     --unwind 57 --no-standard-checks --stop-on-fail
 *
 * Komut (ESBMC):
 *   esbmc -D__ESBMC__ tests/cbmc_validate_onion.c \
 *     --unwind 57 --no-unwinding-assertions --context-bound 2
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* ================================================================
 * Sabitler
 * ================================================================ */
#define NOX_ONION_LEN  62U  /* 56 base32 + ".onion" */

/* ================================================================
 * CBMC + ESBMC nondeterministic stubs
 * ================================================================ */
#ifdef __CPROVER__
extern size_t  __VERIFIER_nondet_size_t(void);
extern int     __VERIFIER_nondet_int(void);
extern char    __VERIFIER_nondet_char(void);
extern _Bool   __VERIFIER_nondet_bool(void);
#endif

#ifdef __ESBMC__
extern size_t __VERIFIER_nondet_size_t(void);
extern int    __VERIFIER_nondet_int(void);
extern char   __VERIFIER_nondet_char(void);
extern _Bool  __VERIFIER_nondet_bool(void);
void __CPROVER_assume(_Bool cond) { if (!cond) __ESBMC_assume(0); }
#endif

/* ================================================================
 * Fonksiyon kopyası — src/network.c:60-80
 * ================================================================ */
bool validate_onion_address(const char *addr) {
  if (!addr)
    return false;

  size_t len = strlen(addr);
  if (len != NOX_ONION_LEN)
    return false;

  /* ".onion" suffix kontrolü */
  if (strcmp(addr + 56, ".onion") != 0)
    return false;

  /* İlk 56 karakter base32 olmalı: a-z, 2-7 */
  for (size_t i = 0; i < 56; i++) {
    char c = addr[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
      return false;
  }

  return true;
}

/* ================================================================
 * Test fonksiyonları
 * ================================================================ */

/* T1: NULL input → false */
static void test_null(void) {
    assert(validate_onion_address(NULL) == false);
}

/* T2: Boş string → false */
static void test_empty(void) {
    assert(validate_onion_address("") == false);
}

/* T3: 61 karakter (kısa) → false */
static void test_too_short(void) {
    char buf[62];
    memset(buf, 'a', 61);
    buf[61] = '\0';
    assert(validate_onion_address(buf) == false);
}

/* T4: 63 karakter (uzun) → false */
static void test_too_long(void) {
    char buf[64];
    memset(buf, 'a', 63);
    buf[63] = '\0';
    assert(validate_onion_address(buf) == false);
}

/* T5: ".onion" suffix yok → false */
static void test_wrong_suffix(void) {
    char buf[63];
    memset(buf, 'a', 56);
    memcpy(buf + 56, ".com\0", 5);
    buf[61] = '\0';
    assert(validate_onion_address(buf) == false);
}

/* T6: Geçersiz charset — büyük harf */
static void test_uppercase(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[0] = 'A';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T7: Geçersiz charset — rakam '1' */
static void test_digit_1(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[0] = '1';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T8: Geçersiz charset — rakam '8' */
static void test_digit_8(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[0] = '8';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T9: Geçersiz karakter — boşluk */
static void test_space(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[28] = ' ';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T10: Geçerli v3 onion — tüm base32 */
static void test_valid_alphabet(void) {
    char buf[63];
    memcpy(buf, "abcdefghijklmnopqrstuvwxyz234567", 32);
    memcpy(buf + 32, "abcdefghijklmnopqrstuvwxyz234567", 24);
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T11: Sınır — sadece 'a' */
static void test_all_a(void) {
    char buf[63];
    memset(buf, 'a', 56);
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T12: Sınır — sadece 'z' */
static void test_all_z(void) {
    char buf[63];
    memset(buf, 'z', 56);
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T13: Sınır — sadece '2' */
static void test_all_2(void) {
    char buf[63];
    memset(buf, '2', 56);
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T14: Sınır — sadece '7' */
static void test_all_7(void) {
    char buf[63];
    memset(buf, '7', 56);
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T15: Sınır dışı — 'b' (geçerli) ama son karakter ':' (geçersiz) */
static void test_colon_at_end(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[55] = ':';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T16: Nondeterministic input — property-based */
static void test_nondeterministic(void) {
    char buf[63];
    for (size_t i = 0; i < 56; i++)
        buf[i] = __VERIFIER_nondet_char();
    memcpy(buf + 56, ".onion", 7);

    bool result = validate_onion_address(buf);

    if (result) {
        /* True döndüyse tüm ilk 56 karakter base32 olmalı */
        for (size_t i = 0; i < 56; i++) {
            char c = buf[i];
            assert((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'));
        }
    }
}

/* T17: Nondeterministic suffix */
static void test_nondeterministic_suffix(void) {
    char buf[63];
    memset(buf, 'a', 56);
    for (size_t i = 0; i < 6; i++)
        buf[56 + i] = __VERIFIER_nondet_char();
    buf[62] = '\0';

    bool result = validate_onion_address(buf);

    if (result) {
        assert(buf[56] == '.');
        assert(buf[57] == 'o');
        assert(buf[58] == 'n');
        assert(buf[59] == 'i');
        assert(buf[60] == 'o');
        assert(buf[61] == 'n');
    }
}

/* ================================================================
 * main
 * ================================================================ */
int main(void) {
    test_null();                    /* T1 */
    test_empty();                   /* T2 */
    test_too_short();               /* T3 */
    test_too_long();                /* T4 */
    test_wrong_suffix();            /* T5 */
    test_uppercase();               /* T6 */
    test_digit_1();                 /* T7 */
    test_digit_8();                 /* T8 */
    test_space();                   /* T9 */
    test_valid_alphabet();          /* T10 */
    test_all_a();                   /* T11 */
    test_all_z();                   /* T12 */
    test_all_2();                   /* T13 */
    test_all_7();                   /* T14 */
    test_colon_at_end();            /* T15 */
    test_nondeterministic();        /* T16 */
    test_nondeterministic_suffix(); /* T17 */
    return 0;
}
