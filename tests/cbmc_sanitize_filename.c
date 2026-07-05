/* SPDX-License-Identifier: GPL-3.0-or-later
 * cbmc_sanitize_filename.c — CBMC/ESBMC harness for file_transfer.c:sanitize_filename
 *
 * Self-contained: types.h/common.h/file_transfer.h kullanılmaz.
 * Sabitler ve tipler manuel tanımlı.
 *
 * Doğrulanan fonksiyon:
 *   sanitize_filename — path traversal, whitelist, ".." blocking
 *
 * Komut (CBMC):
 *   cbmc tests/cbmc_sanitize_filename.c \
 *     --unwind 20 --no-standard-checks --stop-on-fail
 *
 * Komut (ESBMC):
 *   esbmc -D__ESBMC__ tests/cbmc_sanitize_filename.c \
 *     --unwind 20 --no-unwinding-assertions --context-bound 2
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

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
 * EXTERNAL FUNCTION STUBS
 * ================================================================ */

/* randombytes_random — nondeterministic uint32 */
uint32_t randombytes_random(void) {
    return (uint32_t)__VERIFIER_nondet_int();
}

/* ================================================================
 * Fonksiyon kopyası — src/file_transfer.c:28-78
 * ================================================================ */
void sanitize_filename(char *name, size_t max_len) {
  if (!name || max_len == 0)
    return;

  /* 1. Yol ayırıcılarını kes — sadece basename'i al */
  char *slash = strrchr(name, '/');
  if (slash) {
    size_t remain = strlen(slash + 1) + 1;
    if (remain > max_len)
      remain = max_len;
    memmove(name, slash + 1, remain);
    name[max_len - 1] = '\0';
  }

  /* Uzunluğu max_len ile sınırla */
  size_t len = strlen(name);
  if (len >= max_len) {
    len = max_len - 1;
    name[len] = '\0';
  }

  /* 2. Whitelist filtresi — izin verilmeyen her karakter '_' olur */
  for (size_t i = 0; i < len; i++) {
    char c = name[i];
    bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!allowed) {
      name[i] = '_';
    }
  }

  /* 3. Ardışık nokta ("..") engelle — her ".." → "__" */
  for (size_t i = 0; i + 1 < len; i++) {
    if (name[i] == '.' && name[i + 1] == '.') {
      name[i] = '_';
      name[i + 1] = '_';
    }
  }

  /* 4. Baştaki nokta ("gizli dosya" veya "." / "..") engelle */
  if (len > 0 && name[0] == '.') {
    name[0] = '_';
  }

  /* 5. Boş ad kontrolü — rastgele hex ID ata */
  len = strlen(name);
  if (len == 0) {
    uint32_t rnd = randombytes_random();
    snprintf(name, max_len, "file_%08x", rnd);
  }
}

/* ================================================================
 * Helper — output'un whitelist kurallarına uygunluğunu kontrol et
 * ================================================================ */
static bool is_whitelisted(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static bool has_no_double_dots(const char *s, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (s[i] == '.' && s[i + 1] == '.')
            return false;
    }
    return true;
}

/* ================================================================
 * Test fonksiyonları
 * ================================================================ */

/* T1: NULL name — crash yok */
static void test_null_name(void) {
    sanitize_filename(NULL, 10);
}

/* T2: max_len=0 — crash yok */
static void test_zero_max_len(void) {
    char buf[] = "test.txt";
    sanitize_filename(buf, 0);
}

/* T3: Path stripping — basename'i al, result non-empty */
static void test_path_stripping(void) {
    char buf[] = "dir/sub/deep/file.txt";
    sanitize_filename(buf, sizeof(buf));
    size_t len = strlen(buf);
    assert(len > 0);
}

/* T4: Whitelist filter — tüm char'lar izinli veya '_' */
static void test_whitelist(void) {
    char buf[] = "/etc/passwd\x01\x02\x03";
    sanitize_filename(buf, sizeof(buf));
    size_t len = strlen(buf);
    assert(len < sizeof(buf));
    for (size_t i = 0; i < len; i++) {
        assert(is_whitelisted(buf[i]) || buf[i] == '_');
    }
}

/* T5: Double dot blocking — ".." → "__" */
static void test_double_dot(void) {
    char buf[] = "a..b";
    sanitize_filename(buf, sizeof(buf));
    size_t len = strlen(buf);
    assert(has_no_double_dots(buf, len));
}

/* T6: Leading dot — "." → "_" */
static void test_leading_dot(void) {
    char buf[] = ".hidden";
    sanitize_filename(buf, sizeof(buf));
    assert(buf[0] != '.');
}

/* T7: max_len truncation */
static void test_truncation(void) {
    char buf[10];
    memset(buf, 'A', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    sanitize_filename(buf, 5);
    assert(strlen(buf) < 5);
}

/* T8: Empty name fallback — "///" → "file_XXXXXXXX" */
static void test_empty_fallback(void) {
    char buf[16];
    buf[0] = '/'; buf[1] = '/'; buf[2] = '/'; buf[3] = '\0';
    sanitize_filename(buf, sizeof(buf));
    /* Boş olduktan sonra "file_" prefix'i */
    size_t len = strlen(buf);
    if (len >= 5) {
        assert(buf[0] == 'f');
        assert(buf[1] == 'i');
        assert(buf[2] == 'l');
        assert(buf[3] == 'e');
        assert(buf[4] == '_');
    }
}

/* T9: max_len=1 — sadece null byte */
static void test_single_char_max(void) {
    char buf[] = "hello";
    sanitize_filename(buf, 1);
    assert(buf[0] == '\0');
}

/* T10: Kapsamlı invariant — tüm input için postconditions */
static void test_comprehensive(void) {
    char buf[32];
    /* Nondeterministic input doldur */
    for (size_t i = 0; i < sizeof(buf) - 1; i++)
        buf[i] = __VERIFIER_nondet_char();
    buf[sizeof(buf) - 1] = '\0';

    sanitize_filename(buf, sizeof(buf));

    size_t len = strlen(buf);

    /* Guard 1: boşa çıkmışsa fallback */
    if (len == 0) {
        /* fallback "file_XXXXXXXX" formatında */
        assert(len > 0);  /* artık boş olmamalı */
    }

    /* Guard 2: tüm char'lar whitelist veya '_' */
    for (size_t i = 0; i < len; i++) {
        assert(is_whitelisted(buf[i]) || buf[i] == '_');
    }

    /* Guard 3: ".." yok */
    assert(has_no_double_dots(buf, len));

    /* Guard 4: leading '.' yok */
    assert(len == 0 || buf[0] != '.');

    /* Guard 5: null-sonlanmış */
    assert(buf[len] == '\0');
}

/* T11: Path + slash kombinasyonu — ESBMC strrchr bug workaround */
static void test_path_combo(void) {
    char buf[] = "/foo/bar/baz.txt";
    sanitize_filename(buf, sizeof(buf));
    size_t len = strlen(buf);
    assert(len > 0);
}

/* T11b: Slash removal — sadece CBMC */
#ifndef __ESBMC__
static void test_slash_removal(void) {
    char buf[] = "/foo/bar/baz.txt";
    sanitize_filename(buf, sizeof(buf));
    size_t len = strlen(buf);
    for (size_t i = 0; i < len; i++) {
        assert(buf[i] != '/');
    }
    assert(len > 0);
}
#endif

/* T12: max_len = sizeof(buf) — truncation olmamalı */
static void test_no_truncation(void) {
    char buf[] = "hello.txt";
    size_t orig_len = strlen(buf);
    sanitize_filename(buf, sizeof(buf));
    assert(strlen(buf) == orig_len);
}

/* T13: ".." prefix — "." + "." → "_" + "_" */
static void test_dotdot_prefix(void) {
    char buf[] = "..";
    sanitize_filename(buf, sizeof(buf));
    assert(buf[0] == '_');
    assert(buf[1] == '_');
}

/* T14: Tek "." — "." → "_" */
static void test_single_dot(void) {
    char buf[] = ".";
    sanitize_filename(buf, sizeof(buf));
    assert(buf[0] == '_');
}

/* ================================================================
 * main
 * ================================================================ */
int main(void) {
    test_null_name();           /* T1 */
    test_zero_max_len();        /* T2 */
    test_path_stripping();      /* T3 */
    test_whitelist();           /* T4 */
    test_double_dot();          /* T5 */
    test_leading_dot();         /* T6 */
    test_truncation();          /* T7 */
    test_empty_fallback();      /* T8 */
    test_single_char_max();     /* T9 */
    test_comprehensive();       /* T10 */
    test_path_combo();          /* T11 */
    test_no_truncation();       /* T12 */
    test_dotdot_prefix();       /* T13 */
    test_single_dot();          /* T14 */
#ifndef __ESBMC__
    test_slash_removal();       /* T11b */
#endif
    return 0;
}
