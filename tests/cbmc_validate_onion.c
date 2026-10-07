/* SPDX-License-Identifier: GPL-3.0-or-later
 * cbmc_validate_onion.c — CBMC/ESBMC harness for crypto_onion_pubkey
 *                          format zinciri + network.c:validate_onion_address
 *
 * Self-contained: types.h/common.h/network.h kullanılmaz.
 * Sabitler manuel tanımlı.
 *
 * H-2 GÜNCELLEMESİ: validate_onion_address artık crypto_onion_pubkey'e
 * delege eder — uzunluk + suffix + charset + base32 decode + version
 * (0x03) + SHA3-256 checksum. Bu harness FORMAT zincirini kanıtlar:
 *   - onion_b32_decode OOB (out[35], 56-char loop) — bounds-check
 *   - format ihlali → false (checksum'a ulaşmadan)
 *   - format geçerli → decode + version doğrulanır
 *
 * SHA3-256 checksum MODELİ: model_sha3_checksum_ok() her zaman true
 * döner — SHA3 libsodium'dadır (trusted library, harness kapsamı dışı).
 * GERÇEK checksum davranışı (canlı Tor vektörü + bozuk checksum ret)
 * tests/test_onion_bind.c'de runtime'da kanıtlanır.
 *
 * Komut (CBMC):
 *   cbmc --c23 --bounds-check --pointer-check \
 *     --no-unwinding-assertions --unwind 57 \
 *     tests/cbmc_validate_onion.c
 *
 * Komut (ESBMC):
 *   esbmc -D__ESBMC__ --overflow-check --memory-leak-check \
 *     --unwind 57 tests/cbmc_validate_onion.c
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
#define NOX_ONION_LEN      62U  /* 56 base32 + ".onion" */
#define NOX_ONION_B32_LEN  56U  /* base32 kısım */
#define NOX_ONION_BODY_LEN 35U  /* pub(32) + checksum(2) + version(1) */

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
 * SHA3-256 checksum MODELİ — her zaman true
 *
 * Gerçek checksum src/crypto.c:crypto_onion_pubkey içinde
 * crypto_hash_sha3256 (libsodium, trusted) ile yapılır. Burada
 * model olarak true döner; pozitif testler format+version zincirini,
 * negatif testler checksum'a ulaşmayan erken ret yollarını kanıtlar.
 * ================================================================ */
static bool model_sha3_checksum_ok(const char *addr) {
    (void)addr;
    return true;
}

/* ================================================================
 * Fonksiyon kopyası — src/crypto.c onion_b32_decode
 * (OOB hassas bölge — bounds-check hedefi)
 * ================================================================ */
static int onion_b32_decode(const char *in, uint8_t out[NOX_ONION_BODY_LEN]) {
    uint32_t acc  = 0;
    unsigned bits = 0;
    size_t   o    = 0;

    for (size_t i = 0; i < NOX_ONION_B32_LEN; i++) {
        char c = in[i];
        unsigned v;
        if (c >= 'a' && c <= 'z')
            v = (unsigned)(c - 'a');
        else if (c >= '2' && c <= '7')
            v = 26u + (unsigned)(c - '2');
        else
            return -1;

        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    if (bits != 0 || o != NOX_ONION_BODY_LEN)
        return -1;
    return 0;
}

/* ================================================================
 * Fonksiyon kopyası — src/crypto.c:crypto_onion_pubkey format zinciri
 * + src/network.c:validate_onion_address sarmalayıcı
 * ================================================================ */
static bool crypto_onion_pubkey_format(const char *addr) {
    if (!addr)
        return false;

    /* 1-2. uzunluk + suffix + charset */
    if (strlen(addr) != NOX_ONION_LEN)
        return false;
    if (strcmp(addr + NOX_ONION_B32_LEN, ".onion") != 0)
        return false;
    for (size_t i = 0; i < NOX_ONION_B32_LEN; i++) {
        char c = addr[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
            return false;
    }

    /* 3. decode → 35B body */
    uint8_t body[NOX_ONION_BODY_LEN];
    if (onion_b32_decode(addr, body) != 0)
        return false;

    /* 4. version == 0x03 */
    if (body[NOX_ONION_BODY_LEN - 1] != 0x03)
        return false;

    /* 5. checksum — MODEL (gerçek SHA3 libsodium'da) */
    bool ok = model_sha3_checksum_ok(addr);

    /* body stack'te — hassas değil (pub anahtarı public) ama temizlik */
    memset(body, 0, sizeof(body));
    return ok;
}

bool validate_onion_address(const char *addr) {
    return crypto_onion_pubkey_format(addr);
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

/* ================================================================
 * Pozitif testler — version byte (body[34]) 0x03 olacak şekilde
 * son iki char ayarlanır: body[34] = ((v[54] & 7) << 5) | v[55]
 * 0x03 → v[55] = 3 ('d'), v[54] ∈ {a,i,q,y} (index %8 == 0)
 * ================================================================ */

/* T10: Geçerli v3 onion — tüm base32 (version uyumlu son) */
static void test_valid_alphabet(void) {
    char buf[63];
    memcpy(buf, "abcdefghijklmnopqrstuvwxyz234567", 32);
    memcpy(buf + 32, "abcdefghijklmnopqrstuvwxyz234567", 24);
    buf[54] = 'y'; /* &7 == 0 */
    buf[55] = 'd'; /* v = 3 → body[34] = 0x03 */
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T11: Sınır — 'a' (son iki char version için) */
static void test_all_a(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[55] = 'd';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T12: Sınır — 'z' (version uyumlu son) */
static void test_all_z(void) {
    char buf[63];
    memset(buf, 'z', 56);
    buf[54] = 'y';
    buf[55] = 'd';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T13: Sınır — '2' (version uyumlu son) */
static void test_all_2(void) {
    char buf[63];
    memset(buf, '2', 56);
    buf[54] = 'a';
    buf[55] = 'd';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T14: Sınır — '7' (version uyumlu son) */
static void test_all_7(void) {
    char buf[63];
    memset(buf, '7', 56);
    buf[54] = 'i'; /* 'i' index 8, %8==0 — charset geçerli */
    buf[55] = 'd';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == true);
}

/* T15: Sınır dışı — son base32 char ':' (geçersiz) */
static void test_colon_at_end(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[55] = ':';
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T16: Version byte 0x03 DEĞİL → false (charset geçerli olsa bile)
 * body[34] != 0x03: v[55] != 3 (örn. 'a' → 0) */
static void test_wrong_version(void) {
    char buf[63];
    memset(buf, 'a', 56);
    buf[55] = 'a'; /* v=0 → body[34] = 0 != 0x03 */
    memcpy(buf + 56, ".onion", 7);
    assert(validate_onion_address(buf) == false);
}

/* T17: Nondeterministic input — property-based */
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
        /* ...ve decode version byte 0x03 üretmeli */
        uint8_t body[NOX_ONION_BODY_LEN];
        assert(onion_b32_decode(buf, body) == 0);
        assert(body[NOX_ONION_BODY_LEN - 1] == 0x03);
        memset(body, 0, sizeof(body));
    }
}

/* T18: Nondeterministic suffix */
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

/* T19: decode doğrudan nondeterministic charset ile — OOB yok
 * (bounds-check: out[o++] o asla 35'i aşamaz) */
static void test_decode_bounds(void) {
    char buf[NOX_ONION_B32_LEN];
    for (size_t i = 0; i < NOX_ONION_B32_LEN; i++)
        buf[i] = __VERIFIER_nondet_char();

    uint8_t body[NOX_ONION_BODY_LEN];
    int rc = onion_b32_decode(buf, body);
    if (rc == 0) {
        /* başarılıysa tam 35 byte dolu — o[] sınırı aşılmadı */
        assert(body[0] <= 0xFF); /* okuma indeksi geçerli (bounds-check) */
    }
    memset(body, 0, sizeof(body));
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
    test_wrong_version();           /* T16 */
    test_nondeterministic();        /* T17 */
    test_nondeterministic_suffix(); /* T18 */
    test_decode_bounds();           /* T19 */
    return 0;
}
