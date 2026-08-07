/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_onion_derive.c — Onion seed / Tor expanded key birim testleri
 *
 * Kapsam (docs/onion-key-derived-plan.md §5):
 *   1. Determinizm: aynı master_key → aynı onion_seed / expanded / pub
 *   2. Ayrım: master_key değişince seed/adres değişmeli (D1-D3)
 *   3. KRİTİK format: expanded = [clamped_scalar(32) || prefix(32)]
 *      — RFC 8032 §5.1.5 clamp doğrulaması (3. tur kriptograf düzeltmesi)
 *   4. pub == scalarmult_ed25519_base(clamped_scalar) — Tor'un scalar'dan
 *      türeteceği pub ile birebir aynı (plan "pub GÜVENİLİR" iddiası)
 *   5. Sabit vektörler (bağımsız Python/nacl doğrulamasıyla üretildi)
 *   6. NULL güvenlik
 *
 * Ayrıca .sh harness'i için:
 *   --emit-key  : expanded key'in base64'ünü basar (ADD_ONION e2e için)
 *   --emit-addr : v3 onion adresini basar (determinizm .sh karşılaştırması)
 */

#include "common.h"
#include "types.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>


/* ================================================================
 * SABİT TEST VEKTÖRLERİ
 *
 * master_key = 0x00..0x1f (mk) ve 0x01..0x20 (mk2).
 * Vektörler bağımsız kaynaklarla üretildi ve üç yoldan doğrulandı:
 *   - libsodium crypto_kdf (ctypes)  → seed
 *   - hashlib SHA-512 + RFC 8032 clamp → expanded
 *   - nacl scalarmult_ed25519_base  → pub
 * ================================================================ */
static const uint8_t MK1[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
};
static const uint8_t MK2[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
};

/* crypto_derive_onion_seed(MK1) — libsodium crypto_kdf(subkey=4) çıktısı */
static const uint8_t VEC_SEED1[32] = {
    0x8c,0x3c,0xa5,0x4a,0x2e,0x7d,0xf9,0xb8,
    0x61,0xd6,0x63,0xd7,0xf9,0x67,0x42,0x53,
    0x52,0x45,0xa9,0xdc,0x91,0x90,0x86,0x49,
    0xe5,0xe7,0x51,0xce,0x1d,0xd2,0x12,0x20,
};

/* derive_tor_expanded_key(VEC_SEED1) — SHA-512 + clamp (hashlib doğrulandı) */
static const uint8_t VEC_EXP1[64] = {
    0xe8,0x92,0x92,0xda,0x29,0x6b,0x0e,0x9f,
    0x15,0x30,0x1a,0x0e,0xb1,0xda,0x9c,0xa9,
    0xf3,0x02,0x93,0xef,0xd1,0x38,0x62,0x05,
    0x2f,0x0c,0xdf,0x5a,0xb1,0xd2,0x27,0x61,
    0x55,0x1d,0xca,0x08,0x8c,0xee,0xf8,0xfc,
    0xa4,0x22,0xb3,0x59,0xb8,0x96,0xb8,0xd8,
    0x34,0x68,0x6b,0x45,0xf3,0xed,0xef,0xa4,
    0xe2,0xc5,0x7a,0x6b,0xbe,0x66,0xa7,0x84,
};

/* derive_tor_expanded_key pub çıktısı — scalarmult(clamped_scalar) (nacl doğrulandı) */
static const uint8_t VEC_PUB1[32] = {
    0x28,0xfa,0x78,0xc8,0xc6,0xcf,0x7a,0xc8,
    0xdb,0x85,0x60,0x90,0x88,0x7a,0x40,0x20,
    0x43,0xe8,0x86,0x8a,0x0b,0xcf,0x5a,0xbd,
    0x2d,0xa9,0x70,0xa7,0x48,0x89,0x9a,0x9f,
};

/* derive_tor_expanded_key(MK2 seed) pub çıktısı — farklılık testi için */
static const uint8_t VEC_PUB2[32] = {
    0xeb,0x67,0x41,0xfd,0x5b,0x32,0x6e,0x19,
    0xf6,0xa3,0xd5,0x81,0xc9,0xcb,0x80,0x9f,
    0xef,0x84,0xa6,0xd2,0x02,0xd3,0x5b,0x1a,
    0x19,0x0e,0x24,0x6b,0x3a,0xd7,0x82,0xfb,
};


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
 * TEST: Determinizm — aynı master_key → aynı seed/expanded/pub
 * ================================================================ */
static int test_determinism(void)
{
    uint8_t seed_a[32], seed_b[32];
    uint8_t exp_a[64], exp_b[64];
    uint8_t pub_a[32], pub_b[32];

    TEST_ASSERT(crypto_derive_onion_seed(seed_a, MK1) == NOX_OK);
    TEST_ASSERT(crypto_derive_onion_seed(seed_b, MK1) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(seed_a, seed_b, 32) == 0);

    TEST_ASSERT(derive_tor_expanded_key(exp_a, pub_a, seed_a) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(exp_b, pub_b, seed_b) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(exp_a, exp_b, 64) == 0);
    TEST_ASSERT(sodium_memcmp(pub_a, pub_b, 32) == 0);

    return 0;
}

/* ================================================================
 * TEST: master_key ayrımı — farklı master → farklı seed ve pub
 * ================================================================ */
static int test_master_key_separation(void)
{
    uint8_t seed1[32], seed2[32];
    uint8_t exp1[64], exp2[64];
    uint8_t pub1[32], pub2[32];

    TEST_ASSERT(crypto_derive_onion_seed(seed1, MK1) == NOX_OK);
    TEST_ASSERT(crypto_derive_onion_seed(seed2, MK2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(seed1, seed2, 32) != 0);

    TEST_ASSERT(derive_tor_expanded_key(exp1, pub1, seed1) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(exp2, pub2, seed2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(exp1, exp2, 64) != 0);
    TEST_ASSERT(sodium_memcmp(pub1, pub2, 32) != 0);

    return 0;
}

/* ================================================================
 * TEST: KRİTİK — expanded format = [clamped_scalar || prefix]
 *
 * RFC 8032 §5.1.5 / Tor ed25519_secret_key_from_seed uyumu:
 *   h = SHA-512(seed)
 *   h[0]  &= 248  (alt 3 bit temizlenir)
 *   h[31] &= 63   (üst 2 bit temizlenir)
 *   h[31] |= 64   (5. bit set edilir)
 * ================================================================ */
static int test_expanded_format_clamp(void)
{
    uint8_t seed[32];
    uint8_t exp[64], pub[32];

    TEST_ASSERT(crypto_derive_onion_seed(seed, MK1) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);

    /* scalar (ilk 32 byte) clamp kurallarına uymalı */
    TEST_ASSERT((exp[0] & 0x07) == 0);            /* h[0] &= 248 */
    TEST_ASSERT((exp[31] & 0xC0) == 0x40);        /* h[31] &= 63; |= 64 */
    TEST_ASSERT((exp[31] & 0x80) == 0);           /* bit 7 temiz */
    TEST_ASSERT((exp[31] & 0x40) == 0x40);        /* bit 6 set (|=64) */

    /* prefix (son 32 byte) SHA-512 çıktısının ham kuyruğu olmalı */
    uint8_t sha[64];
    crypto_hash_sha512(sha, seed, 32);
    TEST_ASSERT(sodium_memcmp(exp + 32, sha + 32, 32) == 0);

    return 0;
}

/* ================================================================
 * TEST: pub == scalarmult_ed25519_base(clamped_scalar)
 *
 * Planın "pub GÜVENİLİR" iddiası: libsodium pk, Tor'un scalar'dan
 * türeteceği public key ile birebir aynı olmalı. Bu olmadan
 * ADD_ONION ServiceID ile pub'tan hesaplanan adres eşleşmez.
 * ================================================================ */
static int test_pub_equals_scalarmult(void)
{
    uint8_t seed[32];
    uint8_t exp[64], pub[32];

    TEST_ASSERT(crypto_derive_onion_seed(seed, MK1) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);

    uint8_t pk_from_scalar[32];
    TEST_ASSERT(crypto_scalarmult_ed25519_base(pk_from_scalar, exp) == 0);
    TEST_ASSERT(sodium_memcmp(pub, pk_from_scalar, 32) == 0);

    return 0;
}

/* ================================================================
 * TEST: Sabit vektörler — MK1/MK2 beklenen değerleri üretmeli
 * (vektörler Python/nacl ile bağımsız üretildi + doğrulandı)
 * ================================================================ */
static int test_fixed_vectors(void)
{
    uint8_t seed[32], exp[64], pub[32];

    TEST_ASSERT(crypto_derive_onion_seed(seed, MK1) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(seed, VEC_SEED1, 32) == 0);

    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(exp, VEC_EXP1, 64) == 0);
    TEST_ASSERT(sodium_memcmp(pub, VEC_PUB1, 32) == 0);

    /* MK2 → farklı pub (VEC_PUB2) */
    uint8_t seed2[32], exp2[64];
    TEST_ASSERT(crypto_derive_onion_seed(seed2, MK2) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(exp2, pub, seed2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(pub, VEC_PUB2, 32) == 0);

    return 0;
}

/* ================================================================
 * TEST: subkey ayrımı — onion seed, db/identity/session'dan farklı
 * ================================================================ */
static int test_subkey_separation(void)
{
    uint8_t db[32], unlock[32], session[32], seed[32];

    TEST_ASSERT(crypto_derive_subkeys(MK1, db, unlock, session) == NOX_OK);
    TEST_ASSERT(crypto_derive_onion_seed(seed, MK1) == NOX_OK);

    TEST_ASSERT(sodium_memcmp(seed, db, 32) != 0);
    TEST_ASSERT(sodium_memcmp(seed, unlock, 32) != 0);
    TEST_ASSERT(sodium_memcmp(seed, session, 32) != 0);

    return 0;
}

/* ================================================================
 * TEST: NULL güvenlik
 * ================================================================ */
static int test_null_safety(void)
{
    uint8_t buf[64];

    TEST_ASSERT(crypto_derive_onion_seed(NULL, MK1) == NOX_ERR_CRYPTO);
    TEST_ASSERT(crypto_derive_onion_seed(buf, NULL) == NOX_ERR_CRYPTO);

    TEST_ASSERT(derive_tor_expanded_key(NULL, buf, buf) == NOX_ERR_CRYPTO);
    TEST_ASSERT(derive_tor_expanded_key(buf, NULL, buf) == NOX_ERR_CRYPTO);
    TEST_ASSERT(derive_tor_expanded_key(buf, buf, NULL) == NOX_ERR_CRYPTO);

    return 0;
}

/* ================================================================
 * V3 ADRES HELPER — .sh harness'i için (--emit-addr)
 *
 * v3 onion adresi: base32(pub(32) || checksum(2) || 0x03)
 * checksum = SHA3-256(".onion checksum" || pub || 0x03)[0:2]
 * ================================================================ */
static void base32_encode(const uint8_t *in, size_t inlen, char *out)
{
    static const char *ALPHA = "abcdefghijklmnopqrstuvwxyz234567";
    size_t bitbuf = 0;
    int bits = 0;
    size_t o = 0;

    for (size_t i = 0; i < inlen; i++) {
        bitbuf = (bitbuf << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            out[o++] = ALPHA[(bitbuf >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if (bits > 0)
        out[o++] = ALPHA[(bitbuf << (5 - bits)) & 0x1F];
    out[o] = '\0';
}

static void derive_v3_address(const uint8_t pub[32], char *addr_out)
{
    uint8_t checksum[32];
    uint8_t salted[15 + 32 + 1];   /* ".onion checksum" (15) || pub (32) || version (1) */

    salted[0] = '.';
    salted[1] = 'o';
    salted[2] = 'n';
    salted[3] = 'i';
    salted[4] = 'o';
    salted[5] = 'n';
    salted[6] = ' ';
    salted[7] = 'c';
    salted[8] = 'h';
    salted[9] = 'e';
    salted[10] = 'c';
    salted[11] = 'k';
    salted[12] = 's';
    salted[13] = 'u';
    salted[14] = 'm';

    memcpy(salted + 15, pub, 32);
    salted[47] = 0x03;
    crypto_hash_sha3256(checksum, salted, 48);

    uint8_t blob[35];
    memcpy(blob, pub, 32);
    memcpy(blob + 32, checksum, 2);
    blob[34] = 0x03;

    base32_encode(blob, 35, addr_out);
    /* addr_out 56 char base32 + NUL — çağıran buffer ≥ 57 sağlamalı */
}

/* ================================================================
 * EMIT MODLARI — .sh harness entegrasyonu
 * ================================================================ */
static int emit_key(const uint8_t mk[32])
{
    uint8_t seed[32], exp[64], pub[32];
    char b64[128];

    if (crypto_derive_onion_seed(seed, mk) != NOX_OK) return 1;
    if (derive_tor_expanded_key(exp, pub, seed) != NOX_OK) return 1;

    if (sodium_bin2base64(b64, sizeof(b64), exp, 64,
                          sodium_base64_VARIANT_ORIGINAL) == NULL) return 1;
    printf("%s\n", b64);
    return 0;
}

static int emit_addr(const uint8_t mk[32])
{
    uint8_t seed[32], exp[64], pub[32];
    char addr[60];

    if (crypto_derive_onion_seed(seed, mk) != NOX_OK) return 1;
    if (derive_tor_expanded_key(exp, pub, seed) != NOX_OK) return 1;

    derive_v3_address(pub, addr);
    printf("%s.onion\n", addr);
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    /* .sh harness modları */
    if (argc >= 3) {
        if (strcmp(argv[1], "--emit-key") == 0)
            return emit_key((const uint8_t *)argv[2]);
        if (strcmp(argv[1], "--emit-addr") == 0)
            return emit_addr((const uint8_t *)argv[2]);
        fprintf(stderr, "Bilinmeyen mod: %s\n", argv[1]);
        return 2;
    }

    fprintf(stderr, "\n=== test_onion_derive ===\n\n");

    RUN_TEST(test_determinism);
    RUN_TEST(test_master_key_separation);
    RUN_TEST(test_expanded_format_clamp);
    RUN_TEST(test_pub_equals_scalarmult);
    RUN_TEST(test_fixed_vectors);
    RUN_TEST(test_subkey_separation);
    RUN_TEST(test_null_safety);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
