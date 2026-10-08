/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_onion_bind.c — H-1/H-2 onion ↔ oturum bağı birim testleri
 *
 * Testler:
 *   1. Canlı Tor adresi crypto_onion_pubkey'ten geçer (checksum formülü
 *      Tor'un ServiceID üretimiyle birebir — canlı ADD_ONION kanıtı)
 *   2. Bozuk checksum'lı adres reddedilir (H-2)
 *   3. Seed → pub → address encode roundtrip (encoder/decoder tutarlı)
 *   4. Sign/verify roundtrip (claim ↔ onion ↔ static key bağı)
 *   5. Bozuk imza → NOX_ERR_AUTH
 *   6. Yanlış static key (başka rs) → NOX_ERR_AUTH
 *   7. Adres tek karakter bozulması → NOX_ERR_PROTO (checksum)
 *   8. Legacy payload uzunlukları (57/63) → NOX_ERR_PROTO (hard cut)
 *   9. Payload v1 sabitleri tutarlı (1 + 62 + 64 == 127)
 *  10. Full Noise XX handshake 127 byte payload ile tamamlanır
 *      (NOISE_MAX_HANDSHAKE_LEN=256 kapasite koruması — L-1 benzeri)
 *  11. validate_onion_address: canlı adres true, bozuk checksum false
 */

#include "common.h"
#include "types.h"
#include "crypto.h"
#include "noise.h"
#include "network.h"

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

/* Canlı Tor ADD_ONION ile bu makinede üretilen gerçek v3 adres
 * (test_onion_derive.sh, canlı Tor). Checksum formülünü Tor'un
 * ServiceID üretimiyle birebir doğrular — public, secret değil. */
#define LIVE_TOR_ONION \
    "je63abepbqzrn7tvqfrdi5g7tp76uq3fv5dh7jwmala7yqwgkrfdlxad.onion"

/* ================================================================
 * YARDIMCILAR — base32 encode + v3 adres kurulumu (test için)
 * ================================================================ */
static const char B32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

/* 35 byte body → 56 char base32 (RFC4648, padding yok, lowercase) */
static void b32_encode_35(const uint8_t in[NOX_ONION_BODY_LEN],
                          char out[NOX_ONION_B32_LEN])
{
    uint32_t acc  = 0;
    unsigned bits = 0;
    size_t   o    = 0;
    for (size_t i = 0; i < NOX_ONION_BODY_LEN; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o++] = B32_ALPHABET[(acc >> bits) & 31u];
        }
    }
    /* 35×8 = 280 = 56×5 — artan bit kalmaz */
}

/* pub → v3 onion adresi (checksum + version dahil) üret */
static int make_onion_addr(char out[NOX_ONION_LEN + 1],
                            const uint8_t pub[NOX_KEY_LEN])
{
    uint8_t body[NOX_ONION_BODY_LEN];
    memcpy(body, pub, NOX_KEY_LEN);
    body[NOX_ONION_BODY_LEN - 1] = 0x03;

    uint8_t ck_in[15 + NOX_KEY_LEN + 1];
    memcpy(ck_in, ".onion checksum", 15);
    memcpy(ck_in + 15, pub, NOX_KEY_LEN);
    ck_in[15 + NOX_KEY_LEN] = 0x03;

    uint8_t digest[crypto_hash_sha3256_BYTES];
    TEST_ASSERT(crypto_hash_sha3256(digest, ck_in, sizeof(ck_in)) == 0);
    memcpy(body + NOX_KEY_LEN, digest, 2); /* checksum = SHA3(...)[:2] */

    b32_encode_35(body, out);
    memcpy(out + NOX_ONION_B32_LEN, ".onion", 7); /* ".onion" + NUL */
    return 0;
}

/* ================================================================
 * 1. CANLI TOR ADRESİ — checksum formülü Tor ile birebir
 * ================================================================ */
static int test_live_tor_address_accepted(void)
{
    uint8_t pub[NOX_KEY_LEN];
    TEST_ASSERT(crypto_onion_pubkey(pub, LIVE_TOR_ONION) == NOX_OK);
    return 0;
}

/* ================================================================
 * 2. BOZUK CHECKSUM — H-2 zorunluluğu
 * ================================================================ */
static int test_bad_checksum_rejected(void)
{
    /* Canlı adresten checksum byte'larından birini değiştir —
     * charset içinde kalmalı (checksum karakterlerinden biri). */
    char bad[NOX_ONION_LEN + 1];
    memcpy(bad, LIVE_TOR_ONION, NOX_ONION_LEN + 1);
    /* ilk 56 char base32 — sonrakiler checksum bölgesi değil,
     * gerçek adresin karakterlerinden birini flip et (a↔b) */
    bad[0] = (bad[0] == 'a') ? 'b' : 'a';

    uint8_t pub[NOX_KEY_LEN];
    TEST_ASSERT(crypto_onion_pubkey(pub, bad) != NOX_OK);

    /* suffix bozuk */
    memcpy(bad, LIVE_TOR_ONION, NOX_ONION_LEN + 1);
    bad[NOX_ONION_LEN - 1] = 'x'; /* son onion char'ı */
    TEST_ASSERT(crypto_onion_pubkey(pub, bad) != NOX_OK);
    return 0;
}

/* ================================================================
 * 3. SEED → PUB → ADRES ENCODE → DECODE ROUNDTRIP
 * ================================================================ */
static int test_address_roundtrip(void)
{
    uint8_t seed[32], pub[32], exp[64], back[NOX_KEY_LEN];
    char addr[NOX_ONION_LEN + 1];

    randombytes_buf(seed, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);

    TEST_ASSERT(crypto_onion_pubkey(back, addr) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(pub, back, NOX_KEY_LEN) == 0);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    return 0;
}

/* ================================================================
 * 4. SIGN/VERIFY ROUNDTRIP — çekirdek H-1 bağı
 * ================================================================ */
static int test_sign_verify_roundtrip(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t static_priv[NOX_KEY_LEN], static_pub[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    randombytes_buf(seed, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(static_pub, static_priv); /* X25519 static */

    TEST_ASSERT(crypto_onion_sign(sig, addr, static_pub, seed) == NOX_OK);
    TEST_ASSERT(crypto_onion_verify(sig, addr, static_pub) == NOX_OK);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    sodium_memzero(static_priv, sizeof(static_priv));
    return 0;
}

/* ================================================================
 * 5. BOZUK İMZA → NOX_ERR_AUTH
 * ================================================================ */
static int test_tampered_signature(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t spub[NOX_KEY_LEN], spriv[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    randombytes_buf(seed, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(spub, spriv);
    TEST_ASSERT(crypto_onion_sign(sig, addr, spub, seed) == NOX_OK);

    sig[0] ^= 0x01; /* imzayı boz */
    TEST_ASSERT(crypto_onion_verify(sig, addr, spub) == NOX_ERR_AUTH);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    sodium_memzero(spriv, sizeof(spriv));
    return 0;
}

/* ================================================================
 * 6. YANLIŞ STATIC KEY (başka rs) → NOX_ERR_AUTH
 * imza rs'e bağlı: saldırgan kendi oturumuna kurban imzasını
 * taşıyamaz (H-1'in doğrudan testi)
 * ================================================================ */
static int test_wrong_static_key(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t victim_static[NOX_KEY_LEN], victim_priv[NOX_KEY_LEN];
    uint8_t attacker_static[NOX_KEY_LEN], attacker_priv[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    randombytes_buf(seed, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(victim_static, victim_priv);
    crypto_box_keypair(attacker_static, attacker_priv);

    /* kurban, kendi static key'iyle imzaladı */
    TEST_ASSERT(crypto_onion_sign(sig, addr, victim_static, seed) == NOX_OK);
    /* saldırganın rs'i ile verify edilemez */
    TEST_ASSERT(crypto_onion_verify(sig, addr, attacker_static) == NOX_ERR_AUTH);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    sodium_memzero(victim_priv, sizeof(victim_priv));
    sodium_memzero(attacker_priv, sizeof(attacker_priv));
    return 0;
}

/* ================================================================
 * 7. ADRES TEK KARAKTER BOZULMASI → NOX_ERR_PROTO (checksum)
 * ================================================================ */
static int test_bitflipped_onion_rejected(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t spub[NOX_KEY_LEN], spriv[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    randombytes_buf(seed, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(spub, spriv);
    TEST_ASSERT(crypto_onion_sign(sig, addr, spub, seed) == NOX_OK);

    /* imza doğru, ADRS bozuk — checksum yakalamalı */
    char bad[NOX_ONION_LEN + 1];
    memcpy(bad, addr, sizeof(bad));
    bad[10] = (bad[10] == 'a') ? 'c' : 'a';
    TEST_ASSERT(crypto_onion_verify(sig, bad, spub) != NOX_OK);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    sodium_memzero(spriv, sizeof(spriv));
    return 0;
}

/* ================================================================
 * 8. LEGACY PAYLOAD UZUNLUKLARI → RED (hard cut)
 * eski format: [onion(62) || NUL] = 63 byte. crypto_onion_verify
 * NUL-only / kısa girdileri reddetmeli — 57 ve 63'te dahil.
 * ================================================================ */
static int test_legacy_lengths_rejected(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t spub[NOX_KEY_LEN], spriv[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    randombytes_buf(seed, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(spub, spriv);
    TEST_ASSERT(crypto_onion_sign(sig, addr, spub, seed) == NOX_OK);

    /* 63B legacy ([onion||NUL] tam uzunluk) — addr zaten 62+NUL,
     * legacy payload 63B idi: doğrulanabilir DIFFERENT bir girdi
     * değil, aynı string — asıl hard cut event_loop pl_len kontrolü.
     * Burada: kısa (57B) ve uzun (63B ham) girdiler reddedilir. */
    char short57[58];
    memcpy(short57, addr, 56);
    short57[56] = '\0'; /* 56 char, suffix yok */
    TEST_ASSERT(crypto_onion_verify(sig, short57, spub) != NOX_OK);

    char long63[64];
    memcpy(long63, addr, NOX_ONION_LEN + 1);
    long63[NOX_ONION_LEN] = 'x'; /* 62. pozisyon NUL değil → 63 char string */
    long63[NOX_ONION_LEN + 1] = '\0';
    TEST_ASSERT(crypto_onion_verify(sig, long63, spub) != NOX_OK);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    sodium_memzero(spriv, sizeof(spriv));
    return 0;
}

/* ================================================================
 * 9. PAYLOAD v1 SABİTLERİ TUTARLILIK
 * ================================================================ */
static int test_payload_layout_constants(void)
{
    TEST_ASSERT(NOX_HS_PAYLOAD_V1_LEN ==
                1 + NOX_ONION_LEN + crypto_sign_BYTES);
    TEST_ASSERT(NOX_HS_PAYLOAD_V1_LEN == 127);
    TEST_ASSERT(NOX_HS_PAYLOAD_V1_VER == 0x01);
    /* msg2/msg3 kapasite: NOISE_MAX_HANDSHAKE_LEN (256) içine sığmalı
     * msg2 = e(32) + enc(s)(48) + enc(payload)(127+16) = 223 */
    TEST_ASSERT(32 + 48 + NOX_HS_PAYLOAD_V1_LEN + NOX_MAC_LEN <=
                NOISE_MAX_HANDSHAKE_LEN);
    /* msg3 = enc(s)(48) + enc(payload)(143) = 191 */
    TEST_ASSERT(48 + NOX_HS_PAYLOAD_V1_LEN + NOX_MAC_LEN <=
                NOISE_MAX_HANDSHAKE_LEN);
    return 0;
}

/* ================================================================
 * 10. FULL XX HANDSHAKE — 127 byte payload (kapasite + roundtrip)
 * Production akışı: msg1 NULL payload (initiator), msg2 (responder),
 * msg3 (initiator) — hepsi event_loop'da 127B claim taşır.
 * ================================================================ */
static int test_handshake_with_v1_payload(void)
{
    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    uint8_t b_priv[NOX_KEY_LEN], b_pub[NOX_KEY_LEN];
    crypto_box_keypair(a_pub, a_priv);
    crypto_box_keypair(b_pub, b_priv);

    struct noise_handshake ha, hb;
    TEST_ASSERT(handshake_init(&ha, true, a_priv, a_pub) == NOX_OK);
    TEST_ASSERT(handshake_init(&hb, false, b_priv, b_pub) == NOX_OK);

    uint8_t m[NOISE_MAX_HANDSHAKE_LEN];
    size_t  mlen;
    uint8_t pl_in[NOX_HS_PAYLOAD_V1_LEN];
    uint8_t pl_out[NOX_HS_PAYLOAD_V1_LEN];
    size_t  pl_len;

    /* msg1: initiator, payload YOK (production) */
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&ha, NULL, 0, m, &mlen) == NOX_OK);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&hb, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == 0);

    /* msg2: responder claim (127B) */
    memset(pl_in, 0x41, sizeof(pl_in));
    pl_in[0] = NOX_HS_PAYLOAD_V1_VER;
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&hb, pl_in, sizeof(pl_in), m, &mlen) == NOX_OK);
    TEST_ASSERT(mlen <= NOISE_MAX_HANDSHAKE_LEN);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&ha, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_HS_PAYLOAD_V1_LEN);
    TEST_ASSERT(memcmp(pl_in, pl_out, NOX_HS_PAYLOAD_V1_LEN) == 0);

    /* msg3: initiator claim (127B) */
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&ha, pl_in, sizeof(pl_in), m, &mlen) == NOX_OK);
    TEST_ASSERT(mlen <= NOISE_MAX_HANDSHAKE_LEN);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&hb, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_HS_PAYLOAD_V1_LEN);
    TEST_ASSERT(memcmp(pl_in, pl_out, NOX_HS_PAYLOAD_V1_LEN) == 0);

    struct noise_session sa, sb;
    TEST_ASSERT(handshake_split(&ha, &sa) == NOX_OK);
    TEST_ASSERT(handshake_split(&hb, &sb) == NOX_OK);

    sodium_memzero(&sa, sizeof(sa));
    sodium_memzero(&sb, sizeof(sb));
    sodium_memzero(a_priv, sizeof(a_priv));
    sodium_memzero(b_priv, sizeof(b_priv));
    return 0;
}

/* ================================================================
 * 11. validate_onion_address — checksum artık zorunlu (H-2)
 * ================================================================ */
static int test_validate_requires_checksum(void)
{
    TEST_ASSERT(validate_onion_address(LIVE_TOR_ONION) == true);

    char bad[NOX_ONION_LEN + 1];
    memcpy(bad, LIVE_TOR_ONION, sizeof(bad));
    bad[3] = (bad[3] == 'a') ? 'c' : 'a'; /* charset içi, checksum bozuk */
    TEST_ASSERT(validate_onion_address(bad) == false);

    TEST_ASSERT(validate_onion_address("a.onion") == false);
    TEST_ASSERT(validate_onion_address(NULL) == false);
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "=== H-1/H-2 Onion Binding Testleri ===\n");

    RUN_TEST(test_live_tor_address_accepted);
    RUN_TEST(test_bad_checksum_rejected);
    RUN_TEST(test_address_roundtrip);
    RUN_TEST(test_sign_verify_roundtrip);
    RUN_TEST(test_tampered_signature);
    RUN_TEST(test_wrong_static_key);
    RUN_TEST(test_bitflipped_onion_rejected);
    RUN_TEST(test_legacy_lengths_rejected);
    RUN_TEST(test_payload_layout_constants);
    RUN_TEST(test_handshake_with_v1_payload);
    RUN_TEST(test_validate_requires_checksum);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
