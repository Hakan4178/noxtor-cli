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
 *   7. Sabit seed + adres tek karakter bozulması → NOX_ERR_PROTO (checksum)
 *   8. crypto_onion_verify: kısa/uzun adres → NOX_ERR_PROTO
 *      (asıl handshake payload hard cut: test_event_frames)
 *   9. Payload v1 sabitleri tutarlı (1 + 62 + 64 == 127)
 *  10. Full Noise XX handshake gerçek v1 claim'lerle; msg2/msg3
 *      authenticated rs ile verify + split sonrası transport roundtrip
 *  11. validate_onion_address: canlı adres true, bozuk checksum false
 *  12. Başka onion'un anahtarıyla imzalanan claim → NOX_ERR_AUTH
 *  13. Relay: saldırganın rs'iyle kurban claim'i → NOX_ERR_AUTH
 */

#include "common.h"
#include "types.h"
#include "crypto.h"
#include "noise.h"
#include "network.h"
#include "event_loop.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "test_common.h"


/* Test 7 deterministik olsun: rastgele seed'de checksum çakışması
 * olasılığı 2^-16; sabit seed ile "bozuk adres → PROTO" kesin. */
static const uint8_t FIXED_SEED[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/* Canlı Tor ADD_ONION ile bu makinede üretilen gerçek v3 adres
 * (test_onion_derive.sh, canlı Tor). Checksum formülünü Tor'un
 * ServiceID üretimiyle birebir doğrular — public, secret değil. */
#define LIVE_TOR_ONION \
    "je63abepbqzrn7tvqfrdi5g7tp76uq3fv5dh7jwmala7yqwgkrfdlxad.onion"

/* ================================================================
 * YARDIMCILAR — v3 adres kurulumu (test için)
 * (base32 encode: test_common.h → nox_test_base32_encode)
 * ================================================================ */

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

    nox_test_base32_encode(body, NOX_ONION_BODY_LEN, out);
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
 *
 * ÖNEMLİ: assert != NOX_OK yetmez. Checksum kontrolü tamamen
 * kaldırılsa bile crypto_onion_verify, bozuk adresten çıkan farklı
 * pubkey ile imza doğrulamasına gider ve NOX_ERR_AUTH döner; test
 * yine yeşil kalırdı. Bu yüzden kesin olarak NOX_ERR_PROTO aranır.
 * Sabit seed: rastgele seed'de bozuk adresin checksum'ı 2^-16
 * olasılıkla tesadüfen tutabilir ve test flaky olurdu.
 * ================================================================ */
static int test_bitflipped_onion_rejected(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t spub[NOX_KEY_LEN], spriv[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    memcpy(seed, FIXED_SEED, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(spub, spriv);
    TEST_ASSERT(crypto_onion_sign(sig, addr, spub, seed) == NOX_OK);

    /* imza doğru, ADRES bozuk — checksum yakalamalı */
    char bad[NOX_ONION_LEN + 1];
    memcpy(bad, addr, sizeof(bad));
    bad[10] = (bad[10] == 'a') ? 'c' : 'a';
    TEST_ASSERT(crypto_onion_verify(sig, bad, spub) == NOX_ERR_PROTO);

    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(exp, sizeof(exp));
    sodium_memzero(spriv, sizeof(spriv));
    return 0;
}

/* ================================================================
 * 8. crypto_onion_verify KISA/UZUN ADRES → NOX_ERR_PROTO
 *
 * Bu test yalnızca verify'ın adres string uzunluğunu reddettiğini
 * kanıtlar. Handshake payload'ının 57/63/126/128 byte hard-cut'ı
 * event_loop'ta pl_len kontrolüdür; o sözleşme test_event_frames'te
 * ayrıca sınanır. Eski "short57" adı yanlıştı: 56 karakterdi.
 * ================================================================ */
static int test_verify_rejects_bad_length(void)
{
    uint8_t seed[32], pub[32], exp[64];
    uint8_t spub[NOX_KEY_LEN], spriv[NOX_KEY_LEN];
    uint8_t sig[crypto_sign_BYTES];
    char addr[NOX_ONION_LEN + 1];

    memcpy(seed, FIXED_SEED, sizeof(seed));
    TEST_ASSERT(derive_tor_expanded_key(exp, pub, seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(addr, pub) == 0);
    crypto_box_keypair(spub, spriv);
    TEST_ASSERT(crypto_onion_sign(sig, addr, spub, seed) == NOX_OK);

    /* 56 char: suffix yok */
    char short56[57];
    memcpy(short56, addr, 56);
    short56[56] = '\0';
    TEST_ASSERT(crypto_onion_verify(sig, short56, spub) == NOX_ERR_PROTO);

    /* 63 char: 62. pozisyon NUL değil */
    char long63[64];
    memcpy(long63, addr, NOX_ONION_LEN + 1);
    long63[NOX_ONION_LEN] = 'x';
    long63[NOX_ONION_LEN + 1] = '\0';
    TEST_ASSERT(crypto_onion_verify(sig, long63, spub) == NOX_ERR_PROTO);

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
 * 10. FULL XX HANDSHAKE — GERÇEK v1 CLAIM'LER + TRANSPORT ROUNDTRIP
 *
 * Eski test 0x41 dolgu gönderiyordu: payload'ın claim olduğunu,
 * imzanın karşı tarafın authenticated rs'iyle (hs->rs) doğrulandığını
 * ve split sonrası anahtarların gerçekten uyuştuğunu kanıtlamıyordu.
 * Burada msg2/msg3 gerçek hs_build_claim_payload çıktısıdır; verify
 * için handshake'in kendi rs'i kullanılır. Split sonrası iki yönlü
 * encrypt/decrypt yapılır — anahtar uyuşmazlığı bu testten geçemez.
 * ================================================================ */
static int test_handshake_with_v1_payload(void)
{
    static struct app_state sa, sb;
    memset(&sa, 0, sizeof(sa));
    memset(&sb, 0, sizeof(sb));

    uint8_t a_seed[32], b_seed[32];
    memcpy(a_seed, FIXED_SEED, sizeof(a_seed));
    memcpy(b_seed, FIXED_SEED, sizeof(b_seed));
    b_seed[0] ^= 0x01; /* A'dan farklı onion anahtarı */

    uint8_t a_onion_pub[NOX_KEY_LEN], b_onion_pub[NOX_KEY_LEN];
    uint8_t a_exp[64], b_exp[64];
    TEST_ASSERT(derive_tor_expanded_key(a_exp, a_onion_pub, a_seed) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(b_exp, b_onion_pub, b_seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(sa.onion_addr, a_onion_pub) == 0);
    TEST_ASSERT(make_onion_addr(sb.onion_addr, b_onion_pub) == 0);
    TEST_ASSERT(strcmp(sa.onion_addr, sb.onion_addr) != 0);

    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    uint8_t b_priv[NOX_KEY_LEN], b_pub[NOX_KEY_LEN];
    crypto_box_keypair(a_pub, a_priv);
    crypto_box_keypair(b_pub, b_priv);

    sa.my_onion_seed = a_seed;
    sa.my_static_pub = a_pub;
    sb.my_onion_seed = b_seed;
    sb.my_static_pub = b_pub;

    uint8_t claim_a[NOX_HS_PAYLOAD_V1_LEN];
    uint8_t claim_b[NOX_HS_PAYLOAD_V1_LEN];
    TEST_ASSERT(hs_build_claim_payload(claim_a, &sa) == NOX_OK);
    TEST_ASSERT(hs_build_claim_payload(claim_b, &sb) == NOX_OK);
    TEST_ASSERT(crypto_onion_verify(claim_a + 1 + NOX_ONION_LEN,
                                    sa.onion_addr, a_pub) == NOX_OK);
    TEST_ASSERT(crypto_onion_verify(claim_b + 1 + NOX_ONION_LEN,
                                    sb.onion_addr, b_pub) == NOX_OK);

    struct noise_handshake ha, hb;
    TEST_ASSERT(handshake_init(&ha, true, a_priv, a_pub) == NOX_OK);
    TEST_ASSERT(handshake_init(&hb, false, b_priv, b_pub) == NOX_OK);

    uint8_t m[NOISE_MAX_HANDSHAKE_LEN];
    size_t  mlen;
    uint8_t pl_out[NOX_HS_PAYLOAD_V1_LEN];
    size_t  pl_len;

    /* msg1: initiator, payload YOK (production) */
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&ha, NULL, 0, m, &mlen) == NOX_OK);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&hb, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == 0);

    /* msg2: responder B'nin gerçek claim'i */
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&hb, claim_b, sizeof(claim_b), m, &mlen) == NOX_OK);
    TEST_ASSERT(mlen <= NOISE_MAX_HANDSHAKE_LEN);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&ha, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_HS_PAYLOAD_V1_LEN);
    TEST_ASSERT(memcmp(claim_b, pl_out, NOX_HS_PAYLOAD_V1_LEN) == 0);
    TEST_ASSERT(sodium_memcmp(ha.rs, b_pub, NOX_KEY_LEN) == 0);
    /* H-1: claim, handshake'in authenticated rs'iyle doğrulanır. */
    TEST_ASSERT(crypto_onion_verify(pl_out + 1 + NOX_ONION_LEN,
                                    sb.onion_addr, ha.rs) == NOX_OK);

    /* msg3: initiator A'nın gerçek claim'i */
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&ha, claim_a, sizeof(claim_a), m, &mlen) == NOX_OK);
    TEST_ASSERT(mlen <= NOISE_MAX_HANDSHAKE_LEN);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&hb, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_HS_PAYLOAD_V1_LEN);
    TEST_ASSERT(memcmp(claim_a, pl_out, NOX_HS_PAYLOAD_V1_LEN) == 0);
    TEST_ASSERT(sodium_memcmp(hb.rs, a_pub, NOX_KEY_LEN) == 0);
    TEST_ASSERT(crypto_onion_verify(pl_out + 1 + NOX_ONION_LEN,
                                    sa.onion_addr, hb.rs) == NOX_OK);

    struct noise_session sa_sess, sb_sess;
    TEST_ASSERT(handshake_split(&ha, &sa_sess) == NOX_OK);
    TEST_ASSERT(handshake_split(&hb, &sb_sess) == NOX_OK);

    /* Split sonrası gerçek transport: anahtarlar uyuşmazsa decrypt fail. */
    uint8_t ad[FRAME_HEADER_WIRE_SIZE];
    memset(ad, 0xA5, sizeof(ad));
    uint8_t ct[64], pt[64];
    const uint8_t msg_a[] = "A->B";
    ssize_t n = noise_encrypt(&sa_sess, ad, sizeof(ad),
                              msg_a, sizeof(msg_a) - 1, ct);
    TEST_ASSERT(n == (ssize_t)(sizeof(msg_a) - 1 + NOX_MAC_LEN));
    ssize_t d = noise_decrypt(&sb_sess, ad, sizeof(ad),
                              ct, (size_t)n, pt);
    TEST_ASSERT(d == (ssize_t)(sizeof(msg_a) - 1));
    TEST_ASSERT(memcmp(pt, msg_a, sizeof(msg_a) - 1) == 0);

    const uint8_t msg_b[] = "B->A";
    n = noise_encrypt(&sb_sess, ad, sizeof(ad),
                      msg_b, sizeof(msg_b) - 1, ct);
    TEST_ASSERT(n == (ssize_t)(sizeof(msg_b) - 1 + NOX_MAC_LEN));
    d = noise_decrypt(&sa_sess, ad, sizeof(ad), ct, (size_t)n, pt);
    TEST_ASSERT(d == (ssize_t)(sizeof(msg_b) - 1));
    TEST_ASSERT(memcmp(pt, msg_b, sizeof(msg_b) - 1) == 0);

    sodium_memzero(&sa_sess, sizeof(sa_sess));
    sodium_memzero(&sb_sess, sizeof(sb_sess));
    sodium_memzero(&ha, sizeof(ha));
    sodium_memzero(&hb, sizeof(hb));
    sodium_memzero(a_seed, sizeof(a_seed));
    sodium_memzero(b_seed, sizeof(b_seed));
    sodium_memzero(a_exp, sizeof(a_exp));
    sodium_memzero(b_exp, sizeof(b_exp));
    sodium_memzero(a_priv, sizeof(a_priv));
    sodium_memzero(b_priv, sizeof(b_priv));
    sodium_memzero(&sa, sizeof(sa));
    sodium_memzero(&sb, sizeof(sb));
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
 * 12. YABANCI ONION İMZASI — başka onion'un anahtarıyla imzala,
 * geçerli checksum'lı A adresine karşı verify et → NOX_ERR_AUTH.
 * Test 6 yanlış static key'i kapatıyordu; bu test imza anahtarının
 * adresin kendi onion key'i olması gerektiğini kanıtlar.
 * ================================================================ */
static int test_foreign_onion_signature_rejected(void)
{
    uint8_t seed_a[32], seed_b[32];
    memcpy(seed_a, FIXED_SEED, sizeof(seed_a));
    memcpy(seed_b, FIXED_SEED, sizeof(seed_b));
    seed_b[0] ^= 0x01;

    uint8_t pub_a[NOX_KEY_LEN], pub_b[NOX_KEY_LEN];
    uint8_t exp_a[64], exp_b[64];
    TEST_ASSERT(derive_tor_expanded_key(exp_a, pub_a, seed_a) == NOX_OK);
    TEST_ASSERT(derive_tor_expanded_key(exp_b, pub_b, seed_b) == NOX_OK);

    char addr_a[NOX_ONION_LEN + 1], addr_b[NOX_ONION_LEN + 1];
    TEST_ASSERT(make_onion_addr(addr_a, pub_a) == 0);
    TEST_ASSERT(make_onion_addr(addr_b, pub_b) == 0);
    TEST_ASSERT(strcmp(addr_a, addr_b) != 0);

    uint8_t spub[NOX_KEY_LEN], spriv[NOX_KEY_LEN];
    crypto_box_keypair(spub, spriv);
    uint8_t sig[crypto_sign_BYTES];

    /* Saldırgan B anahtarıyla A adresini imzalar. */
    TEST_ASSERT(crypto_onion_sign(sig, addr_a, spub, seed_b) == NOX_OK);
    TEST_ASSERT(crypto_onion_verify(sig, addr_a, spub) == NOX_ERR_AUTH);

    /* Kontrol: B kendi adresini imzalarsa doğrulanır. */
    TEST_ASSERT(crypto_onion_sign(sig, addr_b, spub, seed_b) == NOX_OK);
    TEST_ASSERT(crypto_onion_verify(sig, addr_b, spub) == NOX_OK);

    sodium_memzero(seed_a, sizeof(seed_a));
    sodium_memzero(seed_b, sizeof(seed_b));
    sodium_memzero(exp_a, sizeof(exp_a));
    sodium_memzero(exp_b, sizeof(exp_b));
    sodium_memzero(spriv, sizeof(spriv));
    return 0;
}

/* ================================================================
 * 13. RELAY — saldırgan C kendi static'iyle Noise kurar, kurban
 * B'nin geçerli claim'ini msg2'de iletir. Initiator'ın hs->rs'i C
 * olduğu için B claim'i NOX_ERR_AUTH ile reddedilmelidir.
 * ================================================================ */
static int test_relayed_claim_rejected(void)
{
    static struct app_state victim;
    memset(&victim, 0, sizeof(victim));

    uint8_t victim_seed[32];
    memcpy(victim_seed, FIXED_SEED, sizeof(victim_seed));
    victim_seed[0] ^= 0x01;
    uint8_t victim_onion_pub[NOX_KEY_LEN], victim_exp[64];
    TEST_ASSERT(derive_tor_expanded_key(victim_exp, victim_onion_pub,
                                        victim_seed) == NOX_OK);
    TEST_ASSERT(make_onion_addr(victim.onion_addr, victim_onion_pub) == 0);

    uint8_t victim_static[NOX_KEY_LEN], victim_static_priv[NOX_KEY_LEN];
    crypto_box_keypair(victim_static, victim_static_priv);
    victim.my_onion_seed = victim_seed;
    victim.my_static_pub = victim_static;

    uint8_t victim_claim[NOX_HS_PAYLOAD_V1_LEN];
    TEST_ASSERT(hs_build_claim_payload(victim_claim, &victim) == NOX_OK);
    TEST_ASSERT(crypto_onion_verify(victim_claim + 1 + NOX_ONION_LEN,
                                    victim.onion_addr,
                                    victim_static) == NOX_OK);

    /* Saldırgan C: kendi static'iyle responder. */
    uint8_t c_priv[NOX_KEY_LEN], c_pub[NOX_KEY_LEN];
    crypto_box_keypair(c_pub, c_priv);
    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    crypto_box_keypair(a_pub, a_priv);

    struct noise_handshake ha, hc;
    TEST_ASSERT(handshake_init(&ha, true, a_priv, a_pub) == NOX_OK);
    TEST_ASSERT(handshake_init(&hc, false, c_priv, c_pub) == NOX_OK);

    uint8_t m[NOISE_MAX_HANDSHAKE_LEN];
    size_t mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&ha, NULL, 0, m, &mlen) == NOX_OK);
    uint8_t pl_out[NOX_HS_PAYLOAD_V1_LEN];
    size_t pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&hc, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);

    /* C, kurbanın claim'ini relay eder. */
    mlen = sizeof(m);
    TEST_ASSERT(handshake_write(&hc, victim_claim, sizeof(victim_claim),
                                m, &mlen) == NOX_OK);
    pl_len = sizeof(pl_out);
    TEST_ASSERT(handshake_read(&ha, m, mlen, pl_out, sizeof(pl_out),
                               &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_HS_PAYLOAD_V1_LEN);
    TEST_ASSERT(sodium_memcmp(ha.rs, c_pub, NOX_KEY_LEN) == 0);

    /* Authenticated rs C; kurban claim'i B imzası taşıyor → AUTH. */
    TEST_ASSERT(crypto_onion_verify(pl_out + 1 + NOX_ONION_LEN,
                                    victim.onion_addr,
                                    ha.rs) == NOX_ERR_AUTH);

    sodium_memzero(&ha, sizeof(ha));
    sodium_memzero(&hc, sizeof(hc));
    sodium_memzero(victim_seed, sizeof(victim_seed));
    sodium_memzero(victim_exp, sizeof(victim_exp));
    sodium_memzero(victim_static_priv, sizeof(victim_static_priv));
    sodium_memzero(a_priv, sizeof(a_priv));
    sodium_memzero(c_priv, sizeof(c_priv));
    sodium_memzero(&victim, sizeof(victim));
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
    RUN_TEST(test_verify_rejects_bad_length);
    RUN_TEST(test_payload_layout_constants);
    RUN_TEST(test_handshake_with_v1_payload);
    RUN_TEST(test_validate_requires_checksum);
    RUN_TEST(test_foreign_onion_signature_rejected);
    RUN_TEST(test_relayed_claim_rejected);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
