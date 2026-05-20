/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_noise.c — Noise XX handshake + transport testleri
 *
 * Testler:
 *   1. Loopback handshake — initiator ↔ responder aynı process
 *   2. Transport round-trip — şifrele/çöz
 *   3. MAC tamper — bozulmuş ciphertext reddedilmeli
 *   4. Nonce replay — aynı nonce ile iki kez şifreleme farklı çıktı
 *   5. Handshake yanlış sıra — state hatası
 *   6. Remote static key doğrulama
 */

#include "common.h"
#include "types.h"
#include "noise.h"

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
 * YARDIMCI — Curve25519 key pair üret
 * ================================================================ */
static void gen_static_keypair(uint8_t priv[NOX_KEY_LEN],
                               uint8_t pub[NOX_KEY_LEN])
{
    /* Curve25519 keypair — NaCl box API'si ile */
    crypto_box_curve25519xsalsa20poly1305_keypair(pub, priv);
}

/* ================================================================
 * TEST: Tam loopback handshake
 *
 * Initiator (Alice) ↔ Responder (Bob)
 * 3 mesaj sonunda her iki taraf da transport-ready olmalı.
 * ================================================================ */
static int test_loopback_handshake(void)
{
    /* Key pairs */
    uint8_t alice_priv[NOX_KEY_LEN], alice_pub[NOX_KEY_LEN];
    uint8_t bob_priv[NOX_KEY_LEN],   bob_pub[NOX_KEY_LEN];
    gen_static_keypair(alice_priv, alice_pub);
    gen_static_keypair(bob_priv, bob_pub);

    /* Handshake state'leri */
    struct noise_handshake hs_alice, hs_bob;

    TEST_ASSERT(handshake_init(&hs_alice, true,  alice_priv, alice_pub) == NOX_OK);
    TEST_ASSERT(handshake_init(&hs_bob,   false, bob_priv,   bob_pub)   == NOX_OK);

    uint8_t msg_buf[NOISE_MAX_HANDSHAKE_LEN];
    uint8_t payload_buf[64];
    size_t msg_len, pl_len;

    /* msg0: Alice → Bob: → e */
    msg_len = sizeof(msg_buf);
    TEST_ASSERT(handshake_write(&hs_alice, NULL, 0, msg_buf, &msg_len) == NOX_OK);
    TEST_ASSERT(msg_len == NOX_KEY_LEN); /* sadece e_pub */

    pl_len = sizeof(payload_buf);
    TEST_ASSERT(handshake_read(&hs_bob, msg_buf, msg_len,
                               payload_buf, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == 0); /* boş payload */

    /* msg1: Bob → Alice: ← e, ee, s, es */
    msg_len = sizeof(msg_buf);
    TEST_ASSERT(handshake_write(&hs_bob, NULL, 0, msg_buf, &msg_len) == NOX_OK);
    /* e(32) + encrypted_s(32+16) + encrypted_payload(0+16) = 96 */
    TEST_ASSERT(msg_len == 96);

    pl_len = sizeof(payload_buf);
    TEST_ASSERT(handshake_read(&hs_alice, msg_buf, msg_len,
                               payload_buf, &pl_len) == NOX_OK);

    /* msg2: Alice → Bob: → s, se */
    msg_len = sizeof(msg_buf);
    TEST_ASSERT(handshake_write(&hs_alice, NULL, 0, msg_buf, &msg_len) == NOX_OK);
    /* encrypted_s(32+16) + encrypted_payload(0+16) = 64 */
    TEST_ASSERT(msg_len == 64);

    pl_len = sizeof(payload_buf);
    TEST_ASSERT(handshake_read(&hs_bob, msg_buf, msg_len,
                               payload_buf, &pl_len) == NOX_OK);

    /* Her iki taraf da tamamlanmış olmalı */
    TEST_ASSERT(handshake_is_complete(&hs_alice));
    TEST_ASSERT(handshake_is_complete(&hs_bob));

    return 0;
}

/* ================================================================
 * TEST: Transport round-trip
 * ================================================================ */
static int test_transport_roundtrip(void)
{
    /* Handshake yap */
    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    uint8_t b_priv[NOX_KEY_LEN], b_pub[NOX_KEY_LEN];
    gen_static_keypair(a_priv, a_pub);
    gen_static_keypair(b_priv, b_pub);

    struct noise_handshake hs_a, hs_b;
    handshake_init(&hs_a, true, a_priv, a_pub);
    handshake_init(&hs_b, false, b_priv, b_pub);

    uint8_t buf[NOISE_MAX_HANDSHAKE_LEN];
    uint8_t pl[64];
    size_t len, pl_len;

    /* 3 mesaj */
    len = sizeof(buf);
    handshake_write(&hs_a, NULL, 0, buf, &len);
    pl_len = sizeof(pl);
    handshake_read(&hs_b, buf, len, pl, &pl_len);

    len = sizeof(buf);
    handshake_write(&hs_b, NULL, 0, buf, &len);
    pl_len = sizeof(pl);
    handshake_read(&hs_a, buf, len, pl, &pl_len);

    len = sizeof(buf);
    handshake_write(&hs_a, NULL, 0, buf, &len);
    pl_len = sizeof(pl);
    handshake_read(&hs_b, buf, len, pl, &pl_len);

    /* Split */
    struct noise_session sa, sb;
    TEST_ASSERT(handshake_split(&hs_a, &sa) == NOX_OK);
    TEST_ASSERT(handshake_split(&hs_b, &sb) == NOX_OK);

    /* Alice → Bob: "merhaba dünya" */
    const uint8_t msg[] = "merhaba dunya";
    uint8_t ct[sizeof(msg) + NOX_MAC_LEN];
    uint8_t pt[sizeof(msg)];

    ssize_t ct_len = noise_encrypt(&sa, msg, sizeof(msg), ct);
    TEST_ASSERT(ct_len == (ssize_t)(sizeof(msg) + NOX_MAC_LEN));

    ssize_t pt_len = noise_decrypt(&sb, ct, (size_t)ct_len, pt);
    TEST_ASSERT(pt_len == (ssize_t)sizeof(msg));
    TEST_ASSERT(sodium_memcmp(pt, msg, sizeof(msg)) == 0);

    /* Bob → Alice: "selam" */
    const uint8_t reply[] = "selam";
    uint8_t ct2[sizeof(reply) + NOX_MAC_LEN];
    uint8_t pt2[sizeof(reply)];

    ct_len = noise_encrypt(&sb, reply, sizeof(reply), ct2);
    TEST_ASSERT(ct_len > 0);

    pt_len = noise_decrypt(&sa, ct2, (size_t)ct_len, pt2);
    TEST_ASSERT(pt_len == (ssize_t)sizeof(reply));
    TEST_ASSERT(sodium_memcmp(pt2, reply, sizeof(reply)) == 0);

    return 0;
}

/* ================================================================
 * TEST: MAC tamper — bozulmuş ciphertext reddedilmeli
 * ================================================================ */
static int test_mac_tamper(void)
{
    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    uint8_t b_priv[NOX_KEY_LEN], b_pub[NOX_KEY_LEN];
    gen_static_keypair(a_priv, a_pub);
    gen_static_keypair(b_priv, b_pub);

    struct noise_handshake hs_a, hs_b;
    handshake_init(&hs_a, true, a_priv, a_pub);
    handshake_init(&hs_b, false, b_priv, b_pub);

    uint8_t buf[NOISE_MAX_HANDSHAKE_LEN];
    uint8_t pl[64];
    size_t len, pl_len;

    /* Handshake */
    len = sizeof(buf); handshake_write(&hs_a, NULL, 0, buf, &len);
    pl_len = sizeof(pl); handshake_read(&hs_b, buf, len, pl, &pl_len);
    len = sizeof(buf); handshake_write(&hs_b, NULL, 0, buf, &len);
    pl_len = sizeof(pl); handshake_read(&hs_a, buf, len, pl, &pl_len);
    len = sizeof(buf); handshake_write(&hs_a, NULL, 0, buf, &len);
    pl_len = sizeof(pl); handshake_read(&hs_b, buf, len, pl, &pl_len);

    struct noise_session sa, sb;
    handshake_split(&hs_a, &sa);
    handshake_split(&hs_b, &sb);

    /* Şifrele */
    const uint8_t msg[] = "secret";
    uint8_t ct[sizeof(msg) + NOX_MAC_LEN];
    ssize_t ct_len = noise_encrypt(&sa, msg, sizeof(msg), ct);
    TEST_ASSERT(ct_len > 0);

    /* 1 bit boz */
    ct[0] ^= 0x01;

    /* Çözme başarısız olmalı */
    uint8_t pt[sizeof(msg)];
    ssize_t pt_len = noise_decrypt(&sb, ct, (size_t)ct_len, pt);
    TEST_ASSERT(pt_len == -1);

    return 0;
}

/* ================================================================
 * TEST: Remote static key doğrulama
 * ================================================================ */
static int test_remote_static_key(void)
{
    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    uint8_t b_priv[NOX_KEY_LEN], b_pub[NOX_KEY_LEN];
    gen_static_keypair(a_priv, a_pub);
    gen_static_keypair(b_priv, b_pub);

    struct noise_handshake hs_a, hs_b;
    handshake_init(&hs_a, true, a_priv, a_pub);
    handshake_init(&hs_b, false, b_priv, b_pub);

    uint8_t buf[NOISE_MAX_HANDSHAKE_LEN];
    uint8_t pl[64];
    size_t len, pl_len;

    /* Full handshake */
    len = sizeof(buf); handshake_write(&hs_a, NULL, 0, buf, &len);
    pl_len = sizeof(pl); handshake_read(&hs_b, buf, len, pl, &pl_len);
    len = sizeof(buf); handshake_write(&hs_b, NULL, 0, buf, &len);
    pl_len = sizeof(pl); handshake_read(&hs_a, buf, len, pl, &pl_len);
    len = sizeof(buf); handshake_write(&hs_a, NULL, 0, buf, &len);
    pl_len = sizeof(pl); handshake_read(&hs_b, buf, len, pl, &pl_len);

    struct noise_session sa, sb;
    handshake_split(&hs_a, &sa);
    handshake_split(&hs_b, &sb);

    /* Alice, Bob'un public key'ini bilmeli */
    TEST_ASSERT(sodium_memcmp(sa.remote_static, b_pub, NOX_KEY_LEN) == 0);

    /* Bob, Alice'in public key'ini bilmeli */
    TEST_ASSERT(sodium_memcmp(sb.remote_static, a_pub, NOX_KEY_LEN) == 0);

    return 0;
}

/* ================================================================
 * TEST: Handshake yanlış sıra → state hatası
 * ================================================================ */
static int test_wrong_order(void)
{
    uint8_t priv[NOX_KEY_LEN], pub[NOX_KEY_LEN];
    gen_static_keypair(priv, pub);

    struct noise_handshake hs;
    handshake_init(&hs, true, priv, pub);

    /* Initiator msg_index=0'da read yapamaz (write yapmalı) */
    uint8_t buf[64];
    size_t len = sizeof(buf);
    TEST_ASSERT(handshake_read(&hs, buf, 32, buf, &len) == NOX_ERR_STATE);

    return 0;
}

/* ================================================================
 * TEST: NULL parametre güvenliği
 * ================================================================ */
static int test_noise_null_safety(void)
{
    TEST_ASSERT(handshake_init(NULL, true, NULL, NULL) == NOX_ERR_PROTO);

    struct noise_handshake hs;
    TEST_ASSERT(handshake_write(&hs, NULL, 0, NULL, NULL) == NOX_ERR_PROTO);

    TEST_ASSERT(noise_encrypt(NULL, NULL, 0, NULL) == -1);
    TEST_ASSERT(noise_decrypt(NULL, NULL, 0, NULL) == -1);

    return 0;
}

/* ================================================================
 * TEST: Handshake onion payload exchange
 * ================================================================ */
static int test_handshake_onion_payload(void)
{
    uint8_t a_priv[NOX_KEY_LEN], a_pub[NOX_KEY_LEN];
    uint8_t b_priv[NOX_KEY_LEN], b_pub[NOX_KEY_LEN];
    gen_static_keypair(a_priv, a_pub);
    gen_static_keypair(b_priv, b_pub);

    struct noise_handshake hs_a, hs_b;
    TEST_ASSERT(handshake_init(&hs_a, true, a_priv, a_pub) == NOX_OK);
    TEST_ASSERT(handshake_init(&hs_b, false, b_priv, b_pub) == NOX_OK);

    const char *alice_onion = "alice12345678901234567890123456789012345678901234567890.onion";
    const char *bob_onion = "bob12345678901234567890123456789012345678901234567890.onion";

    uint8_t buf[NOISE_MAX_HANDSHAKE_LEN];
    uint8_t pl[128];
    size_t len, pl_len;

    /* msg0: Alice -> Bob (no payload) */
    len = sizeof(buf);
    TEST_ASSERT(handshake_write(&hs_a, NULL, 0, buf, &len) == NOX_OK);
    pl_len = sizeof(pl);
    TEST_ASSERT(handshake_read(&hs_b, buf, len, pl, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == 0);

    /* msg1: Bob -> Alice (carrying bob_onion) */
    len = sizeof(buf);
    TEST_ASSERT(handshake_write(&hs_b, (const uint8_t *)bob_onion, NOX_ONION_LEN + 1, buf, &len) == NOX_OK);
    pl_len = sizeof(pl);
    TEST_ASSERT(handshake_read(&hs_a, buf, len, pl, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_ONION_LEN + 1);
    TEST_ASSERT(strcmp((const char *)pl, bob_onion) == 0);

    /* msg2: Alice -> Bob (carrying alice_onion) */
    len = sizeof(buf);
    TEST_ASSERT(handshake_write(&hs_a, (const uint8_t *)alice_onion, NOX_ONION_LEN + 1, buf, &len) == NOX_OK);
    pl_len = sizeof(pl);
    TEST_ASSERT(handshake_read(&hs_b, buf, len, pl, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == NOX_ONION_LEN + 1);
    TEST_ASSERT(strcmp((const char *)pl, alice_onion) == 0);

    TEST_ASSERT(handshake_is_complete(&hs_a));
    TEST_ASSERT(handshake_is_complete(&hs_b));

    return 0;
}

/* ================================================================
 * TEST: Cacophony spec vektörleri — Noise_XX_25519_ChaChaPoly_BLAKE2b
 *
 * Kaynak: cacophony.txt (dissononce/tgalal)
 * Prologue: "John Galt" (0x4a6f686e2047616c74)
 * Her mesajda payload var — deterministik ciphertext karşılaştırması.
 * ================================================================ */
#ifdef NOISE_TEST_DETERMINISTIC
static int test_spec_vectors(void)
{
    /* --- Cacophony: Noise_XX_25519_ChaChaPoly_BLAKE2b --- */

    /* Prologue: "John Galt" */
    static const uint8_t prologue[9] = {
        0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x47, 0x61, 0x6c, 0x74
    };

    /* Initiator (Alice) static private key */
    static const uint8_t init_s_priv[32] = {
        0xe6, 0x1e, 0xf9, 0x91, 0x9c, 0xde, 0x45, 0xdd,
        0x5f, 0x82, 0x16, 0x64, 0x04, 0xbd, 0x08, 0xe3,
        0x8b, 0xce, 0xb5, 0xdf, 0xdf, 0xde, 0xd0, 0xa3,
        0x4c, 0x8d, 0xf7, 0xed, 0x54, 0x22, 0x14, 0xd1
    };

    /* Initiator ephemeral private key */
    static const uint8_t init_e_priv[32] = {
        0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6,
        0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7,
        0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a,
        0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a
    };

    /* Responder (Bob) static private key */
    static const uint8_t resp_s_priv[32] = {
        0x4a, 0x3a, 0xcb, 0xfd, 0xb1, 0x63, 0xde, 0xc6,
        0x51, 0xdf, 0xa3, 0x19, 0x4d, 0xec, 0xe6, 0x76,
        0xd4, 0x37, 0x02, 0x9c, 0x62, 0xa4, 0x08, 0xb4,
        0xc5, 0xea, 0x91, 0x14, 0x24, 0x6e, 0x48, 0x93
    };

    /* Responder ephemeral private key */
    static const uint8_t resp_e_priv[32] = {
        0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
        0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
        0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
        0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
    };

    /* msg0 payload: "Ludwig von Mises" */
    static const uint8_t msg0_payload[16] = {
        0x4c, 0x75, 0x64, 0x77, 0x69, 0x67, 0x20, 0x76,
        0x6f, 0x6e, 0x20, 0x4d, 0x69, 0x73, 0x65, 0x73
    };

    /* msg1 payload: "Murray Rothbard" */
    static const uint8_t msg1_payload[15] = {
        0x4d, 0x75, 0x72, 0x72, 0x61, 0x79, 0x20, 0x52,
        0x6f, 0x74, 0x68, 0x62, 0x61, 0x72, 0x64
    };

    /* msg2 payload: "F. A. Hayek" */
    static const uint8_t msg2_payload[11] = {
        0x46, 0x2e, 0x20, 0x41, 0x2e, 0x20, 0x48, 0x61,
        0x79, 0x65, 0x6b
    };

    /* Expected ciphertext — msg0: e_pub(32) + payload(16) = 48 bytes */
    static const uint8_t expected_msg0[48] = {
        0xca, 0x35, 0xde, 0xf5, 0xae, 0x56, 0xce, 0xc3,
        0x3d, 0xc2, 0x03, 0x67, 0x31, 0xab, 0x14, 0x89,
        0x6b, 0xc4, 0xc7, 0x5d, 0xbb, 0x07, 0xa6, 0x1f,
        0x87, 0x9f, 0x8e, 0x3a, 0xfa, 0x4c, 0x79, 0x44,
        0x4c, 0x75, 0x64, 0x77, 0x69, 0x67, 0x20, 0x76,
        0x6f, 0x6e, 0x20, 0x4d, 0x69, 0x73, 0x65, 0x73
    };

    /* Expected ciphertext — msg1: e(32) + enc_s(48) + enc_pl(31) = 111 */
    static const uint8_t expected_msg1[111] = {
        0x95, 0xeb, 0xc6, 0x0d, 0x2b, 0x1f, 0xa6, 0x72,
        0xc1, 0xf4, 0x6a, 0x8a, 0xa2, 0x65, 0xef, 0x51,
        0xbf, 0xe3, 0x8e, 0x7c, 0xcb, 0x39, 0xec, 0x5b,
        0xe3, 0x40, 0x69, 0xf1, 0x44, 0x80, 0x88, 0x43,
        0x05, 0x05, 0xb6, 0x74, 0x5c, 0xe6, 0x4a, 0x5f,
        0x33, 0xf0, 0xe8, 0xe3, 0xb8, 0x3f, 0x11, 0xce,
        0x88, 0x02, 0xbc, 0xa5, 0x07, 0xf4, 0xf2, 0xd8,
        0xb5, 0x64, 0xdb, 0xe2, 0x77, 0xe1, 0x96, 0x61,
        0x16, 0xe1, 0x32, 0xfa, 0xa2, 0xdf, 0xd7, 0x0b,
        0x8b, 0x07, 0x7b, 0x9f, 0x94, 0xb9, 0x13, 0xdf,
        0x50, 0x56, 0xae, 0x13, 0x19, 0x46, 0x9b, 0x82,
        0x4a, 0x98, 0xd5, 0x4b, 0xba, 0xa8, 0x2c, 0x32,
        0x55, 0x95, 0x58, 0x70, 0x64, 0xf9, 0x78, 0xc4,
        0xb6, 0xd1, 0x04, 0xf7, 0x59, 0x6e, 0x6f
    };

    /* Expected ciphertext — msg2: enc_s(48) + enc_pl(27) = 75 */
    static const uint8_t expected_msg2[75] = {
        0x99, 0x57, 0x9e, 0x1c, 0x1e, 0xe1, 0x5e, 0x42,
        0x2a, 0x57, 0xdd, 0xd6, 0xb1, 0x6d, 0x37, 0x08,
        0x7b, 0x17, 0x55, 0x8e, 0x83, 0x69, 0xc1, 0x89,
        0x91, 0xb4, 0xb2, 0xca, 0x3a, 0x82, 0x4a, 0xbf,
        0x90, 0x4c, 0xdc, 0xf5, 0x45, 0x8b, 0x54, 0x31,
        0xa7, 0x5a, 0xf0, 0x34, 0xca, 0x9e, 0x9b, 0x98,
        0x2d, 0xe0, 0x39, 0xea, 0xaf, 0x15, 0x67, 0x75,
        0xe2, 0xd5, 0x80, 0xcd, 0x4e, 0x5e, 0xba, 0xe8,
        0x9c, 0x3f, 0x8c, 0xb2, 0x59, 0x4b, 0x55, 0x6d,
        0x8a, 0x81, 0x69
    };

    /* --- Public key'leri private key'lerden türet --- */
    uint8_t init_s_pub[32], resp_s_pub[32];
    crypto_scalarmult_base(init_s_pub, init_s_priv);
    crypto_scalarmult_base(resp_s_pub, resp_s_priv);

    /* --- Handshake init (prologue destekli) --- */
    struct noise_handshake hs_i, hs_r;
    TEST_ASSERT(handshake_init_with_prologue(&hs_i, true,
                    init_s_priv, init_s_pub,
                    prologue, sizeof(prologue)) == NOX_OK);
    TEST_ASSERT(handshake_init_with_prologue(&hs_r, false,
                    resp_s_priv, resp_s_pub,
                    prologue, sizeof(prologue)) == NOX_OK);

    /* --- Ephemeral key injection --- */
    TEST_ASSERT(handshake_inject_ephemeral(&hs_i, init_e_priv) == NOX_OK);
    TEST_ASSERT(handshake_inject_ephemeral(&hs_r, resp_e_priv) == NOX_OK);

    uint8_t out[512];
    size_t  out_len;
    uint8_t pl[128];
    size_t  pl_len;

    /* --- msg0: Alice → Bob: → e, payload --- */
    out_len = sizeof(out);
    TEST_ASSERT(handshake_write(&hs_i, msg0_payload, sizeof(msg0_payload),
                                out, &out_len) == NOX_OK);
    TEST_ASSERT(out_len == sizeof(expected_msg0));
    TEST_ASSERT(sodium_memcmp(out, expected_msg0, out_len) == 0);

    pl_len = sizeof(pl);
    TEST_ASSERT(handshake_read(&hs_r, out, out_len,
                               pl, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == sizeof(msg0_payload));
    TEST_ASSERT(sodium_memcmp(pl, msg0_payload, pl_len) == 0);

    /* --- msg1: Bob → Alice: ← e, ee, s, es, payload --- */
    out_len = sizeof(out);
    TEST_ASSERT(handshake_write(&hs_r, msg1_payload, sizeof(msg1_payload),
                                out, &out_len) == NOX_OK);
    TEST_ASSERT(out_len == sizeof(expected_msg1));
    if (sodium_memcmp(out, expected_msg1, out_len) != 0) {
        printf("Mismatch at msg1!\n");
        printf("Expected: ");
        for (size_t i = 0; i < sizeof(expected_msg1); i++) printf("%02x", expected_msg1[i]);
        printf("\nActual:   ");
        for (size_t i = 0; i < out_len; i++) printf("%02x", out[i]);
        printf("\n");
        TEST_ASSERT(0);
    }

    pl_len = sizeof(pl);
    TEST_ASSERT(handshake_read(&hs_i, out, out_len,
                               pl, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == sizeof(msg1_payload));
    TEST_ASSERT(sodium_memcmp(pl, msg1_payload, pl_len) == 0);

    /* --- msg2: Alice → Bob: → s, se, payload --- */
    out_len = sizeof(out);
    TEST_ASSERT(handshake_write(&hs_i, msg2_payload, sizeof(msg2_payload),
                                out, &out_len) == NOX_OK);
    TEST_ASSERT(out_len == sizeof(expected_msg2));
    TEST_ASSERT(sodium_memcmp(out, expected_msg2, out_len) == 0);

    pl_len = sizeof(pl);
    TEST_ASSERT(handshake_read(&hs_r, out, out_len,
                               pl, &pl_len) == NOX_OK);
    TEST_ASSERT(pl_len == sizeof(msg2_payload));
    TEST_ASSERT(sodium_memcmp(pl, msg2_payload, pl_len) == 0);

    /* --- Her iki taraf da tamamlanmış olmalı --- */
    TEST_ASSERT(handshake_is_complete(&hs_i));
    TEST_ASSERT(handshake_is_complete(&hs_r));

    return 0;
}
#endif /* NOISE_TEST_DETERMINISTIC */

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== test_noise ===\n\n");

    RUN_TEST(test_noise_null_safety);
    RUN_TEST(test_loopback_handshake);
    RUN_TEST(test_transport_roundtrip);
    RUN_TEST(test_mac_tamper);
    RUN_TEST(test_remote_static_key);
    RUN_TEST(test_wrong_order);
    RUN_TEST(test_handshake_onion_payload);
#ifdef NOISE_TEST_DETERMINISTIC
    RUN_TEST(test_spec_vectors);
#endif

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
