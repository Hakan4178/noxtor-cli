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

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
