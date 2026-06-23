/* ================================================================
 * Differential Fuzzing: noise-c (reference) vs our noise.c
 *
 * noise-c 0.3.x API — ephemeral key enjeksiyonu ile deterministik.
 *
 * İki aşamalı test stratejisi:
 *   AŞAMA 1 — Hedefli testler (13 test, sabit deterministic key'ler):
 *     Happy path, corrupted msg, various ephemerals, cross-verify,
 *     multi-message, payload sizes, bidirectional, split key verification,
 *     handshake hash match, nonce counter, empty payload, error recovery,
 *     input variety
 *
 *   AŞAMA 2 — Kapsamlı brute-force testler (full):
 *     105 key (100 random + 5 known) × 12 prologue × 4 pattern × 10 payload
 *     + Kapsamlı error behavior (corrupt/zeros/short × msg0/1/2 + wrong key)
 *     + Parametre boyut doğrulaması
 *
 * Derneleme:
 *   cc -std=c23 -DNOISE_TEST_DETERMINISTIC -Iinclude \
 *     tests/fuzz_noise_differential.c src/noise.c \
 *     -L/usr/local/lib -lnoiseprotocol -lsodium -o tests/fuzz_noise_differential
 * ================================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

/* noise-c header'larını bizimkinden önce include et — redefinition önlemek için */
#include <noise/protocol.h>

/* NOISE_MAX_PAYLOAD_LEN çakışmasını önle */
#ifdef NOISE_MAX_PAYLOAD_LEN
#undef NOISE_MAX_PAYLOAD_LEN
#endif

#include "common.h"
#include "noise.h"

/* ================================================================
 * Stub: noise.c nox_log_impl gerektirir — test'te noop
 * ================================================================ */
void nox_log_impl(log_level_t level, log_module_t mod,
                  const char *file, int line, const char *fmt, ...) {
    (void)level; (void)mod; (void)file; (void)line; (void)fmt;
}

/* ================================================================
 * ASSERT makrosu
 * ================================================================ */
static int g_pass = 0, g_fail = 0;

#define DIFF_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "  FAIL: %s\n", msg); \
            g_fail++; \
        } else { \
            g_pass++; \
        } \
    } while (0)

/* ================================================================
 * noise-c YARDIMCI
 * ================================================================ */
static NoiseHandshakeState *g_nc_i = NULL;
static NoiseHandshakeState *g_nc_r = NULL;
static NoiseCipherState *g_nc_i_c1 = NULL, *g_nc_i_c2 = NULL;
static NoiseCipherState *g_nc_r_c1 = NULL, *g_nc_r_c2 = NULL;

static void nc_cleanup(void) {
    if (g_nc_i_c1) { noise_cipherstate_free(g_nc_i_c1); g_nc_i_c1 = NULL; }
    if (g_nc_i_c2) { noise_cipherstate_free(g_nc_i_c2); g_nc_i_c2 = NULL; }
    if (g_nc_r_c1) { noise_cipherstate_free(g_nc_r_c1); g_nc_r_c1 = NULL; }
    if (g_nc_r_c2) { noise_cipherstate_free(g_nc_r_c2); g_nc_r_c2 = NULL; }
    if (g_nc_i) { noise_handshakestate_free(g_nc_i); g_nc_i = NULL; }
    if (g_nc_r) { noise_handshakestate_free(g_nc_r); g_nc_r = NULL; }
}

static int nc_setup(const uint8_t i_priv[32], const uint8_t i_pub[32],
                    const uint8_t r_priv[32], const uint8_t r_pub[32],
                    const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                    const uint8_t *prologue, size_t prologue_len) {
    int rc;
    NoiseDHState *dh;

    rc = noise_init();
    if (rc != NOISE_ERROR_NONE) return -1;

    rc = noise_handshakestate_new_by_name(
        &g_nc_i, "Noise_XX_25519_ChaChaPoly_BLAKE2b", NOISE_ROLE_INITIATOR);
    if (rc != NOISE_ERROR_NONE) return -1;

    dh = noise_handshakestate_get_local_keypair_dh(g_nc_i);
    rc = noise_dhstate_set_keypair_private(dh, i_priv, 32);
    if (rc != NOISE_ERROR_NONE) return -1;

    dh = noise_handshakestate_get_remote_public_key_dh(g_nc_i);
    rc = noise_dhstate_set_public_key(dh, r_pub, 32);
    if (rc != NOISE_ERROR_NONE) return -1;

    dh = noise_handshakestate_get_fixed_ephemeral_dh(g_nc_i);
    if (dh) {
        rc = noise_dhstate_set_keypair_private(dh, e_priv_i, 32);
        if (rc != NOISE_ERROR_NONE) return -1;
    }

    rc = noise_handshakestate_new_by_name(
        &g_nc_r, "Noise_XX_25519_ChaChaPoly_BLAKE2b", NOISE_ROLE_RESPONDER);
    if (rc != NOISE_ERROR_NONE) return -1;

    dh = noise_handshakestate_get_local_keypair_dh(g_nc_r);
    rc = noise_dhstate_set_keypair_private(dh, r_priv, 32);
    if (rc != NOISE_ERROR_NONE) return -1;

    dh = noise_handshakestate_get_remote_public_key_dh(g_nc_r);
    rc = noise_dhstate_set_public_key(dh, i_pub, 32);
    if (rc != NOISE_ERROR_NONE) return -1;

    dh = noise_handshakestate_get_fixed_ephemeral_dh(g_nc_r);
    if (dh) {
        rc = noise_dhstate_set_keypair_private(dh, e_priv_r, 32);
        if (rc != NOISE_ERROR_NONE) return -1;
    }

    noise_handshakestate_set_prologue(g_nc_i, prologue, prologue_len);
    noise_handshakestate_set_prologue(g_nc_r, prologue, prologue_len);

    rc = noise_handshakestate_start(g_nc_i);
    if (rc != NOISE_ERROR_NONE) return -1;
    rc = noise_handshakestate_start(g_nc_r);
    if (rc != NOISE_ERROR_NONE) return -1;

    return 0;
}

static int nc_write_msg(NoiseHandshakeState *state,
                        uint8_t *out, size_t *out_len) {
    NoiseBuffer mbuf, pbuf;
    noise_buffer_init(mbuf);
    noise_buffer_set_output(mbuf, out, 512);
    noise_buffer_init(pbuf);
    uint8_t zero = 0;
    noise_buffer_set_input(pbuf, &zero, 0);
    int rc = noise_handshakestate_write_message(state, &mbuf, &pbuf);
    *out_len = mbuf.size;
    return rc;
}

static int nc_read_msg(NoiseHandshakeState *state,
                       uint8_t *in, size_t in_len) {
    NoiseBuffer mbuf, pbuf;
    noise_buffer_init(mbuf);
    noise_buffer_set_input(mbuf, in, in_len);
    noise_buffer_init(pbuf);
    uint8_t tmp[512];
    noise_buffer_set_output(pbuf, tmp, 512);
    return noise_handshakestate_read_message(state, &mbuf, &pbuf);
}

/* ================================================================
 * Our code YARDIMCI
 * ================================================================ */
static struct noise_handshake g_our_i, g_our_r;

static void our_setup(const uint8_t i_priv[32], const uint8_t i_pub[32],
                      const uint8_t r_priv[32], const uint8_t r_pub[32],
                      const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                      const uint8_t *prologue, size_t prologue_len) {
    handshake_init_with_prologue(&g_our_i, true, i_priv, i_pub,
                                 prologue, prologue_len);
    handshake_init_with_prologue(&g_our_r, false, r_priv, r_pub,
                                 prologue, prologue_len);
    handshake_inject_ephemeral(&g_our_i, e_priv_i);
    handshake_inject_ephemeral(&g_our_r, e_priv_r);
}

/* Sabit prologue — hedefli testler tarafından kullanılır */
static const char PROLOGUE_DEFAULT[] = "Mustafa Kemal Atatürk";
#define PROLOGUE_DEFAULT_LEN (sizeof(PROLOGUE_DEFAULT) - 1)

/* ================================================================
 * HELPER: Happy path handshake + split (testler tarafından kullanılır)
 * ================================================================ */
static struct noise_session g_our_i_session, g_our_r_session;

static void do_full_handshake(const uint8_t i_priv[32], const uint8_t i_pub[32],
                              const uint8_t r_priv[32], const uint8_t r_pub[32],
                              const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                              struct noise_session *i_sess, struct noise_session *r_sess) {
    uint8_t payload_buf[512];
    size_t pl_len;

    /* noise-c */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t nc_msg0[512], nc_msg1[512], nc_msg2[512];
    size_t nc_m0l, nc_m1l, nc_m2l;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0l);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0l);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1l);
    nc_read_msg(g_nc_i, nc_msg1, nc_m1l);
    nc_write_msg(g_nc_i, nc_msg2, &nc_m2l);
    nc_read_msg(g_nc_r, nc_msg2, nc_m2l);
    noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);

    /* Our code */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t our_msg0[512], our_msg1[512], our_msg2[512];
    size_t our_m0l = sizeof(our_msg0), our_m1l = sizeof(our_msg1), our_m2l = sizeof(our_msg2);
    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg0, our_m0l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_r, NULL, 0, our_msg1, &our_m1l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_i, our_msg1, our_m1l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_i, NULL, 0, our_msg2, &our_m2l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg2, our_m2l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_split(&g_our_i, i_sess);
    handshake_split(&g_our_r, r_sess);
}

/* ================================================================
 * HELPER: Tek bir transport testi çalıştır (encrypt + compare + decrypt)
 * ================================================================ */
static int do_transport_test(const uint8_t *plain, size_t plain_len, const char *label_prefix) {
    char label[128];

    /* noise-c: encrypt */
    uint8_t nc_enc[4200];
    size_t nc_enc_len = 0;
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        if (plain_len > 0) memcpy(nc_enc, plain, plain_len);
        noise_buffer_set_inout(b, nc_enc, plain_len, sizeof(nc_enc));
        noise_cipherstate_encrypt(g_nc_i_c1, &b);
        nc_enc_len = b.size;
    }

    /* Our code: encrypt */
    uint8_t our_enc[4200];
    ssize_t our_enc_len = noise_encrypt(&g_our_i_session, plain, plain_len, our_enc);

    snprintf(label, sizeof(label), "%s enc len: nc(%zu)==our(%zd)", label_prefix, nc_enc_len, our_enc_len);
    DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
    if (nc_enc_len == (size_t)our_enc_len && plain_len > 0) {
        snprintf(label, sizeof(label), "%s enc content: nc==our", label_prefix);
        DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, label);
    }

    /* Our code: decrypt */
    if (nc_enc_len > 0) {
        uint8_t our_dec[4200];
        ssize_t our_dec_len = noise_decrypt(&g_our_r_session, our_enc, nc_enc_len, our_dec);
        snprintf(label, sizeof(label), "%s dec len: %zd==%zu", label_prefix, our_dec_len, plain_len);
        DIFF_ASSERT(our_dec_len == (ssize_t)plain_len, label);
        if (our_dec_len == (ssize_t)plain_len && plain_len > 0) {
            snprintf(label, sizeof(label), "%s dec content match", label_prefix);
            DIFF_ASSERT(memcmp(our_dec, plain, plain_len) == 0, label);
        }
    }

    return 0;
}

/* ================================================================
 * AŞAMA 1 — HEDEFLİ TESTLER (deterministic keys)
 * ================================================================ */

/* ================================================================
 * TEST 1: Happy path — 3 mesaj XX handshake + split + transport
 * ================================================================ */
static void test_happy_path(const uint8_t i_priv[32], const uint8_t i_pub[32],
                            const uint8_t r_priv[32], const uint8_t r_pub[32],
                            const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_happy_path...\n");

    char label[64];

    /* === noise-c XX handshake — her adımda inline karşılaştırma === */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);

    /* Our code setup */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);

    uint8_t nc_msg[512], our_msg[512];
    size_t nc_mlen, our_mlen;
    uint8_t payload_buf[512];
    size_t pl_len;
    nox_err_t our_rc;
    int nc_rc;

    /* --- MSG 0: initiator → responder --- */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: msg0 write");

    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);
    DIFF_ASSERT(our_rc == NOX_OK, "our: msg0 write");

    snprintf(label, sizeof(label), "msg0 len: nc(%zu)==our(%zu)", nc_mlen, our_mlen);
    DIFF_ASSERT(nc_mlen == our_mlen, label);
    if (nc_mlen == our_mlen) {
        DIFF_ASSERT(memcmp(nc_msg, our_msg, nc_mlen) == 0, "msg0 content: nc==our");
    }

    /* Read msg0 — responder side */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: msg0 read");

    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc == NOX_OK, "our: msg0 read");

    /* --- MSG 1: responder → initiator --- */
    nc_rc = nc_write_msg(g_nc_r, nc_msg, &nc_mlen);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: msg1 write");

    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_r, NULL, 0, our_msg, &our_mlen);
    DIFF_ASSERT(our_rc == NOX_OK, "our: msg1 write");

    snprintf(label, sizeof(label), "msg1 len: nc(%zu)==our(%zu)", nc_mlen, our_mlen);
    DIFF_ASSERT(nc_mlen == our_mlen, label);
    if (nc_mlen == our_mlen) {
        DIFF_ASSERT(memcmp(nc_msg, our_msg, nc_mlen) == 0, "msg1 content: nc==our");
    }

    /* Read msg1 — initiator side */
    nc_rc = nc_read_msg(g_nc_i, nc_msg, nc_mlen);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: msg1 read");

    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_i, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc == NOX_OK, "our: msg1 read");

    /* --- MSG 2: initiator → responder --- */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: msg2 write");

    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);
    DIFF_ASSERT(our_rc == NOX_OK, "our: msg2 write");

    snprintf(label, sizeof(label), "msg2 len: nc(%zu)==our(%zu)", nc_mlen, our_mlen);
    DIFF_ASSERT(nc_mlen == our_mlen, label);
    if (nc_mlen == our_mlen) {
        DIFF_ASSERT(memcmp(nc_msg, our_msg, nc_mlen) == 0, "msg2 content: nc==our");
    }

    /* Read msg2 — responder side */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: msg2 read");

    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc == NOX_OK, "our: msg2 read");

    /* === Split === */
    nc_rc = noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: initiator split");
    nc_rc = noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: responder split");

    struct noise_session i_sess = {0}, r_sess = {0};
    our_rc = handshake_split(&g_our_i, &i_sess);
    DIFF_ASSERT(our_rc == NOX_OK, "our: initiator split");
    our_rc = handshake_split(&g_our_r, &r_sess);
    DIFF_ASSERT(our_rc == NOX_OK, "our: responder split");

    /* === Transport: initiator encrypt → responder decrypt === */
    const uint8_t plain[] = "Differential fuzzing testi 1234567890";
    size_t plain_len = sizeof(plain) - 1;

    /* noise-c */
    uint8_t nc_enc[256], nc_dec[256];
    size_t nc_enc_len = 0;
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        memcpy(nc_enc, plain, plain_len);
        noise_buffer_set_inout(b, nc_enc, plain_len, sizeof(nc_enc));
        nc_rc = noise_cipherstate_encrypt(g_nc_i_c1, &b);
        DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: transport encrypt");
        nc_enc_len = b.size;
    }

    /* Our code */
    uint8_t our_enc[256], our_dec[256];
    ssize_t our_enc_len = noise_encrypt(&i_sess, plain, plain_len, our_enc);
    DIFF_ASSERT(our_enc_len > 0, "our: transport encrypt");

    /* Ciphertext karşılaştırması — EN KRİTİK TEST */
    snprintf(label, sizeof(label), "ciphertext len: nc(%zu)==our(%zd)", nc_enc_len, our_enc_len);
    DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
    if (nc_enc_len == (size_t)our_enc_len) {
        DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0,
                    "ciphertext content: nc==our");
    }

    /* Decrypt — noise-c: nc_r_c2 (responder receive) */
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        noise_buffer_set_input(b, nc_enc, nc_enc_len);
        nc_rc = noise_cipherstate_decrypt(g_nc_r_c2, &b);
        DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "nc: transport decrypt");
        if (nc_rc == NOISE_ERROR_NONE) {
            DIFF_ASSERT(b.size == plain_len, "nc: decrypt len match");
            DIFF_ASSERT(memcmp(b.data, plain, plain_len) == 0,
                        "nc: decrypt content match");
        }
    }

    /* Decrypt — our code: r_sess (responder receive) */
    ssize_t our_dec_len = noise_decrypt(&r_sess, our_enc,
                                        (size_t)our_enc_len, our_dec);
    DIFF_ASSERT(our_dec_len == (ssize_t)plain_len, "our: decrypt len match");
    if (our_dec_len == (ssize_t)plain_len) {
        DIFF_ASSERT(memcmp(our_dec, plain, plain_len) == 0,
                    "our: decrypt content match");
    }

    nc_cleanup();
}

/* ================================================================
 * TEST 2: Corrupted msg — bozuk msg her iki tarafta da red
 * ================================================================ */
static void test_corrupted_msg(const uint8_t i_priv[32], const uint8_t i_pub[32],
                               const uint8_t r_priv[32], const uint8_t r_pub[32],
                               const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_corrupted_msg...\n");

    uint8_t payload_buf[512];
    size_t pl_len;

    /* noise-c: msg0 + msg1 üret, msg1'i boz */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);

    uint8_t nc_msg0[512], nc_msg1[512];
    size_t nc_m0_len, nc_m1_len;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0_len);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0_len);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1_len);

    if (nc_m1_len > 0) nc_msg1[0] ^= 0xFF;
    int nc_rc = nc_read_msg(g_nc_i, nc_msg1, nc_m1_len);
    DIFF_ASSERT(nc_rc != NOISE_ERROR_NONE, "nc: reject corrupted msg1");
    nc_cleanup();

    /* Our code: msg0 + msg1 üret, msg1'i boz */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);

    uint8_t our_msg0[512], our_msg1[512];
    size_t our_m0_len = sizeof(our_msg0), our_m1_len = sizeof(our_msg1);

    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0_len);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg0, our_m0_len, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_r, NULL, 0, our_msg1, &our_m1_len);

    if (our_m1_len > 0) our_msg1[0] ^= 0xFF;
    pl_len = sizeof(payload_buf);
    nox_err_t our_rc = handshake_read(&g_our_i, our_msg1, our_m1_len, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc != NOX_OK, "our: reject corrupted msg1");
}

/* ================================================================
 * TEST 3: Farklı ephemeral key çiftleri — msg0 uzunluk karşılaştırması
 * ================================================================ */
static void test_various_ephemerals(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                    const uint8_t r_priv[32], const uint8_t r_pub[32]) {
    fprintf(stderr, "[diff] test_various_ephemerals...\n");

    static const uint8_t e_keys[][32] = {
        {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
         0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
         0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
         0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20},
        {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
         0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
         0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
         0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99},
        {0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,
         0xF7,0xF6,0xF5,0xF4,0xF3,0xF2,0xF1,0xF0,
         0xEF,0xEE,0xED,0xEC,0xEB,0xEA,0xE9,0xE8,
         0xE7,0xE6,0xE5,0xE4,0xE3,0xE2,0xE1,0xE0},
    };

    for (size_t t = 0; t < sizeof(e_keys)/sizeof(e_keys[0]); t++) {
        const uint8_t *e_i = e_keys[t];
        const uint8_t *e_r = e_keys[(t + 1) % 3];

        /* noise-c */
        nc_setup(i_priv, i_pub, r_priv, r_pub, e_i, e_r,
                 (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
        uint8_t nc_msg0[512];
        size_t nc_m0_len = 0;
        nc_write_msg(g_nc_i, nc_msg0, &nc_m0_len);
        nc_cleanup();

        /* Our code */
        our_setup(i_priv, i_pub, r_priv, r_pub, e_i, e_r,
                  (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
        uint8_t our_msg0[512];
        size_t our_m0_len = sizeof(our_msg0);
        handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0_len);

        char label[64];
        snprintf(label, sizeof(label), "eph set %zu: msg0 len %zu==%zu", t, nc_m0_len, our_m0_len);
        DIFF_ASSERT(nc_m0_len == our_m0_len, label);
        if (nc_m0_len == our_m0_len) {
            snprintf(label, sizeof(label), "eph set %zu: msg0 match", t);
            DIFF_ASSERT(memcmp(nc_msg0, our_msg0, nc_m0_len) == 0, label);
        }
    }
}

/* ================================================================
 * TEST 4: Cross-verification
 * ================================================================ */
static void test_cross_verify(const uint8_t i_priv[32], const uint8_t i_pub[32],
                              const uint8_t r_priv[32], const uint8_t r_pub[32],
                              const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_cross_verify...\n");

    /* nc msg0 → our read */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t nc_msg0[512];
    size_t nc_m0_len = 0;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0_len);
    nc_cleanup();

    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t cross_payload[512];
    size_t cross_pl_len = sizeof(cross_payload);
    nox_err_t rc = handshake_read(&g_our_r, nc_msg0, nc_m0_len, cross_payload, sizeof(cross_payload), &cross_pl_len);
    DIFF_ASSERT(rc == NOX_OK, "cross: our reads nc msg0");

    /* our msg0 → nc read */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t our_msg0[512];
    size_t our_m0_len = sizeof(our_msg0);
    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0_len);

    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    int nc_rc = nc_read_msg(g_nc_r, our_msg0, our_m0_len);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "cross: nc reads our msg0");

    nc_cleanup();
}

/* ================================================================
 * TEST 5: Transport multi-message — 10 mesaj encrypt/decrypt
 * ================================================================ */
static void test_transport_multi_msg(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                     const uint8_t r_priv[32], const uint8_t r_pub[32],
                                     const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_transport_multi_msg...\n");

    struct noise_session i_sess, r_sess;
    do_full_handshake(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r, &i_sess, &r_sess);

    char label[64];
    for (int idx = 0; idx < 10; idx++) {
        uint8_t plain[64];
        memset(plain, (uint8_t)('A' + idx), sizeof(plain));

        /* noise-c: encrypt (initiator send = c1) */
        uint8_t nc_enc[256];
        size_t nc_enc_len = 0;
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            memcpy(nc_enc, plain, sizeof(plain));
            noise_buffer_set_inout(b, nc_enc, sizeof(plain), sizeof(nc_enc));
            noise_cipherstate_encrypt(g_nc_i_c1, &b);
            nc_enc_len = b.size;
        }

        /* Our code: encrypt */
        uint8_t our_enc[256];
        ssize_t our_enc_len = noise_encrypt(&i_sess, plain, sizeof(plain), our_enc);

        snprintf(label, sizeof(label), "msg%d enc len: nc(%zu)==our(%zd)", idx, nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
        if (nc_enc_len == (size_t)our_enc_len) {
            snprintf(label, sizeof(label), "msg%d enc content: nc==our", idx);
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, label);
        }

        /* noise-c: decrypt (responder receive = c2) */
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            noise_buffer_set_input(b, nc_enc, nc_enc_len);
            noise_cipherstate_decrypt(g_nc_r_c2, &b);
        }

        /* Our code: decrypt */
        uint8_t our_dec[256];
        ssize_t our_dec_len = noise_decrypt(&r_sess, our_enc, (size_t)our_enc_len, our_dec);

        snprintf(label, sizeof(label), "msg%d dec len: %zd==%zu", idx, our_dec_len, sizeof(plain));
        DIFF_ASSERT(our_dec_len == (ssize_t)sizeof(plain), label);
        if (our_dec_len == (ssize_t)sizeof(plain)) {
            snprintf(label, sizeof(label), "msg%d dec content match", idx);
            DIFF_ASSERT(memcmp(our_dec, plain, sizeof(plain)) == 0, label);
        }
    }
    nc_cleanup();
}

/* ================================================================
 * TEST 6: Transport payload sizes — farklı boyutlarda ciphertext
 * ================================================================ */
static void test_transport_payload_sizes(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                         const uint8_t r_priv[32], const uint8_t r_pub[32],
                                         const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_transport_payload_sizes...\n");

    struct noise_session i_sess, r_sess;
    do_full_handshake(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r, &i_sess, &r_sess);

    static const size_t sizes[] = {0, 1, 100, 4000};
    static const size_t num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    char label[64];

    for (size_t t = 0; t < num_sizes; t++) {
        size_t sz = sizes[t];
        uint8_t plain[4000];
        if (sz > 0) memset(plain, 0xAB, sz);

        /* noise-c: encrypt */
        uint8_t nc_enc[4200];
        size_t nc_enc_len = 0;
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            if (sz > 0) memcpy(nc_enc, plain, sz);
            noise_buffer_set_inout(b, nc_enc, sz, sizeof(nc_enc));
            noise_cipherstate_encrypt(g_nc_i_c1, &b);
            nc_enc_len = b.size;
        }

        /* Our code: encrypt */
        uint8_t our_enc[4200];
        ssize_t our_enc_len = noise_encrypt(&i_sess, (sz > 0 ? plain : NULL), sz, our_enc);

        snprintf(label, sizeof(label), "size %zu: enc len nc(%zu)==our(%zd)", sz, nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
        if (nc_enc_len == (size_t)our_enc_len && sz > 0) {
            snprintf(label, sizeof(label), "size %zu: enc content nc==our", sz);
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, label);
        }
    }
    nc_cleanup();
}

/* ================================================================
 * TEST 7: Bidirectional transport — i→r VE r→i
 * ================================================================ */
static void test_transport_bidirectional(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                         const uint8_t r_priv[32], const uint8_t r_pub[32],
                                         const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_transport_bidirectional...\n");

    struct noise_session i_sess, r_sess;
    do_full_handshake(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r, &i_sess, &r_sess);

    char label[64];

    /* Direction 1: initiator → responder */
    {
        const uint8_t plain[] = "Hello from initiator";
        size_t plain_len = sizeof(plain) - 1;

        uint8_t nc_enc[256];
        size_t nc_enc_len = 0;
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            memcpy(nc_enc, plain, plain_len);
            noise_buffer_set_inout(b, nc_enc, plain_len, sizeof(nc_enc));
            noise_cipherstate_encrypt(g_nc_i_c1, &b);
            nc_enc_len = b.size;
        }

        uint8_t our_enc[256];
        ssize_t our_enc_len = noise_encrypt(&i_sess, plain, plain_len, our_enc);

        snprintf(label, sizeof(label), "i→r enc len: nc(%zu)==our(%zd)", nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
        if (nc_enc_len == (size_t)our_enc_len) {
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, "i→r enc content: nc==our");
        }

        uint8_t our_dec[256];
        ssize_t our_dec_len = noise_decrypt(&r_sess, our_enc, (size_t)our_enc_len, our_dec);
        DIFF_ASSERT(our_dec_len == (ssize_t)plain_len, "i→r dec len match");
        if (our_dec_len == (ssize_t)plain_len) {
            DIFF_ASSERT(memcmp(our_dec, plain, plain_len) == 0, "i→r dec content match");
        }
    }

    /* Direction 2: responder → initiator */
    {
        const uint8_t plain[] = "Hello from responder";
        size_t plain_len = sizeof(plain) - 1;

        uint8_t nc_enc[256];
        size_t nc_enc_len = 0;
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            memcpy(nc_enc, plain, plain_len);
            noise_buffer_set_inout(b, nc_enc, plain_len, sizeof(nc_enc));
            noise_cipherstate_encrypt(g_nc_r_c1, &b);
            nc_enc_len = b.size;
        }

        uint8_t our_enc[256];
        ssize_t our_enc_len = noise_encrypt(&r_sess, plain, plain_len, our_enc);

        snprintf(label, sizeof(label), "r→i enc len: nc(%zu)==our(%zd)", nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
        if (nc_enc_len == (size_t)our_enc_len) {
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, "r→i enc content: nc==our");
        }

        uint8_t our_dec[256];
        ssize_t our_dec_len = noise_decrypt(&i_sess, our_enc, (size_t)our_enc_len, our_dec);
        DIFF_ASSERT(our_dec_len == (ssize_t)plain_len, "r→i dec len match");
        if (our_dec_len == (ssize_t)plain_len) {
            DIFF_ASSERT(memcmp(our_dec, plain, plain_len) == 0, "r→i dec content match");
        }
    }
    nc_cleanup();
}

/* ================================================================
 * TEST 8: Split key verification — tx/rx key'lerinin noise-c ile eşleşmesi
 * ================================================================ */
static void test_split_key_verification(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                        const uint8_t r_priv[32], const uint8_t r_pub[32],
                                        const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_split_key_verification...\n");

    /* noise-c handshake */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t nc_msg0[512], nc_msg1[512], nc_msg2[512];
    size_t nc_m0l, nc_m1l, nc_m2l;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0l);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0l);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1l);
    nc_read_msg(g_nc_i, nc_msg1, nc_m1l);
    nc_write_msg(g_nc_i, nc_msg2, &nc_m2l);
    nc_read_msg(g_nc_r, nc_msg2, nc_m2l);

    noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);

    /* Our code handshake + split */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t our_msg0[512], our_msg1[512], our_msg2[512];
    size_t our_m0l = sizeof(our_msg0), our_m1l = sizeof(our_msg1), our_m2l = sizeof(our_msg2);
    uint8_t payload_buf[512];
    size_t pl_len;
    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg0, our_m0l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_r, NULL, 0, our_msg1, &our_m1l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_i, our_msg1, our_m1l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_i, NULL, 0, our_msg2, &our_m2l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg2, our_m2l, payload_buf, sizeof(payload_buf), &pl_len);

    struct noise_session i_sess = {0}, r_sess = {0};
    handshake_split(&g_our_i, &i_sess);
    handshake_split(&g_our_r, &r_sess);

    /* Split sonrası: encryption key'leri karşılaştır */
    const uint8_t test_plain[] = "split_key_test";
    size_t test_len = sizeof(test_plain) - 1;

    uint8_t nc_enc[256], our_enc[256];
    size_t nc_enc_len = 0;
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        memcpy(nc_enc, test_plain, test_len);
        noise_buffer_set_inout(b, nc_enc, test_len, sizeof(nc_enc));
        noise_cipherstate_encrypt(g_nc_i_c1, &b);
        nc_enc_len = b.size;
    }

    ssize_t our_enc_len = noise_encrypt(&i_sess, test_plain, test_len, our_enc);

    DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, "split: enc len match");
    if (nc_enc_len == (size_t)our_enc_len) {
        DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, "split: enc content match (same key)");
    }

    /* Cross-decrypt: noise-c encrypt → our decrypt */
    uint8_t cross_dec[256];
    ssize_t cross_dec_len = noise_decrypt(&r_sess, nc_enc, nc_enc_len, cross_dec);
    DIFF_ASSERT(cross_dec_len == (ssize_t)test_len, "split: cross-decrypt len");
    if (cross_dec_len == (ssize_t)test_len) {
        DIFF_ASSERT(memcmp(cross_dec, test_plain, test_len) == 0, "split: cross-decrypt content");
    }

    nc_cleanup();
}

/* ================================================================
 * TEST 9: Handshake hash match — her msg sonrası h/ck/k karşılaştırması
 * ================================================================ */
static void test_handshake_hash_match(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                      const uint8_t r_priv[32], const uint8_t r_pub[32],
                                      const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_handshake_hash_match...\n");

    static const size_t msg_counts[] = {0, 1, 2};
    char label[64];

    for (size_t m = 0; m < sizeof(msg_counts)/sizeof(msg_counts[0]); m++) {
        size_t after_msg = msg_counts[m];

        nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
        uint8_t nc_msgs[3][512];
        size_t nc_lens[3];
        nc_write_msg(g_nc_i, nc_msgs[0], &nc_lens[0]);
        nc_read_msg(g_nc_r, nc_msgs[0], nc_lens[0]);
        nc_write_msg(g_nc_r, nc_msgs[1], &nc_lens[1]);
        nc_read_msg(g_nc_i, nc_msgs[1], nc_lens[1]);
        nc_write_msg(g_nc_i, nc_msgs[2], &nc_lens[2]);
        nc_read_msg(g_nc_r, nc_msgs[2], nc_lens[2]);

        noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
        const uint8_t test_plain[] = "hash_verify";
        uint8_t nc_enc[256];
        size_t nc_enc_len = 0;
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            memcpy(nc_enc, test_plain, sizeof(test_plain) - 1);
            noise_buffer_set_inout(b, nc_enc, sizeof(test_plain) - 1, sizeof(nc_enc));
            noise_cipherstate_encrypt(g_nc_i_c1, &b);
            nc_enc_len = b.size;
        }

        our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                  (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
        uint8_t our_msgs[3][512];
        size_t our_lens[3] = {sizeof(our_msgs[0]), sizeof(our_msgs[1]), sizeof(our_msgs[2])};
        uint8_t payload_buf[512];
        size_t pl_len;
        handshake_write(&g_our_i, NULL, 0, our_msgs[0], &our_lens[0]);
        pl_len = sizeof(payload_buf);
        handshake_read(&g_our_r, our_msgs[0], our_lens[0], payload_buf, sizeof(payload_buf), &pl_len);
        handshake_write(&g_our_r, NULL, 0, our_msgs[1], &our_lens[1]);
        pl_len = sizeof(payload_buf);
        handshake_read(&g_our_i, our_msgs[1], our_lens[1], payload_buf, sizeof(payload_buf), &pl_len);
        handshake_write(&g_our_i, NULL, 0, our_msgs[2], &our_lens[2]);
        pl_len = sizeof(payload_buf);
        handshake_read(&g_our_r, our_msgs[2], our_lens[2], payload_buf, sizeof(payload_buf), &pl_len);

        struct noise_session i_sess = {0};
        handshake_split(&g_our_i, &i_sess);
        uint8_t our_enc[256];
        ssize_t our_enc_len = noise_encrypt(&i_sess, test_plain, sizeof(test_plain) - 1, our_enc);

        snprintf(label, sizeof(label), "after msg%zu: enc len nc(%zu)==our(%zd)", after_msg, nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
        if (nc_enc_len == (size_t)our_enc_len) {
            snprintf(label, sizeof(label), "after msg%zu: enc content nc==our", after_msg);
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, label);
        }

        nc_cleanup();
    }
}

/* ================================================================
 * TEST 10: Nonce counter — her encrypt'te nonce artmalı
 * ================================================================ */
static void test_nonce_counter(const uint8_t i_priv[32], const uint8_t i_pub[32],
                               const uint8_t r_priv[32], const uint8_t r_pub[32],
                               const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_nonce_counter...\n");

    struct noise_session i_sess, r_sess;
    do_full_handshake(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r, &i_sess, &r_sess);

    const uint8_t plain[] = "nonce_test";
    size_t plain_len = sizeof(plain) - 1;
    uint8_t enc1[256], enc2[256], enc3[256];
    ssize_t len1, len2, len3;

    len1 = noise_encrypt(&i_sess, plain, plain_len, enc1);
    len2 = noise_encrypt(&i_sess, plain, plain_len, enc2);
    len3 = noise_encrypt(&i_sess, plain, plain_len, enc3);

    DIFF_ASSERT(len1 > 0, "nonce: enc1 success");
    DIFF_ASSERT(len2 > 0, "nonce: enc2 success");
    DIFF_ASSERT(len3 > 0, "nonce: enc3 success");

    if (len1 > 0 && len2 > 0) {
        DIFF_ASSERT(memcmp(enc1, enc2, (size_t)len1) != 0, "nonce: enc1 != enc2 (counter progressed)");
    }
    if (len2 > 0 && len3 > 0) {
        DIFF_ASSERT(memcmp(enc2, enc3, (size_t)len2) != 0, "nonce: enc2 != enc3 (counter progressed)");
    }
    if (len1 > 0 && len3 > 0) {
        DIFF_ASSERT(memcmp(enc1, enc3, (size_t)len1) != 0, "nonce: enc1 != enc3");
    }

    uint8_t dec[256];
    ssize_t dec_len;

    dec_len = noise_decrypt(&r_sess, enc1, (size_t)len1, dec);
    DIFF_ASSERT(dec_len == (ssize_t)plain_len, "nonce: dec1 len");
    if (dec_len == (ssize_t)plain_len) {
        DIFF_ASSERT(memcmp(dec, plain, plain_len) == 0, "nonce: dec1 content");
    }

    dec_len = noise_decrypt(&r_sess, enc2, (size_t)len2, dec);
    DIFF_ASSERT(dec_len == (ssize_t)plain_len, "nonce: dec2 len");
    if (dec_len == (ssize_t)plain_len) {
        DIFF_ASSERT(memcmp(dec, plain, plain_len) == 0, "nonce: dec2 content");
    }

    dec_len = noise_decrypt(&r_sess, enc3, (size_t)len3, dec);
    DIFF_ASSERT(dec_len == (ssize_t)plain_len, "nonce: dec3 len");
    if (dec_len == (ssize_t)plain_len) {
        DIFF_ASSERT(memcmp(dec, plain, plain_len) == 0, "nonce: dec3 content");
    }
}

/* ================================================================
 * TEST 11: Empty payload handshake — boş payload ile XX handshake
 * ================================================================ */
static void test_empty_payload_handshake(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                         const uint8_t r_priv[32], const uint8_t r_pub[32],
                                         const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_empty_payload_handshake...\n");

    char label[64];

    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t nc_msg0[512], nc_msg1[512], nc_msg2[512];
    size_t nc_m0l, nc_m1l, nc_m2l;

    nc_write_msg(g_nc_i, nc_msg0, &nc_m0l);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0l);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1l);
    nc_read_msg(g_nc_i, nc_msg1, nc_m1l);
    nc_write_msg(g_nc_i, nc_msg2, &nc_m2l);
    nc_read_msg(g_nc_r, nc_msg2, nc_m2l);

    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t our_msg0[512], our_msg1[512], our_msg2[512];
    size_t our_m0l = sizeof(our_msg0), our_m1l = sizeof(our_msg1), our_m2l = sizeof(our_msg2);
    uint8_t payload_buf[512];
    size_t pl_len;

    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg0, our_m0l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_r, NULL, 0, our_msg1, &our_m1l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_i, our_msg1, our_m1l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_i, NULL, 0, our_msg2, &our_m2l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg2, our_m2l, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(label, sizeof(label), "empty msg0 len: nc(%zu)==our(%zu)", nc_m0l, our_m0l);
    DIFF_ASSERT(nc_m0l == our_m0l, label);
    snprintf(label, sizeof(label), "empty msg1 len: nc(%zu)==our(%zu)", nc_m1l, our_m1l);
    DIFF_ASSERT(nc_m1l == our_m1l, label);
    snprintf(label, sizeof(label), "empty msg2 len: nc(%zu)==our(%zu)", nc_m2l, our_m2l);
    DIFF_ASSERT(nc_m2l == our_m2l, label);

    noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);
    struct noise_session i_sess = {0}, r_sess = {0};
    handshake_split(&g_our_i, &i_sess);
    handshake_split(&g_our_r, &r_sess);

    const uint8_t test_plain[] = "empty_payload_test";
    uint8_t nc_enc[256], our_enc[256];
    size_t nc_enc_len = 0;
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        memcpy(nc_enc, test_plain, sizeof(test_plain) - 1);
        noise_buffer_set_inout(b, nc_enc, sizeof(test_plain) - 1, sizeof(nc_enc));
        noise_cipherstate_encrypt(g_nc_i_c1, &b);
        nc_enc_len = b.size;
    }
    ssize_t our_enc_len = noise_encrypt(&i_sess, test_plain, sizeof(test_plain) - 1, our_enc);

    snprintf(label, sizeof(label), "empty split enc len: nc(%zu)==our(%zd)", nc_enc_len, our_enc_len);
    DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, label);
    if (nc_enc_len == (size_t)our_enc_len) {
        DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, "empty split enc content: nc==our");
    }

    nc_cleanup();
}

/* ================================================================
 * TEST 12: Error state recovery — MAC hatası sonrası yeni handshake
 * ================================================================ */
static void test_error_state_recovery(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                      const uint8_t r_priv[32], const uint8_t r_pub[32],
                                      const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_error_state_recovery...\n");

    /* noise-c ile bozuk mesaj testi */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
             (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t nc_msg0[512], nc_msg1[512];
    size_t nc_m0l, nc_m1l;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0l);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0l);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1l);
    if (nc_m1l > 0) nc_msg1[0] ^= 0xFF;
    int nc_rc = nc_read_msg(g_nc_i, nc_msg1, nc_m1l);
    DIFF_ASSERT(nc_rc != NOISE_ERROR_NONE, "recovery: nc rejects corrupted msg");
    nc_cleanup();

    /* Our code ile bozuk mesaj testi */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    uint8_t our_msg0[512], our_msg1[512];
    size_t our_m0l = sizeof(our_msg0), our_m1l = sizeof(our_msg1);
    uint8_t payload_buf[512];
    size_t pl_len;

    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0l);
    pl_len = sizeof(payload_buf);
    handshake_read(&g_our_r, our_msg0, our_m0l, payload_buf, sizeof(payload_buf), &pl_len);
    handshake_write(&g_our_r, NULL, 0, our_msg1, &our_m1l);
    if (our_m1l > 0) our_msg1[0] ^= 0xFF;
    pl_len = sizeof(payload_buf);
    nox_err_t our_rc = handshake_read(&g_our_i, our_msg1, our_m1l, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc != NOX_OK, "recovery: our rejects corrupted msg");

    /* Yeni handshake — başarıyla tamamlanmalı */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              (const uint8_t *)PROLOGUE_DEFAULT, PROLOGUE_DEFAULT_LEN);
    struct noise_session i_sess = {0}, r_sess = {0};

    uint8_t new_msg0[512], new_msg1[512], new_msg2[512];
    size_t new_m0l = sizeof(new_msg0), new_m1l = sizeof(new_msg1), new_m2l = sizeof(new_msg2);

    our_rc = handshake_write(&g_our_i, NULL, 0, new_msg0, &new_m0l);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new handshake msg0 write");
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, new_msg0, new_m0l, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new handshake msg0 read");

    our_rc = handshake_write(&g_our_r, NULL, 0, new_msg1, &new_m1l);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new handshake msg1 write");
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_i, new_msg1, new_m1l, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new handshake msg1 read");

    our_rc = handshake_write(&g_our_i, NULL, 0, new_msg2, &new_m2l);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new handshake msg2 write");
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, new_msg2, new_m2l, payload_buf, sizeof(payload_buf), &pl_len);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new handshake msg2 read");

    /* Split + transport test */
    our_rc = handshake_split(&g_our_i, &i_sess);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new split");
    our_rc = handshake_split(&g_our_r, &r_sess);
    DIFF_ASSERT(our_rc == NOX_OK, "recovery: new split (responder)");

    const uint8_t test_plain[] = "recovery_test";
    uint8_t enc[256], dec[256];
    ssize_t enc_len = noise_encrypt(&i_sess, test_plain, sizeof(test_plain) - 1, enc);
    DIFF_ASSERT(enc_len > 0, "recovery: transport encrypt");
    ssize_t dec_len = noise_decrypt(&r_sess, enc, (size_t)enc_len, dec);
    DIFF_ASSERT(dec_len == (ssize_t)(sizeof(test_plain) - 1), "recovery: transport decrypt len");
    if (dec_len == (ssize_t)(sizeof(test_plain) - 1)) {
        DIFF_ASSERT(memcmp(dec, test_plain, sizeof(test_plain) - 1) == 0, "recovery: transport decrypt content");
    }
}

/* ================================================================
 * TEST 13: Input variety — kapsamlı input çeşidi karşılaştırması
 * ================================================================ */
static void test_input_variety(const uint8_t i_priv[32], const uint8_t i_pub[32],
                               const uint8_t r_priv[32], const uint8_t r_pub[32],
                               const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_input_variety...\n");

    /* 1. Unicode/UTF-8 */
    static const uint8_t unicode[] = {
        'M', 'e', 'r', 'h', 'a', 'b', 'a',
        0xE2, 0x98, 0x83,
        0xF0, 0x9F, 0x98, 0x80,
        0xC3, 0xB6,
        0xE4, 0xB8, 0x96, 0xE7, 0x95, 0x8C,
        0
    };

    /* 2. Binary data */
    static const uint8_t binary[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x7F, 0x80, 0x81, 0xFE, 0xFF
    };

    /* 3. All-zero (32 byte) */
    static const uint8_t all_zero[32] = {0};

    /* 4. All-0xFF (256 byte) */
    uint8_t all_ff[256];
    memset(all_ff, 0xFF, sizeof(all_ff));

    /* 5. Karışık: printable + non-printable */
    static const uint8_t mixed[] = {
        'H', 'e', 'l', 'l', 'o', ' ', 0x00, 'W', 'o',
        'r', 'l', 'd', 0xFF, 0xFE, 0xFD, '\n', '\t',
        0x1B, '[', '3', '1', 'm',
        0xF0, 0x9F, 0x98, 0x81
    };

    /* 6. Tekrarlayan pattern */
    uint8_t pattern[512];
    for (size_t i = 0; i < sizeof(pattern); i++)
        pattern[i] = (i % 2 == 0) ? 'A' : 'B';

    /* 7. Max payload (4096) */
    uint8_t max_payload[4096];
    for (size_t i = 0; i < sizeof(max_payload); i++)
        max_payload[i] = (uint8_t)(i & 0xFF);

    /* 8-9. Tek byte */
    static const uint8_t single_zero = 0x00;
    static const uint8_t single_ff = 0xFF;

    /* 10. Basit ASCII */
    static const uint8_t simple_ascii[] = "Hello, World! 1234567890";

    struct { const uint8_t *data; size_t len; const char *name; } inputs[] = {
        {unicode, sizeof(unicode) - 1, "unicode"},
        {binary, sizeof(binary), "binary"},
        {all_zero, sizeof(all_zero), "all_zero_32"},
        {all_ff, sizeof(all_ff), "all_ff_256"},
        {mixed, sizeof(mixed), "mixed"},
        {pattern, sizeof(pattern), "pattern_512"},
        {max_payload, sizeof(max_payload), "max_4096"},
        {&single_zero, 1, "single_zero"},
        {&single_ff, 1, "single_ff"},
        {simple_ascii, sizeof(simple_ascii) - 1, "simple_ascii"},
    };
    size_t num_inputs = sizeof(inputs) / sizeof(inputs[0]);

    for (size_t t = 0; t < num_inputs; t++) {
        do_full_handshake(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                          &g_our_i_session, &g_our_r_session);
        do_transport_test(inputs[t].data, inputs[t].len, inputs[t].name);
        nc_cleanup();
    }
}

/* ================================================================
 * AŞAMA 2 — KAPSAMLI TESTLER (full brute-force)
 * ================================================================ */

/* ================================================================
 * run_one_test — tek bir parametre seti ile tam test
 * (msg0+msg1+msg2 + h/ck karşılaştırması + split + transport)
 * ================================================================ */
static void run_one_test(const uint8_t i_priv[32], const uint8_t i_pub[32],
                         const uint8_t r_priv[32], const uint8_t r_pub[32],
                         const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                         const uint8_t *prologue, size_t prologue_len,
                         const uint8_t *payload, size_t payload_len,
                         const char *label) {
    char errmsg[128];

    /* noise-c setup */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup failed", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    /* our setup */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              prologue, prologue_len);

    uint8_t nc_msg[512], our_msg[512];
    size_t nc_mlen, our_mlen;
    uint8_t payload_buf[512];
    size_t pl_len;
    nox_err_t our_rc;
    int nc_rc;

    /* MSG 0 */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg0 write", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg0 write", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    if (nc_rc == NOISE_ERROR_NONE && our_rc == NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: msg0 len %zu==%zu", label, nc_mlen, our_mlen);
        DIFF_ASSERT(nc_mlen == our_mlen, errmsg);
        if (nc_mlen == our_mlen) {
            snprintf(errmsg, sizeof(errmsg), "%s: msg0 content", label);
            DIFF_ASSERT(memcmp(nc_msg, our_msg, nc_mlen) == 0, errmsg);
        }
    }

    /* Read msg0 */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg0 read", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg0 read", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    /* MSG 1 */
    nc_rc = nc_write_msg(g_nc_r, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_r, NULL, 0, our_msg, &our_mlen);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg1 write", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg1 write", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    if (nc_rc == NOISE_ERROR_NONE && our_rc == NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: msg1 len %zu==%zu", label, nc_mlen, our_mlen);
        DIFF_ASSERT(nc_mlen == our_mlen, errmsg);
        if (nc_mlen == our_mlen) {
            snprintf(errmsg, sizeof(errmsg), "%s: msg1 content", label);
            DIFF_ASSERT(memcmp(nc_msg, our_msg, nc_mlen) == 0, errmsg);
        }
    }

    /* Read msg1 */
    nc_rc = nc_read_msg(g_nc_i, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_i, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg1 read", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg1 read", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    /* MSG 2 */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg2 write", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg2 write", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    if (nc_rc == NOISE_ERROR_NONE && our_rc == NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: msg2 len %zu==%zu", label, nc_mlen, our_mlen);
        DIFF_ASSERT(nc_mlen == our_mlen, errmsg);
        if (nc_mlen == our_mlen) {
            snprintf(errmsg, sizeof(errmsg), "%s: msg2 content", label);
            DIFF_ASSERT(memcmp(nc_msg, our_msg, nc_mlen) == 0, errmsg);
        }
    }

    /* Read msg2 */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg2 read", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg2 read", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    /* Karşılaştırma #6: Handshake hash (h) — split ÖNCESİ */
    {
        uint8_t nc_h_i[64], our_h_i[64];
        uint8_t nc_h_r[64], our_h_r[64];

        noise_handshakestate_get_handshake_hash(g_nc_i, nc_h_i, sizeof(nc_h_i));
        handshake_get_h(&g_our_i, our_h_i);

        noise_handshakestate_get_handshake_hash(g_nc_r, nc_h_r, sizeof(nc_h_r));
        handshake_get_h(&g_our_r, our_h_r);

        snprintf(errmsg, sizeof(errmsg), "%s: h_i == h_r (nc)", label);
        DIFF_ASSERT(memcmp(nc_h_i, nc_h_r, 64) == 0, errmsg);
        snprintf(errmsg, sizeof(errmsg), "%s: h_i == h_r (our)", label);
        DIFF_ASSERT(memcmp(our_h_i, our_h_r, 64) == 0, errmsg);

        snprintf(errmsg, sizeof(errmsg), "%s: h nc == our (i)", label);
        DIFF_ASSERT(memcmp(nc_h_i, our_h_i, 64) == 0, errmsg);
        snprintf(errmsg, sizeof(errmsg), "%s: h nc == our (r)", label);
        DIFF_ASSERT(memcmp(nc_h_r, our_h_r, 64) == 0, errmsg);
    }

    /* Karşılaştırma #7: Chaining key (ck) — split ÖNCESİ */
    {
        uint8_t our_ck_i[64], our_ck_r[64];
        handshake_get_ck(&g_our_i, our_ck_i);
        handshake_get_ck(&g_our_r, our_ck_r);

        snprintf(errmsg, sizeof(errmsg), "%s: ck_i == ck_r", label);
        DIFF_ASSERT(memcmp(our_ck_i, our_ck_r, 64) == 0, errmsg);

        uint8_t zero64[64] = {0};
        snprintf(errmsg, sizeof(errmsg), "%s: ck non-zero", label);
        DIFF_ASSERT(memcmp(our_ck_i, zero64, 64) != 0, errmsg);
    }

    /* Split */
    nc_rc = noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    snprintf(errmsg, sizeof(errmsg), "%s: nc i split", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);

    nc_rc = noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);
    snprintf(errmsg, sizeof(errmsg), "%s: nc r split", label);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, errmsg);

    struct noise_session i_sess = {0}, r_sess = {0};
    our_rc = handshake_split(&g_our_i, &i_sess);
    snprintf(errmsg, sizeof(errmsg), "%s: our i split", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    our_rc = handshake_split(&g_our_r, &r_sess);
    snprintf(errmsg, sizeof(errmsg), "%s: our r split", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    /* Transport: i→r */
    size_t ct_max = payload_len + 16 + 64;
    if (ct_max < 64) ct_max = 64;
    uint8_t *nc_enc = malloc(ct_max);
    uint8_t *our_enc = malloc(ct_max);
    uint8_t *our_dec = malloc(ct_max > 4096 ? ct_max : 4096);
    if (!nc_enc || !our_enc || !our_dec) {
        free(nc_enc); free(our_enc); free(our_dec);
        nc_cleanup();
        return;
    }
    size_t nc_enc_len = 0;
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        if (payload && payload_len > 0)
            memcpy(nc_enc, payload, payload_len);
        noise_buffer_set_inout(b, nc_enc, payload_len, ct_max);
        nc_rc = noise_cipherstate_encrypt(g_nc_i_c1, &b);
        nc_enc_len = b.size;
    }

    ssize_t our_enc_len = noise_encrypt(&i_sess, payload ? payload : (const uint8_t *)"", payload_len, our_enc);

    if (nc_rc == NOISE_ERROR_NONE) {
        snprintf(errmsg, sizeof(errmsg), "%s: transport enc len %zu==%zd", label, nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, errmsg);
        if (nc_enc_len == (size_t)our_enc_len) {
            snprintf(errmsg, sizeof(errmsg), "%s: transport ciphertext", label);
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, errmsg);
        }
    }

    /* Decrypt r side */
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        noise_buffer_set_input(b, nc_enc, nc_enc_len);
        nc_rc = noise_cipherstate_decrypt(g_nc_r_c2, &b);
    }

    ssize_t our_dec_len = noise_decrypt(&r_sess, our_enc, (size_t)our_enc_len, our_dec);

    if (nc_rc == NOISE_ERROR_NONE) {
        snprintf(errmsg, sizeof(errmsg), "%s: transport dec", label);
        DIFF_ASSERT(our_dec_len == (ssize_t)payload_len, errmsg);
        if (our_dec_len == (ssize_t)payload_len) {
            snprintf(errmsg, sizeof(errmsg), "%s: transport plaintext", label);
            DIFF_ASSERT(payload_len == 0 || memcmp(our_dec, payload, payload_len) == 0, errmsg);
        }
    }

    /* Transport: r→i (bidirectional) */
    {
        size_t ct_max_r = payload_len + 16 + 64;
        if (ct_max_r < 64) ct_max_r = 64;
        uint8_t *nc_enc_r = malloc(ct_max_r);
        uint8_t *our_enc_r = malloc(ct_max_r);
        uint8_t *our_dec_r = malloc(ct_max_r > 4096 ? ct_max_r : 4096);
        if (nc_enc_r && our_enc_r && our_dec_r) {
            size_t nc_enc_len_r = 0;
            {
                NoiseBuffer b;
                noise_buffer_init(b);
                if (payload && payload_len > 0)
                    memcpy(nc_enc_r, payload, payload_len);
                noise_buffer_set_inout(b, nc_enc_r, payload_len, ct_max_r);
                nc_rc = noise_cipherstate_encrypt(g_nc_r_c1, &b);
                nc_enc_len_r = b.size;
            }

            ssize_t our_enc_len_r = noise_encrypt(&r_sess, payload ? payload : (const uint8_t *)"", payload_len, our_enc_r);

            if (nc_rc == NOISE_ERROR_NONE) {
                snprintf(errmsg, sizeof(errmsg), "%s: r→i enc len %zu==%zd", label, nc_enc_len_r, our_enc_len_r);
                DIFF_ASSERT(nc_enc_len_r == (size_t)our_enc_len_r, errmsg);
                if (nc_enc_len_r == (size_t)our_enc_len_r) {
                    snprintf(errmsg, sizeof(errmsg), "%s: r→i ciphertext", label);
                    DIFF_ASSERT(memcmp(nc_enc_r, our_enc_r, nc_enc_len_r) == 0, errmsg);
                }
            }

            /* Decrypt i side */
            {
                NoiseBuffer b;
                noise_buffer_init(b);
                noise_buffer_set_input(b, nc_enc_r, nc_enc_len_r);
                nc_rc = noise_cipherstate_decrypt(g_nc_i_c2, &b);
            }

            ssize_t our_dec_len_r = noise_decrypt(&i_sess, our_enc_r, (size_t)our_enc_len_r, our_dec_r);

            if (nc_rc == NOISE_ERROR_NONE) {
                snprintf(errmsg, sizeof(errmsg), "%s: r→i dec", label);
                DIFF_ASSERT(our_dec_len_r == (ssize_t)payload_len, errmsg);
                if (our_dec_len_r == (ssize_t)payload_len) {
                    snprintf(errmsg, sizeof(errmsg), "%s: r→i plaintext", label);
                    DIFF_ASSERT(payload_len == 0 || memcmp(our_dec_r, payload, payload_len) == 0, errmsg);
                }
            }
        }
        free(nc_enc_r);
        free(our_enc_r);
        free(our_dec_r);
    }

    free(nc_enc);
    free(our_enc);
    free(our_dec);
    nc_cleanup();
}

/* ================================================================
 * run_param_test — noise-c API boyut doğrulaması
 * ================================================================ */
static void run_param_test(const char *label) {
    char errmsg[128];

    NoiseCipherState *cs;
    noise_cipherstate_new_by_name(&cs, "ChaChaPoly");

    snprintf(errmsg, sizeof(errmsg), "%s: cipher key_len==32", label);
    DIFF_ASSERT(noise_cipherstate_get_key_length(cs) == 32, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: cipher mac_len==16", label);
    DIFF_ASSERT(noise_cipherstate_get_mac_length(cs) == 16, errmsg);

    noise_cipherstate_free(cs);

    NoiseHashState *hs;
    noise_hashstate_new_by_name(&hs, "BLAKE2b");

    snprintf(errmsg, sizeof(errmsg), "%s: hash hash_len==64", label);
    DIFF_ASSERT(noise_hashstate_get_hash_length(hs) == 64, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: hash block_len==128", label);
    DIFF_ASSERT(noise_hashstate_get_block_length(hs) == 128, errmsg);

    noise_hashstate_free(hs);

    NoiseHandshakeState *nc;
    noise_handshakestate_new_by_name(&nc, "Noise_XX_25519_ChaChaPoly_BLAKE2b", NOISE_ROLE_INITIATOR);
    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(nc);

    snprintf(errmsg, sizeof(errmsg), "%s: dh priv_len==32", label);
    DIFF_ASSERT(noise_dhstate_get_private_key_length(dh) == 32, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: dh pub_len==32", label);
    DIFF_ASSERT(noise_dhstate_get_public_key_length(dh) == 32, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: dh shared_len==32", label);
    DIFF_ASSERT(noise_dhstate_get_shared_key_length(dh) == 32, errmsg);

    noise_handshakestate_free(nc);
}

/* ================================================================
 * run_one_error_case — tek bir hata testini çalıştır
 * ================================================================ */
static void run_one_error_case(
    const uint8_t i_priv[32], const uint8_t i_pub[32],
    const uint8_t r_priv[32], const uint8_t r_pub[32],
    const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
    const uint8_t *prologue, size_t prologue_len,
    int error_msg,
    int error_type,
    const char *label) {
    char errmsg[128];

    /* noise-c tarafı */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    uint8_t msg0[512], msg1[512], msg2[512];
    size_t len0, len1, len2;
    uint8_t tmp[512];
    NoiseBuffer mb, pb;

    /* MSG 0 write */
    noise_buffer_init(mb); noise_buffer_set_output(mb, msg0, 512);
    noise_buffer_init(pb); uint8_t z = 0; noise_buffer_set_input(pb, &z, 0);
    noise_handshakestate_write_message(g_nc_i, &mb, &pb);
    len0 = mb.size;

    /* MSG 0 read (responder) */
    noise_buffer_init(mb); noise_buffer_set_input(mb, msg0, len0);
    noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
    noise_handshakestate_read_message(g_nc_r, &mb, &pb);

    /* MSG 1 write */
    noise_buffer_init(mb); noise_buffer_set_output(mb, msg1, 512);
    noise_buffer_init(pb); noise_buffer_set_input(pb, &z, 0);
    noise_handshakestate_write_message(g_nc_r, &mb, &pb);
    len1 = mb.size;

    /* MSG 1 read (initiator) */
    noise_buffer_init(mb); noise_buffer_set_input(mb, msg1, len1);
    noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
    noise_handshakestate_read_message(g_nc_i, &mb, &pb);

    /* MSG 2 write */
    noise_buffer_init(mb); noise_buffer_set_output(mb, msg2, 512);
    noise_buffer_init(pb); noise_buffer_set_input(pb, &z, 0);
    noise_handshakestate_write_message(g_nc_i, &mb, &pb);
    len2 = mb.size;

    /* noise-c: hatalı msg'yi okumayı dene */
    int nc_bad = 0;
    if (error_msg == 0) {
        uint8_t bad[512]; memcpy(bad, msg0, len0);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, len0); }
        else if (error_type == 2) { len0 = 4; }
        noise_buffer_init(mb); noise_buffer_set_input(mb, bad, len0);
        noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
        nc_bad = noise_handshakestate_read_message(g_nc_r, &mb, &pb);
    } else if (error_msg == 1) {
        uint8_t bad[512]; memcpy(bad, msg1, len1);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, len1); }
        else if (error_type == 2) { len1 = 4; }
        noise_buffer_init(mb); noise_buffer_set_input(mb, bad, len1);
        noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
        nc_bad = noise_handshakestate_read_message(g_nc_i, &mb, &pb);
    } else {
        uint8_t bad[512]; memcpy(bad, msg2, len2);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, len2); }
        else if (error_type == 2) { len2 = 4; }
        noise_buffer_init(mb); noise_buffer_set_input(mb, bad, len2);
        noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
        nc_bad = noise_handshakestate_read_message(g_nc_r, &mb, &pb);
    }

    snprintf(errmsg, sizeof(errmsg), "%s: nc reject", label);
    DIFF_ASSERT(nc_bad != NOISE_ERROR_NONE, errmsg);

    nc_cleanup();

    /* our tarafı */
    struct noise_handshake our_i, our_r;
    handshake_init_with_prologue(&our_i, true, i_priv, i_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    uint8_t our_m0[512], our_m1[512], our_m2[512];
    size_t ol0, ol1, ol2;
    uint8_t obuf[512];
    size_t oplen;

    /* MSG 0 */
    ol0 = sizeof(our_m0);
    handshake_write(&our_i, NULL, 0, our_m0, &ol0);
    oplen = sizeof(obuf);
    handshake_read(&our_r, our_m0, ol0, obuf, sizeof(obuf), &oplen);

    /* MSG 1 */
    ol1 = sizeof(our_m1);
    handshake_write(&our_r, NULL, 0, our_m1, &ol1);
    oplen = sizeof(obuf);
    handshake_read(&our_i, our_m1, ol1, obuf, sizeof(obuf), &oplen);

    /* MSG 2 */
    ol2 = sizeof(our_m2);
    handshake_write(&our_i, NULL, 0, our_m2, &ol2);

    /* our: hatalı msg'yi okumayı dene */
    nox_err_t our_bad = NOX_OK;
    if (error_msg == 0) {
        uint8_t bad[512]; memcpy(bad, our_m0, ol0);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, ol0); }
        else if (error_type == 2) { ol0 = 4; }
        oplen = sizeof(obuf);
        our_bad = handshake_read(&our_r, bad, ol0, obuf, sizeof(obuf), &oplen);
    } else if (error_msg == 1) {
        uint8_t bad[512]; memcpy(bad, our_m1, ol1);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, ol1); }
        else if (error_type == 2) { ol1 = 4; }
        oplen = sizeof(obuf);
        our_bad = handshake_read(&our_i, bad, ol1, obuf, sizeof(obuf), &oplen);
    } else {
        uint8_t bad[512]; memcpy(bad, our_m2, ol2);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, ol2); }
        else if (error_type == 2) { ol2 = 4; }
        oplen = sizeof(obuf);
        our_bad = handshake_read(&our_r, bad, ol2, obuf, sizeof(obuf), &oplen);
    }

    snprintf(errmsg, sizeof(errmsg), "%s: our reject", label);
    DIFF_ASSERT(our_bad != NOX_OK, errmsg);
}

/* ================================================================
 * run_wrong_static_key_test — yanlış static key davranışı
 * ================================================================ */
static void run_wrong_static_key_test(
    const uint8_t i_priv[32], const uint8_t i_pub[32],
    const uint8_t r_priv[32], const uint8_t r_pub[32],
    const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
    const uint8_t *prologue, size_t prologue_len,
    const char *label) {
    char errmsg[128];
    uint8_t wrong_priv[32], wrong_pub[32];
    randombytes_buf(wrong_priv, 32);
    crypto_scalarmult_base(wrong_pub, wrong_priv);

    /* noise-c tarafı */
    if (nc_setup(wrong_priv, wrong_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    uint8_t msg[512]; size_t mlen;
    NoiseBuffer mb, pb;

    /* MSG 0 */
    noise_buffer_init(mb); noise_buffer_set_output(mb, msg, 512);
    noise_buffer_init(pb); uint8_t z = 0; noise_buffer_set_input(pb, &z, 0);
    noise_handshakestate_write_message(g_nc_i, &mb, &pb);
    mlen = mb.size;
    noise_buffer_init(mb); noise_buffer_set_input(mb, msg, mlen);
    noise_buffer_init(pb); uint8_t tmp[512]; noise_buffer_set_output(pb, tmp, 512);
    noise_handshakestate_read_message(g_nc_r, &mb, &pb);

    /* MSG 1 */
    noise_buffer_init(mb); noise_buffer_set_output(mb, msg, 512);
    noise_buffer_init(pb); noise_buffer_set_input(pb, &z, 0);
    noise_handshakestate_write_message(g_nc_r, &mb, &pb);
    mlen = mb.size;
    noise_buffer_init(mb); noise_buffer_set_input(mb, msg, mlen);
    noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
    noise_handshakestate_read_message(g_nc_i, &mb, &pb);

    /* MSG 2 */
    noise_buffer_init(mb); noise_buffer_set_output(mb, msg, 512);
    noise_buffer_init(pb); noise_buffer_set_input(pb, &z, 0);
    noise_handshakestate_write_message(g_nc_i, &mb, &pb);
    mlen = mb.size;
    noise_buffer_init(mb); noise_buffer_set_input(mb, msg, mlen);
    noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
    int nc_rc = noise_handshakestate_read_message(g_nc_r, &mb, &pb);
    bool nc_ok = (nc_rc == NOISE_ERROR_NONE);

    /* noise-c split */
    NoiseCipherState *c1, *c2;
    if (nc_ok) {
        noise_handshakestate_split(g_nc_i, &c1, &c2);
        noise_cipherstate_free(c1); noise_cipherstate_free(c2);
        noise_handshakestate_split(g_nc_r, &c1, &c2);
        noise_cipherstate_free(c1); noise_cipherstate_free(c2);
    }
    nc_cleanup();

    /* our tarafı */
    struct noise_handshake our_i, our_r;
    handshake_init_with_prologue(&our_i, true, wrong_priv, wrong_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    uint8_t our_m[512]; size_t ol;
    uint8_t obuf[512]; size_t oplen;

    ol = sizeof(our_m);
    handshake_write(&our_i, NULL, 0, our_m, &ol);
    oplen = sizeof(obuf);
    handshake_read(&our_r, our_m, ol, obuf, sizeof(obuf), &oplen);

    ol = sizeof(our_m);
    handshake_write(&our_r, NULL, 0, our_m, &ol);
    oplen = sizeof(obuf);
    handshake_read(&our_i, our_m, ol, obuf, sizeof(obuf), &oplen);

    ol = sizeof(our_m);
    handshake_write(&our_i, NULL, 0, our_m, &ol);

    oplen = sizeof(obuf);
    nox_err_t our_rc = handshake_read(&our_r, our_m, ol, obuf, sizeof(obuf), &oplen);
    bool our_ok = (our_rc == NOX_OK);

    snprintf(errmsg, sizeof(errmsg), "%s: nc==our outcome (nc=%d our=%d)",
             label, nc_ok, our_ok);
    DIFF_ASSERT(nc_ok == our_ok, errmsg);
}

/* ================================================================
 * run_error_test_full — kapsamlı error behavior (#24-35)
 * ================================================================ */
static void run_error_test_full(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                const uint8_t r_priv[32], const uint8_t r_pub[32],
                                const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                                const uint8_t *prologue, size_t prologue_len,
                                const char *label) {
    char sub[128];

    /* #24-26: MSG 0/1/2 corrupt first byte */
    for (int m = 0; m < 3; m++) {
        snprintf(sub, sizeof(sub), "%s_corrupt_m%d", label, m);
        run_one_error_case(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                           prologue, prologue_len, m, 0, sub);
    }

    /* #27-28, #30: MSG 0/1/2 all zeros */
    for (int m = 0; m < 3; m++) {
        snprintf(sub, sizeof(sub), "%s_zeros_m%d", label, m);
        run_one_error_case(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                           prologue, prologue_len, m, 1, sub);
    }

    /* #33-35: MSG 0/1/2 short length (4 byte) */
    for (int m = 0; m < 3; m++) {
        snprintf(sub, sizeof(sub), "%s_short_m%d", label, m);
        run_one_error_case(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                           prologue, prologue_len, m, 2, sub);
    }

    /* #31-32: Yanlış static key */
    snprintf(sub, sizeof(sub), "%s_wrong_key", label);
    run_wrong_static_key_test(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                              prologue, prologue_len, sub);
}

/* ================================================================
 * run_multi_msg_test — split sonrası 5 mesaj i→r, her adımda ciphertext karşılaştırması
 *
 * Nonce counter'ın her iki implementasyonda da aynı ilerlediğini doğrula.
 * ================================================================ */
static void run_multi_msg_test(const uint8_t i_priv[32], const uint8_t i_pub[32],
                               const uint8_t r_priv[32], const uint8_t r_pub[32],
                               const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                               const uint8_t *prologue, size_t prologue_len,
                               const char *label) {
    char errmsg[128];

    /* noise-c handshake */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    uint8_t nc_msg0[512], nc_msg1[512], nc_msg2[512];
    size_t nc_m0l, nc_m1l, nc_m2l;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0l);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0l);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1l);
    nc_read_msg(g_nc_i, nc_msg1, nc_m1l);
    nc_write_msg(g_nc_i, nc_msg2, &nc_m2l);
    nc_read_msg(g_nc_r, nc_msg2, nc_m2l);

    noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);

    /* Our handshake */
    struct noise_handshake our_i, our_r;
    handshake_init_with_prologue(&our_i, true, i_priv, i_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    uint8_t our_m0[512], our_m1[512], our_m2[512];
    size_t ol0 = sizeof(our_m0), ol1 = sizeof(our_m1), ol2 = sizeof(our_m2);
    uint8_t obuf[512]; size_t oplen;

    handshake_write(&our_i, NULL, 0, our_m0, &ol0);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m0, ol0, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_r, NULL, 0, our_m1, &ol1);
    oplen = sizeof(obuf); handshake_read(&our_i, our_m1, ol1, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_i, NULL, 0, our_m2, &ol2);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m2, ol2, obuf, sizeof(obuf), &oplen);

    struct noise_session i_sess = {0};
    handshake_split(&our_i, &i_sess);

    /* 5 mesaj gönder, her birini karşılaştır */
    for (int idx = 0; idx < 5; idx++) {
        uint8_t plain[64];
        memset(plain, (uint8_t)('A' + idx), sizeof(plain));

        /* noise-c encrypt */
        uint8_t nc_enc[256];
        size_t nc_enc_len = 0;
        {
            NoiseBuffer b;
            noise_buffer_init(b);
            memcpy(nc_enc, plain, sizeof(plain));
            noise_buffer_set_inout(b, nc_enc, sizeof(plain), sizeof(nc_enc));
            noise_cipherstate_encrypt(g_nc_i_c1, &b);
            nc_enc_len = b.size;
        }

        /* Our encrypt */
        uint8_t our_enc[256];
        ssize_t our_enc_len = noise_encrypt(&i_sess, plain, sizeof(plain), our_enc);

        snprintf(errmsg, sizeof(errmsg), "%s msg%d: enc len %zu==%zd", label, idx, nc_enc_len, our_enc_len);
        DIFF_ASSERT(nc_enc_len == (size_t)our_enc_len, errmsg);
        if (nc_enc_len == (size_t)our_enc_len) {
            snprintf(errmsg, sizeof(errmsg), "%s msg%d: ciphertext", label, idx);
            DIFF_ASSERT(memcmp(nc_enc, our_enc, nc_enc_len) == 0, errmsg);
        }
    }

    nc_cleanup();
}

/* ================================================================
 * run_nonce_counter_test — aynı plaintext 3 kez şifrele, farklı ciphertext
 * ================================================================ */
static void run_nonce_counter_test(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                   const uint8_t r_priv[32], const uint8_t r_pub[32],
                                   const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                                   const uint8_t *prologue, size_t prologue_len,
                                   const char *label) {
    char errmsg[128];

    /* noise-c handshake */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    uint8_t nc_msg0[512], nc_msg1[512], nc_msg2[512];
    size_t nc_m0l, nc_m1l, nc_m2l;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0l);
    nc_read_msg(g_nc_r, nc_msg0, nc_m0l);
    nc_write_msg(g_nc_r, nc_msg1, &nc_m1l);
    nc_read_msg(g_nc_i, nc_msg1, nc_m1l);
    nc_write_msg(g_nc_i, nc_msg2, &nc_m2l);
    nc_read_msg(g_nc_r, nc_msg2, nc_m2l);

    noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);

    /* Our handshake */
    struct noise_handshake our_i, our_r;
    handshake_init_with_prologue(&our_i, true, i_priv, i_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    uint8_t our_m0[512], our_m1[512], our_m2[512];
    size_t ol0 = sizeof(our_m0), ol1 = sizeof(our_m1), ol2 = sizeof(our_m2);
    uint8_t obuf[512]; size_t oplen;

    handshake_write(&our_i, NULL, 0, our_m0, &ol0);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m0, ol0, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_r, NULL, 0, our_m1, &ol1);
    oplen = sizeof(obuf); handshake_read(&our_i, our_m1, ol1, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_i, NULL, 0, our_m2, &ol2);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m2, ol2, obuf, sizeof(obuf), &oplen);

    struct noise_session i_sess = {0};
    handshake_split(&our_i, &i_sess);

    /* Aynı plaintext'i 3 kez şifrele */
    const uint8_t plain[] = "nonce_test";
    size_t plain_len = sizeof(plain) - 1;
    uint8_t enc1[256], enc2[256], enc3[256];
    ssize_t len1, len2, len3;

    len1 = noise_encrypt(&i_sess, plain, plain_len, enc1);
    len2 = noise_encrypt(&i_sess, plain, plain_len, enc2);
    len3 = noise_encrypt(&i_sess, plain, plain_len, enc3);

    snprintf(errmsg, sizeof(errmsg), "%s: enc1 success", label);
    DIFF_ASSERT(len1 > 0, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: enc2 success", label);
    DIFF_ASSERT(len2 > 0, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: enc3 success", label);
    DIFF_ASSERT(len3 > 0, errmsg);

    if (len1 > 0 && len2 > 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: enc1!=enc2", label);
        DIFF_ASSERT(memcmp(enc1, enc2, (size_t)len1) != 0, errmsg);
    }
    if (len2 > 0 && len3 > 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: enc2!=enc3", label);
        DIFF_ASSERT(memcmp(enc2, enc3, (size_t)len2) != 0, errmsg);
    }
    if (len1 > 0 && len3 > 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: enc1!=enc3", label);
        DIFF_ASSERT(memcmp(enc1, enc3, (size_t)len1) != 0, errmsg);
    }

    nc_cleanup();
}

/* ================================================================
 * run_error_recovery_test — bozuk msg → hata → yeni handshake → başarılı transport
 * ================================================================ */
static void run_error_recovery_test(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                    const uint8_t r_priv[32], const uint8_t r_pub[32],
                                    const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                                    const uint8_t *prologue, size_t prologue_len,
                                    const char *label) {
    char errmsg[128];

    /* noise-c tarafı: bozuk msg testi */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    uint8_t nc_m0[512], nc_m1[512];
    size_t nc_l0, nc_l1;
    nc_write_msg(g_nc_i, nc_m0, &nc_l0);
    nc_read_msg(g_nc_r, nc_m0, nc_l0);
    nc_write_msg(g_nc_r, nc_m1, &nc_l1);
    if (nc_l1 > 0) nc_m1[0] ^= 0xFF;
    int nc_rc = nc_read_msg(g_nc_i, nc_m1, nc_l1);
    snprintf(errmsg, sizeof(errmsg), "%s: nc rejects bad msg", label);
    DIFF_ASSERT(nc_rc != NOISE_ERROR_NONE, errmsg);
    nc_cleanup();

    /* Our tarafı: bozuk msg testi */
    struct noise_handshake our_i, our_r;
    handshake_init_with_prologue(&our_i, true, i_priv, i_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    uint8_t our_m0[512], our_m1[512];
    size_t ol0 = sizeof(our_m0), ol1 = sizeof(our_m1);
    uint8_t obuf[512]; size_t oplen;

    handshake_write(&our_i, NULL, 0, our_m0, &ol0);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m0, ol0, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_r, NULL, 0, our_m1, &ol1);
    if (ol1 > 0) our_m1[0] ^= 0xFF;
    oplen = sizeof(obuf);
    nox_err_t our_rc = handshake_read(&our_i, our_m1, ol1, obuf, sizeof(obuf), &oplen);
    snprintf(errmsg, sizeof(errmsg), "%s: our rejects bad msg", label);
    DIFF_ASSERT(our_rc != NOX_OK, errmsg);

    /* Yeni handshake — başarılı olmalı */
    handshake_init_with_prologue(&our_i, true, i_priv, i_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    struct noise_session i_sess = {0}, r_sess = {0};
    uint8_t n_m0[512], n_m1[512], n_m2[512];
    size_t n_l0 = sizeof(n_m0), n_l1 = sizeof(n_m1), n_l2 = sizeof(n_m2);

    our_rc = handshake_write(&our_i, NULL, 0, n_m0, &n_l0);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery msg0 write", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);
    oplen = sizeof(obuf); our_rc = handshake_read(&our_r, n_m0, n_l0, obuf, sizeof(obuf), &oplen);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery msg0 read", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    our_rc = handshake_write(&our_r, NULL, 0, n_m1, &n_l1);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery msg1 write", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);
    oplen = sizeof(obuf); our_rc = handshake_read(&our_i, n_m1, n_l1, obuf, sizeof(obuf), &oplen);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery msg1 read", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    our_rc = handshake_write(&our_i, NULL, 0, n_m2, &n_l2);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery msg2 write", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);
    oplen = sizeof(obuf); our_rc = handshake_read(&our_r, n_m2, n_l2, obuf, sizeof(obuf), &oplen);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery msg2 read", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    /* Split + transport */
    our_rc = handshake_split(&our_i, &i_sess);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery split i", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);
    our_rc = handshake_split(&our_r, &r_sess);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery split r", label);
    DIFF_ASSERT(our_rc == NOX_OK, errmsg);

    const uint8_t test_plain[] = "recovery_test";
    uint8_t enc[256], dec[256];
    ssize_t enc_len = noise_encrypt(&i_sess, test_plain, sizeof(test_plain) - 1, enc);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery encrypt", label);
    DIFF_ASSERT(enc_len > 0, errmsg);
    ssize_t dec_len = noise_decrypt(&r_sess, enc, (size_t)enc_len, dec);
    snprintf(errmsg, sizeof(errmsg), "%s: recovery decrypt len", label);
    DIFF_ASSERT(dec_len == (ssize_t)(sizeof(test_plain) - 1), errmsg);
    if (dec_len == (ssize_t)(sizeof(test_plain) - 1)) {
        snprintf(errmsg, sizeof(errmsg), "%s: recovery decrypt content", label);
        DIFF_ASSERT(memcmp(dec, test_plain, sizeof(test_plain) - 1) == 0, errmsg);
    }
}

/* ================================================================
 * run_split_cross_decrypt_test — noise-c encrypt → our decrypt
 *
 * Split sonrası noise-c ile şifrelenen mesaj bizim decrypt ile çözülebilmeli.
 * ================================================================ */
static void run_split_cross_decrypt_test(const uint8_t i_priv[32], const uint8_t i_pub[32],
                                         const uint8_t r_priv[32], const uint8_t r_pub[32],
                                         const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                                         const uint8_t *prologue, size_t prologue_len,
                                         const uint8_t *payload, size_t payload_len,
                                         const char *label) {
    char errmsg[128];

    /* noise-c handshake */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        DIFF_ASSERT(0, errmsg);
        return;
    }

    uint8_t nc_m0[512], nc_m1[512], nc_m2[512];
    size_t nc_l0, nc_l1, nc_l2;
    nc_write_msg(g_nc_i, nc_m0, &nc_l0);
    nc_read_msg(g_nc_r, nc_m0, nc_l0);
    nc_write_msg(g_nc_r, nc_m1, &nc_l1);
    nc_read_msg(g_nc_i, nc_m1, nc_l1);
    nc_write_msg(g_nc_i, nc_m2, &nc_l2);
    nc_read_msg(g_nc_r, nc_m2, nc_l2);

    noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);

    /* Our handshake */
    struct noise_handshake our_i, our_r;
    handshake_init_with_prologue(&our_i, true, i_priv, i_pub, prologue, prologue_len);
    handshake_init_with_prologue(&our_r, false, r_priv, r_pub, prologue, prologue_len);
    handshake_inject_ephemeral(&our_i, e_priv_i);
    handshake_inject_ephemeral(&our_r, e_priv_r);

    uint8_t our_m0[512], our_m1[512], our_m2[512];
    size_t ol0 = sizeof(our_m0), ol1 = sizeof(our_m1), ol2 = sizeof(our_m2);
    uint8_t obuf[512]; size_t oplen;

    handshake_write(&our_i, NULL, 0, our_m0, &ol0);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m0, ol0, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_r, NULL, 0, our_m1, &ol1);
    oplen = sizeof(obuf); handshake_read(&our_i, our_m1, ol1, obuf, sizeof(obuf), &oplen);
    handshake_write(&our_i, NULL, 0, our_m2, &ol2);
    oplen = sizeof(obuf); handshake_read(&our_r, our_m2, ol2, obuf, sizeof(obuf), &oplen);

    struct noise_session r_sess = {0};
    handshake_split(&our_r, &r_sess);

    /* noise-c encrypt → our decrypt */
    size_t ct_max = payload_len + 16 + 64;
    if (ct_max < 64) ct_max = 64;
    uint8_t *nc_enc = malloc(ct_max);
    uint8_t *our_dec = malloc(ct_max > 4096 ? ct_max : 4096);
    if (!nc_enc || !our_dec) {
        free(nc_enc); free(our_dec);
        nc_cleanup();
        return;
    }

    size_t nc_enc_len = 0;
    {
        NoiseBuffer b;
        noise_buffer_init(b);
        if (payload && payload_len > 0)
            memcpy(nc_enc, payload, payload_len);
        noise_buffer_set_inout(b, nc_enc, payload_len, ct_max);
        noise_cipherstate_encrypt(g_nc_i_c1, &b);
        nc_enc_len = b.size;
    }

    ssize_t our_dec_len = noise_decrypt(&r_sess, nc_enc, nc_enc_len, our_dec);

    snprintf(errmsg, sizeof(errmsg), "%s: cross-decrypt len %zd==%zu", label, our_dec_len, payload_len);
    DIFF_ASSERT(our_dec_len == (ssize_t)payload_len, errmsg);
    if (our_dec_len == (ssize_t)payload_len && payload_len > 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: cross-decrypt content", label);
        DIFF_ASSERT(memcmp(our_dec, payload, payload_len) == 0, errmsg);
    }

    free(nc_enc);
    free(our_dec);
    nc_cleanup();
}

/* ================================================================
 * Payload doldurma fonksiyonları
 * ================================================================ */
static void fill_zero(uint8_t *buf, size_t len) { memset(buf, 0x00, len); }
static void fill_ff(uint8_t *buf, size_t len) { memset(buf, 0xff, len); }
static void fill_ascii(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = 'A' + (uint8_t)(i % 26);
}
typedef void (*fill_fn)(uint8_t *buf, size_t len);
static fill_fn fill_fns[] = { NULL, fill_zero, fill_ff, fill_ascii };

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    /* ═══════════════════════════════════════════════════════════════
     * AŞAMA 1: Hedefli testler (deterministic keys, 13 test)
     * ═══════════════════════════════════════════════════════════════ */
    fprintf(stderr, "\n══════ AŞAMA 1: Hedefli testler ══════\n");

    static const uint8_t i_priv[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
    };
    static const uint8_t r_priv[32] = {
        0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
        0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,
        0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
        0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,0x60
    };
    static const uint8_t e_priv_i[32] = {
        0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,
        0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,
        0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,
        0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0
    };
    static const uint8_t e_priv_r[32] = {
        0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,
        0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,0xE0,
        0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,
        0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0
    };

    uint8_t i_pub[32], r_pub[32];
    crypto_scalarmult_base(i_pub, i_priv);
    crypto_scalarmult_base(r_pub, r_priv);

    test_corrupted_msg(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_various_ephemerals(i_priv, i_pub, r_priv, r_pub);
    test_happy_path(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_cross_verify(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_transport_multi_msg(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_transport_payload_sizes(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_transport_bidirectional(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_split_key_verification(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_handshake_hash_match(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_nonce_counter(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_empty_payload_handshake(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_error_state_recovery(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    test_input_variety(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);

    fprintf(stderr, "\n[diff] Aşama 1 sonucu: %d pass, %d fail\n", g_pass, g_fail);

    /* ═══════════════════════════════════════════════════════════════
     * AŞAMA 2: Kapsamlı brute-force testler
     * 105 key × 12 prologue × 4 pattern × 10 payload
     * ═══════════════════════════════════════════════════════════════ */
    fprintf(stderr, "\n══════ AŞAMA 2: Kapsamlı testler (105 key × 12 prologue × 4 pattern × 10 payload) ══════\n");

    /* #9-14: Parametre boyut karşılaştırması */
    run_param_test("params");

    /* Prologue'lar — edge cases dahil */
    static const char pl_empty[] = "";
    static const char pl_1[] = "X";
    static const char pl_9[] = "John Galt";
    static const char pl_100[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static const char pl_unicode[] = "Mustafa Kemal Atatürk";
    static const char pl_null[] = "\x00";
    static const char pl_1max[] =
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678";
    static const char pl_emoji[] = "test \xF0\x9F\x9A\x80\xF0\x9F\x94\x92";
    static const char pl_rtl[] = "test \xD9\x85\xD8\xB1\xD8\xAD\xD8\xA8\xD8\xA7";
    static const char pl_newlines[] = "line1\nline2\r\nline3\ttab";
    static const char pl_binary[] = "\x00\x01\x02\x03\xff\xfe\xfd";

    struct { const char *data; size_t len; const char *name; } prologues[] = {
        {pl_empty, 0, "empty"},
        {pl_1, 1, "1byte"},
        {pl_9, 9, "9byte"},
        {pl_100, 100, "100byte"},
        {pl_unicode, 21, "unicode"},
        {pl_null, 1, "null_byte"},
        {pl_1max, 509, "509byte"},
        {pl_emoji, 9, "emoji"},
        {pl_rtl, 10, "rtl_arabic"},
        {pl_newlines, 19, "newlines"},
        {pl_binary, 7, "binary"},
        {NULL, 0, "null_ptr"},
    };

    /* Payload uzunlukları */
    size_t payload_lens[] = {0, 1, 4, 16, 32, 100, 255, 511, 4096, 8192};

    int n_patterns = 4;

    for (int ki = 0; ki < 105; ki++) {
        uint8_t ki_i_priv[32], ki_r_priv[32];
        uint8_t ki_i_pub[32], ki_r_pub[32];
        uint8_t ki_e_priv_i[32], ki_e_priv_r[32];

        if (ki < 100) {
            randombytes_buf(ki_i_priv, 32);
            randombytes_buf(ki_r_priv, 32);
            randombytes_buf(ki_e_priv_i, 32);
            randombytes_buf(ki_e_priv_r, 32);
            crypto_scalarmult_base(ki_i_pub, ki_i_priv);
            crypto_scalarmult_base(ki_r_pub, ki_r_priv);
        } else {
            static const uint8_t ones[32] = {
                1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
                1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
            };
            static const uint8_t alt1[32] = {
                0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,
                0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,
                0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,
                0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55
            };
            static const uint8_t alt2[32] = {
                0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,
                0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,
                0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa,
                0x55,0xaa,0x55,0xaa,0x55,0xaa,0x55,0xaa
            };
            static const uint8_t seq[32] = {
                1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
            };
            static const uint8_t rev[32] = {
                31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,
                15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
            };

            switch (ki - 100) {
            case 0:
                memcpy(ki_i_priv, alt1, 32); memcpy(ki_r_priv, alt2, 32);
                memcpy(ki_e_priv_i, alt1, 32); memcpy(ki_e_priv_r, alt2, 32);
                break;
            case 1:
                memcpy(ki_i_priv, seq, 32); memcpy(ki_r_priv, rev, 32);
                memcpy(ki_e_priv_i, seq, 32); memcpy(ki_e_priv_r, rev, 32);
                break;
            case 2:
                memcpy(ki_i_priv, ones, 32); memcpy(ki_r_priv, alt1, 32);
                memcpy(ki_e_priv_i, ones, 32); memcpy(ki_e_priv_r, alt1, 32);
                break;
            case 3:
                memset(ki_i_priv, 0, 32); ki_i_priv[0] = 9;
                memset(ki_r_priv, 0, 32); ki_r_priv[31] = 1;
                memset(ki_e_priv_i, 0, 32); ki_e_priv_i[16] = 7;
                memset(ki_e_priv_r, 0, 32); ki_e_priv_r[16] = 3;
                break;
            case 4:
                for (int j = 0; j < 32; j++) {
                    ki_i_priv[j] = (uint8_t)(j | 1);
                    ki_r_priv[j] = (uint8_t)(j | 0x80);
                    ki_e_priv_i[j] = (uint8_t)((j * 7 + 3) & 0xff);
                    ki_e_priv_r[j] = (uint8_t)((j * 13 + 5) & 0xff);
                }
                break;
            }
            crypto_scalarmult_base(ki_i_pub, ki_i_priv);
            crypto_scalarmult_base(ki_r_pub, ki_r_priv);
        }

        int n_pro = (ki < 100) ? 12 : 3;
        for (int pi = 0; pi < n_pro; pi++) {
            for (int pati = 0; pati < n_patterns; pati++) {
                for (int li = 0; li < 10; li++) {
                    size_t plen = payload_lens[li];
                    uint8_t *payload = NULL;
                    if (plen > 0) {
                        payload = malloc(plen);
                        if (!payload) continue;
                        if (pati == 0) {
                            randombytes_buf(payload, plen);
                        } else {
                            fill_fns[pati](payload, plen);
                        }
                    }

                    char label[128];
                    snprintf(label, sizeof(label), "k%d_p%d_pat%d_l%zu",
                             ki, pi, pati, plen);

                    run_one_test(ki_i_priv, ki_i_pub, ki_r_priv, ki_r_pub,
                                 ki_e_priv_i, ki_e_priv_r,
                                 (const uint8_t *)prologues[pi].data,
                                 prologues[pi].len,
                                 payload, plen, label);

                    free(payload);
                }
            }
        }

        /* Kapsamlı error behavior test — her key için 3 prologue ile */
        for (int epi = 0; epi < 3 && epi < n_pro; epi++) {
            char elabel[128];
            snprintf(elabel, sizeof(elabel), "k%d_err%d", ki, epi);
            run_error_test_full(ki_i_priv, ki_i_pub, ki_r_priv, ki_r_pub,
                                ki_e_priv_i, ki_e_priv_r,
                                (const uint8_t *)prologues[epi].data,
                                prologues[epi].len, elabel);
        }

        /* Multi-message test — her key için 3 prologue ile */
        for (int mpi = 0; mpi < 3 && mpi < n_pro; mpi++) {
            char mlabel[128];
            snprintf(mlabel, sizeof(mlabel), "k%d_mm%d", ki, mpi);
            run_multi_msg_test(ki_i_priv, ki_i_pub, ki_r_priv, ki_r_pub,
                               ki_e_priv_i, ki_e_priv_r,
                               (const uint8_t *)prologues[mpi].data,
                               prologues[mpi].len, mlabel);
        }

        /* Nonce counter test — her key için 3 prologue ile */
        for (int npi = 0; npi < 3 && npi < n_pro; npi++) {
            char nlabel[128];
            snprintf(nlabel, sizeof(nlabel), "k%d_nonce%d", ki, npi);
            run_nonce_counter_test(ki_i_priv, ki_i_pub, ki_r_priv, ki_r_pub,
                                   ki_e_priv_i, ki_e_priv_r,
                                   (const uint8_t *)prologues[npi].data,
                                   prologues[npi].len, nlabel);
        }

        /* Error recovery test — her key için 3 prologue ile */
        for (int rpi = 0; rpi < 3 && rpi < n_pro; rpi++) {
            char rlabel[128];
            snprintf(rlabel, sizeof(rlabel), "k%d_recovery%d", ki, rpi);
            run_error_recovery_test(ki_i_priv, ki_i_pub, ki_r_priv, ki_r_pub,
                                    ki_e_priv_i, ki_e_priv_r,
                                    (const uint8_t *)prologues[rpi].data,
                                    prologues[rpi].len, rlabel);
        }

        /* Split cross-decrypt test — her key için 3 prologue × 4 pattern × 3 payload */
        {
            static const size_t cross_payloads[] = {0, 100, 4096};
            for (int cpi = 0; cpi < 3 && cpi < n_pro; cpi++) {
                for (int cpat = 0; cpat < n_patterns; cpat++) {
                    for (int cli = 0; cli < 3; cli++) {
                        size_t cplen = cross_payloads[cli];
                        uint8_t *cpayload = NULL;
                        if (cplen > 0) {
                            cpayload = malloc(cplen);
                            if (!cpayload) continue;
                            if (cpat == 0) {
                                randombytes_buf(cpayload, cplen);
                            } else {
                                fill_fns[cpat](cpayload, cplen);
                            }
                        }
                        char clabel[128];
                        snprintf(clabel, sizeof(clabel), "k%d_xdec%d_p%d_l%zu",
                                 ki, cpi, cpat, cplen);
                        run_split_cross_decrypt_test(ki_i_priv, ki_i_pub, ki_r_priv, ki_r_pub,
                                                     ki_e_priv_i, ki_e_priv_r,
                                                     (const uint8_t *)prologues[cpi].data,
                                                     prologues[cpi].len,
                                                     cpayload, cplen, clabel);
                        free(cpayload);
                    }
                }
            }
        }

        if ((ki + 1) % 10 == 0)
            fprintf(stderr, "[diff] %d/105 key seti tamamlandı (%d pass, %d fail)\n",
                    ki + 1, g_pass, g_fail);
    }

    /* ═══════════════════════════════════════════════════════════════
     * SONUÇ
     * ═══════════════════════════════════════════════════════════════ */
    fprintf(stderr, "\n[diff] Results: %d pass, %d fail\n", g_pass, g_fail);

    if (g_fail > 0) {
        fprintf(stderr, "[diff] DIFFERENTIAL MISMATCH DETECTED\n");
        return 1;
    }
    fprintf(stderr, "[diff] ALL MATCH — all %d tests passed\n", g_pass);
    return 0;
}
