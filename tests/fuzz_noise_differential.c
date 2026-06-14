/* ================================================================
 * Differential Fuzzing: noise-c (reference) vs our noise.c
 *
 * noise-c 0.3.x API — ephemeral key enjeksiyonu ile deterministik.
 *
 * Temel bulgular:
 *   1. noise_buffer_init() MUTLAKA çağrılmalı (set_output/set_input önce)
 *   2. Payload buffer geçerli pointer olmalı (NULL olmaz, 0 byte olsa bile)
 *   3. Split sonrası: initiator c1=send, c2=receive; responder c1=send, c2=receive
 *   4. Cross-side: i c1 encrypt → r c2 decrypt
 *   5. Prologue: "Mustafa Kemal Atatürk" (bizim kod hardcoded)
 *   6. noise_handshakestate_free() buffer'ları sıfırlar — hex dump free ÖNCESinde yapılmalı
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
                    const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
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

    static const char PROLOGUE[] = "Mustafa Kemal Atatürk";
    noise_handshakestate_set_prologue(g_nc_i, PROLOGUE, sizeof(PROLOGUE) - 1);
    noise_handshakestate_set_prologue(g_nc_r, PROLOGUE, sizeof(PROLOGUE) - 1);

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
                      const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    handshake_init(&g_our_i, true, i_priv, i_pub);
    handshake_init(&g_our_r, false, r_priv, r_pub);
    handshake_inject_ephemeral(&g_our_i, e_priv_i);
    handshake_inject_ephemeral(&g_our_r, e_priv_r);
}

/* ================================================================
 * TEST 1: Happy path — 3 mesaj XX handshake + split + transport
 *
 * noise-c free sonrası buffer sıfırlar, bu yüzden mesaj karşılaştırması
 * her adımda hemen yapılır (inline). Transport ciphertext free öncesinde karşılaştırılır.
 * ================================================================ */
static void test_happy_path(const uint8_t i_priv[32], const uint8_t i_pub[32],
                            const uint8_t r_priv[32], const uint8_t r_pub[32],
                            const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_happy_path...\n");

    char label[64];

    /* === noise-c XX handshake — her adımda inline karşılaştırma === */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);

    /* Our code setup */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);

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
 * TEST 2: Bozuk msg1 — MAC korumalı
 * ================================================================ */
static void test_corrupted_msg(const uint8_t i_priv[32], const uint8_t i_pub[32],
                               const uint8_t r_priv[32], const uint8_t r_pub[32],
                               const uint8_t e_priv_i[32], const uint8_t e_priv_r[32]) {
    fprintf(stderr, "[diff] test_corrupted_msg...\n");

    uint8_t payload_buf[512];
    size_t pl_len;

    /* noise-c: msg0 + msg1 üret, msg1'i boz */
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);

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
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);

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
 * TEST 3: Farklı ephemeral key çiftleri — sadece msg0 uzunluk karşılaştırması
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
        nc_setup(i_priv, i_pub, r_priv, r_pub, e_i, e_r);
        uint8_t nc_msg0[512];
        size_t nc_m0_len = 0;
        nc_write_msg(g_nc_i, nc_msg0, &nc_m0_len);
        nc_cleanup();

        /* Our code */
        our_setup(i_priv, i_pub, r_priv, r_pub, e_i, e_r);
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
    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    uint8_t nc_msg0[512];
    size_t nc_m0_len = 0;
    nc_write_msg(g_nc_i, nc_msg0, &nc_m0_len);
    nc_cleanup();

    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    uint8_t cross_payload[512];
    size_t cross_pl_len = sizeof(cross_payload);
    nox_err_t rc = handshake_read(&g_our_r, nc_msg0, nc_m0_len, cross_payload, sizeof(cross_payload), &cross_pl_len);
    DIFF_ASSERT(rc == NOX_OK, "cross: our reads nc msg0");

    /* our msg0 → nc read */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    uint8_t our_msg0[512];
    size_t our_m0_len = sizeof(our_msg0);
    handshake_write(&g_our_i, NULL, 0, our_msg0, &our_m0_len);

    nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r);
    int nc_rc = nc_read_msg(g_nc_r, our_msg0, our_m0_len);
    DIFF_ASSERT(nc_rc == NOISE_ERROR_NONE, "cross: nc reads our msg0");

    nc_cleanup();
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

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

    fprintf(stderr, "\n[diff] Results: %d pass, %d fail\n", g_pass, g_fail);

    if (g_fail > 0) {
        fprintf(stderr, "[diff] DIFFERENTIAL MISMATCH DETECTED\n");
        return 1;
    }
    fprintf(stderr, "[diff] ALL MATCH — implementations are equivalent\n");
    return 0;
}
