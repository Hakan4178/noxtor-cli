/* ================================================================
 * Differential Fuzzing FULL: noise-c vs our noise.c
 *
 * Kapsam:
 *   - 100 rastgele key çifti + 5 bilinen vektör
 *   - 12 farklı prologue (edge cases dahil)
 *   - 10 farklı payload pattern × 7 uzunluk
 *   - Toplam: ~42000 test
 *
 * Her testte karşılaştırılan:
 *   - msg0 bytes (32 byte)
 *   - msg1 bytes (96 byte)
 *   - msg2 bytes (64 byte)
 *   - ciphertext (AEAD output)
 *   - decrypt result (plaintext)
 * ================================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

#include <noise/protocol.h>

#ifdef NOISE_MAX_PAYLOAD_LEN
#undef NOISE_MAX_PAYLOAD_LEN
#endif

#include "common.h"
#include "noise.h"

/* ================================================================
 * Stub
 * ================================================================ */
void nox_log_impl(log_level_t level, log_module_t mod,
                  const char *file, int line, const char *fmt, ...) {
    (void)level; (void)mod; (void)file; (void)line; (void)fmt;
}

/* ================================================================
 * Sayac
 * ================================================================ */
static int g_pass = 0, g_fail = 0;

#define FA(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "  FAIL: %s\n", msg); g_fail++; } \
    else { g_pass++; } \
} while (0)

/* ================================================================
 * noise-c yardımcıları
 * ================================================================ */
static NoiseHandshakeState *g_nc_i = NULL, *g_nc_r = NULL;
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
 * our code yardımcıları
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

/* ================================================================
 * Tek test — tüm parametrelerle
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
        FA(0, errmsg);
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
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg0 write", label);
    FA(our_rc == NOX_OK, errmsg);

    if (nc_rc == NOISE_ERROR_NONE && our_rc == NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: msg0 len %zu==%zu", label, nc_mlen, our_mlen);
        FA(nc_mlen == our_mlen, errmsg);
        if (nc_mlen == our_mlen) {
            snprintf(errmsg, sizeof(errmsg), "%s: msg0 content", label);
            FA(memcmp(nc_msg, our_msg, nc_mlen) == 0, errmsg);
        }
    }

    /* Read msg0 */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg0 read", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg0 read", label);
    FA(our_rc == NOX_OK, errmsg);

    /* MSG 1 */
    nc_rc = nc_write_msg(g_nc_r, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_r, NULL, 0, our_msg, &our_mlen);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg1 write", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg1 write", label);
    FA(our_rc == NOX_OK, errmsg);

    if (nc_rc == NOISE_ERROR_NONE && our_rc == NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: msg1 len %zu==%zu", label, nc_mlen, our_mlen);
        FA(nc_mlen == our_mlen, errmsg);
        if (nc_mlen == our_mlen) {
            snprintf(errmsg, sizeof(errmsg), "%s: msg1 content", label);
            FA(memcmp(nc_msg, our_msg, nc_mlen) == 0, errmsg);
        }
    }

    /* Read msg1 */
    nc_rc = nc_read_msg(g_nc_i, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_i, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg1 read", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg1 read", label);
    FA(our_rc == NOX_OK, errmsg);

    /* MSG 2 */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg2 write", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg2 write", label);
    FA(our_rc == NOX_OK, errmsg);

    if (nc_rc == NOISE_ERROR_NONE && our_rc == NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: msg2 len %zu==%zu", label, nc_mlen, our_mlen);
        FA(nc_mlen == our_mlen, errmsg);
        if (nc_mlen == our_mlen) {
            snprintf(errmsg, sizeof(errmsg), "%s: msg2 content", label);
            FA(memcmp(nc_msg, our_msg, nc_mlen) == 0, errmsg);
        }
    }

    /* Read msg2 */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    snprintf(errmsg, sizeof(errmsg), "%s: nc msg2 read", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: our msg2 read", label);
    FA(our_rc == NOX_OK, errmsg);

    /* ── Karşılaştırma #6: Handshake hash (h) — split ÖNCESİ ── */
    {
        uint8_t nc_h_i[64], our_h_i[64];
        uint8_t nc_h_r[64], our_h_r[64];

        noise_handshakestate_get_handshake_hash(g_nc_i, nc_h_i, sizeof(nc_h_i));
        handshake_get_h(&g_our_i, our_h_i);

        noise_handshakestate_get_handshake_hash(g_nc_r, nc_h_r, sizeof(nc_h_r));
        handshake_get_h(&g_our_r, our_h_r);

        /* Initiator h == Responder h (her iki tarafta da aynı) */
        snprintf(errmsg, sizeof(errmsg), "%s: h_i == h_r (nc)", label);
        FA(memcmp(nc_h_i, nc_h_r, 64) == 0, errmsg);
        snprintf(errmsg, sizeof(errmsg), "%s: h_i == h_r (our)", label);
        FA(memcmp(our_h_i, our_h_r, 64) == 0, errmsg);

        /* noise-c h == our h */
        snprintf(errmsg, sizeof(errmsg), "%s: h nc == our (i)", label);
        FA(memcmp(nc_h_i, our_h_i, 64) == 0, errmsg);
        snprintf(errmsg, sizeof(errmsg), "%s: h nc == our (r)", label);
        FA(memcmp(nc_h_r, our_h_r, 64) == 0, errmsg);
    }

    /* ── Karşılaştırma #7: Chaining key (ck) — split ÖNCESİ ── */
    {
        uint8_t our_ck_i[64], our_ck_r[64];
        handshake_get_ck(&g_our_i, our_ck_i);
        handshake_get_ck(&g_our_r, our_ck_r);

        snprintf(errmsg, sizeof(errmsg), "%s: ck_i == ck_r", label);
        FA(memcmp(our_ck_i, our_ck_r, 64) == 0, errmsg);

        /* ck non-zero */
        uint8_t zero64[64] = {0};
        snprintf(errmsg, sizeof(errmsg), "%s: ck non-zero", label);
        FA(memcmp(our_ck_i, zero64, 64) != 0, errmsg);
    }

    /* Split */
    nc_rc = noise_handshakestate_split(g_nc_i, &g_nc_i_c1, &g_nc_i_c2);
    snprintf(errmsg, sizeof(errmsg), "%s: nc i split", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);

    nc_rc = noise_handshakestate_split(g_nc_r, &g_nc_r_c1, &g_nc_r_c2);
    snprintf(errmsg, sizeof(errmsg), "%s: nc r split", label);
    FA(nc_rc == NOISE_ERROR_NONE, errmsg);

    struct noise_session i_sess = {0}, r_sess = {0};
    our_rc = handshake_split(&g_our_i, &i_sess);
    snprintf(errmsg, sizeof(errmsg), "%s: our i split", label);
    FA(our_rc == NOX_OK, errmsg);

    our_rc = handshake_split(&g_our_r, &r_sess);
    snprintf(errmsg, sizeof(errmsg), "%s: our r split", label);
    FA(our_rc == NOX_OK, errmsg);

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
        FA(nc_enc_len == (size_t)our_enc_len, errmsg);
        if (nc_enc_len == (size_t)our_enc_len) {
            snprintf(errmsg, sizeof(errmsg), "%s: transport ciphertext", label);
            FA(memcmp(nc_enc, our_enc, nc_enc_len) == 0, errmsg);
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
        FA(our_dec_len == (ssize_t)payload_len, errmsg);
        if (our_dec_len == (ssize_t)payload_len) {
            snprintf(errmsg, sizeof(errmsg), "%s: transport plaintext", label);
            FA(payload_len == 0 || memcmp(our_dec, payload, payload_len) == 0, errmsg);
        }
    }

    free(nc_enc);
    free(our_enc);
    free(our_dec);
    nc_cleanup();
}

/* ================================================================
 * Karşılaştırma #8: Error behavior — bozuk mesaj her iki tarafta da red
 * ================================================================ */
static void run_error_test(const uint8_t i_priv[32], const uint8_t i_pub[32],
                           const uint8_t r_priv[32], const uint8_t r_pub[32],
                           const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
                           const uint8_t *prologue, size_t prologue_len,
                           const char *label) {
    char errmsg[128];

    /* Fresh noise-c */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup failed", label);
        FA(0, errmsg);
        return;
    }

    /* Fresh our */
    our_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
              prologue, prologue_len);

    uint8_t nc_msg[512], our_msg[512];
    size_t nc_mlen, our_mlen;
    uint8_t payload_buf[512];
    size_t pl_len;
    int nc_rc;
    nox_err_t our_rc;

    /* MSG 0 */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);
    if (nc_rc != NOISE_ERROR_NONE || our_rc != NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: err setup failed", label);
        FA(0, errmsg);
        nc_cleanup();
        return;
    }

    /* Read MSG 0 */
    nc_rc = nc_read_msg(g_nc_r, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    /* MSG 1 */
    nc_rc = nc_write_msg(g_nc_r, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_r, NULL, 0, our_msg, &our_mlen);
    if (nc_rc != NOISE_ERROR_NONE || our_rc != NOX_OK) {
        snprintf(errmsg, sizeof(errmsg), "%s: err msg1 write", label);
        FA(0, errmsg);
        nc_cleanup();
        return;
    }

    /* Read MSG 1 */
    nc_rc = nc_read_msg(g_nc_i, nc_msg, nc_mlen);
    pl_len = sizeof(payload_buf);
    our_rc = handshake_read(&g_our_i, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

    /* MSG 2 — şimdi boz */
    nc_rc = nc_write_msg(g_nc_i, nc_msg, &nc_mlen);
    our_mlen = sizeof(our_msg);
    our_rc = handshake_write(&g_our_i, NULL, 0, our_msg, &our_mlen);

    /* ── Error #1: msg2'yi boz — her iki taraf da red etmeli ── */
    {
        uint8_t bad_msg[512];
        memcpy(bad_msg, nc_msg, nc_mlen);
        bad_msg[0] ^= 0xFF;  /* İlk byte'ı flip et */

        /* noise-c tarafı */
        int nc_bad = nc_read_msg(g_nc_r, bad_msg, nc_mlen);
        snprintf(errmsg, sizeof(errmsg), "%s: nc reject bad msg2", label);
        FA(nc_bad != NOISE_ERROR_NONE, errmsg);

        /* our tarafı — fresh r setup ile */
        struct noise_handshake fresh_r;
        handshake_init_with_prologue(&fresh_r, false, r_priv, r_pub,
                                     prologue, prologue_len);
        handshake_inject_ephemeral(&fresh_r, e_priv_r);

        /* MSG 0 + 1'i tekrar oyna */
        pl_len = sizeof(payload_buf);
        handshake_read(&fresh_r, our_msg, our_mlen, payload_buf, sizeof(payload_buf), &pl_len);

        uint8_t our_msg2[512];
        size_t our_msg2_len = sizeof(our_msg2);
        handshake_write(&fresh_r, NULL, 0, our_msg2, &our_msg2_len);

        uint8_t our_bad_msg[512];
        memcpy(our_bad_msg, our_msg2, our_msg2_len);
        our_bad_msg[0] ^= 0xFF;

        pl_len = sizeof(payload_buf);
        nox_err_t our_bad = handshake_read(&fresh_r, our_bad_msg, our_msg2_len,
                                           payload_buf, sizeof(payload_buf), &pl_len);
        snprintf(errmsg, sizeof(errmsg), "%s: our reject bad msg2", label);
        FA(our_bad != NOX_OK, errmsg);
    }

    nc_cleanup();
}

/* ================================================================
 * Karşılaştırma #9-14: Parametre boyutları (noise-c API)
 * ================================================================ */
static void run_param_test(const char *label) {
    char errmsg[128];

    NoiseCipherState *cs;
    noise_cipherstate_new_by_name(&cs, "ChaChaPoly");

    snprintf(errmsg, sizeof(errmsg), "%s: cipher key_len==32", label);
    FA(noise_cipherstate_get_key_length(cs) == 32, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: cipher mac_len==16", label);
    FA(noise_cipherstate_get_mac_length(cs) == 16, errmsg);

    noise_cipherstate_free(cs);

    NoiseHashState *hs;
    noise_hashstate_new_by_name(&hs, "BLAKE2b");

    snprintf(errmsg, sizeof(errmsg), "%s: hash hash_len==64", label);
    FA(noise_hashstate_get_hash_length(hs) == 64, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: hash block_len==128", label);
    FA(noise_hashstate_get_block_length(hs) == 128, errmsg);

    noise_hashstate_free(hs);

    NoiseHandshakeState *nc;
    noise_handshakestate_new_by_name(&nc, "Noise_XX_25519_ChaChaPoly_BLAKE2b", NOISE_ROLE_INITIATOR);
    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(nc);

    snprintf(errmsg, sizeof(errmsg), "%s: dh priv_len==32", label);
    FA(noise_dhstate_get_private_key_length(dh) == 32, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: dh pub_len==32", label);
    FA(noise_dhstate_get_public_key_length(dh) == 32, errmsg);
    snprintf(errmsg, sizeof(errmsg), "%s: dh shared_len==32", label);
    FA(noise_dhstate_get_shared_key_length(dh) == 32, errmsg);

    noise_handshakestate_free(nc);
}

/* ================================================================
 * Karşılaştırma #24-35: Kapsamlı error behavior
 *
 * Her senaryo için:
 *   1. noise-c tarafı: hata bekleniyor mu?
 *   2. our tarafı: hata bekleniyor mu?
 *   3. Her ikisi de aynı sonucu mu veriyor?
 *
 * Yardımcı: tek bir handshake'i msg0→msg1→msg2 akışında çalıştır,
 * istenen hata noktasında bozulmuş msg'yi ver.
 * ================================================================ */

/* Yardımcı: tek bir hata testini çalıştır */
static void run_one_error_case(
    const uint8_t i_priv[32], const uint8_t i_pub[32],
    const uint8_t r_priv[32], const uint8_t r_pub[32],
    const uint8_t e_priv_i[32], const uint8_t e_priv_r[32],
    const uint8_t *prologue, size_t prologue_len,
    int error_msg,       /* 0, 1 veya 2 — hangi mesajda hata oluşturulacak */
    int error_type,      /* 0=corrupt first byte, 1=all zeros, 2=short len, 3=wrong static key */
    const char *label) {
    char errmsg[128];

    /* ── noise-c tarafı ── */
    if (nc_setup(i_priv, i_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        FA(0, errmsg);
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
        /* MSG 0 hatası */
        uint8_t bad[512]; memcpy(bad, msg0, len0);
        if (error_type == 0) { bad[0] ^= 0xFF; }           /* corrupt */
        else if (error_type == 1) { memset(bad, 0, len0); } /* zeros */
        else if (error_type == 2) { len0 = 4; }             /* short */
        noise_buffer_init(mb); noise_buffer_set_input(mb, bad, len0);
        noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
        nc_bad = noise_handshakestate_read_message(g_nc_r, &mb, &pb);
    } else if (error_msg == 1) {
        /* MSG 1 hatası */
        uint8_t bad[512]; memcpy(bad, msg1, len1);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, len1); }
        else if (error_type == 2) { len1 = 4; }
        noise_buffer_init(mb); noise_buffer_set_input(mb, bad, len1);
        noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
        nc_bad = noise_handshakestate_read_message(g_nc_i, &mb, &pb);
    } else {
        /* MSG 2 hatası */
        uint8_t bad[512]; memcpy(bad, msg2, len2);
        if (error_type == 0) { bad[0] ^= 0xFF; }
        else if (error_type == 1) { memset(bad, 0, len2); }
        else if (error_type == 2) { len2 = 4; }
        noise_buffer_init(mb); noise_buffer_set_input(mb, bad, len2);
        noise_buffer_init(pb); noise_buffer_set_output(pb, tmp, 512);
        nc_bad = noise_handshakestate_read_message(g_nc_r, &mb, &pb);
    }

    snprintf(errmsg, sizeof(errmsg), "%s: nc reject", label);
    FA(nc_bad != NOISE_ERROR_NONE, errmsg);

    nc_cleanup();

    /* ── our tarafı ── */
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
    FA(our_bad != NOX_OK, errmsg);
}

/* Yanlış static key testi — her iki tarafın aynı davranışı gösterdiğini doğrula */
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

    /* XX pattern: initiator'ın wrong static key'i handshake'i bozmaz
     * (responder kendi static key'ini kullanır). Her iki taraf da
     * aynı davranışı göstermeli: ya ikisi de başarılı ya da ikisi de red. */

    /* noise-c tarafı */
    if (nc_setup(wrong_priv, wrong_pub, r_priv, r_pub, e_priv_i, e_priv_r,
                 prologue, prologue_len) != 0) {
        snprintf(errmsg, sizeof(errmsg), "%s: nc_setup fail", label);
        FA(0, errmsg);
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

    /* Her iki taraf da aynı davranışı göstermeli */
    snprintf(errmsg, sizeof(errmsg), "%s: nc==our outcome (nc=%d our=%d)",
             label, nc_ok, our_ok);
    FA(nc_ok == our_ok, errmsg);
}

/* Kapsamlı error test — tüm senaryolar */
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
 * MAIN — 105 key × 12 prologue × 4 pattern × 10 payload
 * ================================================================ */
int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    fprintf(stderr, "[diff-full] Başlatılıyor: 105 key × 12 prologue × 4 pattern × 10 payload\n");

    /* #9-14: Parametre boyut karşılaştırması (bir kez) */
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
    static const char pl_emoji[] = "test 🚀🔒";  /* 7 byte UTF-8 emoji */
    static const char pl_rtl[] = "test مرحبا";   /* Arabic RTL */
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
        {NULL, 0, "null_ptr"},  /* NULL pointer — prologue_len ignored */
    };

    /* Payload uzunlukları */
    size_t payload_lens[] = {0, 1, 4, 16, 32, 100, 255, 511, 4096, 8192};

    /* Payload pattern'leri */
    int n_patterns = 4;

    for (int ki = 0; ki < 105; ki++) {  /* 100 random + 5 known vectors */
        uint8_t i_priv[32], r_priv[32];
        uint8_t i_pub[32], r_pub[32];
        uint8_t e_priv_i[32], e_priv_r[32];

        if (ki < 100) {
            /* Rastgele key çiftleri */
            randombytes_buf(i_priv, 32);
            randombytes_buf(r_priv, 32);
            randombytes_buf(e_priv_i, 32);
            randombytes_buf(e_priv_r, 32);
            crypto_scalarmult_base(i_pub, i_priv);
            crypto_scalarmult_base(r_pub, r_priv);
        } else {
            /* Bilinen vektörler — edge cases (geçerli Curve25519 scalars) */
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
            case 0: /* alternating 0xaa/0x55 vs 0x55/0xaa */
                memcpy(i_priv, alt1, 32); memcpy(r_priv, alt2, 32);
                memcpy(e_priv_i, alt1, 32); memcpy(e_priv_r, alt2, 32);
                break;
            case 1: /* sequential vs reversed */
                memcpy(i_priv, seq, 32); memcpy(r_priv, rev, 32);
                memcpy(e_priv_i, seq, 32); memcpy(e_priv_r, rev, 32);
                break;
            case 2: /* ones vs alternating */
                memcpy(i_priv, ones, 32); memcpy(r_priv, alt1, 32);
                memcpy(e_priv_i, ones, 32); memcpy(e_priv_r, alt1, 32);
                break;
            case 3: /* single bit set — valid scalars */
                memset(i_priv, 0, 32); i_priv[0] = 9;
                memset(r_priv, 0, 32); r_priv[31] = 1;
                memset(e_priv_i, 0, 32); e_priv_i[16] = 7;
                memset(e_priv_r, 0, 32); e_priv_r[16] = 3;
                break;
            case 4: /* repeated pattern */
                for (int j = 0; j < 32; j++) {
                    i_priv[j] = (uint8_t)(j | 1);   /* odd: always non-zero after clamp */
                    r_priv[j] = (uint8_t)(j | 0x80); /* high bit set */
                    e_priv_i[j] = (uint8_t)((j * 7 + 3) & 0xff);
                    e_priv_r[j] = (uint8_t)((j * 13 + 5) & 0xff);
                }
                break;
            }
            crypto_scalarmult_base(i_pub, i_priv);
            crypto_scalarmult_base(r_pub, r_priv);
        }

        int n_pro = (ki < 100) ? 12 : 3;  /* known vectors: sadece 3 prologue */
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

                    run_one_test(i_priv, i_pub, r_priv, r_pub,
                                 e_priv_i, e_priv_r,
                                 (const uint8_t *)prologues[pi].data,
                                 prologues[pi].len,
                                 payload, plen, label);

                    free(payload);
                }
            }
        }

        /* #24-35: Kapsamlı error behavior test — her key için 3 prologue ile */
        for (int epi = 0; epi < 3 && epi < n_pro; epi++) {
            char elabel[128];
            snprintf(elabel, sizeof(elabel), "k%d_err%d", ki, epi);
            run_error_test_full(i_priv, i_pub, r_priv, r_pub,
                                e_priv_i, e_priv_r,
                                (const uint8_t *)prologues[epi].data,
                                prologues[epi].len, elabel);
        }

        if ((ki + 1) % 10 == 0)
            fprintf(stderr, "[diff-full] %d/105 key seti tamamlandı (%d pass, %d fail)\n",
                    ki + 1, g_pass, g_fail);
    }

    fprintf(stderr, "\n[diff-full] Results: %d pass, %d fail\n", g_pass, g_fail);

    if (g_fail > 0) {
        fprintf(stderr, "[diff-full] DIFFERENTIAL MISMATCH DETECTED\n");
        return 1;
    }
    fprintf(stderr, "[diff-full] ALL MATCH — all %d tests passed\n", g_pass);
    return 0;
}
