/*
 * noise_star_handshake_spike.c — Noise* (HACL*) İKİNCİ oracle, handshake-only.
 *
 * ZORUNLU KAPI DEĞİLDİR. `make noise-star-spike` ile ayrı binary olarak
 * derlenir; `make test` ve `differential-gate` bunu içermez. noise-c hâlâ
 * gerçek diferansiyel kapıdır; Noise* yalnızca handshake happy-path'ini
 * (mesajlar + transcript hash) bağımsız bir uygulamayla çapraz doğrular.
 *
 * HACL* pin'i 349b052'dir: vendored Hacl.h 5 argümanlı blake2b_init bekler.
 * Sonraki sürümler (be4a57c vb.) 3 argümana indirdiği için sessizce yanlış
 * hash üretir. Bkz. third_party/noise-star/README.md ve scripts/build-noise-star.sh.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "noise.h"
#include "XX.h"

/* noise.c'nin gerektirdiği log kancası — testte noop. */
void nox_log_impl(log_level_t level, log_module_t mod,
                  const char *file, int line, const char *fmt, ...) {
    (void)level; (void)mod; (void)file; (void)line; (void)fmt;
}

static int g_fail = 0;

static void cmp_bytes(const char *label,
                      const uint8_t *ref, size_t ref_len,
                      const uint8_t *our, size_t our_len) {
    if (ref_len != our_len) {
        printf("  FAIL %s: uzunluk ref=%zu our=%zu\n", label, ref_len, our_len);
        g_fail++;
        return;
    }
    if (ref_len > 0 && memcmp(ref, our, ref_len) != 0) {
        size_t d = 0;
        while (d < ref_len && ref[d] == our[d]) d++;
        printf("  FAIL %s: içerik farklı (%zu bayt), ilk fark [%zu] "
               "ref=%02x our=%02x\n", label, ref_len, d, ref[d], our[d]);
        g_fail++;
        return;
    }
    printf("  OK   %s: %zu bayt birebir\n", label, ref_len);
}

static bool rcode_ok(Noise_XX_rcode rc) {
    return rc.tag == Noise_XX_Success;
}

static void print_rcode(const char *where, Noise_XX_rcode rc) {
    if (rc.tag == Noise_XX_Stuck)
        printf("  FAIL %s: Stuck (err=%u)\n", where,
               Noise_XX___proj__Stuck__item___0(rc));
    else if (rc.tag == Noise_XX_Error)
        printf("  FAIL %s: Error (err=%u)\n", where,
               Noise_XX___proj__Error__item___0(rc));
    else
        printf("  FAIL %s: tag=%u\n", where, rc.tag);
    g_fail++;
}

/*
 * Tek bir handshake senaryosu: sabit statik/ephemeral anahtarlar + verilen
 * prologue ile Noise* ve bizim noise.c mesajlarını ve hash'ini karşılaştırır.
 */
static void run_case(const char *label,
                     const uint8_t *prlg, uint32_t prlg_len) {
    uint8_t i_priv[32], i_pub[32];
    uint8_t r_priv[32], r_pub[32];
    uint8_t ei_priv[32], ei_pub[32];
    uint8_t er_priv[32], er_pub[32];
    uint8_t dummy_sk[32];

    printf("\n== %s (prologue=%u bayt)\n", label, prlg_len);

    for (int i = 0; i < 32; i++) {
        i_priv[i]  = (uint8_t)(i + 1);
        r_priv[i]  = (uint8_t)(0x40 + i);
        ei_priv[i] = (uint8_t)(0x80 + i);
        er_priv[i] = (uint8_t)(0xC0 + i);
        dummy_sk[i] = 0x5A;
    }

    if (Noise_XX_dh_secret_to_public(i_pub, i_priv) != Noise_XX_CSuccess ||
        Noise_XX_dh_secret_to_public(r_pub, r_priv) != Noise_XX_CSuccess ||
        Noise_XX_dh_secret_to_public(ei_pub, ei_priv) != Noise_XX_CSuccess ||
        Noise_XX_dh_secret_to_public(er_pub, er_priv) != Noise_XX_CSuccess) {
        printf("  FAIL: anahtar türetme\n");
        g_fail++;
        return;
    }

    /* ---- Noise* kurulumu ---- */
    Noise_XX_device_t *di = Noise_XX_device_create(
        prlg_len, (uint8_t *)prlg, (uint8_t *)"initiator", dummy_sk, i_priv);
    Noise_XX_device_t *dr = Noise_XX_device_create(
        prlg_len, (uint8_t *)prlg, (uint8_t *)"responder", dummy_sk, r_priv);
    if (!di || !dr) {
        printf("  FAIL: device_create\n");
        g_fail++;
        return;
    }
    /* XX: her iki taraf da karşı tarafın statik anahtarını tanımalı. */
    if (!Noise_XX_device_add_peer(dr, (uint8_t *)"initiator", i_pub) ||
        !Noise_XX_device_add_peer(di, (uint8_t *)"responder", r_pub)) {
        printf("  FAIL: device_add_peer\n");
        g_fail++;
        Noise_XX_device_free(di);
        Noise_XX_device_free(dr);
        return;
    }
    Noise_XX_session_t *si = Noise_XX__session_create_initiator_with_ephemeral(
        di, ei_priv, ei_pub);
    Noise_XX_session_t *sr = Noise_XX__session_create_responder_with_ephemeral(
        dr, er_priv, er_pub);
    if (!si || !sr) {
        printf("  FAIL: session_create_with_ephemeral\n");
        g_fail++;
        Noise_XX_device_free(di);
        Noise_XX_device_free(dr);
        return;
    }

    /* ---- bizim kurulumumuz ---- */
    struct noise_handshake hi, hr;
    if (handshake_init_with_prologue(&hi, true, i_priv, i_pub,
                                     prlg, prlg_len) != NOX_OK ||
        handshake_init_with_prologue(&hr, false, r_priv, r_pub,
                                     prlg, prlg_len) != NOX_OK ||
        handshake_inject_ephemeral(&hi, ei_priv) != NOX_OK ||
        handshake_inject_ephemeral(&hr, er_priv) != NOX_OK) {
        printf("  FAIL: handshake kurulumu\n");
        g_fail++;
        Noise_XX_session_free(si);
        Noise_XX_session_free(sr);
        Noise_XX_device_free(di);
        Noise_XX_device_free(dr);
        return;
    }

    /* Başlangıç transcript hash'i de aynı olmalı (prologue doğru karışmış). */
    {
        uint8_t sh[64], oh[64];
        Noise_XX_session_get_hash(sh, si);
        handshake_get_h(&hi, oh);
        cmp_bytes("başlangıç h", sh, 64, oh, 64);
    }

    uint8_t plbuf[512];
    size_t pl_len;

    /* ---- msg0: I -> R (e) ---- */
    Noise_XX_encap_message_t *empty = Noise_XX_pack_message(0, NULL);
    uint32_t s0_len = 0; uint8_t *s0 = NULL;
    Noise_XX_rcode rc = Noise_XX_session_write(empty, si, &s0_len, &s0);
    Noise_XX_encap_message_p_free(empty);
    if (!rcode_ok(rc)) { print_rcode("star write msg0", rc); goto cleanup; }

    uint8_t o0[512]; size_t o0_len = sizeof(o0);
    if (handshake_write(&hi, NULL, 0, o0, &o0_len) != NOX_OK) {
        printf("  FAIL: our write msg0\n"); g_fail++; goto cleanup;
    }
    cmp_bytes("msg0 (e)", s0, s0_len, o0, o0_len);

    Noise_XX_encap_message_t *p0 = NULL;
    rc = Noise_XX_session_read(&p0, sr, s0_len, s0);
    if (!rcode_ok(rc)) { print_rcode("star read msg0", rc); goto cleanup; }
    if (p0) Noise_XX_encap_message_p_free(p0);
    free(s0); s0 = NULL;
    pl_len = sizeof(plbuf);
    if (handshake_read(&hr, o0, o0_len, plbuf, sizeof(plbuf), &pl_len) != NOX_OK) {
        printf("  FAIL: our read msg0\n"); g_fail++; goto cleanup;
    }

    /* ---- msg1: R -> I (e, ee, s, es) ---- */
    empty = Noise_XX_pack_message(0, NULL);
    uint32_t s1_len = 0; uint8_t *s1 = NULL;
    rc = Noise_XX_session_write(empty, sr, &s1_len, &s1);
    Noise_XX_encap_message_p_free(empty);
    if (!rcode_ok(rc)) { print_rcode("star write msg1", rc); goto cleanup; }

    uint8_t o1[512]; size_t o1_len = sizeof(o1);
    if (handshake_write(&hr, NULL, 0, o1, &o1_len) != NOX_OK) {
        printf("  FAIL: our write msg1\n"); g_fail++; goto cleanup;
    }
    cmp_bytes("msg1 (e,ee,s,es)", s1, s1_len, o1, o1_len);

    Noise_XX_encap_message_t *p1 = NULL;
    rc = Noise_XX_session_read(&p1, si, s1_len, s1);
    if (!rcode_ok(rc)) { print_rcode("star read msg1", rc); goto cleanup; }
    if (p1) Noise_XX_encap_message_p_free(p1);
    free(s1); s1 = NULL;
    pl_len = sizeof(plbuf);
    if (handshake_read(&hi, o1, o1_len, plbuf, sizeof(plbuf), &pl_len) != NOX_OK) {
        printf("  FAIL: our read msg1\n"); g_fail++; goto cleanup;
    }

    /* ---- msg2: I -> R (s, se) ---- */
    empty = Noise_XX_pack_message(0, NULL);
    uint32_t s2_len = 0; uint8_t *s2 = NULL;
    rc = Noise_XX_session_write(empty, si, &s2_len, &s2);
    Noise_XX_encap_message_p_free(empty);
    if (!rcode_ok(rc)) { print_rcode("star write msg2", rc); goto cleanup; }

    uint8_t o2[512]; size_t o2_len = sizeof(o2);
    if (handshake_write(&hi, NULL, 0, o2, &o2_len) != NOX_OK) {
        printf("  FAIL: our write msg2\n"); g_fail++; goto cleanup;
    }
    cmp_bytes("msg2 (s,se)", s2, s2_len, o2, o2_len);

    Noise_XX_encap_message_t *p2 = NULL;
    rc = Noise_XX_session_read(&p2, sr, s2_len, s2);
    if (!rcode_ok(rc)) { print_rcode("star read msg2", rc); goto cleanup; }
    if (p2) Noise_XX_encap_message_p_free(p2);
    free(s2); s2 = NULL;
    pl_len = sizeof(plbuf);
    if (handshake_read(&hr, o2, o2_len, plbuf, sizeof(plbuf), &pl_len) != NOX_OK) {
        printf("  FAIL: our read msg2\n"); g_fail++; goto cleanup;
    }

    /* ---- nihai transcript hash ---- */
    {
        uint8_t sh_i[64], sh_r[64], oh_i[64], oh_r[64];
        Noise_XX_session_get_hash(sh_i, si);
        Noise_XX_session_get_hash(sh_r, sr);
        handshake_get_h(&hi, oh_i);
        handshake_get_h(&hr, oh_r);
        cmp_bytes("hash initiator", sh_i, 64, oh_i, 64);
        cmp_bytes("hash responder", sh_r, 64, oh_r, 64);
    }

cleanup:
    free(s0); free(s1); free(s2);
    Noise_XX_session_free(si);
    Noise_XX_session_free(sr);
    Noise_XX_device_free(di);
    Noise_XX_device_free(dr);
}

int main(void) {
    /* sodium_malloc/sodium_free (noise.c HKDF) için gerekli. */
    if (sodium_init() < 0) {
        printf("FAIL: sodium_init\n");
        return 1;
    }

    static const uint8_t prlg_a[] = "Mustafa Kemal Atatürk";
    static const uint8_t prlg_b[] = "";
    static const uint8_t prlg_c[] =
        "noxtor-cli | Noise_XX_25519_ChaChaPoly_BLAKE2b | differential spike";

    run_case("varsayılan prologue", prlg_a, (uint32_t)(sizeof(prlg_a) - 1));
    run_case("boş prologue", prlg_b, 0);
    run_case("uzun prologue", prlg_c, (uint32_t)(sizeof(prlg_c) - 1));

    printf("\nSONUÇ: %s\n", g_fail ? "FAIL" : "tüm karşılaştırmalar eşit");
    return g_fail ? 1 : 0;
}
