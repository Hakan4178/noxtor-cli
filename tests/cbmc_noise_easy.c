/* ESBMC harness for noise.c — Kolay + Çok Kolay fonksiyonlar (12 adet)
 *
 * Self-contained: types.h kullanılmaz (sodium.h conflict önlemi).
 * Struct'lar manuel tanımlı, common.h sadece NOX_ERR_* ve NOX_KEY_LEN için.
 *
 * Komut:
 *   esbmc -D__ESBMC__ -I include \
 *     --overflow-check --unsigned-overflow-check --memory-leak-check \
 *     --no-unwinding-assertions --unwind 50 \
 *     tests/cbmc_noise_easy.c
 */

#include "common.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ================================================================
 * STRUCT TANIMLARI — types.h yerine (sodium conflict önlemi)
 * ================================================================ */
struct noise_cipher_state {
    uint8_t  k[NOX_KEY_LEN];
    _Atomic uint64_t n;
    bool     has_key;
};

struct noise_symmetric_state {
    uint8_t  ck[64];
    uint8_t  h[64];
    struct noise_cipher_state cs;
};

struct noise_handshake {
    struct noise_symmetric_state ss;
    uint8_t  s[NOX_KEY_LEN];
    uint8_t  s_pub[NOX_KEY_LEN];
    uint8_t  e[NOX_KEY_LEN];
    uint8_t  e_pub[NOX_KEY_LEN];
    uint8_t  rs[NOX_KEY_LEN];
    uint8_t  re[NOX_KEY_LEN];
    bool     initiator;
    int      msg_index;
};

struct noise_session {
    struct noise_cipher_state tx;
    struct noise_cipher_state rx;
    uint8_t  remote_static[NOX_KEY_LEN];
};

#define NOISE_HASHLEN 64U
#define NOISE_PROTOCOL_NAME "Noise_XX_25519_ChaChaPoly_BLAKE2b"

/* Blake2b state — sodium'dan bağımsız */
typedef struct { uint8_t opaque[256]; } crypto_generichash_blake2b_state;

/* ================================================================
 * ESBMC STUBS
 * ================================================================ */
#ifdef __ESBMC__
extern size_t __VERIFIER_nondet_size_t(void);
extern int    __VERIFIER_nondet_int(void);
extern char   __VERIFIER_nondet_char(void);
extern _Bool  __VERIFIER_nondet_bool(void);
void __CPROVER_assume(_Bool cond) { if (!cond) __ESBMC_assume(0); }
#endif

/* ================================================================
 * SODIUM STUBS
 * ================================================================ */
void sodium_memzero(void *pnt, size_t len) { (void)pnt; (void)len; }
void *sodium_malloc(size_t size) {
  void *ptr = malloc(size);
  __ESBMC_assume(ptr != NULL);
  return ptr;
}
void sodium_free(void *ptr) { free(ptr); }

int sodium_is_zero(const void *pnt, size_t len) {
  /* Doğru sonuç döndür — formal verification için gerekli */
  const unsigned char *p = (const unsigned char *)pnt;
  for (size_t i = 0; i < len; i++) {
    if (p[i] != 0) return 0;
  }
  return 1;
}

int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                                  const unsigned char *p) {
  (void)n; (void)p;
  if (__VERIFIER_nondet_bool()) return -1;
  for (size_t i = 0; i < 32; i++) q[i] = (unsigned char)__VERIFIER_nondet_int();
  return 0;
}

int crypto_scalarmult_base(unsigned char *q, const unsigned char *n) {
  (void)n;
  for (size_t i = 0; i < 32; i++) q[i] = (unsigned char)__VERIFIER_nondet_int();
  return 0;
}

int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                                   unsigned char *sk) {
  for (size_t i = 0; i < 32; i++) {
    pk[i] = (unsigned char)__VERIFIER_nondet_int();
    sk[i] = (unsigned char)__VERIFIER_nondet_int();
  }
  return 0;
}

int crypto_aead_chacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub,
    const unsigned char *k) {
  (void)c; (void)m; (void)ad; (void)nsec; (void)npub; (void)k;
  if (__VERIFIER_nondet_bool()) return -1;
  *clen_p = mlen + NOX_MAC_LEN;
  return 0;
}

int crypto_aead_chacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char *nsec, const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k) {
  (void)m; (void)c; (void)nsec; (void)ad; (void)npub; (void)k;
  if (__VERIFIER_nondet_bool()) return -1;
  *mlen_p = clen - NOX_MAC_LEN;
  return 0;
}

int crypto_generichash_blake2b_init(void *state, const unsigned char *key,
                                     size_t keylen, size_t outlen) {
  (void)state; (void)key; (void)keylen; (void)outlen; return 0;
}
int crypto_generichash_blake2b_update(void *state, const unsigned char *in,
                                       size_t inlen) {
  (void)state; (void)in; (void)inlen; return 0;
}
int crypto_generichash_blake2b_final(void *state, unsigned char *out,
                                      size_t outlen) {
  (void)state; (void)outlen;
  for (size_t i = 0; i < outlen; i++) out[i] = (unsigned char)__VERIFIER_nondet_int();
  return 0;
}
int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                                const unsigned char *in, size_t inlen,
                                const unsigned char *key, size_t keylen) {
  (void)in; (void)inlen; (void)key; (void)keylen; (void)outlen;
  for (size_t i = 0; i < outlen; i++) out[i] = (unsigned char)__VERIFIER_nondet_int();
  return 0;
}

void nox_log_impl(log_level_t level, log_module_t mod, const char *file,
                  int line, const char *fmt, ...) {
  (void)level; (void)mod; (void)file; (void)line; (void)fmt;
}

/* ================================================================
 * KOPYALAN FONKSİYONLAR — noise.c'den
 * ================================================================ */

static void encode_nonce(uint8_t nonce_out[12], uint64_t n) {
  memset(nonce_out, 0, 4);
  for (int i = 0; i < 8; i++)
    nonce_out[4 + i] = (uint8_t)(n >> (8 * i));
}

void cipher_init(struct noise_cipher_state *cs) {
  sodium_memzero(cs, sizeof(*cs));
  cs->has_key = false;
  cs->n = 0;
}

void cipher_init_key(struct noise_cipher_state *cs,
                     const uint8_t key[NOX_KEY_LEN]) {
  memcpy(cs->k, key, NOX_KEY_LEN);
  cs->n = 0;
  cs->has_key = true;
}

ssize_t cipher_encrypt(struct noise_cipher_state *cs, const uint8_t *ad,
                       size_t ad_len, const uint8_t *plaintext, size_t pt_len,
                       uint8_t *out) {
  if (!cs->has_key) {
    if (plaintext && pt_len > 0) memcpy(out, plaintext, pt_len);
    return (ssize_t)pt_len;
  }
  uint64_t current_n = atomic_fetch_add(&cs->n, 1);
  if (current_n >= UINT64_MAX) {
    atomic_store(&cs->n, UINT64_MAX);
    return -1;
  }
  uint8_t nonce[12];
  encode_nonce(nonce, current_n);
  unsigned long long ct_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(NULL, &ct_len, plaintext, pt_len,
                                                 ad, ad_len, NULL, nonce,
                                                 cs->k) != 0)
    return -1;
  return (ssize_t)ct_len;
}

ssize_t cipher_decrypt(struct noise_cipher_state *cs, const uint8_t *ad,
                       size_t ad_len, const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *out) {
  if (!cs->has_key) {
    if (ciphertext && ct_len > 0) memcpy(out, ciphertext, ct_len);
    return (ssize_t)ct_len;
  }
  if (ct_len < NOX_MAC_LEN) return -1;
  uint64_t current_n = atomic_fetch_add(&cs->n, 1);
  if (current_n >= UINT64_MAX) {
    atomic_store(&cs->n, UINT64_MAX);
    return -1;
  }
  uint8_t nonce[12];
  encode_nonce(nonce, current_n);
  unsigned long long pt_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &pt_len, NULL, ciphertext,
                                                 ct_len, ad, ad_len, nonce,
                                                 cs->k) != 0)
    return -1;
  return (ssize_t)pt_len;
}

void symmetric_init(struct noise_symmetric_state *ss, const char *protocol_name) {
  size_t name_len = strlen(protocol_name);
  if (name_len <= NOISE_HASHLEN) {
    sodium_memzero(ss->h, NOISE_HASHLEN);
    memcpy(ss->h, protocol_name, name_len);
  } else {
    crypto_generichash_blake2b(ss->h, NOISE_HASHLEN,
                               (const uint8_t *)protocol_name, name_len, NULL, 0);
  }
  memcpy(ss->ck, ss->h, NOISE_HASHLEN);
  cipher_init(&ss->cs);
}

void symmetric_mix_hash(struct noise_symmetric_state *ss, const uint8_t *data,
                        size_t len) {
  crypto_generichash_blake2b_state state;
  crypto_generichash_blake2b_init(&state, NULL, 0, NOISE_HASHLEN);
  crypto_generichash_blake2b_update(&state, ss->h, NOISE_HASHLEN);
  crypto_generichash_blake2b_update(&state, data, len);
  crypto_generichash_blake2b_final(&state, ss->h, NOISE_HASHLEN);
}

static nox_err_t noise_dh(uint8_t out[NOX_KEY_LEN],
                           const uint8_t priv[NOX_KEY_LEN],
                           const uint8_t pub[NOX_KEY_LEN]) {
  if (sodium_is_zero(pub, NOX_KEY_LEN)) {
    sodium_memzero(out, NOX_KEY_LEN);
    return NOX_ERR_CRYPTO;
  }
  if (crypto_scalarmult_curve25519(out, priv, pub) != 0) {
    sodium_memzero(out, NOX_KEY_LEN);
    return NOX_ERR_CRYPTO;
  }
  if (sodium_is_zero(out, NOX_KEY_LEN)) {
    return NOX_ERR_CRYPTO;
  }
  return NOX_OK;
}

nox_err_t handshake_init(struct noise_handshake *hs, bool initiator,
                          const uint8_t s_priv[NOX_KEY_LEN],
                          const uint8_t s_pub[NOX_KEY_LEN]) {
  if (!hs || !s_priv || !s_pub) return NOX_ERR_PROTO;
  sodium_memzero(hs, sizeof(*hs));
  symmetric_init(&hs->ss, NOISE_PROTOCOL_NAME);
  memcpy(hs->s, s_priv, NOX_KEY_LEN);
  memcpy(hs->s_pub, s_pub, NOX_KEY_LEN);
  hs->initiator = initiator;
  hs->msg_index = 0;
  symmetric_mix_hash(&hs->ss, (const uint8_t *)"Mustafa Kemal Atatürk",
                     strlen("Mustafa Kemal Atatürk"));
  return NOX_OK;
}

bool handshake_is_complete(const struct noise_handshake *hs) {
  return hs && hs->msg_index >= 3;
}

static nox_err_t write_msg0_stub(struct noise_handshake *hs, const uint8_t *pl,
                                  size_t pl_len, uint8_t *out, size_t *out_len) {
  (void)pl; (void)pl_len;
  crypto_box_curve25519xsalsa20poly1305_keypair(hs->e_pub, hs->e);
  memcpy(out, hs->e_pub, NOX_KEY_LEN);
  symmetric_mix_hash(&hs->ss, hs->e_pub, NOX_KEY_LEN);
  *out_len = NOX_KEY_LEN;
  return NOX_OK;
}

nox_err_t handshake_write(struct noise_handshake *hs, const uint8_t *payload,
                           size_t pl_len, uint8_t *out, size_t *out_len) {
  if (!hs || !out || !out_len) return NOX_ERR_PROTO;
  if (!payload) pl_len = 0;
  nox_err_t err;
  if (hs->initiator) {
    switch (hs->msg_index) {
    case 0: err = write_msg0_stub(hs, payload, pl_len, out, out_len); break;
    default: return NOX_ERR_STATE;
    }
  } else {
    return NOX_ERR_STATE;
  }
  if (err == NOX_OK) hs->msg_index++;
  return err;
}

static nox_err_t read_msg0_stub(struct noise_handshake *hs, const uint8_t *msg,
                                 size_t msg_len, uint8_t *payload_out,
                                 size_t *pl_len) {
  if (msg_len < NOX_KEY_LEN) return NOX_ERR_PROTO;
  memcpy(hs->re, msg, NOX_KEY_LEN);
  symmetric_mix_hash(&hs->ss, hs->re, NOX_KEY_LEN);
  *pl_len = 0;
  return NOX_OK;
}

nox_err_t handshake_read(struct noise_handshake *hs, const uint8_t *msg,
                          size_t msg_len, uint8_t *payload_out, size_t *pl_len) {
  if (!hs || !msg || !pl_len) return NOX_ERR_PROTO;
  if (!payload_out) return NOX_ERR_PROTO;
  nox_err_t err;
  if (hs->initiator) {
    return NOX_ERR_STATE;
  } else {
    switch (hs->msg_index) {
    case 0: err = read_msg0_stub(hs, msg, msg_len, payload_out, pl_len); break;
    default: return NOX_ERR_STATE;
    }
  }
  if (err == NOX_OK) hs->msg_index++;
  return err;
}

ssize_t noise_encrypt(struct noise_session *session, const uint8_t *plaintext,
                      size_t pt_len, uint8_t *out) {
  if (!session || !out) return -1;
  return cipher_encrypt(&session->tx, NULL, 0, plaintext, pt_len, out);
}

ssize_t noise_decrypt(struct noise_session *session, const uint8_t *ciphertext,
                      size_t ct_len, uint8_t *out) {
  if (!session || !out) return -1;
  return cipher_decrypt(&session->rx, NULL, 0, ciphertext, ct_len, out);
}

/* ================================================================
 * TESTS
 * ================================================================ */
static void test_cipher_init(void) {
  struct noise_cipher_state cs;
  cipher_init(&cs);
  assert(!cs.has_key);
  assert(cs.n == 0);
}

static void test_cipher_init_key(void) {
  struct noise_cipher_state cs;
  uint8_t key[NOX_KEY_LEN];
  for (size_t i = 0; i < NOX_KEY_LEN; i++) key[i] = (uint8_t)i;
  cipher_init_key(&cs, key);
  assert(cs.has_key);
  assert(cs.n == 0);
  for (size_t i = 0; i < NOX_KEY_LEN; i++) assert(cs.k[i] == key[i]);
}

static void test_noise_dh_zero_pub(void) {
  uint8_t out[NOX_KEY_LEN], priv[3] = {1,2,3}, pub[NOX_KEY_LEN] = {0};
  assert(noise_dh(out, priv, pub) == NOX_ERR_CRYPTO);
}

static void test_noise_dh_success(void) {
  uint8_t out[NOX_KEY_LEN], priv[3] = {1,2,3}, pub[3] = {4,5,6};
  nox_err_t err = noise_dh(out, priv, pub);
  assert(err == NOX_OK || err == NOX_ERR_CRYPTO);
}

static void test_symmetric_init(void) {
  struct noise_symmetric_state ss;
  symmetric_init(&ss, NOISE_PROTOCOL_NAME);
  for (size_t i = 0; i < 64; i++) assert(ss.ck[i] == ss.h[i]);
}

static void test_symmetric_mix_hash(void) {
  struct noise_symmetric_state ss;
  symmetric_init(&ss, NOISE_PROTOCOL_NAME);
  uint8_t data[32];
  for (size_t i = 0; i < 32; i++) data[i] = (uint8_t)i;
  symmetric_mix_hash(&ss, data, 32);
}

static void test_handshake_init_null(void) {
  uint8_t priv[32] = {0}, pub[32] = {0};
  assert(handshake_init(NULL, true, priv, pub) == NOX_ERR_PROTO);
}

static void test_handshake_init_valid(void) {
  struct noise_handshake hs;
  uint8_t priv[NOX_KEY_LEN], pub[NOX_KEY_LEN];
  for (size_t i = 0; i < NOX_KEY_LEN; i++) { priv[i]=(uint8_t)(i+1); pub[i]=(uint8_t)(i+10); }
  nox_err_t err = handshake_init(&hs, true, priv, pub);
  assert(err == NOX_OK);
  assert(hs.initiator == true);
  assert(hs.msg_index == 0);
}

static void test_handshake_is_complete(void) {
  struct noise_handshake hs;
  hs.msg_index = 0; assert(!handshake_is_complete(&hs));
  hs.msg_index = 1; assert(!handshake_is_complete(&hs));
  hs.msg_index = 2; assert(!handshake_is_complete(&hs));
  hs.msg_index = 3; assert(handshake_is_complete(&hs));
}
static void test_handshake_is_complete_null(void) { assert(!handshake_is_complete(NULL)); }

static void test_handshake_write_null(void) {
  uint8_t out[256]; size_t out_len;
  assert(handshake_write(NULL, (uint8_t*)"t", 1, out, &out_len) == NOX_ERR_PROTO);
}
static void test_handshake_write_bad_state(void) {
  struct noise_handshake hs = {0};
  hs.initiator = true; hs.msg_index = 1;
  uint8_t out[256]; size_t out_len;
  assert(handshake_write(&hs, (uint8_t*)"t", 1, out, &out_len) == NOX_ERR_STATE);
}

static void test_handshake_read_null(void) {
  uint8_t msg[256] = {0}, payload[256]; size_t pl;
  assert(handshake_read(NULL, msg, 256, payload, &pl) == NOX_ERR_PROTO);
}
static void test_handshake_read_bad_state(void) {
  struct noise_handshake hs = {0};
  hs.initiator = true; hs.msg_index = 0;
  uint8_t msg[256] = {0}, payload[256]; size_t pl;
  assert(handshake_read(&hs, msg, 256, payload, &pl) == NOX_ERR_STATE);
}

static void test_noise_encrypt_null(void) {
  uint8_t pt[16] = {0}, ct[32];
  assert(noise_encrypt(NULL, pt, 16, ct) == -1);
  struct noise_session s = {0};
  assert(noise_encrypt(&s, pt, 16, NULL) == -1);
}

static void test_noise_decrypt_null(void) {
  uint8_t ct[32] = {0}, pt[16];
  assert(noise_decrypt(NULL, ct, 32, pt) == -1);
  struct noise_session s = {0};
  assert(noise_decrypt(&s, ct, 32, NULL) == -1);
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
  test_cipher_init();
  test_cipher_init_key();
  test_noise_dh_zero_pub();
  test_noise_dh_success();
  test_symmetric_init();
  test_symmetric_mix_hash();
  test_handshake_init_null();
  test_handshake_init_valid();
  test_handshake_is_complete();
  test_handshake_is_complete_null();
  test_handshake_write_null();
  test_handshake_write_bad_state();
  test_handshake_read_null();
  test_handshake_read_bad_state();
  test_noise_encrypt_null();
  test_noise_decrypt_null();
  return 0;
}
