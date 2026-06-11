/* SPDX-License-Identifier: GPL-3.0-or-later
 * noise.c — Noise_XX_25519_ChaChaPoly_BLAKE2b implementasyonu
 *
 * Referans: https://noiseprotocol.org/noise.html (Rev 34)
 *
 * Katmanlar (aşağıdan yukarı):
 *   1. CipherState  — ChaChaPoly-1305 AEAD + 64-bit nonce
 *   2. SymmetricState — HKDF(BLAKE2b) + MixKey/MixHash
 *   3. HandshakeState — XX pattern: →e / ←e,ee,s,es / →s,se
 *   4. Transport     — Session-level encrypt/decrypt
 */

#include "noise.h"
#include "asm_utils.h"
#include "common.h"

#include <sodium.h>
#include <stdatomic.h>
#include <string.h>

/* ================================================================
 * DERLEME ZAMANI KONTROLLERİ
 * ================================================================ */
NOX_STATIC_ASSERT(crypto_aead_chacha20poly1305_ietf_KEYBYTES == NOX_KEY_LEN,
                  "ChaChaPoly key boyutu uyumsuz");
NOX_STATIC_ASSERT(crypto_aead_chacha20poly1305_ietf_ABYTES == NOX_MAC_LEN,
                  "ChaChaPoly MAC boyutu uyumsuz");
NOX_STATIC_ASSERT(crypto_scalarmult_curve25519_BYTES == NOX_KEY_LEN,
                  "Curve25519 key boyutu uyumsuz");

/* BLAKE2b hash boyutu — Noise spec: HASHLEN = 64 */
#define NOISE_HASHLEN 64U

/* ================================================================
 * 1. CIPHER STATE — ChaChaPoly-1305 AEAD
 *
 * Noise spec Section 5.1:
 *   k: 32 byte key (veya empty)
 *   n: 64-bit nonce counter
 * ================================================================ */

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

/*
 * Nonce encoding: Noise spec says nonce is 8 bytes.
 * ChaChaPoly IETF nonce is 12 bytes: [4 zero bytes][8-byte LE counter]
 */
static void encode_nonce(uint8_t nonce_out[12], uint64_t n) {
  memset(nonce_out, 0, 4);
  /* Little-endian 8-byte counter */
  for (int i = 0; i < 8; i++)
    nonce_out[4 + i] = (uint8_t)(n >> (8 * i));
}

ssize_t cipher_encrypt(struct noise_cipher_state *cs, const uint8_t *ad,
                       size_t ad_len, const uint8_t *plaintext, size_t pt_len,
                       uint8_t *out) {
  if (!cs->has_key) {
    /* No key → pass through (handshake initial messages) */
    if (plaintext && pt_len > 0)
      memcpy(out, plaintext, pt_len);
    return (ssize_t)pt_len;
  }

  uint64_t current_n = atomic_fetch_add(&cs->n, 1);
  if (current_n >= UINT64_MAX) {
    atomic_store(&cs->n, UINT64_MAX);
    NOX_ERROR(LOG_MOD_NOISE, "nonce counter tükendi — session yenilenmeli");
    return -1;
  }

  uint8_t nonce[12];
  encode_nonce(nonce, current_n);

  unsigned long long ct_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(out, &ct_len, plaintext, pt_len,
                                                ad, ad_len, NULL, nonce,
                                                cs->k) != 0) {
    return -1;
  }

  return (ssize_t)ct_len;
}

ssize_t cipher_decrypt(struct noise_cipher_state *cs, const uint8_t *ad,
                       size_t ad_len, const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *out) {
  if (!cs->has_key) {
    /* No key → pass through */
    if (ciphertext && ct_len > 0)
      memcpy(out, ciphertext, ct_len);
    return (ssize_t)ct_len;
  }

  if (ct_len < NOX_MAC_LEN)
    return -1;

  uint64_t current_n = atomic_fetch_add(&cs->n, 1);
  if (current_n >= UINT64_MAX) {
    atomic_store(&cs->n, UINT64_MAX);
    NOX_ERROR(LOG_MOD_NOISE, "nonce counter tükendi — session yenilenmeli");
    return -1;
  }

  uint8_t nonce[12];
  encode_nonce(nonce, current_n);

  unsigned long long pt_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &pt_len, NULL, ciphertext,
                                                ct_len, ad, ad_len, nonce,
                                                cs->k) != 0) {
    return -1; /* MAC verification failed */
  }

  return (ssize_t)pt_len;
}

/* ================================================================
 * 2. SYMMETRIC STATE
 *
 * Noise spec Section 5.2:
 *   ck: chaining key (HASHLEN bytes)
 *   h:  handshake hash (HASHLEN bytes)
 *   cs: embedded CipherState
 * ================================================================ */

void symmetric_init(struct noise_symmetric_state *ss,
                    const char *protocol_name) {
  size_t name_len = strlen(protocol_name);

  if (name_len <= NOISE_HASHLEN) {
    /* Pad with zeros */
    sodium_memzero(ss->h, NOISE_HASHLEN);
    memcpy(ss->h, protocol_name, name_len);
  } else {
    /* Hash the name */
    crypto_generichash_blake2b(ss->h, NOISE_HASHLEN,
                               (const uint8_t *)protocol_name, name_len, NULL,
                               0);
  }

  memcpy(ss->ck, ss->h, NOISE_HASHLEN);
  cipher_init(&ss->cs);
}

/*
 * MixHash(data): h = HASH(h || data)
 */
void symmetric_mix_hash(struct noise_symmetric_state *ss, const uint8_t *data,
                        size_t len) {
  crypto_generichash_blake2b_state state;
  crypto_generichash_blake2b_init(&state, NULL, 0, NOISE_HASHLEN);
  crypto_generichash_blake2b_update(&state, ss->h, NOISE_HASHLEN);
  crypto_generichash_blake2b_update(&state, data, len);
  crypto_generichash_blake2b_final(&state, ss->h, NOISE_HASHLEN);
}

#define BLAKE2B_BLOCK_SIZE 128U

/*
 * HMAC-BLAKE2b
 *
 * HMAC(k, m) = BLAKE2b((k ⊕ opad) || BLAKE2b((k ⊕ ipad) || m))
 *
 * block_size = 128 byte (BLAKE2b için)
 * key > 128 byte ise önce hash'le, 64 byte'a indir
 */
__attribute__((strub)) static nox_err_t
hmac_blake2b(const uint8_t *key, size_t key_len, const uint8_t *data,
             size_t data_len, uint8_t out[NOISE_HASHLEN]) {
  uint8_t *k = sodium_malloc(BLAKE2B_BLOCK_SIZE);
  uint8_t *ipad = sodium_malloc(BLAKE2B_BLOCK_SIZE);
  uint8_t *opad = sodium_malloc(BLAKE2B_BLOCK_SIZE);
  uint8_t *inner = sodium_malloc(NOISE_HASHLEN);

  if (!k || !ipad || !opad || !inner) {
    if (k) {
      sodium_free(k);
      k = NULL;
    }
    if (ipad) {
      sodium_free(ipad);
      ipad = NULL;
    }
    if (opad) {
      sodium_free(opad);
      opad = NULL;
    }
    if (inner) {
      sodium_free(inner);
      inner = NULL;
    }
    sodium_memzero(out, NOISE_HASHLEN);
    return NOX_ERR_ALLOC;
  }

  /* 1. key normalize */
  memset(k, 0, BLAKE2B_BLOCK_SIZE);
  if (key_len > BLAKE2B_BLOCK_SIZE) {
    crypto_generichash_blake2b(k, NOISE_HASHLEN, key, key_len, NULL, 0);
  } else {
    memcpy(k, key, key_len);
  }

  /* 2. ipad ve opad üret */
  for (size_t i = 0; i < BLAKE2B_BLOCK_SIZE; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }

  /* 3. inner = BLAKE2b(ipad || data) */
  crypto_generichash_blake2b_state st;
  crypto_generichash_blake2b_init(&st, NULL, 0, NOISE_HASHLEN);
  crypto_generichash_blake2b_update(&st, ipad, BLAKE2B_BLOCK_SIZE);
  crypto_generichash_blake2b_update(&st, data, data_len);
  crypto_generichash_blake2b_final(&st, inner, NOISE_HASHLEN);

  /* 4. out = BLAKE2b(opad || inner) */
  crypto_generichash_blake2b_init(&st, NULL, 0, NOISE_HASHLEN);
  crypto_generichash_blake2b_update(&st, opad, BLAKE2B_BLOCK_SIZE);
  crypto_generichash_blake2b_update(&st, inner, NOISE_HASHLEN);
  crypto_generichash_blake2b_final(&st, out, NOISE_HASHLEN);

  /* Temizlik */
  sodium_free(k);
  k = NULL;
  sodium_free(ipad);
  ipad = NULL;
  sodium_free(opad);
  opad = NULL;
  sodium_free(inner);
  inner = NULL;

  return NOX_OK;
}

/*
 * HKDF helper — Noise spec HKDF(ck, input):
 *   temp_key = HMAC-HASH(ck, input)
 *   output1  = HMAC-HASH(temp_key, 0x01)
 *   output2  = HMAC-HASH(temp_key, output1 || 0x02)
 */
static nox_err_t hkdf_blake2b(const uint8_t ck[NOISE_HASHLEN],
                              const uint8_t *ikm, size_t ikm_len,
                              uint8_t out1[NOISE_HASHLEN],
                              uint8_t out2[NOISE_HASHLEN]) {
  uint8_t *temp_key = sodium_malloc(NOISE_HASHLEN);
  uint8_t *buf = sodium_malloc(NOISE_HASHLEN + 1);
  uint8_t byte_01 = 0x01;
  nox_err_t err;

  if (!temp_key || !buf) {
    if (temp_key) {
      sodium_free(temp_key);
      temp_key = NULL;
    }
    if (buf) {
      sodium_free(buf);
      buf = NULL;
    }
    sodium_memzero(out1, NOISE_HASHLEN);
    sodium_memzero(out2, NOISE_HASHLEN);
    return NOX_ERR_ALLOC;
  }

  /* temp_key = HMAC-BLAKE2b(ck, ikm) */
  err = hmac_blake2b(ck, NOISE_HASHLEN, ikm, ikm_len, temp_key);
  if (err != NOX_OK)
    goto cleanup;

  /* output1 = HMAC-BLAKE2b(temp_key, 0x01) */
  err = hmac_blake2b(temp_key, NOISE_HASHLEN, &byte_01, 1, out1);
  if (err != NOX_OK)
    goto cleanup;

  /* output2 = HMAC-BLAKE2b(temp_key, output1 || 0x02) */
  memcpy(buf, out1, NOISE_HASHLEN);
  buf[NOISE_HASHLEN] = 0x02;
  err = hmac_blake2b(temp_key, NOISE_HASHLEN, buf, NOISE_HASHLEN + 1, out2);

cleanup:
  sodium_free(temp_key);
  temp_key = NULL;
  sodium_free(buf);
  buf = NULL;

  if (err != NOX_OK) {
    sodium_memzero(out1, NOISE_HASHLEN);
    sodium_memzero(out2, NOISE_HASHLEN);
  }
  return err;
}

/*
 * MixKey(input_key_material):
 *   ck, temp_k = HKDF(ck, ikm)
 *   InitializeKey(temp_k)
 */
__attribute__((strub)) nox_err_t symmetric_mix_key(struct noise_symmetric_state *ss,
                            const uint8_t *input_key_material, size_t len) {
  uint8_t temp_k[NOISE_HASHLEN];

  nox_err_t err = hkdf_blake2b(ss->ck, input_key_material, len, ss->ck, temp_k);
  if (err != NOX_OK) {
    sodium_memzero(temp_k, sizeof(temp_k));
    return err;
  }

  cipher_init_key(&ss->cs, temp_k);
  sodium_memzero(temp_k, sizeof(temp_k));
  return NOX_OK;
}

/*
 * EncryptAndHash(plaintext):
 *   ciphertext = Encrypt(k, n, h, plaintext)
 *   MixHash(ciphertext)
 *   return ciphertext
 */
ssize_t symmetric_encrypt_and_hash(struct noise_symmetric_state *ss,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t *out) {
  ssize_t ct_len =
      cipher_encrypt(&ss->cs, ss->h, NOISE_HASHLEN, plaintext, pt_len, out);
  if (ct_len < 0)
    return -1;

  symmetric_mix_hash(ss, out, (size_t)ct_len);
  return ct_len;
}

ssize_t symmetric_decrypt_and_hash(struct noise_symmetric_state *ss,
                                   const uint8_t *ciphertext, size_t ct_len,
                                   uint8_t *out) {
  /* 1. ÖNCE DecryptWithAd(h, ciphertext) */
  ssize_t pt_len =
      cipher_decrypt(&ss->cs, ss->h, NOISE_HASHLEN, ciphertext, ct_len, out);

  /* 2. MAC hatası → hata döndür, MixHash yapma, h sıfırlansın */
  if (pt_len < 0) {
    sodium_memzero(ss->h, NOISE_HASHLEN);
    return -1;
  }

  /* 3. Başarılı → SONRA MixHash(ciphertext) */
  symmetric_mix_hash(ss, ciphertext, ct_len);
  return pt_len;
}

/*
 * Split():
 *   temp_k1, temp_k2 = HKDF(ck, "")
 *   c1 = InitializeKey(temp_k1)
 *   c2 = InitializeKey(temp_k2)
 */
__attribute__((strub)) nox_err_t symmetric_split(struct noise_symmetric_state *ss,
                          struct noise_cipher_state *c1,
                          struct noise_cipher_state *c2) {
  uint8_t temp_k1[NOISE_HASHLEN], temp_k2[NOISE_HASHLEN];

  nox_err_t err =
      hkdf_blake2b(ss->ck, (const uint8_t *)"", 0, temp_k1, temp_k2);
  if (err != NOX_OK) {
    sodium_memzero(temp_k1, sizeof(temp_k1));
    sodium_memzero(temp_k2, sizeof(temp_k2));
    return err;
  }

  cipher_init_key(c1, temp_k1);
  cipher_init_key(c2, temp_k2);

  sodium_memzero(temp_k1, sizeof(temp_k1));
  sodium_memzero(temp_k2, sizeof(temp_k2));

  /* ck ve cs artık gerekli değil */
  sodium_memzero(ss->ck, sizeof(ss->ck));
  cipher_init(&ss->cs);
  sodium_memzero(ss->h, sizeof(ss->h));
  return NOX_OK;
}

/* ================================================================
 * 3. HANDSHAKE STATE — XX Pattern
 *
 * XX:
 *   msg0 (I→R): → e
 *   msg1 (R→I): ← e, ee, s, es
 *   msg2 (I→R): → s, se
 * ================================================================ */

/* DH helper — Curve25519
 *
 * Ek kontroller:
 *   1. Karşı tarafın public key'i all-zero ise reddet (weak key)
 *   2. DH çıktısı all-zero ise reddet (small-subgroup / contributory)
 *
 * RFC 7748 §6 modeli: clamp + all-zero output check.
 * Low-order noktaları tek tek blacklist'lemek gerekmez —
 * clamp (multiple of 8) tüm torsion noktalarında output=0 üretir.
 * libsodium ≥1.0.16 crypto_scalarmult zaten identity (0) noktasını
 * reddeder.
 */
static nox_err_t noise_dh(uint8_t out[NOX_KEY_LEN],
                          const uint8_t priv[NOX_KEY_LEN],
                          const uint8_t pub[NOX_KEY_LEN]) {
  /* Weak key kontrolü: all-zero public key → deterministik sıfır çıktı */
  if (sodium_is_zero(pub, NOX_KEY_LEN)) {
    NOX_ERROR(LOG_MOD_NOISE, "DH reddedildi: karşı tarafın public key'i sıfır");
    sodium_memzero(out, NOX_KEY_LEN);
    return NOX_ERR_CRYPTO;
  }

  if (crypto_scalarmult_curve25519(out, priv, pub) != 0) {
    NOX_ERROR(LOG_MOD_NOISE, "DH hesaplaması başarısız");
    sodium_memzero(out, NOX_KEY_LEN);
    return NOX_ERR_CRYPTO;
  }

  /* RFC 7748 §6 contributory behaviour: DH çıktısı sıfır olmamalı.
   * Clamp edilmiş scalar (multiple of 8) tüm torsion noktalarında
   * output=0 üretir; sodium_is_zero() tüm low-order girdileri yakalar. */
  if (sodium_is_zero(out, NOX_KEY_LEN)) {
    NOX_ERROR(LOG_MOD_NOISE,
              "DH reddedildi: paylaşılan sır sıfır (small-subgroup?)");
    return NOX_ERR_CRYPTO;
  }

  return NOX_OK;
}

nox_err_t handshake_init(struct noise_handshake *hs, bool initiator,
                         const uint8_t s_priv[NOX_KEY_LEN],
                         const uint8_t s_pub[NOX_KEY_LEN]) {
  if (!hs || !s_priv || !s_pub)
    return NOX_ERR_PROTO;

  sodium_memzero(hs, sizeof(*hs));

  /* Initialize SymmetricState */
  symmetric_init(&hs->ss, NOISE_PROTOCOL_NAME);

  /* Static keys */
  memcpy(hs->s, s_priv, NOX_KEY_LEN);
  memcpy(hs->s_pub, s_pub, NOX_KEY_LEN);

  hs->initiator = initiator;
  hs->msg_index = 0;

  /* XX pattern has no pre-messages — prologue is used */
  /* MixHash("") — dolu prologue */
  symmetric_mix_hash(&hs->ss, (const uint8_t *)"Mustafa Kemal Atatürk",
                     strlen("Mustafa Kemal Atatürk"));

  NOX_DEBUG(LOG_MOD_NOISE, "handshake başlatıldı (%s)",
            initiator ? "initiator" : "responder");

  return NOX_OK;
}

/* --- msg0: → e --- */
static nox_err_t write_msg0(struct noise_handshake *hs, const uint8_t *payload,
                            size_t pl_len, uint8_t *out, size_t *out_len) {
  size_t offset = 0;

  /* Generate ephemeral key pair */
#ifndef NOISE_TEST_DETERMINISTIC
  crypto_box_curve25519xsalsa20poly1305_keypair(hs->e_pub, hs->e);
#else
  /* Test: inject edilmişse onu kullan, yoksa rastgele üret */
  if (sodium_is_zero(hs->e, NOX_KEY_LEN))
    crypto_box_curve25519xsalsa20poly1305_keypair(hs->e_pub, hs->e);
  else
    crypto_scalarmult_base(hs->e_pub, hs->e);
#endif

  /* → e: send e_pub */
  memcpy(out + offset, hs->e_pub, NOX_KEY_LEN);
  symmetric_mix_hash(&hs->ss, hs->e_pub, NOX_KEY_LEN);
  offset += NOX_KEY_LEN;

  /* payload (unencrypted — no key yet) */
  ssize_t ct =
      symmetric_encrypt_and_hash(&hs->ss, payload, pl_len, out + offset);
  if (ct < 0)
    return NOX_ERR_CRYPTO;
  offset += (size_t)ct;

  *out_len = offset;
  return NOX_OK;
}

/* --- msg1: ← e, ee, s, es --- */
static nox_err_t write_msg1(struct noise_handshake *hs, const uint8_t *payload,
                            size_t pl_len, uint8_t *out, size_t *out_len) {
  size_t offset = 0;
  uint8_t dh_out[NOX_KEY_LEN];
  nox_err_t err;

  /* Generate ephemeral key pair */
#ifndef NOISE_TEST_DETERMINISTIC
  crypto_box_curve25519xsalsa20poly1305_keypair(hs->e_pub, hs->e);
#else
  /* Test: inject edilmişse onu kullan, yoksa rastgele üret */
  if (sodium_is_zero(hs->e, NOX_KEY_LEN)) {
    crypto_box_curve25519xsalsa20poly1305_keypair(hs->e_pub, hs->e);
  } else {
    crypto_scalarmult_base(hs->e_pub, hs->e);
  }
#endif

  /* ← e */
  memcpy(out + offset, hs->e_pub, NOX_KEY_LEN);
  symmetric_mix_hash(&hs->ss, hs->e_pub, NOX_KEY_LEN);
  offset += NOX_KEY_LEN;

  /* ee: DH(e, re) */
  if (noise_dh(dh_out, hs->e, hs->re) != NOX_OK)
    return NOX_ERR_CRYPTO;
  err = symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
  if (err != NOX_OK) {
    sodium_memzero(dh_out, sizeof(dh_out));
    return err;
  }
  sodium_memzero(dh_out, sizeof(dh_out));

  /* s: EncryptAndHash(s_pub) */
  ssize_t ct =
      symmetric_encrypt_and_hash(&hs->ss, hs->s_pub, NOX_KEY_LEN, out + offset);
  if (ct < 0)
    return NOX_ERR_CRYPTO;
  offset += (size_t)ct;

  /* es: DH(s, re) */
  if (noise_dh(dh_out, hs->s, hs->re) != NOX_OK)
    return NOX_ERR_CRYPTO;
  err = symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
  if (err != NOX_OK) {
    sodium_memzero(dh_out, sizeof(dh_out));
    return err;
  }
  sodium_memzero(dh_out, sizeof(dh_out));

  /* payload */
  ct = symmetric_encrypt_and_hash(&hs->ss, payload, pl_len, out + offset);
  if (ct < 0)
    return NOX_ERR_CRYPTO;
  offset += (size_t)ct;

  *out_len = offset;
  return NOX_OK;
}

/* --- msg2: → s, se --- */
static nox_err_t write_msg2(struct noise_handshake *hs, const uint8_t *payload,
                            size_t pl_len, uint8_t *out, size_t *out_len) {
  size_t offset = 0;
  uint8_t dh_out[NOX_KEY_LEN];
  nox_err_t err;

  /* s: EncryptAndHash(s_pub) */
  ssize_t ct =
      symmetric_encrypt_and_hash(&hs->ss, hs->s_pub, NOX_KEY_LEN, out + offset);
  if (ct < 0)
    return NOX_ERR_CRYPTO;
  offset += (size_t)ct;

  /* se: DH(s, re) */
  if (noise_dh(dh_out, hs->s, hs->re) != NOX_OK)
    return NOX_ERR_CRYPTO;
  err = symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
  if (err != NOX_OK) {
    sodium_memzero(dh_out, sizeof(dh_out));
    return err;
  }
  sodium_memzero(dh_out, sizeof(dh_out));

  /* payload */
  ct = symmetric_encrypt_and_hash(&hs->ss, payload, pl_len, out + offset);
  if (ct < 0)
    return NOX_ERR_CRYPTO;
  offset += (size_t)ct;

  *out_len = offset;
  return NOX_OK;
}

nox_err_t handshake_write(struct noise_handshake *hs, const uint8_t *payload,
                          size_t pl_len, uint8_t *out, size_t *out_len) {
  if (!hs || !out || !out_len)
    return NOX_ERR_PROTO;
  if (!payload)
    pl_len = 0;

  nox_err_t err;

  if (hs->initiator) {
    switch (hs->msg_index) {
    case 0:
      err = write_msg0(hs, payload, pl_len, out, out_len);
      break;
    case 2:
      err = write_msg2(hs, payload, pl_len, out, out_len);
      break;
    default:
      return NOX_ERR_STATE;
    }
  } else {
    switch (hs->msg_index) {
    case 1:
      err = write_msg1(hs, payload, pl_len, out, out_len);
      break;
    default:
      return NOX_ERR_STATE;
    }
  }

  if (err == NOX_OK)
    hs->msg_index++;
  return err;
}

/* --- read msg0: → e --- */
static nox_err_t read_msg0(struct noise_handshake *hs, const uint8_t *msg,
                           size_t msg_len, uint8_t *payload_out,
                           size_t *pl_len) {
  if (msg_len < NOX_KEY_LEN)
    return NOX_ERR_PROTO;
  size_t offset = 0;

  /* re = msg[0..32] */
  memcpy(hs->re, msg + offset, NOX_KEY_LEN);
  symmetric_mix_hash(&hs->ss, hs->re, NOX_KEY_LEN);
  offset += NOX_KEY_LEN;

  /* payload */
  ssize_t pt = symmetric_decrypt_and_hash(&hs->ss, msg + offset,
                                          msg_len - offset, payload_out);
  if (pt < 0)
    return NOX_ERR_AUTH;
  *pl_len = (size_t)pt;

  return NOX_OK;
}

/* --- read msg1: ← e, ee, s, es --- */
static nox_err_t read_msg1(struct noise_handshake *hs, const uint8_t *msg,
                           size_t msg_len, uint8_t *payload_out,
                           size_t *pl_len) {
  if (msg_len < NOX_KEY_LEN + NOX_KEY_LEN + NOX_MAC_LEN)
    return NOX_ERR_PROTO;
  size_t offset = 0;
  uint8_t dh_out[NOX_KEY_LEN];
  nox_err_t err;

  /* re */
  memcpy(hs->re, msg + offset, NOX_KEY_LEN);
  symmetric_mix_hash(&hs->ss, hs->re, NOX_KEY_LEN);
  offset += NOX_KEY_LEN;

  /* ee: DH(e, re) */
  if (noise_dh(dh_out, hs->e, hs->re) != NOX_OK)
    return NOX_ERR_CRYPTO;
  err = symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
  if (err != NOX_OK) {
    sodium_memzero(dh_out, sizeof(dh_out));
    return err;
  }
  sodium_memzero(dh_out, sizeof(dh_out));

  /* s: DecryptAndHash → rs */
  ssize_t pt = symmetric_decrypt_and_hash(&hs->ss, msg + offset,
                                          NOX_KEY_LEN + NOX_MAC_LEN, hs->rs);
  if (pt < 0)
    return NOX_ERR_AUTH;
  offset += NOX_KEY_LEN + NOX_MAC_LEN;

  /* es: DH(e, rs) */
  if (noise_dh(dh_out, hs->e, hs->rs) != NOX_OK)
    return NOX_ERR_CRYPTO;
  err = symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
  if (err != NOX_OK) {
    sodium_memzero(dh_out, sizeof(dh_out));
    return err;
  }
  sodium_memzero(dh_out, sizeof(dh_out));

  /* payload */
  pt = symmetric_decrypt_and_hash(&hs->ss, msg + offset, msg_len - offset,
                                  payload_out);
  if (pt < 0)
    return NOX_ERR_AUTH;
  *pl_len = (size_t)pt;

  return NOX_OK;
}

/* --- read msg2: → s, se --- */
static nox_err_t read_msg2(struct noise_handshake *hs, const uint8_t *msg,
                           size_t msg_len, uint8_t *payload_out,
                           size_t *pl_len) {
  if (msg_len < NOX_KEY_LEN + NOX_MAC_LEN)
    return NOX_ERR_PROTO;
  size_t offset = 0;
  uint8_t dh_out[NOX_KEY_LEN];
  nox_err_t err;

  /* s: DecryptAndHash → rs */
  ssize_t pt = symmetric_decrypt_and_hash(&hs->ss, msg + offset,
                                          NOX_KEY_LEN + NOX_MAC_LEN, hs->rs);
  if (pt < 0)
    return NOX_ERR_AUTH;
  offset += NOX_KEY_LEN + NOX_MAC_LEN;

  /* se: DH(e, rs) */
  if (noise_dh(dh_out, hs->e, hs->rs) != NOX_OK)
    return NOX_ERR_CRYPTO;
  err = symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
  if (err != NOX_OK) {
    sodium_memzero(dh_out, sizeof(dh_out));
    return err;
  }
  sodium_memzero(dh_out, sizeof(dh_out));

  /* payload */
  pt = symmetric_decrypt_and_hash(&hs->ss, msg + offset, msg_len - offset,
                                  payload_out);
  if (pt < 0)
    return NOX_ERR_AUTH;
  *pl_len = (size_t)pt;

  return NOX_OK;
}

nox_err_t handshake_read(struct noise_handshake *hs, const uint8_t *msg,
                         size_t msg_len, uint8_t *payload_out, size_t *pl_len) {
  if (!hs || !msg || !pl_len)
    return NOX_ERR_PROTO;
  if (!payload_out)
    return NOX_ERR_PROTO;

  nox_err_t err;

  if (hs->initiator) {
    switch (hs->msg_index) {
    case 1:
      err = read_msg1(hs, msg, msg_len, payload_out, pl_len);
      /* Initiator: read_msg1 sonrası hs->e artık kullanılmaz — sil */
      if (err == NOX_OK)
        sodium_memzero(hs->e, NOX_KEY_LEN);
      break;
    default:
      return NOX_ERR_STATE;
    }
  } else {
    switch (hs->msg_index) {
    case 0:
      err = read_msg0(hs, msg, msg_len, payload_out, pl_len);
      break;
    case 2:
      err = read_msg2(hs, msg, msg_len, payload_out, pl_len);
      /* Responder: read_msg2 sonrası hs->e artık kullanılmaz — sil */
      if (err == NOX_OK)
        sodium_memzero(hs->e, NOX_KEY_LEN);
      break;
    default:
      return NOX_ERR_STATE;
    }
  }

  if (err == NOX_OK)
    hs->msg_index++;
  return err;
}

bool handshake_is_complete(const struct noise_handshake *hs) {
  return hs && hs->msg_index >= 3;
}

nox_err_t handshake_split(struct noise_handshake *hs,
                          struct noise_session *session) {
  if (!hs || !session)
    return NOX_ERR_PROTO;
  if (!handshake_is_complete(hs))
    return NOX_ERR_STATE;

  nox_err_t err;
  if (hs->initiator) {
    err = symmetric_split(&hs->ss, &session->tx, &session->rx);
  } else {
    err = symmetric_split(&hs->ss, &session->rx, &session->tx);
  }
  if (err != NOX_OK)
    return err;

  memcpy(session->remote_static, hs->rs, NOX_KEY_LEN);

  /* Ephemeral key'leri sil */
  sodium_memzero(hs->e, NOX_KEY_LEN);
  sodium_memzero(hs->e_pub, NOX_KEY_LEN);
  sodium_memzero(hs->s, NOX_KEY_LEN);
  sodium_memzero(hs->s_pub, NOX_KEY_LEN);
  sodium_memzero(hs->re, NOX_KEY_LEN);
  sodium_memzero(hs->rs, NOX_KEY_LEN);
  atomic_thread_fence(memory_order_seq_cst);

  NOX_INFO(LOG_MOD_NOISE, "handshake tamamlandı — transport hazır");
  return NOX_OK;
}

/* ================================================================
 * 4. TRANSPORT — Session-level encrypt/decrypt
 * ================================================================ */

ssize_t noise_encrypt(struct noise_session *session, const uint8_t *plaintext,
                      size_t pt_len, uint8_t *out) {
  if (!session || !out)
    return -1;
  return cipher_encrypt(&session->tx, NULL, 0, plaintext, pt_len, out);
}

ssize_t noise_decrypt(struct noise_session *session, const uint8_t *ciphertext,
                      size_t ct_len, uint8_t *out) {
  if (!session || !out)
    return -1;
  return cipher_decrypt(&session->rx, NULL, 0, ciphertext, ct_len, out);
}

/* ================================================================
 * 5. TEST-ONLY — Deterministik handshake (Cacophony vektörleri)
 *
 * -DNOISE_TEST_DETERMINISTIC olmadan derlenmez.
 * ================================================================ */
#ifdef NOISE_TEST_DETERMINISTIC

nox_err_t handshake_inject_ephemeral(struct noise_handshake *hs,
                                     const uint8_t e_priv[NOX_KEY_LEN]) {
  if (!hs || !e_priv)
    return NOX_ERR_PROTO;
  memcpy(hs->e, e_priv, NOX_KEY_LEN);
  /* e_pub = scalar_mult(e_priv, basepoint) */
  crypto_scalarmult_base(hs->e_pub, hs->e);
  return NOX_OK;
}

nox_err_t handshake_init_with_prologue(struct noise_handshake *hs,
                                       bool initiator,
                                       const uint8_t s_priv[NOX_KEY_LEN],
                                       const uint8_t s_pub[NOX_KEY_LEN],
                                       const uint8_t *prologue,
                                       size_t prologue_len) {
  if (!hs || !s_priv || !s_pub)
    return NOX_ERR_PROTO;

  sodium_memzero(hs, sizeof(*hs));
  symmetric_init(&hs->ss, NOISE_PROTOCOL_NAME);

  memcpy(hs->s, s_priv, NOX_KEY_LEN);
  memcpy(hs->s_pub, s_pub, NOX_KEY_LEN);

  hs->initiator = initiator;
  hs->msg_index = 0;

  /* Prologue — Cacophony vektörlerinde "John Galt" */
  symmetric_mix_hash(&hs->ss, prologue, prologue_len);

  NOX_DEBUG(LOG_MOD_NOISE, "handshake başlatıldı (%s, prologue=%zu byte)",
            initiator ? "initiator" : "responder", prologue_len);

  return NOX_OK;
}

void handshake_get_h(const struct noise_handshake *hs, uint8_t out[64]) {
  memcpy(out, hs->ss.h, 64);
}

void handshake_get_ck(const struct noise_handshake *hs, uint8_t out[64]) {
  memcpy(out, hs->ss.ck, 64);
}

void handshake_get_k(const struct noise_handshake *hs, uint8_t out[32]) {
  memcpy(out, hs->ss.cs.k, 32);
}

#endif /* NOISE_TEST_DETERMINISTIC */
