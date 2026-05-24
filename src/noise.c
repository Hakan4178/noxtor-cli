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
#include "common.h"
#include "asm_utils.h"

#include <string.h>
#include <sodium.h>
#include <stdatomic.h>

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
#define NOISE_HASHLEN  64U

/* ================================================================
 * 1. CIPHER STATE — ChaChaPoly-1305 AEAD
 *
 * Noise spec Section 5.1:
 *   k: 32 byte key (veya empty)
 *   n: 64-bit nonce counter
 * ================================================================ */

void cipher_init(struct noise_cipher_state *cs)
{
    explicit_bzero(cs, sizeof(*cs));
    cs->has_key = false;
    cs->n = 0;
}

void cipher_init_key(struct noise_cipher_state *cs,
                     const uint8_t key[NOX_KEY_LEN])
{
    memcpy(cs->k, key, NOX_KEY_LEN);
    cs->n = 0;
    cs->has_key = true;
}

/*
 * Nonce encoding: Noise spec says nonce is 8 bytes.
 * ChaChaPoly IETF nonce is 12 bytes: [4 zero bytes][8-byte LE counter]
 */
static void encode_nonce(uint8_t nonce_out[12], uint64_t n)
{
    memset(nonce_out, 0, 4);
    /* Little-endian 8-byte counter */
    for (int i = 0; i < 8; i++)
        nonce_out[4 + i] = (uint8_t)(n >> (8 * i));
}

ssize_t cipher_encrypt(struct noise_cipher_state *cs,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *out)
{
    if (!cs->has_key) {
        /* No key → pass through (handshake initial messages) */
        if (plaintext && pt_len > 0)
            memcpy(out, plaintext, pt_len);
        return (ssize_t)pt_len;
    }

    if (cs->n == UINT64_MAX) {
        NOX_ERROR(LOG_MOD_NOISE, "nonce counter tükendi — session yenilenmeli");
        return -1;
    }

    uint8_t nonce[12];
    encode_nonce(nonce, cs->n);

    unsigned long long ct_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            out, &ct_len,
            plaintext, pt_len,
            ad, ad_len,
            NULL, nonce, cs->k) != 0) {
        return -1;
    }

    cs->n++;
    return (ssize_t)ct_len;
}

ssize_t cipher_decrypt(struct noise_cipher_state *cs,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *out)
{
    if (!cs->has_key) {
        /* No key → pass through */
        if (ciphertext && ct_len > 0)
            memcpy(out, ciphertext, ct_len);
        return (ssize_t)ct_len;
    }

    if (ct_len < NOX_MAC_LEN)
        return -1;

    if (cs->n == UINT64_MAX) {
        NOX_ERROR(LOG_MOD_NOISE, "nonce counter tükendi — session yenilenmeli");
        return -1;
    }

    uint8_t nonce[12];
    encode_nonce(nonce, cs->n);

    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &pt_len,
            NULL,
            ciphertext, ct_len,
            ad, ad_len,
            nonce, cs->k) != 0) {
        return -1;  /* MAC verification failed */
    }

    cs->n++;
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
                    const char *protocol_name)
{
    size_t name_len = strlen(protocol_name);

    if (name_len <= NOISE_HASHLEN) {
        /* Pad with zeros */
        memset(ss->h, 0, NOISE_HASHLEN);
        memcpy(ss->h, protocol_name, name_len);
    } else {
        /* Hash the name */
        crypto_generichash_blake2b(ss->h, NOISE_HASHLEN,
                                   (const uint8_t *)protocol_name, name_len,
                                   NULL, 0);
    }

    memcpy(ss->ck, ss->h, NOISE_HASHLEN);
    cipher_init(&ss->cs);
}

/*
 * MixHash(data): h = HASH(h || data)
 */
void symmetric_mix_hash(struct noise_symmetric_state *ss,
                        const uint8_t *data, size_t len)
{
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
__attribute__((strub))
static void hmac_blake2b(const uint8_t *key,   size_t key_len,
                         const uint8_t *data,  size_t data_len,
                         uint8_t        out[NOISE_HASHLEN])
{
    uint8_t k[BLAKE2B_BLOCK_SIZE];
    uint8_t ipad[BLAKE2B_BLOCK_SIZE];
    uint8_t opad[BLAKE2B_BLOCK_SIZE];
    uint8_t inner[NOISE_HASHLEN];

    /* 1. key normalize */
    memset(k, 0, sizeof(k));
    if (key_len > BLAKE2B_BLOCK_SIZE) {
        crypto_generichash_blake2b(k, NOISE_HASHLEN,
                                   key, key_len,
                                   NULL, 0);
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
    sodium_memzero(k,     sizeof(k));
    sodium_memzero(ipad,  sizeof(ipad));
    sodium_memzero(opad,  sizeof(opad));
    sodium_memzero(inner, sizeof(inner));
}

/*
 * HKDF helper — Noise spec HKDF(ck, input):
 *   temp_key = HMAC-HASH(ck, input)
 *   output1  = HMAC-HASH(temp_key, 0x01)
 *   output2  = HMAC-HASH(temp_key, output1 || 0x02)
 */
static void hkdf_blake2b(const uint8_t ck[NOISE_HASHLEN],
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t out1[NOISE_HASHLEN],
                         uint8_t out2[NOISE_HASHLEN])
{
    uint8_t temp_key[NOISE_HASHLEN];
    uint8_t buf[NOISE_HASHLEN + 1];

    /* temp_key = HMAC-BLAKE2b(ck, ikm) */
    hmac_blake2b(ck, NOISE_HASHLEN, ikm, ikm_len, temp_key);

    /* output1 = HMAC-BLAKE2b(temp_key, 0x01) */
    uint8_t byte_01 = 0x01;
    hmac_blake2b(temp_key, NOISE_HASHLEN, &byte_01, 1, out1);

    /* output2 = HMAC-BLAKE2b(temp_key, output1 || 0x02) */
    memcpy(buf, out1, NOISE_HASHLEN);
    buf[NOISE_HASHLEN] = 0x02;
    hmac_blake2b(temp_key, NOISE_HASHLEN, buf, sizeof(buf), out2);

    explicit_bzero(temp_key, sizeof(temp_key));
    explicit_bzero(buf, sizeof(buf));
}

/*
 * MixKey(input_key_material):
 *   ck, temp_k = HKDF(ck, ikm)
 *   InitializeKey(temp_k)
 */
void symmetric_mix_key(struct noise_symmetric_state *ss,
                       const uint8_t *input_key_material, size_t len)
{
    uint8_t temp_k[NOISE_HASHLEN];

    hkdf_blake2b(ss->ck, input_key_material, len,
                 ss->ck, temp_k);

    cipher_init_key(&ss->cs, temp_k);
    explicit_bzero(temp_k, sizeof(temp_k));
}

/*
 * EncryptAndHash(plaintext):
 *   ciphertext = Encrypt(k, n, h, plaintext)
 *   MixHash(ciphertext)
 *   return ciphertext
 */
ssize_t symmetric_encrypt_and_hash(struct noise_symmetric_state *ss,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t *out)
{
    ssize_t ct_len = cipher_encrypt(&ss->cs,
                                    ss->h, NOISE_HASHLEN,
                                    plaintext, pt_len,
                                    out);
    if (ct_len < 0)
        return -1;

    symmetric_mix_hash(ss, out, (size_t)ct_len);
    return ct_len;
}

/*
 * DecryptAndHash(ciphertext):
 *   plaintext = Decrypt(k, n, h, ciphertext)
 *   MixHash(ciphertext)
 *   return plaintext
 */
ssize_t symmetric_decrypt_and_hash(struct noise_symmetric_state *ss,
                                   const uint8_t *ciphertext, size_t ct_len,
                                   uint8_t *out)
{
    /* MixHash ciphertext'i kullanır — çözmeden önce hash'e ekle */
    uint8_t h_backup[NOISE_HASHLEN];
    memcpy(h_backup, ss->h, NOISE_HASHLEN);

    symmetric_mix_hash(ss, ciphertext, ct_len);

    ssize_t pt_len = cipher_decrypt(&ss->cs,
                                    h_backup, NOISE_HASHLEN,
                                    ciphertext, ct_len,
                                    out);

    explicit_bzero(h_backup, sizeof(h_backup));

    if (pt_len < 0) {
        /* MAC failed — h durumu bozulmuş, ama handshake zaten abort */
        return -1;
    }

    return pt_len;
}

/*
 * Split():
 *   temp_k1, temp_k2 = HKDF(ck, "")
 *   c1 = InitializeKey(temp_k1)
 *   c2 = InitializeKey(temp_k2)
 */
void symmetric_split(struct noise_symmetric_state *ss,
                     struct noise_cipher_state *c1,
                     struct noise_cipher_state *c2)
{
    uint8_t temp_k1[NOISE_HASHLEN], temp_k2[NOISE_HASHLEN];

    hkdf_blake2b(ss->ck, (const uint8_t *)"", 0, temp_k1, temp_k2);

    cipher_init_key(c1, temp_k1);
    cipher_init_key(c2, temp_k2);

    explicit_bzero(temp_k1, sizeof(temp_k1));
    explicit_bzero(temp_k2, sizeof(temp_k2));

    /* ck ve cs artık gerekli değil */
    explicit_bzero(ss->ck, sizeof(ss->ck));
    cipher_init(&ss->cs);
}

/* ================================================================
 * 3. HANDSHAKE STATE — XX Pattern
 *
 * XX:
 *   msg0 (I→R): → e
 *   msg1 (R→I): ← e, ee, s, es
 *   msg2 (I→R): → s, se
 * ================================================================ */

/* DH helper — Curve25519 */
static nox_err_t noise_dh(uint8_t out[NOX_KEY_LEN],
                           const uint8_t priv[NOX_KEY_LEN],
                           const uint8_t pub[NOX_KEY_LEN])
{
    if (crypto_scalarmult_curve25519(out, priv, pub) != 0) {
        NOX_ERROR(LOG_MOD_NOISE, "DH hesaplaması başarısız");
        return NOX_ERR_CRYPTO;
    }
    return NOX_OK;
}

nox_err_t handshake_init(struct noise_handshake *hs,
                         bool initiator,
                         const uint8_t s_priv[NOX_KEY_LEN],
                         const uint8_t s_pub[NOX_KEY_LEN])
{
    if (!hs || !s_priv || !s_pub)
        return NOX_ERR_PROTO;

    explicit_bzero(hs, sizeof(*hs));

    /* Initialize SymmetricState */
    symmetric_init(&hs->ss, NOISE_PROTOCOL_NAME);

    /* Static keys */
    memcpy(hs->s, s_priv, NOX_KEY_LEN);
    memcpy(hs->s_pub, s_pub, NOX_KEY_LEN);

    hs->initiator = initiator;
    hs->msg_index = 0;

    /* XX pattern has no pre-messages — prologue is empty */
    /* MixHash("") — boş prologue */
    symmetric_mix_hash(&hs->ss, (const uint8_t *)"", 0);

    NOX_DEBUG(LOG_MOD_NOISE, "handshake başlatıldı (%s)",
              initiator ? "initiator" : "responder");

    return NOX_OK;
}

/* --- msg0: → e --- */
static nox_err_t write_msg0(struct noise_handshake *hs,
                             const uint8_t *payload, size_t pl_len,
                             uint8_t *out, size_t *out_len)
{
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
    ssize_t ct = symmetric_encrypt_and_hash(&hs->ss,
                                            payload, pl_len,
                                            out + offset);
    if (ct < 0) return NOX_ERR_CRYPTO;
    offset += (size_t)ct;

    *out_len = offset;
    return NOX_OK;
}

/* --- msg1: ← e, ee, s, es --- */
static nox_err_t write_msg1(struct noise_handshake *hs,
                             const uint8_t *payload, size_t pl_len,
                             uint8_t *out, size_t *out_len)
{
    size_t offset = 0;
    uint8_t dh_out[NOX_KEY_LEN];

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

    /* ← e */
    memcpy(out + offset, hs->e_pub, NOX_KEY_LEN);
    symmetric_mix_hash(&hs->ss, hs->e_pub, NOX_KEY_LEN);
    offset += NOX_KEY_LEN;

    /* ee: DH(e, re) */
    if (noise_dh(dh_out, hs->e, hs->re) != NOX_OK) return NOX_ERR_CRYPTO;
    symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
    explicit_bzero(dh_out, sizeof(dh_out));

    /* s: EncryptAndHash(s_pub) */
    ssize_t ct = symmetric_encrypt_and_hash(&hs->ss,
                                            hs->s_pub, NOX_KEY_LEN,
                                            out + offset);
    if (ct < 0) return NOX_ERR_CRYPTO;
    offset += (size_t)ct;

    /* es: DH(s, re) */
    if (noise_dh(dh_out, hs->s, hs->re) != NOX_OK) return NOX_ERR_CRYPTO;
    symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
    explicit_bzero(dh_out, sizeof(dh_out));

    /* payload */
    ct = symmetric_encrypt_and_hash(&hs->ss, payload, pl_len, out + offset);
    if (ct < 0) return NOX_ERR_CRYPTO;
    offset += (size_t)ct;

    *out_len = offset;
    return NOX_OK;
}

/* --- msg2: → s, se --- */
static nox_err_t write_msg2(struct noise_handshake *hs,
                             const uint8_t *payload, size_t pl_len,
                             uint8_t *out, size_t *out_len)
{
    size_t offset = 0;
    uint8_t dh_out[NOX_KEY_LEN];

    /* s: EncryptAndHash(s_pub) */
    ssize_t ct = symmetric_encrypt_and_hash(&hs->ss,
                                            hs->s_pub, NOX_KEY_LEN,
                                            out + offset);
    if (ct < 0) return NOX_ERR_CRYPTO;
    offset += (size_t)ct;

    /* se: DH(s, re) */
    if (noise_dh(dh_out, hs->s, hs->re) != NOX_OK) return NOX_ERR_CRYPTO;
    symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
    explicit_bzero(dh_out, sizeof(dh_out));

    /* payload */
    ct = symmetric_encrypt_and_hash(&hs->ss, payload, pl_len, out + offset);
    if (ct < 0) return NOX_ERR_CRYPTO;
    offset += (size_t)ct;

    *out_len = offset;
    return NOX_OK;
}

nox_err_t handshake_write(struct noise_handshake *hs,
                          const uint8_t *payload, size_t pl_len,
                          uint8_t *out, size_t *out_len)
{
    if (!hs || !out || !out_len) return NOX_ERR_PROTO;
    if (!payload) pl_len = 0;

    nox_err_t err;

    if (hs->initiator) {
        switch (hs->msg_index) {
        case 0: err = write_msg0(hs, payload, pl_len, out, out_len); break;
        case 2: err = write_msg2(hs, payload, pl_len, out, out_len); break;
        default: return NOX_ERR_STATE;
        }
    } else {
        switch (hs->msg_index) {
        case 1: err = write_msg1(hs, payload, pl_len, out, out_len); break;
        default: return NOX_ERR_STATE;
        }
    }

    if (err == NOX_OK) hs->msg_index++;
    return err;
}

/* --- read msg0: → e --- */
static nox_err_t read_msg0(struct noise_handshake *hs,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *payload_out, size_t *pl_len)
{
    if (msg_len < NOX_KEY_LEN) return NOX_ERR_PROTO;
    size_t offset = 0;

    /* re = msg[0..32] */
    memcpy(hs->re, msg + offset, NOX_KEY_LEN);
    symmetric_mix_hash(&hs->ss, hs->re, NOX_KEY_LEN);
    offset += NOX_KEY_LEN;

    /* payload */
    ssize_t pt = symmetric_decrypt_and_hash(&hs->ss,
                                            msg + offset, msg_len - offset,
                                            payload_out);
    if (pt < 0) return NOX_ERR_AUTH;
    *pl_len = (size_t)pt;

    return NOX_OK;
}

/* --- read msg1: ← e, ee, s, es --- */
static nox_err_t read_msg1(struct noise_handshake *hs,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *payload_out, size_t *pl_len)
{
    if (msg_len < NOX_KEY_LEN + NOX_KEY_LEN + NOX_MAC_LEN) return NOX_ERR_PROTO;
    size_t offset = 0;
    uint8_t dh_out[NOX_KEY_LEN];

    /* re */
    memcpy(hs->re, msg + offset, NOX_KEY_LEN);
    symmetric_mix_hash(&hs->ss, hs->re, NOX_KEY_LEN);
    offset += NOX_KEY_LEN;

    /* ee: DH(e, re) */
    if (noise_dh(dh_out, hs->e, hs->re) != NOX_OK) return NOX_ERR_CRYPTO;
    symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
    explicit_bzero(dh_out, sizeof(dh_out));

    /* s: DecryptAndHash → rs */
    ssize_t pt = symmetric_decrypt_and_hash(&hs->ss,
                                            msg + offset, NOX_KEY_LEN + NOX_MAC_LEN,
                                            hs->rs);
    if (pt < 0) return NOX_ERR_AUTH;
    offset += NOX_KEY_LEN + NOX_MAC_LEN;

    /* es: DH(e, rs) */
    if (noise_dh(dh_out, hs->e, hs->rs) != NOX_OK) return NOX_ERR_CRYPTO;
    symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
    explicit_bzero(dh_out, sizeof(dh_out));

    /* payload */
    pt = symmetric_decrypt_and_hash(&hs->ss,
                                    msg + offset, msg_len - offset,
                                    payload_out);
    if (pt < 0) return NOX_ERR_AUTH;
    *pl_len = (size_t)pt;

    return NOX_OK;
}

/* --- read msg2: → s, se --- */
static nox_err_t read_msg2(struct noise_handshake *hs,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *payload_out, size_t *pl_len)
{
    if (msg_len < NOX_KEY_LEN + NOX_MAC_LEN) return NOX_ERR_PROTO;
    size_t offset = 0;
    uint8_t dh_out[NOX_KEY_LEN];

    /* s: DecryptAndHash → rs */
    ssize_t pt = symmetric_decrypt_and_hash(&hs->ss,
                                            msg + offset, NOX_KEY_LEN + NOX_MAC_LEN,
                                            hs->rs);
    if (pt < 0) return NOX_ERR_AUTH;
    offset += NOX_KEY_LEN + NOX_MAC_LEN;

    /* se: DH(e, rs) */
    if (noise_dh(dh_out, hs->e, hs->rs) != NOX_OK) return NOX_ERR_CRYPTO;
    symmetric_mix_key(&hs->ss, dh_out, NOX_KEY_LEN);
    explicit_bzero(dh_out, sizeof(dh_out));

    /* payload */
    pt = symmetric_decrypt_and_hash(&hs->ss,
                                    msg + offset, msg_len - offset,
                                    payload_out);
    if (pt < 0) return NOX_ERR_AUTH;
    *pl_len = (size_t)pt;

    return NOX_OK;
}

nox_err_t handshake_read(struct noise_handshake *hs,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *payload_out, size_t *pl_len)
{
    if (!hs || !msg || !pl_len) return NOX_ERR_PROTO;
    if (!payload_out) { size_t dummy = 0; pl_len = &dummy; }

    nox_err_t err;

    if (hs->initiator) {
        switch (hs->msg_index) {
        case 1: err = read_msg1(hs, msg, msg_len, payload_out, pl_len); break;
        default: return NOX_ERR_STATE;
        }
    } else {
        switch (hs->msg_index) {
        case 0: err = read_msg0(hs, msg, msg_len, payload_out, pl_len); break;
        case 2: err = read_msg2(hs, msg, msg_len, payload_out, pl_len); break;
        default: return NOX_ERR_STATE;
        }
    }

    if (err == NOX_OK) hs->msg_index++;
    return err;
}

bool handshake_is_complete(const struct noise_handshake *hs)
{
    return hs && hs->msg_index >= 3;
}

nox_err_t handshake_split(struct noise_handshake *hs,
                          struct noise_session *session)
{
    if (!hs || !session) return NOX_ERR_PROTO;
    if (!handshake_is_complete(hs)) return NOX_ERR_STATE;

    if (hs->initiator) {
        symmetric_split(&hs->ss, &session->tx, &session->rx);
    } else {
        symmetric_split(&hs->ss, &session->rx, &session->tx);
    }

    memcpy(session->remote_static, hs->rs, NOX_KEY_LEN);

    /* Ephemeral key'leri sil */
    explicit_bzero(hs->e, NOX_KEY_LEN);
    explicit_bzero(hs->e_pub, NOX_KEY_LEN);
    explicit_bzero(hs->s,     NOX_KEY_LEN);  
    explicit_bzero(hs->s_pub, NOX_KEY_LEN);  
    explicit_bzero(hs->re,    NOX_KEY_LEN);  
    explicit_bzero(hs->rs,    NOX_KEY_LEN);  
    atomic_thread_fence(memory_order_seq_cst); 

    NOX_INFO(LOG_MOD_NOISE, "handshake tamamlandı — transport hazır");
    return NOX_OK;
}

/* ================================================================
 * 4. TRANSPORT — Session-level encrypt/decrypt
 * ================================================================ */

ssize_t noise_encrypt(struct noise_session *session,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *out)
{
    if (!session || !out) return -1;
    return cipher_encrypt(&session->tx, NULL, 0, plaintext, pt_len, out);
}

ssize_t noise_decrypt(struct noise_session *session,
                      const uint8_t *ciphertext, size_t ct_len,
                      uint8_t *out)
{
    if (!session || !out) return -1;
    return cipher_decrypt(&session->rx, NULL, 0, ciphertext, ct_len, out);
}

/* ================================================================
 * 5. TEST-ONLY — Deterministik handshake (Cacophony vektörleri)
 *
 * -DNOISE_TEST_DETERMINISTIC olmadan derlenmez.
 * ================================================================ */
#ifdef NOISE_TEST_DETERMINISTIC

nox_err_t handshake_inject_ephemeral(struct noise_handshake *hs,
                                      const uint8_t e_priv[NOX_KEY_LEN])
{
    if (!hs || !e_priv) return NOX_ERR_PROTO;
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
                                        size_t prologue_len)
{
    if (!hs || !s_priv || !s_pub) return NOX_ERR_PROTO;

    explicit_bzero(hs, sizeof(*hs));
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

#endif /* NOISE_TEST_DETERMINISTIC */
