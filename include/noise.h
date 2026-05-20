/* SPDX-License-Identifier: GPL-3.0-or-later
 * noise.h — Noise XX handshake + transport public API
 *
 * Pattern: Noise_XX_25519_ChaChaPoly_BLAKE2b
 *
 * XX handshake 3 mesaj:
 *   → e                           (initiator → responder)
 *   ← e, ee, s, es                (responder → initiator)
 *   → s, se                       (initiator → responder)
 *
 * Handshake bitince iki CipherState döner (tx/rx).
 * Transport: ChaChaPoly-1305 AEAD, 64-bit nonce counter.
 */

#ifndef PARANOID_NOISE_H
#define PARANOID_NOISE_H

#include "types.h"

/* ================================================================
 * NOISE SABİTLERİ
 * ================================================================ */

/* Protokol adı — Initialize'da hash edilir */
#define NOISE_PROTOCOL_NAME \
    "Noise_XX_25519_ChaChaPoly_BLAKE2b"

/* Handshake mesaj limitleri */
#define NOISE_MAX_HANDSHAKE_LEN   256U

/* Transport payload limiti (MAC dahil) */
#define NOISE_MAX_PAYLOAD_LEN     (NOX_MAX_MSG_LEN + NOX_MAC_LEN)

/* ================================================================
 * CIPHER STATE API — Transport encryption
 * ================================================================ */

/*
 * cipher_init — CipherState sıfırla
 * cipher_init_key — Key ile başlat (handshake sonunda çağrılır)
 */
void cipher_init(struct noise_cipher_state *cs);
void cipher_init_key(struct noise_cipher_state *cs,
                     const uint8_t key[NOX_KEY_LEN]);

/*
 * cipher_encrypt — AEAD şifreleme
 *
 * @cs:      CipherState (key + nonce counter)
 * @ad:      Associated data (hash)
 * @ad_len:  AD uzunluğu
 * @plaintext:  Şifrelenecek veri
 * @pt_len:  Plaintext uzunluğu
 * @out:     Çıktı buffer (pt_len + 16 byte MAC)
 *
 * Return: Şifreli veri uzunluğu (pt_len + MAC) veya -1
 */
ssize_t cipher_encrypt(struct noise_cipher_state *cs,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *out);

/*
 * cipher_decrypt — AEAD çözme
 *
 * Return: Plaintext uzunluğu veya -1 (MAC hatası)
 */
ssize_t cipher_decrypt(struct noise_cipher_state *cs,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *out);

/* ================================================================
 * SYMMETRIC STATE API — Handshake sırasında
 * ================================================================ */

/*
 * symmetric_init — SymmetricState başlat
 *
 * Protocol name hash → h, ck
 */
void symmetric_init(struct noise_symmetric_state *ss,
                    const char *protocol_name);

/* MixKey — DH çıktısını chaining key'e karıştır */
void symmetric_mix_key(struct noise_symmetric_state *ss,
                       const uint8_t *input_key_material, size_t len);

/* MixHash — Veriyi handshake hash'e karıştır */
void symmetric_mix_hash(struct noise_symmetric_state *ss,
                        const uint8_t *data, size_t len);

/* EncryptAndHash — Veriyi şifrele + hash'e karıştır */
ssize_t symmetric_encrypt_and_hash(struct noise_symmetric_state *ss,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t *out);

/* DecryptAndHash — Çöz + hash'e karıştır */
ssize_t symmetric_decrypt_and_hash(struct noise_symmetric_state *ss,
                                   const uint8_t *ciphertext, size_t ct_len,
                                   uint8_t *out);

/* Split — Handshake bitince iki CipherState döndür */
void symmetric_split(struct noise_symmetric_state *ss,
                     struct noise_cipher_state *c1,
                     struct noise_cipher_state *c2);

/* ================================================================
 * HANDSHAKE API — XX pattern
 * ================================================================ */

/*
 * handshake_init — HandshakeState başlat
 *
 * @hs:         Boş HandshakeState
 * @initiator:  true = bağlantı kuran taraf
 * @s_priv:     Static private key (32 byte, Curve25519)
 * @s_pub:      Static public key (32 byte)
 */
nox_err_t handshake_init(struct noise_handshake *hs,
                         bool initiator,
                         const uint8_t s_priv[NOX_KEY_LEN],
                         const uint8_t s_pub[NOX_KEY_LEN]);

/*
 * handshake_write — Sonraki handshake mesajını yaz
 *
 * @hs:      Aktif HandshakeState
 * @payload: İsteğe bağlı payload (NULL olabilir)
 * @pl_len:  Payload uzunluğu
 * @out:     Çıktı buffer
 * @out_len: Çıktı buffer boyutu (in), yazılan byte sayısı (out)
 *
 * Return: NOX_OK, NOX_ERR_PROTO (yanlış sıra), NOX_ERR_OVERFLOW
 */
nox_err_t handshake_write(struct noise_handshake *hs,
                          const uint8_t *payload, size_t pl_len,
                          uint8_t *out, size_t *out_len);

/*
 * handshake_read — Gelen handshake mesajını oku
 *
 * @hs:      Aktif HandshakeState
 * @msg:     Gelen mesaj
 * @msg_len: Mesaj uzunluğu
 * @payload_out: Çözülen payload çıktısı
 * @pl_len:  Payload buffer boyutu (in), çözülen byte sayısı (out)
 *
 * Return: NOX_OK, NOX_ERR_AUTH (MAC hatası), NOX_ERR_PROTO
 */
nox_err_t handshake_read(struct noise_handshake *hs,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *payload_out, size_t *pl_len);

/*
 * handshake_is_complete — Handshake tamamlandı mı?
 */
bool handshake_is_complete(const struct noise_handshake *hs);

/*
 * handshake_split — Handshake bitince transport session oluştur
 *
 * @hs:      Tamamlanmış HandshakeState
 * @session: Çıktı — tx/rx CipherState + remote public key
 *
 * Handshake state bu çağrıdan sonra explicit_bzero ile silinir.
 */
nox_err_t handshake_split(struct noise_handshake *hs,
                          struct noise_session *session);

/* ================================================================
 * TRANSPORT API — Handshake sonrası mesajlaşma
 * ================================================================ */

/*
 * noise_encrypt — Transport mesajı şifrele
 *
 * @session:   Aktif session
 * @plaintext: Şifrelenecek mesaj
 * @pt_len:    Plaintext uzunluğu
 * @out:       Çıktı buffer (pt_len + 16 byte MAC)
 *
 * Return: Şifreli veri uzunluğu veya -1
 */
ssize_t noise_encrypt(struct noise_session *session,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *out);

/*
 * noise_decrypt — Transport mesajını çöz
 *
 * Return: Plaintext uzunluğu veya -1
 */
ssize_t noise_decrypt(struct noise_session *session,
                      const uint8_t *ciphertext, size_t ct_len,
                      uint8_t *out);

/* ================================================================
 * TEST-ONLY API — Deterministik handshake (Cacophony vektörleri)
 *
 * Production build'de derlenmez.
 * Yalnızca make test sırasında -DNOISE_TEST_DETERMINISTIC aktif.
 * ================================================================ */
#ifdef NOISE_TEST_DETERMINISTIC

/*
 * handshake_inject_ephemeral — Ephemeral key'i dışarıdan enjekte et
 *
 * Test vektörleriyle deterministik handshake için gerekli.
 * Production'da ephemeral key her zaman rastgele üretilir.
 */
nox_err_t handshake_inject_ephemeral(struct noise_handshake *hs,
                                      const uint8_t e_priv[NOX_KEY_LEN]);

/*
 * handshake_init_with_prologue — Prologue destekli handshake init
 *
 * Cacophony test vektörleri non-empty prologue kullanır ("John Galt").
 * Production'da handshake_init() boş prologue ile çalışır.
 */
nox_err_t handshake_init_with_prologue(struct noise_handshake *hs,
                                        bool initiator,
                                        const uint8_t s_priv[NOX_KEY_LEN],
                                        const uint8_t s_pub[NOX_KEY_LEN],
                                        const uint8_t *prologue,
                                        size_t prologue_len);

#endif /* NOISE_TEST_DETERMINISTIC */

#endif /* PARANOID_NOISE_H */
