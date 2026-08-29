/* SPDX-License-Identifier: GPL-3.0-or-later
 * crypto.h — noxtor-cli kriptografi katmanı public API
 *
 * İçerik:
 *   - libsodium global init
 *   - Temel crypto wrapper'lar (random, hash)
 *   - PIN → Argon2id → master_key → subkeys derivation
 *   - Identity key yönetimi (disk'e yaz/oku, secretbox ile şifreli)
 *   - Noise XX handshake ve transport API (ayrı dosyada: noise.c)
 */

#ifndef PARANOID_CRYPTO_H
#define PARANOID_CRYPTO_H

#include "types.h"

/* ================================================================
 * GLOBAL INIT
 * ================================================================ */

/* libsodium'u başlat. Tüm crypto işlemlerinden önce çağrılmalı. */
nox_err_t crypto_global_init(void);

/* ================================================================
 * TEMEL WRAPPER'LAR
 * ================================================================ */

/* Kriptografik olarak güvenli rastgele byte'lar */
void crypto_random_bytes(void *buf, size_t len);

/* BLAKE2b hash — dosya bütünlük doğrulaması ve genel amaçlı */
nox_err_t crypto_hash_blake2b(uint8_t *out, size_t outlen,
                              const uint8_t *in, size_t inlen);

/* ================================================================
 * KEY DERIVATION — PIN → master_key → subkeys
 *
 * Akış:
 *   1. PIN + salt → Argon2id → master_key (32 byte)
 *   2. master_key → HKDF-BLAKE2b → db_key, identity_unlock_key, session_key
 *
 * Parametreler:
 *   Argon2id: OPSLIMIT_MODERATE, MEMLIMIT_INTERACTIVE
 *   Aktivist cihazlarda makul hız/güvenlik dengesi.
 * ================================================================ */

/*
 * crypto_derive_master_key — PIN'den master key türet
 *
 * @master_key: Çıktı, 32 byte (secure arena'da olmalı)
 * @pin:        Kullanıcı PIN'i (UTF-8 string)
 * @pin_len:    PIN uzunluğu (byte)
 * @salt:       16 byte salt (disk'ten okunur veya ilk çalıştırmada üretilir)
 *
 * PIN fonksiyon dönmeden ÖNCE çağıran tarafından silinmeli.
 */
__attribute__((strub))
nox_err_t crypto_derive_master_key(uint8_t master_key[NOX_KEY_LEN],
                                   char *pin, size_t pin_len,
                                   const uint8_t salt[NOX_SALT_LEN]);

/*
 * crypto_derive_subkeys — master_key'den alt key'ler türet
 *
 * BLAKE2b-based key derivation (libsodium crypto_kdf).
 * Her alt key farklı context string ile türetilir.
 */
__attribute__((strub))
nox_err_t crypto_derive_subkeys(const uint8_t master_key[NOX_KEY_LEN],
                                uint8_t db_key[NOX_KEY_LEN],
                                uint8_t identity_unlock_key[NOX_KEY_LEN],
                                uint8_t session_key[NOX_KEY_LEN]);

/*
 * crypto_derive_onion_seed — master_key'den onion seed türet (D1/D2)
 *
 * Subkey ID = NOX_SUBKEY_ONION_SEED (4), ctx = NOX_KDF_CTX.
 * Seed diskte SAKLANMAZ (D3) — her açılışta yeniden türetilir.
 * @onion_seed: Çıktı, 32 byte
 * @master_key: master_key (PIN + salt → Argon2id çıktısı)
 */
__attribute__((strub))
nox_err_t crypto_derive_onion_seed(uint8_t onion_seed[32],
                                   const uint8_t master_key[NOX_KEY_LEN]);

/*
 * derive_tor_expanded_key — onion seed → Tor ADD_ONION KeyBlob (3. tur KRİTİK)
 *
 * libsodium crypto_sign_seed_keypair'ın sk çıktısı [seed||pub] üretir —
 * Tor'un beklediği [clamped_scalar||prefix] (RFC 8032 §5.1.5 expanded)
 * DEĞİLDİR. Bu fonksiyon SHA-512 + clamp ile Tor uyumlu 64-byte key üretir.
 * pub_out, Tor'un scalar'dan türeteceği public key ile birebir aynıdır.
 */
__attribute__((strub))
nox_err_t derive_tor_expanded_key(uint8_t expanded_out[64],
                                  uint8_t pub_out[32],
                                  const uint8_t seed[32]);

/* ================================================================
 * IDENTITY KEY YÖNETİMİ
 *
 * Ed25519 key pair, disk'te secretbox ile şifreli.
 * identity_unlock_key ile encrypt/decrypt edilir.
 *
 * Dosya formatı:
 *   [salt 16B][nonce 24B][encrypted_keypair 64B+MAC 16B]
 *   Toplam: 120 byte
 *
 * INVARIANT: Crypto dosya operasyonlarında config_dir string'i hiçbir zaman
 * path çözümlemede kullanılmaz — YALNIZCA log/hata mesajı için saklanır;
 * yalnızca config_dir_fd kullanılır. Tüm I/O openat/unlinkat/renameat
 * (config_dir_fd, ...) + O_NOFOLLOW ile yapılır — string path → fd
 * TOCTOU'su kapalı.
 * ================================================================ */

/* Salt dosyasını oku veya oluştur — fd-only (TOCTOU kapalı) */
__attribute__((strub))
nox_err_t crypto_load_or_create_salt(uint8_t salt[NOX_SALT_LEN],
                                     int config_dir_fd);

/*
 * İlk çalıştırma: yeni Ed25519 key pair üret ve disk'e yaz
 * identity_unlock_key ile secretbox şifreleme.
 * config_dir_fd: main.c ensure_config_dir'de O_DIRECTORY|O_NOFOLLOW ile açılan fd,
 *                crypto.c'ye geçiyor — tüm I/O openat(config_dir_fd, "identity.key") ile
 *                TOCTOU'suz. fd<0 ise NOX_ERR_CONFIG.
 */
__attribute__((strub))
nox_err_t crypto_generate_identity(int config_dir_fd,
                                   const uint8_t unlock_key[NOX_KEY_LEN],
                                   uint8_t public_key_out[NOX_KEY_LEN]);

/*
 * Sonraki çalıştırmalar: disk'ten oku ve çöz
 * Çözülen private key secure arena'da kalmalı.
 * config_dir_fd: main.c'den gelen O_DIRECTORY|O_NOFOLLOW fd (yukarıdaki gibi).
 */

__attribute__((strub))
nox_err_t crypto_load_identity(int config_dir_fd,
                                const uint8_t unlock_key[NOX_KEY_LEN],
                                uint8_t secret_key_out[crypto_sign_SECRETKEYBYTES],
                                uint8_t public_key_out[NOX_KEY_LEN]);
/*
 * Ed25519 anahtar çiftini Curve25519 (X25519) anahtar çiftine dönüştür.
 * Noise XX handshake'i için kalıcı kimlik (static key) olarak kullanılır.
 */
__attribute__((strub))
nox_err_t crypto_ed25519_to_curve25519(uint8_t curve25519_pk[NOX_KEY_LEN],
                                       uint8_t curve25519_sk[NOX_KEY_LEN],
                                       const uint8_t ed25519_pk[NOX_KEY_LEN],
                                       const uint8_t ed25519_sk[crypto_sign_SECRETKEYBYTES]);

#endif /* PARANOID_CRYPTO_H */
