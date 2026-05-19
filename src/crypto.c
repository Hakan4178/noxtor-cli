/* SPDX-License-Identifier: GPL-3.0-or-later
 * crypto.c — noxtor-cli kriptografi katmanı implementasyonu
 *
 * Adım 2.1: Global init + temel wrapper'lar
 * Adım 2.2: PIN → Argon2id → master_key → subkeys + identity key yönetimi
 *
 * Tüm key materyali secure arena'da yaşar.
 * Geçici hassas veriler fonksiyon dönüşünde explicit_bzero ile silinir.
 */

#include "crypto.h"
#include "common.h"
#include "arena.h"
#include "asm_utils.h"

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

/* ================================================================
 * DERLEME ZAMANI GÜVENLİK KONTROLLERİ
 *
 * libsodium sabitleri ile kendi sabitelerimiz arasında uyum.
 * Platform değişse bile derleme anında patlayacak.
 * ================================================================ */
NOX_STATIC_ASSERT(crypto_sign_PUBLICKEYBYTES == NOX_KEY_LEN,
                  "Ed25519 public key boyutu NOX_KEY_LEN ile uyumsuz");

NOX_STATIC_ASSERT(crypto_secretbox_MACBYTES == NOX_MAC_LEN,
                  "secretbox MAC boyutu NOX_MAC_LEN ile uyumsuz");

NOX_STATIC_ASSERT(crypto_secretbox_NONCEBYTES == NOX_NONCE_LEN,
                  "secretbox nonce boyutu NOX_NONCE_LEN ile uyumsuz");

NOX_STATIC_ASSERT(crypto_pwhash_SALTBYTES == NOX_SALT_LEN,
                  "Argon2id salt boyutu NOX_SALT_LEN ile uyumsuz");

/* ================================================================
 * YARDIMCI — tam okuma / tam yazma
 *
 * Kısmi read/write koruması (yavaş fd, sinyal kesintisi).
 * ================================================================ */
static nox_err_t read_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n <= 0)
            return NOX_ERR_IO;
        p         += (size_t)n;
        remaining -= (size_t)n;
    }
    return NOX_OK;
}

static nox_err_t write_exact(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0)
            return NOX_ERR_IO;
        p         += (size_t)n;
        remaining -= (size_t)n;
    }
    return NOX_OK;
}

/* ================================================================
 * 2.1: GLOBAL INIT
 * ================================================================ */
nox_err_t crypto_global_init(void)
{
    if (sodium_init() < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "libsodium başlatılamadı");
        return NOX_ERR_CRYPTO;
    }
    NOX_INFO(LOG_MOD_CRYPTO, "libsodium başlatıldı");
    return NOX_OK;
}

/* ================================================================
 * 2.1: TEMEL WRAPPER'LAR
 * ================================================================ */
void crypto_random_bytes(void *buf, size_t len)
{
    randombytes_buf(buf, len);
}

nox_err_t crypto_hash_blake2b(uint8_t *out, size_t outlen,
                              const uint8_t *in, size_t inlen)
{
    if (!out || !in || outlen == 0)
        return NOX_ERR_CRYPTO;

    if (crypto_generichash_blake2b(out, outlen, in, inlen,
                                   NULL, 0) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "BLAKE2b hash başarısız");
        return NOX_ERR_CRYPTO;
    }
    return NOX_OK;
}

/* ================================================================
 * 2.2: KEY DERIVATION — PIN → master_key
 *
 * Argon2id parametreleri:
 *   OPSLIMIT_MODERATE — yeterli yavaşlık
 *   MEMLIMIT_INTERACTIVE — aktivist cihazlarda makul bellek
 * ================================================================ */
nox_err_t crypto_derive_master_key(uint8_t master_key[NOX_KEY_LEN],
                                   const char *pin, size_t pin_len,
                                   const uint8_t salt[NOX_SALT_LEN])
{
    if (!master_key || !pin || pin_len == 0 || !salt)
        return NOX_ERR_PIN;

    NOX_INFO(LOG_MOD_CRYPTO, "Argon2id key derivation başlıyor...");

    /*
     * crypto_pwhash:
     *   out      = master_key (32 byte)
     *   passwd   = PIN
     *   salt     = 16 byte (sabit per-identity)
     *   opslimit = MODERATE (3 iterasyon)
     *   memlimit = INTERACTIVE (64 MB)
     *   alg      = Argon2id
     *
     * Bug #5 fix: pin_len cast — crypto_pwhash unsigned long long bekler
     */
    int ret = crypto_pwhash(master_key, NOX_KEY_LEN,
                            pin, (unsigned long long)pin_len,
                            salt,
                            crypto_pwhash_OPSLIMIT_MODERATE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_ARGON2ID13);

    if (ret != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "Argon2id başarısız (bellek yetersiz?)");
        explicit_bzero(master_key, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "master_key türetildi");
    return NOX_OK;
}

/* ================================================================
 * 2.2: KEY DERIVATION — master_key → subkeys
 *
 * libsodium crypto_kdf kullanılır.
 * Her alt key farklı context + subkey_id ile türetilir.
 *
 * Context: "noxtor__" (tam 8 byte, crypto_kdf gereksinimleri)
 * ================================================================ */

/* KDF context — tam 8 byte olmalı (libsodium kısıtlaması) */
#define NOX_KDF_CTX "noxtor__"

NOX_STATIC_ASSERT(sizeof(NOX_KDF_CTX) - 1 == crypto_kdf_CONTEXTBYTES,
                  "KDF context tam 8 byte olmali");

nox_err_t crypto_derive_subkeys(const uint8_t master_key[NOX_KEY_LEN],
                                uint8_t db_key[NOX_KEY_LEN],
                                uint8_t identity_unlock_key[NOX_KEY_LEN],
                                uint8_t session_key[NOX_KEY_LEN])
{
    if (!master_key || !db_key || !identity_unlock_key || !session_key)
        return NOX_ERR_CRYPTO;

    /* subkey_id: 1 = db_key, 2 = identity_unlock, 3 = session */
    if (crypto_kdf_derive_from_key(db_key, NOX_KEY_LEN,
                                   1, NOX_KDF_CTX, master_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "db_key türetme başarısız");
        return NOX_ERR_CRYPTO;
    }

    if (crypto_kdf_derive_from_key(identity_unlock_key, NOX_KEY_LEN,
                                   2, NOX_KDF_CTX, master_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity_unlock_key türetme başarısız");
        return NOX_ERR_CRYPTO;
    }

    if (crypto_kdf_derive_from_key(session_key, NOX_KEY_LEN,
                                   3, NOX_KDF_CTX, master_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "session_key türetme başarısız");
        return NOX_ERR_CRYPTO;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "subkey'ler türetildi (db, identity_unlock, session)");
    return NOX_OK;
}

/* ================================================================
 * 2.2: SALT YÖNETİMİ
 *
 * ~/.config/paranoidcli/salt dosyası.
 * Yoksa üretilir (ilk çalıştırma). Varsa okunur.
 * ================================================================ */
nox_err_t crypto_load_or_create_salt(uint8_t salt[NOX_SALT_LEN],
                                     const char *config_dir)
{
    if (!salt || !config_dir)
        return NOX_ERR_CONFIG;

    char path[NOX_PATH_MAX];
    int ret = snprintf(path, sizeof(path), "%s/salt", config_dir);
    if (ret < 0 || (size_t)ret >= sizeof(path))
        return NOX_ERR_CONFIG;

    /* Dosyayı okumayı dene */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        nox_err_t err = read_exact(fd, salt, NOX_SALT_LEN);
        close(fd);
        if (err == NOX_OK) {
            NOX_INFO(LOG_MOD_CRYPTO, "salt dosyasından okundu");
            return NOX_OK;
        }
        NOX_WARN(LOG_MOD_CRYPTO,
                 "salt dosyası bozuk, yeniden üretiliyor");
    }

    /* Yeni salt üret */
    randombytes_buf(salt, NOX_SALT_LEN);

    /* Dosyaya yaz — 0600 izinleri */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "salt dosyası yazılamadı: %s", strerror(errno));
        return NOX_ERR_IO;
    }

    nox_err_t err = write_exact(fd, salt, NOX_SALT_LEN);
    close(fd);

    if (err != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "salt dosyası eksik yazıldı");
        return NOX_ERR_IO;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "yeni salt üretildi ve kaydedildi");
    return NOX_OK;
}

/* ================================================================
 * 2.2: IDENTITY KEY — OLUŞTUR
 *
 * Ed25519 key pair üret, secretbox ile şifrele, diske yaz.
 *
 * Dosya formatı:
 *   [nonce 24B][encrypted(sk) + MAC] = 24 + 64 + 16 = 104 byte
 *
 * sk = Ed25519 secret key (crypto_sign_SECRETKEYBYTES = 64 byte)
 * ================================================================ */
#define IDENTITY_FILE_SIZE \
    (NOX_NONCE_LEN + crypto_sign_SECRETKEYBYTES + crypto_secretbox_MACBYTES)

nox_err_t crypto_generate_identity(const char *identity_path,
                                   const uint8_t unlock_key[NOX_KEY_LEN],
                                   uint8_t public_key_out[NOX_KEY_LEN])
{
    if (!identity_path || !unlock_key || !public_key_out)
        return NOX_ERR_CRYPTO;

    /* Ed25519 key pair üret */
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);

    NOX_INFO(LOG_MOD_CRYPTO, "yeni Ed25519 key pair üretildi");

    /* Şifrele: secretbox(sk, nonce, unlock_key) */
    uint8_t nonce[NOX_NONCE_LEN];
    randombytes_buf(nonce, NOX_NONCE_LEN);

    uint8_t ciphertext[crypto_sign_SECRETKEYBYTES + crypto_secretbox_MACBYTES];
    if (crypto_secretbox_easy(ciphertext, sk, crypto_sign_SECRETKEYBYTES,
                              nonce, unlock_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity key şifreleme başarısız");
        explicit_bzero(sk, sizeof(sk));
        return NOX_ERR_CRYPTO;
    }

    /* Dosyaya yaz: [nonce][ciphertext] */
    int fd = open(identity_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity.key dosyası açılamadı: %s", strerror(errno));
        explicit_bzero(sk, sizeof(sk));
        explicit_bzero(ciphertext, sizeof(ciphertext));
        return NOX_ERR_IO;
    }

    /* Bug #1 fix: ayrı write + ayrı hata kontrolü */
    nox_err_t err = write_exact(fd, nonce, NOX_NONCE_LEN);
    if (err != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "nonce yazılamadı: %s", strerror(errno));
        close(fd);
        explicit_bzero(sk, sizeof(sk));
        explicit_bzero(ciphertext, sizeof(ciphertext));
        return NOX_ERR_IO;
    }

    err = write_exact(fd, ciphertext, sizeof(ciphertext));
    if (err != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "ciphertext yazılamadı: %s", strerror(errno));
        close(fd);
        explicit_bzero(sk, sizeof(sk));
        explicit_bzero(ciphertext, sizeof(ciphertext));
        return NOX_ERR_IO;
    }

    close(fd);

    /* Public key'i çıktıya kopyala */
    memcpy(public_key_out, pk, crypto_sign_PUBLICKEYBYTES);

    /* Hassas verileri temizle */
    explicit_bzero(sk, sizeof(sk));
    explicit_bzero(ciphertext, sizeof(ciphertext));
    memory_barrier();

    NOX_INFO(LOG_MOD_CRYPTO, "identity.key şifrelenmiş olarak kaydedildi");
    return NOX_OK;
}

/* ================================================================
 * 2.2: IDENTITY KEY — YÜKLE
 *
 * Disk'ten oku, secretbox ile çöz.
 * Çözülen private key çağıranın sağladığı alana yazılır (arena olmalı).
 * ================================================================ */
nox_err_t crypto_load_identity(const char *identity_path,
                               const uint8_t unlock_key[NOX_KEY_LEN],
                               uint8_t secret_key_out[64],
                               uint8_t public_key_out[NOX_KEY_LEN])
{
    if (!identity_path || !unlock_key || !secret_key_out || !public_key_out)
        return NOX_ERR_CRYPTO;

    /* Dosyayı oku — read_exact ile kısmi okuma koruması */
    int fd = open(identity_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity.key açılamadı: %s", strerror(errno));
        return NOX_ERR_IO;
    }

    uint8_t file_buf[IDENTITY_FILE_SIZE];
    nox_err_t err = read_exact(fd, file_buf, sizeof(file_buf));
    close(fd);

    if (err != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity.key okunamadı veya bozuk");
        explicit_bzero(file_buf, sizeof(file_buf));
        return NOX_ERR_IO;
    }

    /* Ayrıştır: [nonce 24B][ciphertext 80B] */
    const uint8_t *nonce      = file_buf;
    const uint8_t *ciphertext = file_buf + NOX_NONCE_LEN;
    size_t ct_len = crypto_sign_SECRETKEYBYTES + crypto_secretbox_MACBYTES;

    /* Çöz */
    if (crypto_secretbox_open_easy(secret_key_out, ciphertext, ct_len,
                                   nonce, unlock_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity.key çözme başarısız — yanlış PIN?");
        explicit_bzero(file_buf, sizeof(file_buf));
        explicit_bzero(secret_key_out, crypto_sign_SECRETKEYBYTES);
        return NOX_ERR_AUTH;
    }

    /*
     * Ed25519 secret key formatı (libsodium):
     *   [seed 32B][public_key 32B]
     * Public key secret key'in son 32 byte'ında.
     */
    memcpy(public_key_out,
           secret_key_out + crypto_sign_SEEDBYTES,
           crypto_sign_PUBLICKEYBYTES);

    explicit_bzero(file_buf, sizeof(file_buf));
    memory_barrier();

    NOX_INFO(LOG_MOD_CRYPTO, "identity.key başarıyla çözüldü");
    return NOX_OK;
}

/* ================================================================
 * 2.3: IDENTITY KEY CONVERSION — Ed25519 → Curve25519
 * ================================================================ */
nox_err_t crypto_ed25519_to_curve25519(uint8_t curve25519_pk[NOX_KEY_LEN],
                                       uint8_t curve25519_sk[NOX_KEY_LEN],
                                       const uint8_t ed25519_pk[NOX_KEY_LEN],
                                       const uint8_t ed25519_sk[64])
{
    if (ed25519_pk && curve25519_pk) {
        if (crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk) != 0) {
            NOX_ERROR(LOG_MOD_CRYPTO, "Ed25519 public key'i Curve25519'a dönüştürme başarısız");
            return NOX_ERR_CRYPTO;
        }
    }
    if (ed25519_sk && curve25519_sk) {
        if (crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk) != 0) {
            NOX_ERROR(LOG_MOD_CRYPTO, "Ed25519 secret key'i Curve25519'a dönüştürme başarısız");
            return NOX_ERR_CRYPTO;
        }
    }
    return NOX_OK;
}
