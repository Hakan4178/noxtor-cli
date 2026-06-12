/* SPDX-License-Identifier: GPL-3.0-or-later
 * crypto.c — noxtor-cli kriptografi katmanı implementasyonu
 *
 * Adım 2.1: Global init + temel wrapper'lar
 * Adım 2.2: PIN → Argon2id → master_key → subkeys + identity key yönetimi
 *
 * Tüm key materyali secure arena'da yaşar.
 * Geçici hassas veriler fonksiyon dönüşünde explicit_bzero ile silinir.
 *
 * Audit patch'leri (tümü uygulandı):
 *   [P1] read_exact/write_exact — EINTR retry + EOF ayrımı
 *   [P2] Salt dosyası — atomic write (tmp + rename + O_EXCL)
 *   [P3] fsync — identity ve salt yazımı sonrası garanti flush
 *   [P4] crypto_sign_keypair — dönüş değeri kontrol edildi
 *   [P5] sk buffer — sodium_malloc ile stack'ten kaldırıldı
 *   [P6] goto cleanup — DRY, tek noktadan temizleme
 *   [P7] fstat — salt dosyası boyut kontrolü
 *   [P8] config_dir izin kontrolü — 0700 zorunlu
 *   [P9] PIN min/max uzunluk kontrolü
 *   [P10] Subkey ID enum — magic number yok
 *   [P11] NOX_KDF_CTX değişmezlik uyarısı
 *   [B-1] crypto_load_identity — file_buf sodium_malloc'a taşındı,
 *         fstat hata ayrımı (UB önleme), sodium_free otomatik sıfırlama
 *   [A-1] crypto_generate_identity — O_TRUNC→atomic write (tmp+rename)
 *   [A-2] crypto_ed25519_to_curve25519 — kısmi dönüşüm koruması,
 *         NULL kaynak kontrolü, ed25519_sk boyutu crypto_sign_SECRETKEYBYTES
 *   [F-1] crypto_load_or_create_salt — TOCTOU: stat+chmod→fstat+fchmod
 *   [F-2] crypto_load_or_create_salt — PID race: random suffix eklendi
 */

#include "crypto.h"
#include "common.h"
#include "arena.h"
#include "asm_utils.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>

/* ================================================================
 * DERLEME ZAMANI GÜVENLİK KONTROLLERİ
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
 * [P10] Subkey ID enum — magic number yok
 * ================================================================ */
enum nox_subkey_id {
    NOX_SUBKEY_DB               = 1,
    NOX_SUBKEY_IDENTITY_UNLOCK  = 2,
    NOX_SUBKEY_SESSION          = 3,
    /* Gelecekte: NOX_SUBKEY_RATCHET_ROOT = 4, ... */
};

/* ================================================================
 * [P11] KDF context — ASLA değiştirilmemeli
 *
 * ⚠️  DİKKAT: Bu değer production'a girince DEĞİŞTİRİLEMEZ.
 *     Değiştirilirse tüm mevcut identity'ler bozulur.
 *     Sadece major version bump + migration path ile değişebilir.
 * ================================================================ */
#define NOX_KDF_CTX "noxtor__"

NOX_STATIC_ASSERT(sizeof(NOX_KDF_CTX) - 1 == crypto_kdf_CONTEXTBYTES,
                  "KDF context tam 8 byte olmali");

/* ================================================================
 * [P9] PIN uzunluk limitleri
 * ================================================================ */
#define NOX_MIN_PIN_LEN  8U
#define NOX_MAX_PIN_LEN  1024U

/* ================================================================
 * Identity dosya boyutu
 * ================================================================ */
#define IDENTITY_FILE_SIZE \
    (NOX_NONCE_LEN + crypto_sign_SECRETKEYBYTES + crypto_secretbox_MACBYTES)

/* ================================================================
 * [P1] YARDIMCI — tam okuma / tam yazma
 *
 * EINTR → retry (signal kesintisi)
 * n == 0 → EOF (dosya beklenenden kısa)
 * n < 0, errno != EINTR → gerçek hata
 * ================================================================ */
static nox_err_t read_exact(int fd, void *buf, size_t len)
{
    uint8_t *p        = (uint8_t *)buf;
    size_t   remaining = len;

    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;   /* [P1] signal → retry */
            NOX_ERROR(LOG_MOD_CRYPTO, "read hatası: %s", strerror(errno));
            return NOX_ERR_IO;
        }
        if (n == 0) {                       /* [P1] EOF ayrımı */
            NOX_ERROR(LOG_MOD_CRYPTO, "read: beklenmedik EOF");
            return NOX_ERR_IO;
        }
        p         += (size_t)n;
        remaining -= (size_t)n;
    }
    return NOX_OK;
}

static nox_err_t write_exact(int fd, const void *buf, size_t len)
{
    const uint8_t *p        = (const uint8_t *)buf;
    size_t          remaining = len;

    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;   /* [P1] signal → retry */
            NOX_ERROR(LOG_MOD_CRYPTO, "write hatası: %s", strerror(errno));
            return NOX_ERR_IO;
        }
        if (n == 0) {
            NOX_ERROR(LOG_MOD_CRYPTO, "write: sıfır byte yazıldı");
            return NOX_ERR_IO;
        }
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
 * [P9] PIN uzunluk kontrolü eklendi.
 * ================================================================ */
nox_err_t crypto_derive_master_key(uint8_t master_key[NOX_KEY_LEN],
                                    char *pin, size_t pin_len,
                                    const uint8_t salt[NOX_SALT_LEN])
{
    if (!master_key || !pin || !salt)
        return NOX_ERR_PIN;

    /* [P9] PIN uzunluk kontrolü */
    if (pin_len < NOX_MIN_PIN_LEN) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "PIN çok kısa (min %u karakter)", NOX_MIN_PIN_LEN);
        return NOX_ERR_PIN;
    }
    if (pin_len > NOX_MAX_PIN_LEN) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "PIN çok uzun (max %u karakter)", NOX_MAX_PIN_LEN);
        return NOX_ERR_PIN;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "Argon2id key derivation başlıyor...");

    int ret = crypto_pwhash(master_key, NOX_KEY_LEN,
                            pin, (unsigned long long)pin_len,
                            salt,
                            crypto_pwhash_OPSLIMIT_MODERATE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_ARGON2ID13);

    if (ret != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "Argon2id başarısız (bellek yetersiz?)");
        explicit_bzero(master_key, NOX_KEY_LEN);
        /* [P9] Hata durumunda PIN sil — core dump veya bellek sniffing
         * sızmasını engeller. */
        sodium_memzero(pin, pin_len);
        return NOX_ERR_CRYPTO;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "master_key türetildi");
    return NOX_OK;
}

/* ================================================================
 * 2.2: KEY DERIVATION — master_key → subkeys
 *
 * [P10] Subkey ID'leri enum ile tanımlı.
 * ================================================================ */
nox_err_t crypto_derive_subkeys(const uint8_t master_key[NOX_KEY_LEN],
                                 uint8_t db_key[NOX_KEY_LEN],
                                 uint8_t identity_unlock_key[NOX_KEY_LEN],
                                 uint8_t session_key[NOX_KEY_LEN])
{
    if (!master_key || !db_key || !identity_unlock_key || !session_key)
        return NOX_ERR_CRYPTO;

    if (crypto_kdf_derive_from_key(db_key, NOX_KEY_LEN,
                                   NOX_SUBKEY_DB,
                                   NOX_KDF_CTX, master_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "db_key türetme başarısız");
        return NOX_ERR_CRYPTO;
    }

    if (crypto_kdf_derive_from_key(identity_unlock_key, NOX_KEY_LEN,
                                   NOX_SUBKEY_IDENTITY_UNLOCK,
                                   NOX_KDF_CTX, master_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity_unlock_key türetme başarısız");
        sodium_memzero(db_key, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    if (crypto_kdf_derive_from_key(session_key, NOX_KEY_LEN,
                                   NOX_SUBKEY_SESSION,
                                   NOX_KDF_CTX, master_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "session_key türetme başarısız");
        sodium_memzero(db_key, NOX_KEY_LEN);
        sodium_memzero(identity_unlock_key, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    NOX_INFO(LOG_MOD_CRYPTO,
             "subkey'ler türetildi (db, identity_unlock, session)");
    return NOX_OK;
}

/* ================================================================
 * 2.2: SALT YÖNETİMİ
 *
 * [P1] EINTR retry read_exact/write_exact içinde
 * [P2] Atomic write — tmp dosya + rename
 * [P3] fsync — diske garanti flush
 * [P7] fstat — dosya boyutu kontrolü
 * [P8] config_dir izin kontrolü
 * ================================================================ */
nox_err_t crypto_load_or_create_salt(uint8_t salt[NOX_SALT_LEN],
                                      const char *config_dir)
{
    if (!salt || !config_dir)
        return NOX_ERR_CONFIG;

    /* [F-1] TOCTOU koruması — fd tabanlı izin kontrolü */
    int dir_fd = open(config_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd >= 0) {
        struct stat dir_st;
        if (fstat(dir_fd, &dir_st) == 0) {
            if ((dir_st.st_mode & 0777) != 0700) {
                NOX_ERROR(LOG_MOD_CRYPTO,
                          "config_dir izinleri güvensiz (%03o), "
                          "fchmod deneniyor",
                          dir_st.st_mode & 0777);
                if (fchmod(dir_fd, 0700) != 0) {
                    NOX_ERROR(LOG_MOD_CRYPTO,
                              "config_dir izinleri düzeltilemiyor: %s — "
                              "güvensiz dizinde kriptografik işlem yapılamaz",
                              strerror(errno));
                    close(dir_fd);
                    return NOX_ERR_CONFIG;
                }
                NOX_INFO(LOG_MOD_CRYPTO, "config_dir izinleri 0700'e düzeltildi");
            }
        }
        close(dir_fd);
    }

    char path[NOX_PATH_MAX];
    int ret = snprintf(path, sizeof(path), "%s/salt", config_dir);
    if (ret < 0 || (size_t)ret >= sizeof(path))
        return NOX_ERR_CONFIG;

    /* Mevcut salt dosyasını oku */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        /* [P7] Dosya boyutu kontrolü */
        struct stat st;
        if (fstat(fd, &st) != 0 ||
            st.st_size != (off_t)NOX_SALT_LEN) {
            NOX_WARN(LOG_MOD_CRYPTO,
                     "salt dosyası boyutu hatalı (%lld byte), yeniden üretiliyor",
                     (long long)(fd >= 0 ? st.st_size : -1));
            close(fd);
            fd = -1;
        } else {
            nox_err_t err = read_exact(fd, salt, NOX_SALT_LEN);
            close(fd);
            if (err == NOX_OK) {
                NOX_INFO(LOG_MOD_CRYPTO, "salt dosyasından okundu");
                return NOX_OK;
            }
            /* I/O hatası (disk dolu, NFS kopuk, EIO) — salt üretmeye çalışma!
             * Eski salt ile türetilmiş master key hâlâ geçerli; yenisi tüm
             * şifrelenmiş veriyi kalıcı olarak erişilmez kılar. */
            NOX_ERROR(LOG_MOD_CRYPTO,
                      "salt okunamadı (I/O hatası, dosya dokunulmuyor)");
            return err;
        }
    }

    /* Yeni salt üret */
    randombytes_buf(salt, NOX_SALT_LEN);

    /* [F-2] PID + random suffix — PID race koruması */
    char tmp_path[NOX_PATH_MAX];
    uint8_t rnd[4];
    randombytes_buf(rnd, sizeof(rnd));
    int tmp_ret = snprintf(tmp_path, sizeof(tmp_path),
                           "%s/salt.tmp.%d.%02x%02x%02x%02x",
                           config_dir, (int)getpid(),
                           rnd[0], rnd[1], rnd[2], rnd[3]);
    if (tmp_ret < 0 || (size_t)tmp_ret >= sizeof(tmp_path))
        return NOX_ERR_CONFIG;

    int tmp_fd = open(tmp_path,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                      0600);
    if (tmp_fd < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "salt tmp dosyası açılamadı: %s", strerror(errno));
        return NOX_ERR_IO;
    }

    nox_err_t werr = write_exact(tmp_fd, salt, NOX_SALT_LEN);

    /* [P3] fsync — diske garanti yaz */
    if (werr == NOX_OK) {
        if (fsync(tmp_fd) != 0)
            NOX_WARN(LOG_MOD_CRYPTO,
                     "salt fsync başarısız: %s", strerror(errno));
    }
    close(tmp_fd);

    if (werr != NOX_OK) {
        unlink(tmp_path);
        return NOX_ERR_IO;
    }

    /* Atomic rename */
    if (rename(tmp_path, path) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "salt rename başarısız: %s", strerror(errno));
        unlink(tmp_path);
        return NOX_ERR_IO;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "yeni salt üretildi ve kaydedildi (atomic)");
    return NOX_OK;
}

/* ================================================================
 * 2.2: IDENTITY KEY — OLUŞTUR
 *
 * [P4] crypto_sign_keypair dönüş değeri kontrol ediliyor
 * [P5] sk → sodium_malloc (stack'ten kaldırıldı)
 * [P3] fsync — diske garanti flush
 * [P6] goto cleanup — tek noktadan temizleme (DRY)
 *
 * Dosya formatı:
 *   [nonce 24B][encrypted(sk) + MAC] = 24 + 64 + 16 = 104 byte
 * ================================================================ */
nox_err_t crypto_generate_identity(const char *identity_path,
                                    const uint8_t unlock_key[NOX_KEY_LEN],
                                    uint8_t public_key_out[NOX_KEY_LEN])
{
    if (!identity_path || !unlock_key || !public_key_out)
        return NOX_ERR_CRYPTO;

    nox_err_t ret = NOX_ERR_CRYPTO;
    int        fd  = -1;

    uint8_t pk[crypto_sign_PUBLICKEYBYTES]                          = {0};
    uint8_t nonce[NOX_NONCE_LEN]                                    = {0};
    uint8_t ciphertext[crypto_sign_SECRETKEYBYTES +
                        crypto_secretbox_MACBYTES]                  = {0};

    /* [A-1] Atomic write — tmp yolu hazırla */
    char tmp_path[NOX_PATH_MAX];
    uint8_t rnd[4];
    randombytes_buf(rnd, sizeof(rnd));
    int tmp_ret = snprintf(tmp_path, sizeof(tmp_path),
                           "%s.tmp.%d.%02x%02x%02x%02x",
                           identity_path, (int)getpid(),
                           rnd[0], rnd[1], rnd[2], rnd[3]);
    if (tmp_ret < 0 || (size_t)tmp_ret >= sizeof(tmp_path)) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity tmp yolu çok uzun");
        return NOX_ERR_CONFIG;
    }

    /* [P5] sk — sodium_malloc ile güvenli heap, stack'te değil */
    uint8_t *sk = sodium_malloc(crypto_sign_SECRETKEYBYTES);
    if (!sk) {
        NOX_ERROR(LOG_MOD_CRYPTO, "sodium_malloc başarısız");
        return NOX_ERR_ALLOC;
    }

    /* [P4] Dönüş değeri kontrol ediliyor */
    if (crypto_sign_keypair(pk, sk) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "Ed25519 keypair üretimi başarısız");
        goto cleanup;
    }

    NOX_INFO(LOG_MOD_CRYPTO, "yeni Ed25519 key pair üretildi");

    /* Şifrele: secretbox(sk, nonce, unlock_key) */
    randombytes_buf(nonce, NOX_NONCE_LEN);

    if (crypto_secretbox_easy(ciphertext, sk,
                               crypto_sign_SECRETKEYBYTES,
                               nonce, unlock_key) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity key şifreleme başarısız");
        goto cleanup;
    }

    /* [A-1] Dosyaya yaz: tmp + O_EXCL (atomic write) */
    /* CodeQL #9 cpp/path-injection: tmp_path identity_path + ".tmp.PID.RND" */
    assert(strncmp(tmp_path, identity_path, strlen(identity_path)) == 0);
    fd = open(tmp_path,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
              0600);
    if (fd < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity tmp dosyası açılamadı: %s", strerror(errno));
        goto cleanup;
    }

    if (write_exact(fd, nonce, NOX_NONCE_LEN) != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "nonce yazılamadı");
        goto cleanup;
    }

    if (write_exact(fd, ciphertext, sizeof(ciphertext)) != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "ciphertext yazılamadı");
        goto cleanup;
    }

    /* [P3] fsync — diske garanti flush */
    if (fsync(fd) != 0)
        NOX_WARN(LOG_MOD_CRYPTO,
                 "identity fsync başarısız: %s", strerror(errno));

    close(fd); fd = -1;

    /* [A-1] Atomic rename */
    if (rename(tmp_path, identity_path) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity rename başarısız: %s", strerror(errno));
        goto cleanup;
    }

    /* Public key çıktıya kopyala */
    memcpy(public_key_out, pk, crypto_sign_PUBLICKEYBYTES);
    ret = NOX_OK;

    NOX_INFO(LOG_MOD_CRYPTO,
             "identity.key şifrelenmiş olarak kaydedildi");

cleanup:
    if (fd >= 0) {
        close(fd);
        unlink(tmp_path);   /* başarısız tmp'yi temizle */
    } else if (ret != NOX_OK) {
        unlink(tmp_path);   /* fd kapatılmıştı ama rename başarısız */
    }

    /* [P6] Tek noktadan temizleme */
    sodium_free(sk);                                  /* sk — sodium heap */
    explicit_bzero(ciphertext, sizeof(ciphertext));
    explicit_bzero(nonce,      sizeof(nonce));
    explicit_bzero(pk,         sizeof(pk));
    memory_barrier();

    return ret;
}

/* ================================================================
 * 2.2: IDENTITY KEY — YÜKLE
 *
 * [P1] read_exact EINTR retry içinde
 * [P7] fstat — dosya boyutu kontrolü
 *
 * Çözülen private key çağıranın sağladığı alana yazılır (arena olmalı).
 * ================================================================ */
nox_err_t crypto_load_identity(const char *identity_path,
                                const uint8_t unlock_key[NOX_KEY_LEN],
                                uint8_t secret_key_out[crypto_sign_SECRETKEYBYTES],
                                uint8_t public_key_out[NOX_KEY_LEN])
{
    if (!identity_path || !unlock_key ||
        !secret_key_out || !public_key_out)
        return NOX_ERR_CRYPTO;

    int fd = open(identity_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity.key açılamadı: %s", strerror(errno));
        return NOX_ERR_IO;
    }

    /* [B-1] fstat hata ayrımı — UB önleme */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "fstat başarısız: %s", strerror(errno));
        close(fd);
        return NOX_ERR_IO;
    }
    if (st.st_size != (off_t)IDENTITY_FILE_SIZE) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity.key boyutu hatalı (%lld byte, beklenen %zu)",
                  (long long)st.st_size, (size_t)IDENTITY_FILE_SIZE);
        close(fd);
        return NOX_ERR_IO;
    }

    /* [B-1] sodium_malloc — swap koruması + guard page */
    uint8_t *file_buf = sodium_malloc(IDENTITY_FILE_SIZE);
    if (!file_buf) {
        NOX_ERROR(LOG_MOD_CRYPTO, "sodium_malloc başarısız");
        close(fd);
        return NOX_ERR_ALLOC;
    }

    nox_err_t err = read_exact(fd, file_buf, IDENTITY_FILE_SIZE);
    close(fd);

    if (err != NOX_OK) {
        NOX_ERROR(LOG_MOD_CRYPTO, "identity.key okunamadı veya bozuk");
        sodium_free(file_buf);   /* otomatik sıfırlar */
        return NOX_ERR_IO;
    }

    /* Ayrıştır: [nonce 24B][ciphertext 80B] */
    const uint8_t *nonce      = file_buf;
    const uint8_t *ciphertext = file_buf + NOX_NONCE_LEN;
    size_t         ct_len     = crypto_sign_SECRETKEYBYTES +
                                crypto_secretbox_MACBYTES;

    int open_ret = crypto_secretbox_open_easy(
        secret_key_out, ciphertext, ct_len, nonce, unlock_key);

    sodium_free(file_buf);   /* her durumda — sodium_free sıfırlar */

    if (open_ret != 0) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "identity.key çözme başarısız — yanlış PIN?");
        sodium_memzero(secret_key_out, crypto_sign_SECRETKEYBYTES);
        return NOX_ERR_AUTH;
    }

    /*
     * Ed25519 secret key formatı (libsodium):
     *   [seed 32B][public_key 32B]
     */
    memcpy(public_key_out,
           secret_key_out + crypto_sign_SEEDBYTES,
           crypto_sign_PUBLICKEYBYTES);

    memory_barrier();
    NOX_INFO(LOG_MOD_CRYPTO, "identity.key başarıyla çözüldü");
    return NOX_OK;
}

/* ================================================================
 * 2.3: IDENTITY KEY CONVERSION — Ed25519 → Curve25519
 * ================================================================ */
nox_err_t crypto_ed25519_to_curve25519(
    uint8_t       curve25519_pk[NOX_KEY_LEN],
    uint8_t       curve25519_sk[NOX_KEY_LEN],
    const uint8_t ed25519_pk[NOX_KEY_LEN],
    const uint8_t ed25519_sk[crypto_sign_SECRETKEYBYTES])
{
    /* [A-2] En az bir dönüşüm yapılmalı */
    if (!ed25519_pk && !ed25519_sk) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "ed25519_to_curve25519: her iki kaynak NULL");
        return NOX_ERR_CRYPTO;
    }

    /* [A-2] Kısmi kaynak → hedef verilmişse hata.
     * curve25519_* verilmiş ama karşılıklı ed25519_* kaynağı yoksa
     * → başlatılmamış çıktı NOX_OK ile dönüyor. */
    if (curve25519_pk && !ed25519_pk) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "ed25519_to_curve25519: curve25519_pk hedefi verilmiş ama ed25519_pk kaynağı yok");
        sodium_memzero(curve25519_pk, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }
    if (curve25519_sk && !ed25519_sk) {
        NOX_ERROR(LOG_MOD_CRYPTO,
                  "ed25519_to_curve25519: curve25519_sk hedefi verilmiş ama ed25519_sk kaynağı yok");
        sodium_memzero(curve25519_sk, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    if (ed25519_pk && curve25519_pk) {
        if (crypto_sign_ed25519_pk_to_curve25519(
                curve25519_pk, ed25519_pk) != 0) {
            NOX_ERROR(LOG_MOD_CRYPTO,
                      "Ed25519 public key Curve25519'a dönüştürme başarısız");
            sodium_memzero(curve25519_pk, NOX_KEY_LEN);
            return NOX_ERR_CRYPTO;
        }
    }

    if (ed25519_sk && curve25519_sk) {
        if (crypto_sign_ed25519_sk_to_curve25519(
                curve25519_sk, ed25519_sk) != 0) {
            NOX_ERROR(LOG_MOD_CRYPTO,
                      "Ed25519 secret key Curve25519'a dönüştürme başarısız");
            /* [A-2] Kısmi başarı → pk'yı da sıfırla */
            if (ed25519_pk && curve25519_pk)
                sodium_memzero(curve25519_pk, NOX_KEY_LEN);
            sodium_memzero(curve25519_sk, NOX_KEY_LEN);
            return NOX_ERR_CRYPTO;
        }
        /* crypto_sign_ed25519_sk_to_curve25519 zaten clamp uygular:
         * h[0] &= 248; h[31] &= 127; h[31] |= 64;
         * Ek manuel clamp gerekmez — libsodium kaynak koduyla doğrulanmış.
         * noise_dh()RFC 7748 §6 compliant all-zero output check uygular. */
    }

    return NOX_OK;
}
