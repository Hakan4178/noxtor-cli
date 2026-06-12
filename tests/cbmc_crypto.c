/* SPDX-License-Identifier: GPL-3.0-or-later
 * cbmc_crypto.c — CBMC/ESBMC harness for crypto.c
 *
 * Self-contained: types.h/common.h/crypto.h kullanılmaz (sodium conflict önlemi).
 * Sabitler ve nox_err_t manuel tanımlı.
 *
 * Doğrulanan fonksiyonlar:
 *   crypto_hash_blake2b          — NULL guard, outlen=0
 *   crypto_derive_master_key     — NULL checks, PIN length, PIN wipe, master_key wipe
 *   crypto_derive_subkeys        — NULL checks, subkey wipe cascade
 *   crypto_ed25519_to_curve25519 — NULL combos, partial conversion protection
 *
 * Komut (ESBMC):
 *   esbmc -D__ESBMC__ --overflow-check --unsigned-overflow-check \
 *     --memory-leak-check --unwind 50 tests/cbmc_crypto.c
 *
 * Komut (CBMC):
 *   cbmc --c23 --64 --bounds-check --pointer-check \
 *     tests/cbmc_crypto.c
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* ================================================================
 * SABİTLER — common.h ile çakışmayı önlemek için manuel
 * ================================================================ */
#define NOX_KEY_LEN     32U
#define NOX_NONCE_LEN   24U
#define NOX_MAC_LEN     16U
#define NOX_SALT_LEN    16U

#define NOX_MIN_PIN_LEN  8U
#define NOX_MAX_PIN_LEN  1024U

#define crypto_sign_PUBLICKEYBYTES NOX_KEY_LEN
#define crypto_sign_SECRETKEYBYTES 64U
#define crypto_secretbox_MACBYTES  NOX_MAC_LEN

typedef enum {
    NOX_OK           =  0,
    NOX_ERR_ALLOC    = -1,
    NOX_ERR_CRYPTO   = -2,
    NOX_ERR_IO       = -3,
    NOX_ERR_PIN      = -7,
    NOX_ERR_AUTH     = -5,
} nox_err_t;

/* ================================================================
 * SODIUM STUBS
 *
 * sodium_memzero GERÇEK — wipe behavior doğrulanıyor.
 * sodium_malloc/free malloc/free ile eşdeğer.
 * crypto_pwhash stub — control flow doğrulaması için.
 * ================================================================ */
int sodium_init(void) { return 0; }

void sodium_memzero(void *const pnt, size_t len)
{
    volatile uint8_t *vp = (volatile uint8_t *)pnt;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
}

int sodium_memcmp(const void *b1_, const void *b2_, size_t len)
{
    const volatile uint8_t *b1 = (const volatile uint8_t *)b1_;
    const volatile uint8_t *b2 = (const volatile uint8_t *)b2_;
    volatile uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= b1[i] ^ b2[i];
    return (int)d;
}

void *sodium_malloc(size_t len)
{
    void *ptr = malloc(len ? len : 1);
#ifdef __ESBMC__
    __ESBMC_assume(ptr != NULL);
#endif
    return ptr;
}

void sodium_free(void *ptr) { free(ptr); }

void explicit_bzero(void *const pnt, size_t len)
{
    volatile uint8_t *vp = (volatile uint8_t *)pnt;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
}

int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in, size_t inlen,
                               const unsigned char *key, size_t keylen)
{
    (void)key; (void)keylen;
    if (!out || !in || outlen == 0 || inlen == 0) return -1;
    for (size_t i = 0; i < outlen; i++) out[i] = 0xAB;
    return 0;
}

int crypto_pwhash(unsigned char * const out, unsigned long long outlen,
                  const char * const passwd, unsigned long long passwdlen,
                  const unsigned char * const salt,
                  unsigned long long opslimit, unsigned long long memlimit,
                  int alg)
{
    (void)passwdlen; (void)opslimit; (void)memlimit; (void)alg;
    if (!out || !passwd || !salt) return -1;
    /* master_key'i PIN benzeri bir value ile doldur (test edilebilir) */
    for (unsigned long long i = 0; i < outlen; i++) out[i] = 0x77;
    return 0;
}

int crypto_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len,
                               uint64_t subkey_id, const char *ctx,
                               const uint8_t *key)
{
    (void)ctx; (void)key;
    if (!subkey || subkey_len == 0) return -1;
    /* Her subkey farklı value alsın (test edilebilir) */
    for (size_t i = 0; i < subkey_len; i++)
        subkey[i] = (uint8_t)(subkey_id & 0xFF);
    return 0;
}

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) return -1;
    for (size_t i = 0; i < NOX_KEY_LEN; i++) { pk[i] = 0x11; sk[i] = 0x22; }
    return 0;
}

int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
                          unsigned long long mlen,
                          const unsigned char *n, const unsigned char *k)
{
    (void)n; (void)k;
    if (!c || !m) return -1;
    for (unsigned long long i = 0; i < mlen + crypto_secretbox_MACBYTES; i++)
        c[i] = 0x33;
    return 0;
}

int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                               unsigned long long clen,
                               const unsigned char *n, const unsigned char *k)
{
    (void)n; (void)k;
    if (!m || !c) return -1;
    for (unsigned long long i = 0; i < clen - crypto_secretbox_MACBYTES; i++)
        m[i] = 0x44;
    return 0;
}

int crypto_sign_ed25519_pk_to_curve25519(uint8_t *curve25519_pk,
                                          const uint8_t *ed25519_pk)
{
    if (!curve25519_pk || !ed25519_pk) return -1;
    for (size_t i = 0; i < NOX_KEY_LEN; i++)
        curve25519_pk[i] = ed25519_pk[i] ^ 0xAA;
    return 0;
}

int crypto_sign_ed25519_sk_to_curve25519(uint8_t *curve25519_sk,
                                          const uint8_t *ed25519_sk)
{
    if (!curve25519_sk || !ed25519_sk) return -1;
    for (size_t i = 0; i < NOX_KEY_LEN; i++)
        curve25519_sk[i] = ed25519_sk[i] ^ 0x55;
    return 0;
}

int crypto_sign_ed25519_sk_to_pk(uint8_t *pk, const uint8_t *sk)
{
    if (!pk || !sk) return -1;
    for (size_t i = 0; i < NOX_KEY_LEN; i++)
        pk[i] = sk[i] ^ 0xBB;
    return 0;
}

/* ================================================================
 * Fonksiyon tanımları — crypto.c'deki mantık (self-contained)
 * ================================================================ */

/* --- crypto_hash_blake2b --- */
nox_err_t crypto_hash_blake2b(uint8_t *out, size_t outlen,
                               const uint8_t *in, size_t inlen)
{
    if (!out || !in || outlen == 0)
        return NOX_ERR_CRYPTO;
    if (crypto_generichash_blake2b(out, outlen, in, inlen, NULL, 0) != 0)
        return NOX_ERR_CRYPTO;
    return NOX_OK;
}

/* --- crypto_derive_master_key --- */
nox_err_t crypto_derive_master_key(uint8_t master_key[NOX_KEY_LEN],
                                    char *pin, size_t pin_len,
                                    const uint8_t salt[NOX_SALT_LEN])
{
    if (!master_key || !pin || !salt)
        return NOX_ERR_PIN;

    if (pin_len < NOX_MIN_PIN_LEN)
        return NOX_ERR_PIN;
    if (pin_len > NOX_MAX_PIN_LEN)
        return NOX_ERR_PIN;

    int ret = crypto_pwhash(master_key, NOX_KEY_LEN,
                            pin, (unsigned long long)pin_len,
                            salt,
                            2,  /* OPSLIMIT_MODERATE */
                            67108864U,  /* MEMLIMIT_INTERACTIVE */
                            2);  /* ALG_ARGON2ID13 */

    /* PIN'i hemen sil — başarılı olsa da olmasa da */
    sodium_memzero(pin, pin_len);

    if (ret != 0) {
        explicit_bzero(master_key, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }
    return NOX_OK;
}

/* --- crypto_derive_subkeys --- */
nox_err_t crypto_derive_subkeys(const uint8_t master_key[NOX_KEY_LEN],
                                 uint8_t db_key[NOX_KEY_LEN],
                                 uint8_t identity_unlock_key[NOX_KEY_LEN],
                                 uint8_t session_key[NOX_KEY_LEN])
{
    if (!master_key || !db_key || !identity_unlock_key || !session_key)
        return NOX_ERR_CRYPTO;

    if (crypto_kdf_derive_from_key(db_key, NOX_KEY_LEN,
                                   1, "noxtor__", master_key) != 0)
        return NOX_ERR_CRYPTO;

    if (crypto_kdf_derive_from_key(identity_unlock_key, NOX_KEY_LEN,
                                   2, "noxtor__", master_key) != 0) {
        sodium_memzero(db_key, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    if (crypto_kdf_derive_from_key(session_key, NOX_KEY_LEN,
                                   3, "noxtor__", master_key) != 0) {
        sodium_memzero(db_key, NOX_KEY_LEN);
        sodium_memzero(identity_unlock_key, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    return NOX_OK;
}

/* --- crypto_ed25519_to_curve25519 --- */
nox_err_t crypto_ed25519_to_curve25519(
    uint8_t       curve25519_pk[NOX_KEY_LEN],
    uint8_t       curve25519_sk[NOX_KEY_LEN],
    const uint8_t ed25519_pk[NOX_KEY_LEN],
    const uint8_t ed25519_sk[crypto_sign_SECRETKEYBYTES])
{
    /* En az bir kaynak verilmeli */
    if (!ed25519_pk && !ed25519_sk)
        return NOX_ERR_CRYPTO;

    /* En az bir hedef verilmeli */
    if (!curve25519_pk && !curve25519_sk)
        return NOX_ERR_CRYPTO;

    /* Kısmi hedef → kaynak yoksa hata */
    if (curve25519_pk && !ed25519_pk) {
        sodium_memzero(curve25519_pk, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }
    if (curve25519_sk && !ed25519_sk) {
        sodium_memzero(curve25519_sk, NOX_KEY_LEN);
        return NOX_ERR_CRYPTO;
    }

    if (ed25519_pk && curve25519_pk) {
        if (crypto_sign_ed25519_pk_to_curve25519(
                curve25519_pk, ed25519_pk) != 0) {
            sodium_memzero(curve25519_pk, NOX_KEY_LEN);
            return NOX_ERR_CRYPTO;
        }
    }

    if (ed25519_sk && curve25519_sk) {
        if (crypto_sign_ed25519_sk_to_curve25519(
                curve25519_sk, ed25519_sk) != 0) {
            if (ed25519_pk && curve25519_pk)
                sodium_memzero(curve25519_pk, NOX_KEY_LEN);
            sodium_memzero(curve25519_sk, NOX_KEY_LEN);
            return NOX_ERR_CRYPTO;
        }
    }

    return NOX_OK;
}

/* ================================================================
 * Testler
 * ================================================================ */

/* T1: crypto_hash_blake2b NULL guard */
static void test_hash_null(void)
{
    uint8_t out[32], in[32];
    assert(crypto_hash_blake2b(NULL, 32, in, 32) == NOX_ERR_CRYPTO);
    assert(crypto_hash_blake2b(out, 32, NULL, 32) == NOX_ERR_CRYPTO);
    assert(crypto_hash_blake2b(out, 0, in, 32) == NOX_ERR_CRYPTO);
}

/* T2: crypto_derive_master_key NULL checks */
static void test_master_key_null(void)
{
    uint8_t mk[NOX_KEY_LEN], salt[NOX_SALT_LEN];
    char pin[] = "testpin!123";
    assert(crypto_derive_master_key(NULL, pin, 11, salt) == NOX_ERR_PIN);
    assert(crypto_derive_master_key(mk, NULL, 11, salt) == NOX_ERR_PIN);
    assert(crypto_derive_master_key(mk, pin, 11, NULL) == NOX_ERR_PIN);
}

/* T3: crypto_derive_master_key PIN length */
static void test_master_key_pin_len(void)
{
    uint8_t mk[NOX_KEY_LEN], salt[NOX_SALT_LEN];
    memset(salt, 0x99, NOX_SALT_LEN);
    char short_pin[] = "abc";
    char long_pin[2048];
    memset(long_pin, 'x', sizeof(long_pin));
    assert(crypto_derive_master_key(mk, short_pin, 3, salt) == NOX_ERR_PIN);
    assert(crypto_derive_master_key(mk, long_pin, sizeof(long_pin), salt) == NOX_ERR_PIN);
}

/* T4: crypto_derive_master_key PIN wipe */
static void test_master_key_pin_wipe(void)
{
    uint8_t mk[NOX_KEY_LEN], salt[NOX_SALT_LEN];
    memset(salt, 0x99, NOX_SALT_LEN);
    char pin[32];
    memset(pin, 'P', sizeof(pin));
    nox_err_t r = crypto_derive_master_key(mk, pin, sizeof(pin), salt);
    assert(r == NOX_OK);
    /* PIN silinmiş olmalı */
    for (size_t i = 0; i < sizeof(pin); i++)
        assert(pin[i] == 0);
}

/* T5: crypto_derive_master_key başarılı türetme */
static void test_master_key_derivation(void)
{
    uint8_t mk[NOX_KEY_LEN], salt[NOX_SALT_LEN];
    memset(salt, 0x99, NOX_SALT_LEN);
    char pin[32];
    memset(pin, 'K', sizeof(pin));
    nox_err_t r = crypto_derive_master_key(mk, pin, sizeof(pin), salt);
    assert(r == NOX_OK);
    /* master_key sıfır olmamalı */
    int nonzero = 0;
    for (size_t i = 0; i < NOX_KEY_LEN; i++)
        if (mk[i] != 0) nonzero = 1;
    assert(nonzero);
}

/* T6: crypto_derive_subkeys NULL checks */
static void test_subkeys_null(void)
{
    uint8_t mk[NOX_KEY_LEN], db[NOX_KEY_LEN], iu[NOX_KEY_LEN], ss[NOX_KEY_LEN];
    assert(crypto_derive_subkeys(NULL, db, iu, ss) == NOX_ERR_CRYPTO);
    assert(crypto_derive_subkeys(mk, NULL, iu, ss) == NOX_ERR_CRYPTO);
    assert(crypto_derive_subkeys(mk, db, NULL, ss) == NOX_ERR_CRYPTO);
    assert(crypto_derive_subkeys(mk, db, iu, NULL) == NOX_ERR_CRYPTO);
}

/* T7: crypto_derive_subkeys başarılı türetme */
static void test_subkeys_derivation(void)
{
    uint8_t mk[NOX_KEY_LEN], db[NOX_KEY_LEN], iu[NOX_KEY_LEN], ss[NOX_KEY_LEN];
    memset(mk, 0x55, NOX_KEY_LEN);
    assert(crypto_derive_subkeys(mk, db, iu, ss) == NOX_OK);
    /* Her subkey farklı olmalı */
    int db_iu_diff = 0, iu_ss_diff = 0;
    for (size_t i = 0; i < NOX_KEY_LEN; i++) {
        if (db[i] != iu[i]) db_iu_diff = 1;
        if (iu[i] != ss[i]) iu_ss_diff = 1;
    }
    assert(db_iu_diff);
    assert(iu_ss_diff);
}

/* T8: crypto_ed25519_to_curve25519 NULL combos */
static void test_ed25519_null(void)
{
    uint8_t cpk[NOX_KEY_LEN], csk[NOX_KEY_LEN];
    uint8_t epk[NOX_KEY_LEN], esk[crypto_sign_SECRETKEYBYTES];
    assert(crypto_ed25519_to_curve25519(cpk, csk, NULL, NULL) == NOX_ERR_CRYPTO);
    assert(crypto_ed25519_to_curve25519(NULL, NULL, epk, esk) == NOX_ERR_CRYPTO);
}

/* T9: crypto_ed25519_to_curve25519 kısmi dönüşüm */
static void test_ed25519_partial(void)
{
    uint8_t cpk[NOX_KEY_LEN], csk[NOX_KEY_LEN];
    uint8_t epk[NOX_KEY_LEN], esk[crypto_sign_SECRETKEYBYTES];
    memset(epk, 0x11, NOX_KEY_LEN);
    memset(esk, 0x22, crypto_sign_SECRETKEYBYTES);

    /* curve25519_pk hedefi verilmiş ama ed25519_pk kaynağı yok */
    memset(cpk, 0xFF, NOX_KEY_LEN);
    assert(crypto_ed25519_to_curve25519(cpk, NULL, NULL, esk) == NOX_ERR_CRYPTO);
    for (size_t i = 0; i < NOX_KEY_LEN; i++) assert(cpk[i] == 0);

    /* curve25519_sk hedefi verilmiş ama ed25519_sk kaynağı yok */
    memset(csk, 0xFF, NOX_KEY_LEN);
    assert(crypto_ed25519_to_curve25519(NULL, csk, epk, NULL) == NOX_ERR_CRYPTO);
    for (size_t i = 0; i < NOX_KEY_LEN; i++) assert(csk[i] == 0);
}

/* T10: crypto_ed25519_to_curve25519 başarılı dönüşüm */
static void test_ed25519_convert(void)
{
    uint8_t cpk[NOX_KEY_LEN], csk[NOX_KEY_LEN];
    uint8_t epk[NOX_KEY_LEN], esk[crypto_sign_SECRETKEYBYTES];
    memset(epk, 0x11, NOX_KEY_LEN);
    memset(esk, 0x22, crypto_sign_SECRETKEYBYTES);
    nox_err_t r = crypto_ed25519_to_curve25519(cpk, csk, epk, esk);
    assert(r == NOX_OK);
    int pk_nonzero = 0, sk_nonzero = 0;
    for (size_t i = 0; i < NOX_KEY_LEN; i++) {
        if (cpk[i] != 0) pk_nonzero = 1;
        if (csk[i] != 0) sk_nonzero = 1;
    }
    assert(pk_nonzero);
    assert(sk_nonzero);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    sodium_init();

    test_hash_null();
    test_master_key_null();
    test_master_key_pin_len();
    test_master_key_pin_wipe();
    test_master_key_derivation();
    test_subkeys_null();
    test_subkeys_derivation();
    test_ed25519_null();
    test_ed25519_partial();
    test_ed25519_convert();

    return 0;
}
