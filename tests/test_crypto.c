/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_crypto.c — Crypto modül birim testleri
 *
 * Testler:
 *   1. Argon2id key derivation (PIN → master_key)
 *   2. Subkey derivation (master_key → db, unlock, session)
 *   3. Salt yönetimi (üret, kaydet, oku)
 *   4. Identity key üret + yükle (secretbox round-trip)
 *   5. Yanlış PIN ile identity yükleme → NOX_ERR_AUTH
 *   6. Subkey'lerin birbirinden farklı olduğunu doğrula
 */

#include "common.h"
#include "types.h"
#include "crypto.h"
#include "arena.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>


/* ================================================================
 * TEST MAKROLARI
 * ================================================================ */
static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond) do {                                      \
    if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL %s:%d: %s\n",                        \
                __FILE__, __LINE__, #cond);                         \
        return 1;                                                   \
    }                                                               \
} while (0)

#define RUN_TEST(test_fn) do {                                      \
    tests_run++;                                                    \
    fprintf(stderr, "  [%d] %-45s ", tests_run, #test_fn);          \
    if (test_fn() == 0) {                                           \
        tests_passed++;                                             \
        fprintf(stderr, "\033[32mOK\033[0m\n");                     \
    } else {                                                        \
        fprintf(stderr, "\033[31mFAIL\033[0m\n");                   \
    }                                                               \
} while (0)

/* Test config dizini — /tmp kullanmıyoruz, workspace içinde */
static const char *TEST_DIR = "tests/.tmp_crypto";

static void setup_test_dir(void)
{
    mkdir(TEST_DIR, 0700);
}

static void cleanup_test_dir(void)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/salt", TEST_DIR);
    unlink(path);

    snprintf(path, sizeof(path), "%s/identity.key", TEST_DIR);
    unlink(path);

    rmdir(TEST_DIR);
}

/* ================================================================
 * TEST: Argon2id key derivation
 * ================================================================ */
static int test_argon2id_derive(void)
{
    uint8_t master_key[NOX_KEY_LEN] = {0};
    uint8_t salt[NOX_SALT_LEN];

    /* Sabit salt — tekrarlanabilir test */
    memset(salt, 0x42, NOX_SALT_LEN);

    char pin[] = "testpassword1234";
    nox_err_t err = crypto_derive_master_key(master_key, pin, strlen(pin), salt);
    TEST_ASSERT(err == NOX_OK);

    /* master_key sıfır olmamalı */
    uint8_t zero[NOX_KEY_LEN] = {0};
    TEST_ASSERT(sodium_memcmp(master_key, zero, NOX_KEY_LEN) != 0);

    /* Aynı PIN + salt → aynı key (deterministic) */
    uint8_t master_key2[NOX_KEY_LEN] = {0};
    char pin_dup[] = "testpassword1234";
    err = crypto_derive_master_key(master_key2, pin_dup, strlen(pin_dup), salt);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(sodium_memcmp(master_key, master_key2, NOX_KEY_LEN) == 0);

    /* Farklı PIN → farklı key */
    uint8_t master_key3[NOX_KEY_LEN] = {0};
    char pin2[] = "differentpin9999";
    err = crypto_derive_master_key(master_key3, pin2, strlen(pin2), salt);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(sodium_memcmp(master_key, master_key3, NOX_KEY_LEN) != 0);

    explicit_bzero(master_key, sizeof(master_key));
    explicit_bzero(master_key2, sizeof(master_key2));
    explicit_bzero(master_key3, sizeof(master_key3));
    return 0;
}

/* ================================================================
 * TEST: Subkey derivation — farklılık kontrolü
 * ================================================================ */
static int test_subkey_derive(void)
{
    /* Sahte master_key */
    uint8_t master_key[NOX_KEY_LEN];
    randombytes_buf(master_key, NOX_KEY_LEN);

    uint8_t db_key[NOX_KEY_LEN]      = {0};
    uint8_t unlock_key[NOX_KEY_LEN]  = {0};
    uint8_t session_key[NOX_KEY_LEN] = {0};

    nox_err_t err = crypto_derive_subkeys(master_key, db_key,
                                          unlock_key, session_key);
    TEST_ASSERT(err == NOX_OK);

    /* Üç key birbirinden farklı olmalı */
    TEST_ASSERT(sodium_memcmp(db_key, unlock_key, NOX_KEY_LEN) != 0);
    TEST_ASSERT(sodium_memcmp(db_key, session_key, NOX_KEY_LEN) != 0);
    TEST_ASSERT(sodium_memcmp(unlock_key, session_key, NOX_KEY_LEN) != 0);

    /* Hiçbiri sıfır olmamalı */
    uint8_t zero[NOX_KEY_LEN] = {0};
    TEST_ASSERT(sodium_memcmp(db_key, zero, NOX_KEY_LEN) != 0);
    TEST_ASSERT(sodium_memcmp(unlock_key, zero, NOX_KEY_LEN) != 0);
    TEST_ASSERT(sodium_memcmp(session_key, zero, NOX_KEY_LEN) != 0);

    /* Aynı master_key → aynı subkey'ler (deterministic) */
    uint8_t db2[NOX_KEY_LEN], unlock2[NOX_KEY_LEN], session2[NOX_KEY_LEN];
    err = crypto_derive_subkeys(master_key, db2, unlock2, session2);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(sodium_memcmp(db_key, db2, NOX_KEY_LEN) == 0);
    TEST_ASSERT(sodium_memcmp(unlock_key, unlock2, NOX_KEY_LEN) == 0);
    TEST_ASSERT(sodium_memcmp(session_key, session2, NOX_KEY_LEN) == 0);

    explicit_bzero(master_key, sizeof(master_key));
    return 0;
}

/* ================================================================
 * TEST: Salt yönetimi — üret, kaydet, tekrar oku
 * ================================================================ */
static int test_salt_management(void)
{
    setup_test_dir();

    uint8_t salt1[NOX_SALT_LEN] = {0};
    nox_err_t err = crypto_load_or_create_salt(salt1, TEST_DIR);
    TEST_ASSERT(err == NOX_OK);

    /* Salt sıfır olmamalı */
    uint8_t zero[NOX_SALT_LEN] = {0};
    TEST_ASSERT(sodium_memcmp(salt1, zero, NOX_SALT_LEN) != 0);

    /* İkinci okuma — aynı salt dönmeli */
    uint8_t salt2[NOX_SALT_LEN] = {0};
    err = crypto_load_or_create_salt(salt2, TEST_DIR);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(sodium_memcmp(salt1, salt2, NOX_SALT_LEN) == 0);

    return 0;
}

/* ================================================================
 * TEST: Identity key round-trip — üret + yükle
 * ================================================================ */
static int test_identity_roundtrip(void)
{
    setup_test_dir();

    uint8_t unlock_key[NOX_KEY_LEN];
    randombytes_buf(unlock_key, NOX_KEY_LEN);

    char id_path[256];
    snprintf(id_path, sizeof(id_path), "%s/identity.key", TEST_DIR);

    /* Üret */
    uint8_t pub_gen[NOX_KEY_LEN] = {0};
    nox_err_t err = crypto_generate_identity(id_path, unlock_key, pub_gen);
    TEST_ASSERT(err == NOX_OK);

    /* Public key sıfır olmamalı */
    uint8_t zero[NOX_KEY_LEN] = {0};
    TEST_ASSERT(sodium_memcmp(pub_gen, zero, NOX_KEY_LEN) != 0);

    /* Yükle — aynı key pair dönmeli */
    uint8_t sk_loaded[64] = {0};
    uint8_t pub_loaded[NOX_KEY_LEN] = {0};
    err = crypto_load_identity(id_path, unlock_key, sk_loaded, pub_loaded);
    TEST_ASSERT(err == NOX_OK);

    /* Public key'ler eşleşmeli */
    TEST_ASSERT(sodium_memcmp(pub_gen, pub_loaded, NOX_KEY_LEN) == 0);

    /* Yüklenen secret key ile imza doğrulanmalı */
    const uint8_t msg[] = "test message";
    uint8_t sig[crypto_sign_BYTES];
    TEST_ASSERT(crypto_sign_detached(sig, NULL, msg, sizeof(msg) - 1,
                                      sk_loaded) == 0);
    TEST_ASSERT(crypto_sign_verify_detached(sig, msg, sizeof(msg) - 1,
                                             pub_loaded) == 0);

    explicit_bzero(unlock_key, sizeof(unlock_key));
    explicit_bzero(sk_loaded, sizeof(sk_loaded));
    return 0;
}

/* ================================================================
 * TEST: Yanlış PIN → NOX_ERR_AUTH
 * ================================================================ */
static int test_identity_wrong_pin(void)
{
    setup_test_dir();

    uint8_t correct_key[NOX_KEY_LEN];
    randombytes_buf(correct_key, NOX_KEY_LEN);

    char id_path[256];
    snprintf(id_path, sizeof(id_path), "%s/identity.key", TEST_DIR);

    /* Doğru key ile üret */
    uint8_t pub[NOX_KEY_LEN];
    nox_err_t err = crypto_generate_identity(id_path, correct_key, pub);
    TEST_ASSERT(err == NOX_OK);

    /* Yanlış key ile yükle → AUTH hatası */
    uint8_t wrong_key[NOX_KEY_LEN];
    randombytes_buf(wrong_key, NOX_KEY_LEN);

    uint8_t sk[64], pk[NOX_KEY_LEN];
    err = crypto_load_identity(id_path, wrong_key, sk, pk);
    TEST_ASSERT(err == NOX_ERR_AUTH);

    explicit_bzero(correct_key, sizeof(correct_key));
    explicit_bzero(wrong_key, sizeof(wrong_key));
    return 0;
}

/* ================================================================
 * TEST: NULL parametre güvenliği
 * ================================================================ */
static int test_null_safety(void)
{
    char short_pin[] = "x";
    TEST_ASSERT(crypto_derive_master_key(NULL, short_pin, 1, (uint8_t[16]){0})
                == NOX_ERR_PIN);

    uint8_t key[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_master_key(key, NULL, 0, (uint8_t[16]){0})
                == NOX_ERR_PIN);

    TEST_ASSERT(crypto_derive_subkeys(NULL, key, key, key)
                == NOX_ERR_CRYPTO);

    TEST_ASSERT(crypto_load_or_create_salt(NULL, "/tmp")
                == NOX_ERR_CONFIG);

    TEST_ASSERT(crypto_generate_identity(NULL, key, key)
                == NOX_ERR_CRYPTO);

    TEST_ASSERT(crypto_load_identity(NULL, key, (uint8_t[64]){0}, key)
                == NOX_ERR_CRYPTO);

    return 0;
}

/* ================================================================
 * TEST: Tam zincir — PIN → salt → master → subkeys → identity
 *
 * Aynı PIN ile ilk çalıştırma + ikinci çalıştırma simülasyonu.
 * ================================================================ */
static int test_full_chain(void)
{
    setup_test_dir();

    char pin[] = "aktivist2024!";
    char id_path[256];
    snprintf(id_path, sizeof(id_path), "%s/identity.key", TEST_DIR);

    /* ── İlk çalıştırma ────────────────────── */

    /* 1. Salt üret */
    uint8_t salt[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt, TEST_DIR) == NOX_OK);

    /* 2. PIN → master_key */
    uint8_t master[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_master_key(master, pin, strlen(pin), salt) == NOX_OK);

    /* 3. master → subkeys */
    uint8_t db[NOX_KEY_LEN], unlock[NOX_KEY_LEN], session[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_subkeys(master, db, unlock, session) == NOX_OK);

    /* 4. Identity üret */
    uint8_t pub1[NOX_KEY_LEN];
    TEST_ASSERT(crypto_generate_identity(id_path, unlock, pub1) == NOX_OK);

    /* ── İkinci çalıştırma (aynı PIN) ──────── */

    /* 1. Salt oku (aynısı) */
    uint8_t salt2[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt2, TEST_DIR) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(salt, salt2, NOX_SALT_LEN) == 0);

    /* 2. Aynı PIN → aynı master_key */
    uint8_t master2[NOX_KEY_LEN];
    char pin2_dup[] = "aktivist2024!";
    TEST_ASSERT(crypto_derive_master_key(master2, pin2_dup, strlen(pin2_dup), salt2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(master, master2, NOX_KEY_LEN) == 0);

    /* 3. Aynı subkeys */
    uint8_t db2[NOX_KEY_LEN], unlock2[NOX_KEY_LEN], session2[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_subkeys(master2, db2, unlock2, session2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(unlock, unlock2, NOX_KEY_LEN) == 0);

    /* 4. Identity yükle → aynı public key */
    uint8_t sk[64], pub2[NOX_KEY_LEN];
    TEST_ASSERT(crypto_load_identity(id_path, unlock2, sk, pub2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(pub1, pub2, NOX_KEY_LEN) == 0);

    explicit_bzero(master, sizeof(master));
    explicit_bzero(master2, sizeof(master2));
    explicit_bzero(sk, sizeof(sk));
    return 0;
}

/* ================================================================
 * TEST: Salt var ama identity.key yok
 *
 * Senaryo: İlk çalıştırma yarıda kesildi.
 *          salt üretildi ama identity.key yazılamadı.
 *          Sonraki çalıştırmada salt tekrar okunmalı,
 *          identity.key yeniden üretilmeli.
 * ================================================================ */
static int test_salt_exists_no_identity(void)
{
    setup_test_dir();

    /* Salt üret */
    uint8_t salt1[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt1, TEST_DIR) == NOX_OK);

    /* identity.key dosyası yok — salt yine doğru okunmalı */
    uint8_t salt2[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt2, TEST_DIR) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(salt1, salt2, NOX_SALT_LEN) == 0);

    /* identity.key üretimi hâlâ çalışmalı */
    char pin[] = "recovery_pin12";
    uint8_t master[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_master_key(master, pin, strlen(pin), salt2) == NOX_OK);

    uint8_t db[NOX_KEY_LEN], unlock[NOX_KEY_LEN], session[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_subkeys(master, db, unlock, session) == NOX_OK);

    char id_path[256];
    snprintf(id_path, sizeof(id_path), "%s/identity.key", TEST_DIR);

    uint8_t pub[NOX_KEY_LEN];
    TEST_ASSERT(crypto_generate_identity(id_path, unlock, pub) == NOX_OK);

    /* Doğrulama — yükleme çalışmalı */
    uint8_t sk[64], pub2[NOX_KEY_LEN];
    TEST_ASSERT(crypto_load_identity(id_path, unlock, sk, pub2) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(pub, pub2, NOX_KEY_LEN) == 0);

    explicit_bzero(master, sizeof(master));
    explicit_bzero(sk, sizeof(sk));
    return 0;
}

/* ================================================================
 * TEST: Bozuk salt dosyası → yeniden üretilmeli
 *
 * salt dosyası 16 byte yerine 5 byte → bozuk sayılır,
 * crypto_load_or_create_salt yeni salt üretmeli.
 * ================================================================ */
static int test_corrupt_salt_recovery(void)
{
    setup_test_dir();

    /* Bozuk salt yaz (5 byte) */
    char salt_path[256];
    snprintf(salt_path, sizeof(salt_path), "%s/salt", TEST_DIR);

    FILE *f = fopen(salt_path, "wb");
    TEST_ASSERT(f != NULL);
    uint8_t garbage[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
    fwrite(garbage, 1, sizeof(garbage), f);
    fclose(f);

    /* Okuma — bozuk tespit edip yeniden üretmeli */
    uint8_t salt[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt, TEST_DIR) == NOX_OK);

    /* Yeni salt sıfır olmamalı */
    uint8_t zero[NOX_SALT_LEN] = {0};
    TEST_ASSERT(sodium_memcmp(salt, zero, NOX_SALT_LEN) != 0);

    /* Tekrar okuma — aynı yeni salt dönmeli */
    uint8_t salt2[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt2, TEST_DIR) == NOX_OK);
    TEST_ASSERT(sodium_memcmp(salt, salt2, NOX_SALT_LEN) == 0);

    return 0;
}

/* ================================================================
 * TEST: Tam zincir yanlış PIN → NOX_ERR_AUTH
 *
 * Farklı PIN → farklı master_key → farklı unlock_key
 * → secretbox_open başarısız → NOX_ERR_AUTH
 * ================================================================ */
static int test_full_chain_wrong_pin(void)
{
    setup_test_dir();

    char id_path[256];
    snprintf(id_path, sizeof(id_path), "%s/identity.key", TEST_DIR);

    /* Doğru PIN ile tam zincir */
    char correct_pin[] = "correct_pin_2024";
    uint8_t salt[NOX_SALT_LEN];
    TEST_ASSERT(crypto_load_or_create_salt(salt, TEST_DIR) == NOX_OK);

    uint8_t master_ok[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_master_key(master_ok, correct_pin,
                strlen(correct_pin), salt) == NOX_OK);

    uint8_t db[NOX_KEY_LEN], unlock_ok[NOX_KEY_LEN], sess[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_subkeys(master_ok, db, unlock_ok, sess) == NOX_OK);

    uint8_t pub[NOX_KEY_LEN];
    TEST_ASSERT(crypto_generate_identity(id_path, unlock_ok, pub) == NOX_OK);

    /* Yanlış PIN ile tam zincir → AUTH hatası */
    char wrong_pin[] = "totally_wrong_99";
    uint8_t master_bad[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_master_key(master_bad, wrong_pin,
                strlen(wrong_pin), salt) == NOX_OK);

    /* master_key farklı olmalı */
    TEST_ASSERT(sodium_memcmp(master_ok, master_bad, NOX_KEY_LEN) != 0);

    uint8_t db2[NOX_KEY_LEN], unlock_bad[NOX_KEY_LEN], sess2[NOX_KEY_LEN];
    TEST_ASSERT(crypto_derive_subkeys(master_bad, db2, unlock_bad, sess2) == NOX_OK);

    /* unlock_key farklı olmalı */
    TEST_ASSERT(sodium_memcmp(unlock_ok, unlock_bad, NOX_KEY_LEN) != 0);

    /* Identity yükleme → secretbox_open başarısız → NOX_ERR_AUTH */
    uint8_t sk[64], pk[NOX_KEY_LEN];
    nox_err_t err = crypto_load_identity(id_path, unlock_bad, sk, pk);
    TEST_ASSERT(err == NOX_ERR_AUTH);

    explicit_bzero(master_ok, sizeof(master_ok));
    explicit_bzero(master_bad, sizeof(master_bad));
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== test_crypto ===\n\n");

    RUN_TEST(test_null_safety);
    RUN_TEST(test_argon2id_derive);
    RUN_TEST(test_subkey_derive);
    RUN_TEST(test_salt_management);
    RUN_TEST(test_identity_roundtrip);
    RUN_TEST(test_identity_wrong_pin);
    RUN_TEST(test_full_chain);
    RUN_TEST(test_salt_exists_no_identity);
    RUN_TEST(test_corrupt_salt_recovery);
    RUN_TEST(test_full_chain_wrong_pin);

    cleanup_test_dir();

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

