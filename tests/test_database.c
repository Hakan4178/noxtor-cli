/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_database.c — Veritabanı modülü birim testleri
 */

#include "common.h"
#include "types.h"
#include "database.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
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

static const char *TEST_DB_DIR = "tests/.tmp_db";

static void setup_test_dir(void)
{
    mkdir(TEST_DB_DIR, 0700);
}

static void cleanup_test_dir(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/contacts.db", TEST_DB_DIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/contacts.db-wal", TEST_DB_DIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/contacts.db-shm", TEST_DB_DIR);
    unlink(path);
    rmdir(TEST_DB_DIR);
}

static uint8_t g_dummy_key[NOX_KEY_LEN];

/* ================================================================
 * TESTLER
 * ================================================================ */

static int test_db_open_close(void)
{
    nox_err_t err = db_init(TEST_DB_DIR, g_dummy_key);
    TEST_ASSERT(err == NOX_OK);

    db_close();
    return 0;
}

static int test_db_contacts(void)
{
    nox_err_t err = db_init(TEST_DB_DIR, g_dummy_key);
    TEST_ASSERT(err == NOX_OK);

    const char *onion = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst.onion";
    const char *name = "Test Contact";
    uint8_t noise_key[NOX_KEY_LEN];
    memset(noise_key, 0xAA, NOX_KEY_LEN);

    /* Ekle */
    err = db_add_contact(onion, name, noise_key);
    TEST_ASSERT(err == NOX_OK);

    /* Oku */
    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];
    err = db_get_contact(onion, name_out, sizeof(name_out), key_out);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(strcmp(name_out, name) == 0);
    TEST_ASSERT(memcmp(key_out, noise_key, NOX_KEY_LEN) == 0);

    /* Bulunmayan kontaktı sorgula */
    const char *unknown_onion = "bcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstu.onion";
    err = db_get_contact(unknown_onion, name_out, sizeof(name_out), key_out);
    TEST_ASSERT(err != NOX_OK);

    /* Güncelle */
    const char *new_name = "Updated Name";
    uint8_t new_key[NOX_KEY_LEN];
    memset(new_key, 0xBB, NOX_KEY_LEN);

    err = db_add_contact(onion, new_name, new_key);
    TEST_ASSERT(err == NOX_OK);

    err = db_get_contact(onion, name_out, sizeof(name_out), key_out);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(strcmp(name_out, new_name) == 0);
    TEST_ASSERT(memcmp(key_out, new_key, NOX_KEY_LEN) == 0);

    db_close();
    return 0;
}

static int test_db_wrong_key(void)
{
    /* İlk olarak doğru anahtarla açıp yaz */
    nox_err_t err = db_init(TEST_DB_DIR, g_dummy_key);
    TEST_ASSERT(err == NOX_OK);

    const char *onion = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst.onion";
    const char *name = "Secure Contact";
    uint8_t noise_key[NOX_KEY_LEN];
    memset(noise_key, 0xCC, NOX_KEY_LEN);

    err = db_add_contact(onion, name, noise_key);
    TEST_ASSERT(err == NOX_OK);
    db_close();

    /* Şimdi yanlış anahtarla açmayı dene */
    uint8_t wrong_key[NOX_KEY_LEN];
    memset(wrong_key, 0x99, NOX_KEY_LEN);

    err = db_init(TEST_DB_DIR, wrong_key);
    TEST_ASSERT(err == NOX_OK);

    /* Kaydı okumaya çalış, deşifre edilememeli veya bulunamamalı (yani NOX_OK dönmemeli) */
    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];
    err = db_get_contact(onion, name_out, sizeof(name_out), key_out);
    TEST_ASSERT(err != NOX_OK);

    db_close();
    return 0;
}

static nox_err_t dummy_send_callback(const char *text, void *ctx)
{
    char *expected = (char *)ctx;
    if (strcmp(text, expected) == 0) {
        return NOX_OK;
    }
    return NOX_ERR_NET;
}

static int test_db_queue(void)
{
    nox_err_t err = db_init(TEST_DB_DIR, g_dummy_key);
    TEST_ASSERT(err == NOX_OK);

    const char *onion = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst.onion";
    const char *msg1 = "Hello offline peer!";
    const char *msg2 = "Another message";

    /* Kuyrukla */
    err = db_queue_message(onion, msg1);
    TEST_ASSERT(err == NOX_OK);

    err = db_queue_message(onion, msg2);
    TEST_ASSERT(err == NOX_OK);

    /* İşle — ilk mesaj için callback */
    char expected_msg[256];
    strcpy(expected_msg, msg1);
    err = db_process_queue(onion, dummy_send_callback, expected_msg);
    /* İlk mesaj başarıyla iletilip silinecek ancak ikincisi callback context'i (msg1 beklediği için)
     * mismatch olacağından fail olacak ve işleme duracak. */
    TEST_ASSERT(err == NOX_ERR_NET);

    /* Şimdi ikincisini doğru context ile gönderelim */
    strcpy(expected_msg, msg2);
    err = db_process_queue(onion, dummy_send_callback, expected_msg);
    TEST_ASSERT(err == NOX_OK);

    /* Tekrar çalıştırınca kuyruk boş olmalı (hata vermez, NOX_OK döner) */
    err = db_process_queue(onion, dummy_send_callback, expected_msg);
    TEST_ASSERT(err == NOX_OK);

    db_close();
    return 0;
}

/* ================================================================
 * ANA GİRİŞ NOKTASI
 * ================================================================ */
int main(void)
{
    sodium_init();
    randombytes_buf(g_dummy_key, NOX_KEY_LEN);

    fprintf(stderr, "=== DATABASE MODÜLÜ TESTLERİ ===\n");

    setup_test_dir();

    RUN_TEST(test_db_open_close);
    RUN_TEST(test_db_contacts);
    RUN_TEST(test_db_wrong_key);
    RUN_TEST(test_db_queue);

    cleanup_test_dir();

    fprintf(stderr, "Sonuç: %d/%d test başarılı.\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
