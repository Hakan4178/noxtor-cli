/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_database.c — Veritabanı modülü birim testleri
 */

#include "common.h"
#include "types.h"
#include "database.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>
#include <sqlite3.h>
#include "test_common.h"


static const char *TEST_DB_DIR = "tests/.tmp_db";
static const char *TEST_DB_FILE = "tests/.tmp_db/contacts.db";

static void setup_test_dir(void)
{
    mkdir(TEST_DB_DIR, 0700);
}

static int open_test_db_dir_fd(void)
{
    return open(TEST_DB_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static void remove_test_db_files(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/contacts.db", TEST_DB_DIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/contacts.db-wal", TEST_DB_DIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/contacts.db-shm", TEST_DB_DIR);
    unlink(path);
}

static void cleanup_test_dir(void)
{
    remove_test_db_files();
    rmdir(TEST_DB_DIR);
}

static uint8_t g_dummy_key[NOX_KEY_LEN];

static nox_err_t db_init_test(const uint8_t *key)
{
    int fd = open_test_db_dir_fd();
    if (fd < 0) return NOX_ERR_CONFIG;
    nox_err_t r = db_init(TEST_DB_DIR, fd, key);
    close(fd);
    return r;
}

/* Her test temiz DB ile başlar; testler arası sıra bağımlılığını kaldırır. */
static nox_err_t reset_test_db(void)
{
    db_close();
    (void)mkdir(TEST_DB_DIR, 0700);
    remove_test_db_files();
    return db_init_test(g_dummy_key);
}

static const char *ONION_A =
    "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst.onion";

static void onion_variant(char out[NOX_ONION_LEN + 1], char first)
{
    snprintf(out, NOX_ONION_LEN + 1, "%s", ONION_A);
    out[0] = first;
}

/* ================================================================
 * TESTLER
 * ================================================================ */

static int test_db_open_close(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    db_close();
    return 0;
}

static int test_db_contacts(void)
{
    nox_err_t err;
    TEST_ASSERT(reset_test_db() == NOX_OK);

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
    nox_err_t err;
    TEST_ASSERT(reset_test_db() == NOX_OK);

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

    err = db_init_test(wrong_key);
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
    nox_err_t err;
    TEST_ASSERT(reset_test_db() == NOX_OK);

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

static void dummy_contact_visitor(const char *onion, const char *name,
                                  const uint8_t noise_key[NOX_KEY_LEN],
                                  void *ctx) {
  (void)onion; (void)name; (void)noise_key;
  int *cnt = (int *)ctx;
  (*cnt)++;
}

static void dummy_history_visitor(const char *text, bool is_outgoing,
                                  time_t timestamp, void *ctx) {
  (void)text; (void)is_outgoing; (void)timestamp;
  int *cnt = (int *)ctx;
  (*cnt)++;
}

static void dummy_summary_visitor(
    const char *onion,
    const char *name,
    const uint8_t noise_key[NOX_KEY_LEN],
    const char *last_msg_text,
    bool last_msg_outgoing,
    time_t last_msg_timestamp,
    void *ctx
) {
  (void)onion; (void)name; (void)noise_key;
  (void)last_msg_outgoing; (void)last_msg_timestamp;
  char *last_msg_out = (char *)ctx;
  if (last_msg_text) {
    strcpy(last_msg_out, last_msg_text);
  }
}

static int test_db_history(void)
{
    nox_err_t err;
    TEST_ASSERT(reset_test_db() == NOX_OK);

    const char *onion = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst.onion";
    const char *name = "Test Contact";
    uint8_t noise_key[NOX_KEY_LEN];
    memset(noise_key, 0x11, NOX_KEY_LEN);

    /* Ekle */
    err = db_add_contact(onion, name, noise_key);
    TEST_ASSERT(err == NOX_OK);

    /* Oku ve doğrula */
    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];

    err = db_get_contact(onion, name_out, sizeof(name_out), key_out);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(strcmp(name_out, name) == 0);
    TEST_ASSERT(memcmp(key_out, noise_key, NOX_KEY_LEN) == 0);

    /* Listele */
    int contact_count = 0;
    err = db_list_contacts(dummy_contact_visitor, &contact_count);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(contact_count == 1);

    /* Mesaj kaydet */
    time_t now = time(NULL);
    err = db_save_message(onion, "Selam, nasılsın?", true, now - 10);
    TEST_ASSERT(err == NOX_OK);

    err = db_save_message(onion, "İyiyim, sen?", false, now);
    TEST_ASSERT(err == NOX_OK);

    /* Geçmiş oku */
    int history_count = 0;
    err = db_get_history(onion, 10, dummy_history_visitor, &history_count);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(history_count == 2);

    /* Son mesaj özetiyle listele */
    char summary_text[256] = {0};
    err = db_list_contacts_with_summary(dummy_summary_visitor, summary_text);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(strcmp(summary_text, "İyiyim, sen?") == 0);

    /* Sohbeti sil */
    err = db_delete_conversation(onion);
    TEST_ASSERT(err == NOX_OK);

    /* Silindikten sonra geçmiş boş olmalı */
    history_count = 0;
    err = db_get_history(onion, 10, dummy_history_visitor, &history_count);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(history_count == 0);

    db_close();
    return 0;
}

/* ================================================================
 * YENİ: Yüksek ROI testleri
 * ================================================================ */

struct text_log {
    char texts[8][128];
    int  count;
};

static nox_err_t log_send_cb(const char *text, void *ctx)
{
    struct text_log *log = ctx;
    if (log->count < (int)(sizeof(log->texts) / sizeof(log->texts[0])))
        snprintf(log->texts[log->count], sizeof(log->texts[0]), "%s", text);
    log->count++;
    return NOX_OK;
}

static void log_history_visitor(const char *text, bool is_outgoing,
                                time_t timestamp, void *ctx)
{
    (void)is_outgoing;
    (void)timestamp;
    struct text_log *log = ctx;
    if (log->count < (int)(sizeof(log->texts) / sizeof(log->texts[0])))
        snprintf(log->texts[log->count], sizeof(log->texts[0]), "%s", text);
    log->count++;
}

struct summary_entry {
    char   onion[NOX_ONION_LEN + 1];
    char   text[128];
    bool   has_text;
    bool   outgoing;
    time_t timestamp;
};

struct summary_log {
    struct summary_entry entries[4];
    int count;
};

static void log_summary_visitor(const char *onion, const char *name,
                                const uint8_t noise_key[NOX_KEY_LEN],
                                const char *last_msg_text,
                                bool last_msg_outgoing,
                                time_t last_msg_timestamp,
                                void *ctx)
{
    (void)name;
    (void)noise_key;
    struct summary_log *log = ctx;
    if (log->count >= (int)(sizeof(log->entries) / sizeof(log->entries[0])))
        return;
    struct summary_entry *e = &log->entries[log->count++];
    snprintf(e->onion, sizeof(e->onion), "%s", onion);
    e->has_text = last_msg_text != NULL;
    if (last_msg_text)
        snprintf(e->text, sizeof(e->text), "%s", last_msg_text);
    e->outgoing = last_msg_outgoing;
    e->timestamp = last_msg_timestamp;
}

static const struct summary_entry *find_summary(const struct summary_log *log,
                                                const char *onion)
{
    for (int i = 0; i < log->count; i++) {
        if (strcmp(log->entries[i].onion, onion) == 0)
            return &log->entries[i];
    }
    return NULL;
}

/* 1) A/B izolasyonu: kuyruk, geçmiş, contact ve silme kapsamı. */
static int test_db_peer_isolation(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    char onion_a[NOX_ONION_LEN + 1], onion_b[NOX_ONION_LEN + 1];
    onion_variant(onion_a, 'a');
    onion_variant(onion_b, 'b');

    uint8_t key_a[NOX_KEY_LEN], key_b[NOX_KEY_LEN];
    memset(key_a, 0x11, sizeof(key_a));
    memset(key_b, 0x22, sizeof(key_b));
    TEST_ASSERT(db_add_contact(onion_a, "Alice", key_a) == NOX_OK);
    TEST_ASSERT(db_add_contact(onion_b, "Bob", key_b) == NOX_OK);

    TEST_ASSERT(db_queue_message(onion_a, "a1") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_a, "a2") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_b, "b1") == NOX_OK);
    TEST_ASSERT(db_save_message(onion_a, "a-hist", true, 100) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_b, "b-hist", false, 200) == NOX_OK);

    /* Sohbet silme yalnız messages'a dokunur; contact ve kuyruk kalır. */
    TEST_ASSERT(db_delete_conversation(onion_a) == NOX_OK);

    int contact_count = 0;
    TEST_ASSERT(db_list_contacts(dummy_contact_visitor, &contact_count) == NOX_OK);
    TEST_ASSERT(contact_count == 2);

    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];
    TEST_ASSERT(db_get_contact(onion_b, name_out, sizeof(name_out), key_out) == NOX_OK);
    TEST_ASSERT(strcmp(name_out, "Bob") == 0);

    struct text_log hist_a = {0}, hist_b = {0};
    TEST_ASSERT(db_get_history(onion_a, 10, log_history_visitor, &hist_a) == NOX_OK);
    TEST_ASSERT(hist_a.count == 0);
    TEST_ASSERT(db_get_history(onion_b, 10, log_history_visitor, &hist_b) == NOX_OK);
    TEST_ASSERT(hist_b.count == 1);
    TEST_ASSERT(strcmp(hist_b.texts[0], "b-hist") == 0);

    struct text_log send_a = {0}, send_b = {0};
    TEST_ASSERT(db_process_queue(onion_a, log_send_cb, &send_a) == NOX_OK);
    TEST_ASSERT(send_a.count == 2);
    TEST_ASSERT(strcmp(send_a.texts[0], "a1") == 0);
    TEST_ASSERT(strcmp(send_a.texts[1], "a2") == 0);
    TEST_ASSERT(db_process_queue(onion_b, log_send_cb, &send_b) == NOX_OK);
    TEST_ASSERT(send_b.count == 1);
    TEST_ASSERT(strcmp(send_b.texts[0], "b1") == 0);

    db_close();
    return 0;
}

/* 2) limit: son N mesaj, artan sıra; limit<=0 varsayılan; bilinmeyen peer. */
static int test_db_history_limit_order(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    char onion_a[NOX_ONION_LEN + 1], onion_unknown[NOX_ONION_LEN + 1];
    onion_variant(onion_a, 'a');
    onion_variant(onion_unknown, 'z');

    const char *texts[] = {"m10", "m20", "m30", "m40", "m50"};
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(db_save_message(onion_a, texts[i], true, 10 * (i + 1)) == NOX_OK);

    struct text_log log = {0};
    TEST_ASSERT(db_get_history(onion_a, 2, log_history_visitor, &log) == NOX_OK);
    TEST_ASSERT(log.count == 2);
    TEST_ASSERT(strcmp(log.texts[0], "m40") == 0);
    TEST_ASSERT(strcmp(log.texts[1], "m50") == 0);

    memset(&log, 0, sizeof(log));
    TEST_ASSERT(db_get_history(onion_a, 1, log_history_visitor, &log) == NOX_OK);
    TEST_ASSERT(log.count == 1);
    TEST_ASSERT(strcmp(log.texts[0], "m50") == 0);

    memset(&log, 0, sizeof(log));
    TEST_ASSERT(db_get_history(onion_a, -1, log_history_visitor, &log) == NOX_OK);
    TEST_ASSERT(log.count == 5);
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(strcmp(log.texts[i], texts[i]) == 0);

    memset(&log, 0, sizeof(log));
    TEST_ASSERT(db_get_history(onion_unknown, 10, log_history_visitor, &log) == NOX_OK);
    TEST_ASSERT(log.count == 0);

    /* Aynı timestamp: son eklenen (yüksek id) seçilir, sonra artan sıra. */
    TEST_ASSERT(db_save_message(onion_a, "tie1", true, 60) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_a, "tie2", false, 60) == NOX_OK);
    memset(&log, 0, sizeof(log));
    TEST_ASSERT(db_get_history(onion_a, 2, log_history_visitor, &log) == NOX_OK);
    TEST_ASSERT(log.count == 2);
    TEST_ASSERT(strcmp(log.texts[0], "tie1") == 0);
    TEST_ASSERT(strcmp(log.texts[1], "tie2") == 0);

    db_close();
    return 0;
}

/* 3) Rollback: tam N satır, doğru peer; diğer peer etkilenmez. */
static int test_db_queue_rollback_exact(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    char onion_a[NOX_ONION_LEN + 1], onion_b[NOX_ONION_LEN + 1];
    onion_variant(onion_a, 'a');
    onion_variant(onion_b, 'b');

    TEST_ASSERT(db_queue_message(onion_a, "a1") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_a, "a2") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_a, "a3") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_b, "b1") == NOX_OK);

    TEST_ASSERT(db_queue_rollback_last(onion_a, 2) == NOX_OK);

    struct text_log send_a = {0}, send_b = {0};
    TEST_ASSERT(db_process_queue(onion_b, log_send_cb, &send_b) == NOX_OK);
    TEST_ASSERT(send_b.count == 1);
    TEST_ASSERT(strcmp(send_b.texts[0], "b1") == 0);

    TEST_ASSERT(db_process_queue(onion_a, log_send_cb, &send_a) == NOX_OK);
    TEST_ASSERT(send_a.count == 1);
    TEST_ASSERT(strcmp(send_a.texts[0], "a1") == 0);

    TEST_ASSERT(db_queue_rollback_last(onion_a, 0) == NOX_ERR_DB);
    TEST_ASSERT(db_queue_rollback_last(NULL, 1) == NOX_ERR_DB);

    db_close();
    return 0;
}

/* 4) Özet: mesajsız contact NULL, her contact kendi son mesajı, tie id. */
static int test_db_summary_multi_contact(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    char onion_a[NOX_ONION_LEN + 1], onion_b[NOX_ONION_LEN + 1];
    char onion_c[NOX_ONION_LEN + 1];
    onion_variant(onion_a, 'a');
    onion_variant(onion_b, 'b');
    onion_variant(onion_c, 'c');

    uint8_t key[NOX_KEY_LEN];
    memset(key, 0x33, sizeof(key));
    TEST_ASSERT(db_add_contact(onion_a, "Alice", key) == NOX_OK);
    TEST_ASSERT(db_add_contact(onion_b, "Bob", key) == NOX_OK);
    TEST_ASSERT(db_add_contact(onion_c, "Carol", key) == NOX_OK);

    TEST_ASSERT(db_save_message(onion_b, "b1", true, 100) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_b, "b2", true, 200) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_b, "b3", false, 200) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_c, "c-old", true, 100) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_c, "c-new", false, 300) == NOX_OK);

    struct summary_log log = {0};
    TEST_ASSERT(db_list_contacts_with_summary(log_summary_visitor, &log) == NOX_OK);
    TEST_ASSERT(log.count == 3);

    const struct summary_entry *ea = find_summary(&log, onion_a);
    const struct summary_entry *eb = find_summary(&log, onion_b);
    const struct summary_entry *ec = find_summary(&log, onion_c);
    TEST_ASSERT(ea && eb && ec);

    TEST_ASSERT(ea->has_text == false);
    TEST_ASSERT(ea->timestamp == 0);
    TEST_ASSERT(ea->outgoing == false);

    TEST_ASSERT(eb->has_text == true);
    TEST_ASSERT(strcmp(eb->text, "b3") == 0);
    TEST_ASSERT(eb->timestamp == 200);
    TEST_ASSERT(eb->outgoing == false);

    TEST_ASSERT(ec->has_text == true);
    TEST_ASSERT(strcmp(ec->text, "c-new") == 0);
    TEST_ASSERT(ec->timestamp == 300);
    TEST_ASSERT(ec->outgoing == false);

    db_close();
    return 0;
}

/* 5) Sınırlar: onion/isim/mesaj boyu, zero key, küçük buffer, state. */
static int test_db_boundaries(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    char onion_a[NOX_ONION_LEN + 1];
    onion_variant(onion_a, 'a');

    /* Açıkken ikinci init reddedilir. */
    TEST_ASSERT(db_init_test(g_dummy_key) == NOX_ERR_STATE);

    char onion61[NOX_ONION_LEN];
    memcpy(onion61, onion_a, NOX_ONION_LEN - 1);
    onion61[NOX_ONION_LEN - 1] = '\0';
    char onion63[NOX_ONION_LEN + 2];
    snprintf(onion63, sizeof(onion63), "%sX", onion_a);

    uint8_t key[NOX_KEY_LEN];
    memset(key, 0x44, sizeof(key));

    TEST_ASSERT(db_add_contact(onion61, "Short", key) == NOX_ERR_DB);
    TEST_ASSERT(db_add_contact(onion63, "Long", key) == NOX_ERR_DB);

    char name64[NOX_CONTACT_NAME_LEN + 1];
    memset(name64, 'N', NOX_CONTACT_NAME_LEN);
    name64[NOX_CONTACT_NAME_LEN] = '\0';
    char name65[NOX_CONTACT_NAME_LEN + 2];
    memset(name65, 'N', NOX_CONTACT_NAME_LEN + 1);
    name65[NOX_CONTACT_NAME_LEN + 1] = '\0';

    uint8_t zero_key[NOX_KEY_LEN] = {0};
    TEST_ASSERT(db_add_contact(onion_a, name64, zero_key) == NOX_OK);

    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];
    TEST_ASSERT(db_get_contact(onion_a, name_out, sizeof(name_out), key_out) == NOX_OK);
    TEST_ASSERT(strcmp(name_out, name64) == 0);
    TEST_ASSERT_MEM_ZERO(key_out, sizeof(key_out));

    TEST_ASSERT(db_add_contact(onion_a, name65, key) == NOX_ERR_DB);

    /* Küçük çıktı tamponu taşmaz; boş string döner. */
    char tiny[1] = {0x7f};
    TEST_ASSERT(db_get_contact(onion_a, tiny, sizeof(tiny), key_out) == NOX_OK);
    TEST_ASSERT(tiny[0] == '\0');

    char msg4095[4096];
    char msg4096[4097];
    memset(msg4095, 'M', sizeof(msg4095) - 1);
    msg4095[sizeof(msg4095) - 1] = '\0';
    memset(msg4096, 'M', sizeof(msg4096) - 1);
    msg4096[sizeof(msg4096) - 1] = '\0';

    TEST_ASSERT(db_queue_message(onion_a, msg4095) == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_a, msg4096) == NOX_ERR_DB);
    TEST_ASSERT(db_save_message(onion_a, msg4095, true, 1) == NOX_OK);
    TEST_ASSERT(db_save_message(onion_a, msg4096, true, 1) == NOX_ERR_DB);

    /* Kapatıldıktan sonra DB_BEGIN fail-closed. */
    db_close();
    TEST_ASSERT(db_add_contact(onion_a, name64, key) == NOX_ERR_STATE);

    return 0;
}

/* ================================================================
 * SALDIRGAN TESTİ — DB dosyasına yazabilen aktör
 *
 * Tehdit: yerel malware / fiziksel erişim / yedekten geri yükleme ile
 * contacts.db'yi doğrudan değiştiren aktör. Amaç sadece veri okumak değil;
 * uygulamayı yanlış mesaj göstermeye, çökmeye veya kuyruğu kilitlemeye
 * zorlamak. Beklenen: MAC doğrulaması geçmeyen hiçbir satır UI'ya ulaşmaz,
 * sağlam satırlar doğru yön/zamanla gelir, kuyruk zehirlenmesi teslimatı
 * durdurmaz.
 * ================================================================ */

struct adv_msg {
    char   text[128];
    bool   outgoing;
    time_t timestamp;
};

struct adv_history {
    struct adv_msg msgs[8];
    int count;
};

static void adv_history_visitor(const char *text, bool is_outgoing,
                                time_t timestamp, void *ctx)
{
    struct adv_history *hist = ctx;
    if (hist->count >= (int)(sizeof(hist->msgs) / sizeof(hist->msgs[0])))
        return;
    struct adv_msg *m = &hist->msgs[hist->count++];
    snprintf(m->text, sizeof(m->text), "%s", text);
    m->outgoing = is_outgoing;
    m->timestamp = timestamp;
}

/* Tablo/kolon adları yalnız bu dosyadaki sabitlerdir; SQL'e değer girmez. */
static int tamper_ids(sqlite3 *db, const char *table, int64_t *ids, int max)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT id FROM %s ORDER BY id ASC;", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    int count = 0;
    while (count < max && sqlite3_step(stmt) == SQLITE_ROW)
        ids[count++] = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

static int tamper_read_blob(sqlite3 *db, const char *table, const char *column,
                            int64_t id, uint8_t **out, int *out_len)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT %s FROM %s WHERE id = ?;", column, table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(stmt, 1, id);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    const void *blob = sqlite3_column_blob(stmt, 0);
    int len = sqlite3_column_bytes(stmt, 0);
    if (!blob || len <= 0) {
        sqlite3_finalize(stmt);
        return -1;
    }
    uint8_t *copy = malloc((size_t)len);
    if (!copy) {
        sqlite3_finalize(stmt);
        return -1;
    }
    memcpy(copy, blob, (size_t)len);
    sqlite3_finalize(stmt);
    *out = copy;
    *out_len = len;
    return 0;
}

static int tamper_write_blob(sqlite3 *db, const char *table, const char *column,
                             int64_t id, const uint8_t *data, int len)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "UPDATE %s SET %s = ? WHERE id = ?;", table, column);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(stmt, 1, data, len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static int tamper_flip(sqlite3 *db, const char *table, int64_t id, int from_end)
{
    uint8_t *blob = NULL;
    int len = 0;
    if (tamper_read_blob(db, table, "encrypted_payload", id, &blob, &len) != 0)
        return -1;
    int pos = len - 1 - from_end;
    if (pos < 0) pos = 0;
    blob[pos] ^= 0x01;
    int rc = tamper_write_blob(db, table, "encrypted_payload", id, blob, len);
    free(blob);
    return rc;
}

static int tamper_truncate(sqlite3 *db, const char *table, int64_t id, int keep)
{
    uint8_t *blob = NULL;
    int len = 0;
    if (tamper_read_blob(db, table, "encrypted_payload", id, &blob, &len) != 0)
        return -1;
    if (keep > len) keep = len;
    int rc = tamper_write_blob(db, table, "encrypted_payload", id, blob, keep);
    free(blob);
    return rc;
}

static int tamper_swap_nonces(sqlite3 *db, const char *table, int64_t a, int64_t b)
{
    uint8_t *na = NULL, *nb = NULL;
    int la = 0, lb = 0;
    if (tamper_read_blob(db, table, "nonce", a, &na, &la) != 0)
        return -1;
    if (tamper_read_blob(db, table, "nonce", b, &nb, &lb) != 0) {
        free(na);
        return -1;
    }
    if (la != (int)NOX_NONCE_LEN || lb != (int)NOX_NONCE_LEN) {
        free(na);
        free(nb);
        return -1;
    }
    int rc1 = tamper_write_blob(db, table, "nonce", a, nb, lb);
    int rc2 = tamper_write_blob(db, table, "nonce", b, na, la);
    free(na);
    free(nb);
    return (rc1 == 0 && rc2 == 0) ? 0 : -1;
}

static int tamper_count_rows(sqlite3 *db, const char *table)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s;", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

/* 6) Saldırgan: ciphertext bozar, nonce takas eder, kuyruğu zehirler. */
static int test_db_adversarial_tamper(void)
{
    TEST_ASSERT(reset_test_db() == NOX_OK);

    char onion_a[NOX_ONION_LEN + 1], onion_b[NOX_ONION_LEN + 1];
    char onion_c[NOX_ONION_LEN + 1];
    onion_variant(onion_a, 'a');
    onion_variant(onion_b, 'b');
    onion_variant(onion_c, 'c');

    uint8_t key[NOX_KEY_LEN];
    memset(key, 0x55, sizeof(key));
    TEST_ASSERT(db_add_contact(onion_a, "Alice", key) == NOX_OK);
    TEST_ASSERT(db_add_contact(onion_b, "Bob", key) == NOX_OK);
    TEST_ASSERT(db_add_contact(onion_c, "Carol", key) == NOX_OK);

    /* A: m1 sağlam, m2 MAC fail, m3 truncate, m4/m5 nonce takası. */
    const char *texts[] = {"m1", "m2", "m3", "m4", "m5"};
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(db_save_message(onion_a, texts[i], i % 2 == 0,
                                    10 * (i + 1)) == NOX_OK);
    /* B: temiz son mesaj; C: mesajsız. */
    TEST_ASSERT(db_save_message(onion_b, "b-clean", false, 70) == NOX_OK);

    /* A kuyruğu: q1, q2 (zehirlenecek), q3; B kuyruğu: bq1. */
    TEST_ASSERT(db_queue_message(onion_a, "q1") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_a, "q2") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_a, "q3") == NOX_OK);
    TEST_ASSERT(db_queue_message(onion_b, "bq1") == NOX_OK);

    db_close();

    /* Saldırganın elinde DB dosyası var: doğrudan SQLite ile yaz. */
    sqlite3 *tdb = NULL;
    TEST_ASSERT(sqlite3_open_v2(TEST_DB_FILE, &tdb, SQLITE_OPEN_READWRITE,
                                NULL) == SQLITE_OK);
    TEST_ASSERT(tdb != NULL);

    int64_t mids[8];
    int mid_count = tamper_ids(tdb, "messages", mids, 8);
    TEST_ASSERT(mid_count == 6);
    int64_t qids[8];
    int qid_count = tamper_ids(tdb, "queue", qids, 8);
    TEST_ASSERT(qid_count == 4);

    TEST_ASSERT(tamper_flip(tdb, "messages", mids[1], 1) == 0);
    TEST_ASSERT(tamper_truncate(tdb, "messages", mids[2], 8) == 0);
    TEST_ASSERT(tamper_swap_nonces(tdb, "messages", mids[3], mids[4]) == 0);
    TEST_ASSERT(tamper_flip(tdb, "queue", qids[1], 1) == 0);

    TEST_ASSERT(sqlite3_close(tdb) == SQLITE_OK);
    TEST_ASSERT(db_init_test(g_dummy_key) == NOX_OK);

    /* Geçmiş: yalnız m1 sağlam; yön ve zaman metadata'sı doğru olmalı. */
    struct adv_history hist = {0};
    TEST_ASSERT(db_get_history(onion_a, 10, adv_history_visitor, &hist) == NOX_OK);
    TEST_ASSERT(hist.count == 1);
    TEST_ASSERT(strcmp(hist.msgs[0].text, "m1") == 0);
    TEST_ASSERT(hist.msgs[0].outgoing == true);
    TEST_ASSERT(hist.msgs[0].timestamp == 10);

    /* Kuyruk: bozuk q2 atlanır/silinir; q1 ve q3 gider, B etkilenmez. */
    struct text_log send_a = {0}, send_b = {0};
    TEST_ASSERT(db_process_queue(onion_a, log_send_cb, &send_a) == NOX_OK);
    TEST_ASSERT(send_a.count == 2);
    TEST_ASSERT(strcmp(send_a.texts[0], "q1") == 0);
    TEST_ASSERT(strcmp(send_a.texts[1], "q3") == 0);
    TEST_ASSERT(db_process_queue(onion_b, log_send_cb, &send_b) == NOX_OK);
    TEST_ASSERT(send_b.count == 1);
    TEST_ASSERT(strcmp(send_b.texts[0], "bq1") == 0);

    /* Özet: A'nın son mesajı bozuk → metin yok; B temiz → doğru metin/yön;
     * C mesajsız → metin yok. Çöp metin veya çökme olmamalı. */
    struct summary_log slog = {0};
    TEST_ASSERT(db_list_contacts_with_summary(log_summary_visitor, &slog) == NOX_OK);
    TEST_ASSERT(slog.count == 3);
    const struct summary_entry *sa = find_summary(&slog, onion_a);
    const struct summary_entry *sb = find_summary(&slog, onion_b);
    const struct summary_entry *sc = find_summary(&slog, onion_c);
    TEST_ASSERT(sa && sb && sc);
    TEST_ASSERT(sa->has_text == false);
    TEST_ASSERT(sb->has_text == true);
    TEST_ASSERT(strcmp(sb->text, "b-clean") == 0);
    TEST_ASSERT(sb->timestamp == 70);
    TEST_ASSERT(sb->outgoing == false);
    TEST_ASSERT(sc->has_text == false);
    TEST_ASSERT(sc->timestamp == 0);

    /* Saldırganın zehirlediği kuyruk satırı kalıcı olarak temizlenmiş olmalı. */
    db_close();
    tdb = NULL;
    TEST_ASSERT(sqlite3_open_v2(TEST_DB_FILE, &tdb, SQLITE_OPEN_READWRITE,
                                NULL) == SQLITE_OK);
    TEST_ASSERT(tdb != NULL);
    TEST_ASSERT(tamper_count_rows(tdb, "queue") == 0);
    TEST_ASSERT(sqlite3_close(tdb) == SQLITE_OK);

    return 0;
}

/* ================================================================
 * ANA GİRİŞ NOKTASI
 * ================================================================ */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }
    randombytes_buf(g_dummy_key, NOX_KEY_LEN);

    fprintf(stderr, "=== DATABASE MODÜLÜ TESTLERİ ===\n");

    setup_test_dir();

    RUN_TEST(test_db_open_close);
    RUN_TEST(test_db_contacts);
    RUN_TEST(test_db_wrong_key);
    RUN_TEST(test_db_queue);
    RUN_TEST(test_db_history);
    RUN_TEST(test_db_peer_isolation);
    RUN_TEST(test_db_history_limit_order);
    RUN_TEST(test_db_queue_rollback_exact);
    RUN_TEST(test_db_summary_multi_contact);
    RUN_TEST(test_db_boundaries);
    RUN_TEST(test_db_adversarial_tamper);

    cleanup_test_dir();

    fprintf(stderr, "Sonuç: %d/%d test başarılı.\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
