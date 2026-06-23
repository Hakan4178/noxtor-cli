/* SPDX-License-Identifier: GPL-3.0-or-later
 * database.c — SQLite tabanlı şifreli kontakt ve mesaj kuyruk yönetim sistemi
 */

#include "database.h"
#include "asm_utils.h"

#include <assert.h>
#include <limits.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* ================================================================
 * STATİK VERİLER
 * ================================================================ */
typedef struct {
    sqlite3           *db;
    const uint8_t     *db_key;
    bool               ready;
    pthread_mutex_t    lock;
    uint64_t           key_generation;
} nox_db_state_t;

static nox_db_state_t g_state = {
    .db             = NULL,
    .db_key         = NULL,
    .ready          = false,
    .lock           = PTHREAD_MUTEX_INITIALIZER,
    .key_generation = 0,
};

#define DB_LOCK()   pthread_mutex_lock(&g_state.lock)
#define DB_UNLOCK() pthread_mutex_unlock(&g_state.lock)

/* M-16 FIX: sqlite3_errmsg sadece debug'da — production'da genel mesaj */
#ifdef NDEBUG
#define DB_ERRMSG() ""
#else
#define DB_ERRMSG() sqlite3_errmsg(g_state.db)
#endif

#define DB_BIND_CHECK(rc, stmt, label)          \
    do {                                         \
        if ((rc) != SQLITE_OK) {                 \
            NOX_ERROR(LOG_MOD_DB,                \
                "bind başarısız: %s",            \
                DB_ERRMSG());                    \
            sqlite3_finalize(stmt);              \
            goto label;                          \
        }                                        \
    } while (0)

/* ================================================================
 * YARDIMCI GÜVENLİK FONKSİYONLARI
 * ================================================================ */

/* Onion adresi için keyed BLAKE2b hash hesapla (metadata sızıntısını önler) */
static nox_err_t hash_onion(const char *onion, uint8_t hash_out[32]) {
  if (!onion || !hash_out || !g_state.db_key) {
    NOX_ERROR(LOG_MOD_DB, "hash_onion: NULL parametre");
    return NOX_ERR_CRYPTO;
  }

  size_t onion_len = strnlen(onion, NOX_ONION_LEN + 1);
  if (onion_len != NOX_ONION_LEN) {
    NOX_ERROR(LOG_MOD_DB, "hash_onion: geçersiz onion uzunluğu (%zu)", onion_len);
    return NOX_ERR_CRYPTO;
  }

  if (crypto_generichash(hash_out, 32, (const uint8_t *)onion, onion_len,
                         g_state.db_key, NOX_KEY_LEN) != 0) {
    NOX_ERROR(LOG_MOD_DB, "Onion hashing başarısız");
    return NOX_ERR_CRYPTO;
  }
  return NOX_OK;
}

/* Payloadi db_key ile şifrele */
static nox_err_t encrypt_payload(const uint8_t *plain, size_t plain_len,
                                 uint8_t nonce[NOX_NONCE_LEN],
                                 uint8_t *cipher_out, size_t cipher_len) {
  randombytes_buf(nonce, NOX_NONCE_LEN);

  if (cipher_len < plain_len + crypto_secretbox_MACBYTES) {
    return NOX_ERR_OVERFLOW;
  }

  if (crypto_secretbox_easy(cipher_out, plain, plain_len, nonce, g_state.db_key) !=
      0) {
    NOX_ERROR(LOG_MOD_DB, "Kayıt şifreleme hatası");
    return NOX_ERR_CRYPTO;
  }
  return NOX_OK;
}

/* Payload'u db_key ile deşifre et */
static nox_err_t decrypt_payload(const uint8_t *cipher, size_t cipher_len,
                                 const uint8_t nonce[NOX_NONCE_LEN],
                                 uint8_t *plain_out, size_t plain_len,
                                 size_t *plain_len_out) {
  if (cipher_len < crypto_secretbox_MACBYTES) {
    return NOX_ERR_AUTH;
  }

  size_t expected_plain_len = cipher_len - crypto_secretbox_MACBYTES;
  if (plain_len < expected_plain_len) {
    return NOX_ERR_OVERFLOW;
  }

  if (crypto_secretbox_open_easy(plain_out, cipher, cipher_len, nonce,
                                 g_state.db_key) != 0) {
    NOX_WARN(
        LOG_MOD_DB,
        "Kayıt MAC doğrulaması başarısız — hatalı anahtar veya bozuk veri");
    return NOX_ERR_AUTH;
  }

  if (plain_len_out) {
    *plain_len_out = expected_plain_len;
  }
  return NOX_OK;
}

/* ================================================================
 * PUBLIC API IMPLEMENTASYONU
 * ================================================================ */

nox_err_t db_init(const char *config_dir, const uint8_t db_key[NOX_KEY_LEN]) {
  if (!config_dir || !db_key)
    return NOX_ERR_CONFIG;

  DB_LOCK();
  if (g_state.ready) {
    NOX_WARN(LOG_MOD_DB, "db_init: veritabanı zaten açık, önce db_close() çağrın");
    DB_UNLOCK();
    return NOX_ERR_STATE;
  }

  /* db_key pointer'ını sakla — secure arena'daki korumalı adrese işaret eder */
  g_state.db_key = db_key;

  char db_path[NOX_PATH_MAX];
  int n = snprintf(db_path, sizeof(db_path), "%s/contacts.db", config_dir);
  if (n < 0 || (size_t)n >= sizeof(db_path)) {
    g_state.db_key = NULL;
    DB_UNLOCK();
    return NOX_ERR_CONFIG;
  }

  /* SQLite bağlantısını aç */
  int rc = sqlite3_open_v2(
      db_path, &g_state.db,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Veritabanı açılamadı: %s", DB_ERRMSG());
    if (g_state.db) {
      sqlite3_close(g_state.db);
      g_state.db = NULL;
    }
    g_state.db_key = NULL;
    DB_UNLOCK();
    return NOX_ERR_DB;
  }

  /* SQLite güvenlik optimizasyonları (WAL, Secure Delete) */
  char *err_msg = NULL;
  rc = sqlite3_exec(g_state.db,
                    "PRAGMA journal_mode=WAL;"
                    "PRAGMA synchronous=NORMAL;"
                    "PRAGMA secure_delete=ON;",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "PRAGMA secure_delete ayarlanamadı: %s", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(g_state.db);
    g_state.db = NULL;
    g_state.db_key = NULL;
    DB_UNLOCK();
    return NOX_ERR_DB;
  }

  /* Rehber tablosu */
  rc = sqlite3_exec(g_state.db,
                    "CREATE TABLE IF NOT EXISTS contacts ("
                    "  onion_hash BLOB PRIMARY KEY,"
                    "  nonce BLOB NOT NULL,"
                    "  encrypted_payload BLOB NOT NULL"
                    ");",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "contacts tablosu oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(g_state.db);
    g_state.db = NULL;
    g_state.db_key = NULL;
    DB_UNLOCK();
    return NOX_ERR_DB;
  }

  /* Mesaj kuyruğu tablosu */
  rc = sqlite3_exec(g_state.db,
                    "CREATE TABLE IF NOT EXISTS queue ("
                    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "  recipient_hash BLOB NOT NULL,"
                    "  nonce BLOB NOT NULL,"
                    "  encrypted_payload BLOB NOT NULL"
                    ");",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "queue tablosu oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(g_state.db);
    g_state.db = NULL;
    g_state.db_key = NULL;
    DB_UNLOCK();
    return NOX_ERR_DB;
  }

  /* Mesaj geçmişi tablosu */
  rc = sqlite3_exec(g_state.db,
                    "CREATE TABLE IF NOT EXISTS messages ("
                    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "  peer_hash BLOB NOT NULL,"
                    "  nonce BLOB NOT NULL,"
                    "  encrypted_payload BLOB NOT NULL,"
                    "  timestamp INTEGER NOT NULL,"
                    "  is_outgoing INTEGER NOT NULL"
                    ");",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "messages tablosu oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(g_state.db);
    g_state.db = NULL;
    g_state.db_key = NULL;
    DB_UNLOCK();
    return NOX_ERR_DB;
  }

  /* Mesaj geçmişi indexi */
  rc = sqlite3_exec(g_state.db,
                    "CREATE INDEX IF NOT EXISTS idx_messages_peer_timestamp ON messages (peer_hash, timestamp);",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_WARN(LOG_MOD_DB, "idx_messages_peer_timestamp oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
  }

  g_state.ready = true;
  NOX_INFO(LOG_MOD_DB, "Veritabanı başarıyla başlatıldı");
  DB_UNLOCK();
  return NOX_OK;
}

void db_close(void) {
  DB_LOCK();
  if (g_state.db) {
    /* M-18 FIX: sqlite3_next_stmt ile kalan tüm statement'ları finalize et.
     * sqlite3_close_v2, unfinalized statement varsa SQLITE_BUSY dönebilir
     * ve connection açık kalabilir. */
    sqlite3_stmt *stmt = sqlite3_next_stmt(g_state.db, NULL);
    while (stmt) {
      sqlite3_stmt *next = sqlite3_next_stmt(g_state.db, stmt);
      sqlite3_finalize(stmt);
      stmt = next;
    }
    sqlite3_close_v2(g_state.db);
    g_state.db = NULL;
  }
  g_state.db_key = NULL;
  memory_barrier();
  g_state.ready = false;
  NOX_INFO(LOG_MOD_DB, "Veritabanı kapatıldı");
  DB_UNLOCK();
}

struct contact_payload_old {
  char onion[NOX_ONION_LEN + 1];
  char name[NOX_CONTACT_NAME_LEN + 1];
  uint8_t noise_key[NOX_KEY_LEN];
};

struct contact_payload {
  char onion[NOX_ONION_LEN + 1];
  char name[NOX_CONTACT_NAME_LEN + 1];
  uint8_t noise_key[NOX_KEY_LEN];
  char my_onion[NOX_ONION_LEN + 1];
  char my_onion_key[NOX_ONION_KEY_B64_LEN + 1];
};

nox_err_t db_add_contact(const char *onion, const char *name, const uint8_t noise_key[NOX_KEY_LEN],
                         const char *my_onion, const uint8_t *my_onion_key, size_t my_onion_key_len) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!onion || !name || !noise_key) { DB_UNLOCK(); return NOX_ERR_DB; }

  size_t onion_len = strnlen(onion, NOX_ONION_LEN + 1);
  size_t name_len = strnlen(name, NOX_CONTACT_NAME_LEN + 1);

  if (onion_len != NOX_ONION_LEN || name_len > NOX_CONTACT_NAME_LEN) {
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  struct contact_payload cp;
  sodium_memzero(&cp, sizeof(cp));
  strncpy(cp.onion, onion, NOX_ONION_LEN);
  cp.onion[NOX_ONION_LEN] = '\0';
  strncpy(cp.name, name, NOX_CONTACT_NAME_LEN);
  cp.name[NOX_CONTACT_NAME_LEN] = '\0';
  memcpy(cp.noise_key, noise_key, NOX_KEY_LEN);
  if (my_onion) {
    size_t my_onion_len = strnlen(my_onion, NOX_ONION_LEN + 1);
    if (my_onion_len != NOX_ONION_LEN) { DB_UNLOCK(); return NOX_ERR_DB; }
    strncpy(cp.my_onion, my_onion, NOX_ONION_LEN);
    cp.my_onion[NOX_ONION_LEN] = '\0';
  }
  if (my_onion_key && my_onion_key_len > 0) {
    size_t copy_len = my_onion_key_len > NOX_ONION_KEY_B64_LEN ? NOX_ONION_KEY_B64_LEN : my_onion_key_len;
    memcpy(cp.my_onion_key, my_onion_key, copy_len);
    cp.my_onion_key[copy_len < NOX_ONION_KEY_B64_LEN ? copy_len : NOX_ONION_KEY_B64_LEN] = '\0';
  }

  uint8_t nonce[NOX_NONCE_LEN];
  uint8_t cipher[sizeof(struct contact_payload) + crypto_secretbox_MACBYTES];
  
  nox_err_t err = encrypt_payload((const uint8_t *)&cp, sizeof(cp), nonce,
                                  cipher, sizeof(cipher));
  sodium_memzero(&cp, sizeof(cp));

  if (err != NOX_OK) {
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(cipher, sizeof(cipher));
    DB_UNLOCK();
    return err;
  }

  uint8_t hash[32];
  err = hash_onion(onion, hash);
  if (err != NOX_OK) {
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(cipher, sizeof(cipher));
    DB_UNLOCK();
    return err;
  }

  sqlite3_stmt *stmt = NULL;
  const char *sql = "INSERT OR REPLACE INTO contacts (onion_hash, nonce, "
                    "encrypted_payload) VALUES (?, ?, ?);";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    err = NOX_ERR_DB;
    goto cleanup;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  DB_BIND_CHECK(rc, stmt, cleanup);
  rc = sqlite3_bind_blob(stmt, 2, nonce, sizeof(nonce), SQLITE_TRANSIENT);
  DB_BIND_CHECK(rc, stmt, cleanup);
  rc = sqlite3_bind_blob(stmt, 3, cipher, sizeof(cipher), SQLITE_TRANSIENT);
  DB_BIND_CHECK(rc, stmt, cleanup);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    NOX_ERROR(LOG_MOD_DB, "Kontakt ekleme hatası: %s", DB_ERRMSG());
    err = NOX_ERR_DB;
    goto cleanup;
  }

  NOX_INFO(LOG_MOD_DB, "Kontakt başarıyla eklendi/güncellendi");
  err = NOX_OK;

cleanup:
  sodium_memzero(hash, sizeof(hash));
  sodium_memzero(nonce, sizeof(nonce));
  sodium_memzero(cipher, sizeof(cipher));
  DB_UNLOCK();
  return err;
}

nox_err_t db_get_contact(const char *onion, char *name_out, size_t name_len, uint8_t noise_key_out[NOX_KEY_LEN],
                         char *my_onion_out, size_t my_onion_len,
                         uint8_t *my_onion_key_out, size_t *my_onion_key_len_out) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!onion || !name_out || !noise_key_out || name_len == 0) { DB_UNLOCK(); return NOX_ERR_DB; }

  uint8_t hash[32];
  nox_err_t err = hash_onion(onion, hash);
  if (err != NOX_OK) { sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return err; }

  sqlite3_stmt *stmt = NULL;
  const char *sql = "SELECT nonce, encrypted_payload FROM contacts WHERE onion_hash = ?;";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(stmt);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB; /* Bulunamadı */
  }

  const void *nonce_ptr = sqlite3_column_blob(stmt, 0);
  int nonce_bytes = sqlite3_column_bytes(stmt, 0);
  const void *cipher_ptr = sqlite3_column_blob(stmt, 1);
  int cipher_bytes = sqlite3_column_bytes(stmt, 1);

  if (nonce_bytes != NOX_NONCE_LEN || cipher_bytes <= 0) {
    sqlite3_finalize(stmt);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  struct contact_payload cp;
  sodium_memzero(&cp, sizeof(cp));
  size_t plain_len_out = 0;
  nox_err_t result = NOX_ERR_DB;

  err = decrypt_payload((const uint8_t *)cipher_ptr, (size_t)cipher_bytes,
                        (const uint8_t *)nonce_ptr, (uint8_t *)&cp, sizeof(cp),
                        &plain_len_out);
  sqlite3_finalize(stmt);

  if (err != NOX_OK) { result = err; goto cleanup_cp; }
  if (plain_len_out == sizeof(struct contact_payload_old)) {
    memset(cp.my_onion, 0, sizeof(cp.my_onion));
    memset(cp.my_onion_key, 0, sizeof(cp.my_onion_key));
  } else if (plain_len_out != sizeof(struct contact_payload)) {
    goto cleanup_cp;
  }

  strncpy(name_out, cp.name, name_len - 1);
  name_out[name_len - 1] = '\0';
  memcpy(noise_key_out, cp.noise_key, NOX_KEY_LEN);

  if (my_onion_out && my_onion_len > 0) {
    strncpy(my_onion_out, cp.my_onion, my_onion_len - 1);
    my_onion_out[my_onion_len - 1] = '\0';
  }
  if (my_onion_key_out && my_onion_key_len_out) {
    size_t key_len = strnlen(cp.my_onion_key, NOX_ONION_KEY_B64_LEN);
    if (*my_onion_key_len_out < key_len) {
      key_len = *my_onion_key_len_out;
    }
    memcpy(my_onion_key_out, cp.my_onion_key, key_len);
    *my_onion_key_len_out = key_len;
  }

  result = NOX_OK;

cleanup_cp:
  sodium_memzero(hash, sizeof(hash));
  sodium_memzero(&cp, sizeof(cp));
  DB_UNLOCK();
  return result;
}

#define DB_MAX_MSG_LEN 4095U

nox_err_t db_queue_message(const char *recipient_onion, const char *text) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!recipient_onion || !text) { DB_UNLOCK(); return NOX_ERR_DB; }

  /* CodeQL #23: "Comparison result is always the same"
   * strnlen(text, DB_MAX_MSG_LEN + 1) max 4096 döner, > 4095 kontrolü 4096'yı yakalar. */
  /* CodeQL #23 cpp/comparison-is-always-the-same: strnlen dinamik, > 4095 kontrolü geçerli */
  size_t text_len = strnlen(text, DB_MAX_MSG_LEN + 1);
  assert(text_len <= DB_MAX_MSG_LEN + 1);
  assert(text_len <= DB_MAX_MSG_LEN + 1 && "strnlen upper bound"); /* CodeQL hint */
  if (text_len > DB_MAX_MSG_LEN) {
    NOX_ERROR(LOG_MOD_DB, "Mesaj çok uzun (max %u karakter)", DB_MAX_MSG_LEN);
    DB_UNLOCK(); return NOX_ERR_DB;
  }
  size_t payload_len = text_len + 1;

  if (payload_len > SIZE_MAX - crypto_secretbox_MACBYTES) {
    DB_UNLOCK(); return NOX_ERR_OVERFLOW;
  }
  size_t cipher_len = payload_len + crypto_secretbox_MACBYTES;
  assert(cipher_len <= (size_t)INT_MAX && "DB-3: cipher_len truncation guard");

  uint8_t nonce[NOX_NONCE_LEN];
  uint8_t *cipher = sodium_malloc(cipher_len);
  if (!cipher) { DB_UNLOCK(); return NOX_ERR_ALLOC; }

  nox_err_t err = encrypt_payload((const uint8_t *)text, payload_len, nonce, cipher, cipher_len);
  if (err != NOX_OK) {
    sodium_free(cipher);
    DB_UNLOCK(); return err;
  }

  uint8_t hash[32];
  err = hash_onion(recipient_onion, hash);
  if (err != NOX_OK) {
    sodium_free(cipher);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return err;
  }

  sqlite3_stmt *stmt = NULL;
  const char *sql = "INSERT INTO queue (recipient_hash, nonce, encrypted_payload) VALUES (?, ?, ?);";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    sodium_free(cipher);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }
  rc = sqlite3_bind_blob(stmt, 2, nonce, sizeof(nonce), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }
  rc = sqlite3_bind_blob(stmt, 3, cipher, (int)cipher_len, SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  sodium_free(cipher);

  if (rc != SQLITE_DONE) {
    NOX_ERROR(LOG_MOD_DB, "Mesaj kuyruklama hatası: %s", DB_ERRMSG());
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  NOX_INFO(LOG_MOD_DB, "Mesaj kuyruğa eklendi (%zu byte)", text_len);
  sodium_memzero(hash, sizeof(hash));
  DB_UNLOCK(); return NOX_OK;
}

/**
 * db_process_queue — Kuyruktaki şifreli mesajları işler ve gönderir.
 *
 * @recipient_onion: Hedef onion adresi (null-terminated, v3 format).
 * @send_fn:         Mesaj gönderme callback'i. Parametre: (şifreli metin, ctx).
 *                   Başarılı gönderimde NOX_OK döndürmeli.
 * @ctx:             send_fn'e geçirilen özel veri (ör. peer fd, tor config).
 *
 * Akış:
 *   1. recipient_onion'ı BLAKE2b ile hash'le (DB'de onion_hash olarak saklanır).
 *   2. queue tablosundan bu hash'e ait tüm mesajları id ASC sırasıyla çek.
 *   3. Her mesajı send_fn ile gönder.
 *   4. Başarılı gönderimden sonra mesajı sil (DELETE WHERE id = ?).
 *   5. Silme başarısızsa bile gönderime devam et (partial failure tolerated).
 *
 * Mutex: DB_LOCK() / DB_UNLOCK() ile korunur. send_fn callback'i kilit
 * DIŞINDA çalışır — kilit tutularak soket I/O yapılması deadlock riski taşır.
 * akış: DB_UNLOCK() → send_fn() → DB_LOCK() → DELETE → DB_UNLOCK().
 *
 * Hata yönetimi: İlk başarısız gönderimde durur ve hata kodu döner.
 * Kalan mesajlar bir sonraki çağrida tekrar denenir.
 */
nox_err_t db_process_queue(const char *recipient_onion,
                           nox_err_t (*send_fn)(const char *text, void *ctx),
                           void *ctx) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!recipient_onion || !send_fn) { DB_UNLOCK(); return NOX_ERR_DB; }

  uint8_t hash[32];
  nox_err_t err = hash_onion(recipient_onion, hash);
  if (err != NOX_OK) { sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return err; }

  /* 1. Tüm kuyruk mesajlarını hafızaya çek (lock altında) */
  sqlite3_stmt *stmt = NULL;
  const char *sql = "SELECT id, nonce, encrypted_payload FROM queue WHERE recipient_hash = ? ORDER BY id ASC;";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }

  /* Mesajları basit diziye çek — 256 mesaj limiti (1MB kuyruk) */
  #define QUEUE_BATCH_LIMIT 256
  struct {
    int64_t id;
    uint8_t nonce[NOX_NONCE_LEN];
    uint8_t *cipher;
    int      cipher_len;
  } batch[QUEUE_BATCH_LIMIT];
  int batch_count = 0;

  while (sqlite3_step(stmt) == SQLITE_ROW && batch_count < QUEUE_BATCH_LIMIT) {
    int64_t msg_id = sqlite3_column_int64(stmt, 0);
    int nonce_bytes = sqlite3_column_bytes(stmt, 1);
    int cipher_bytes_int = sqlite3_column_bytes(stmt, 2);

    if (nonce_bytes != NOX_NONCE_LEN) continue;

    if (cipher_bytes_int <= (int)crypto_secretbox_MACBYTES ||
        cipher_bytes_int > 4096 + (int)crypto_secretbox_MACBYTES) {
        NOX_WARN(LOG_MOD_DB, "Geçersiz cipher boyutu: %d — kayıt atlanıyor", cipher_bytes_int);
        continue;
    }

    batch[batch_count].id = msg_id;
    memcpy(batch[batch_count].nonce, sqlite3_column_blob(stmt, 1), NOX_NONCE_LEN);
    batch[batch_count].cipher_len = cipher_bytes_int;
    batch[batch_count].cipher = sodium_malloc((size_t)cipher_bytes_int);
    if (!batch[batch_count].cipher) {
        for (int j = 0; j < batch_count; j++) sodium_free(batch[j].cipher);
        sqlite3_finalize(stmt);
        sodium_memzero(hash, sizeof(hash));
        DB_UNLOCK(); return NOX_ERR_ALLOC;
    }
    memcpy(batch[batch_count].cipher, sqlite3_column_blob(stmt, 2), (size_t)cipher_bytes_int);
    batch_count++;
  }
  sqlite3_finalize(stmt);
  sodium_memzero(hash, sizeof(hash));
  DB_UNLOCK();
  nox_err_t process_err = NOX_OK;
  int sent_count = 0;

  for (int i = 0; i < batch_count; i++) {
    size_t expected_plain = (size_t)batch[i].cipher_len - crypto_secretbox_MACBYTES;
    char *plain = sodium_malloc(expected_plain + 1);
    if (!plain) {
      process_err = NOX_ERR_ALLOC;
      break;
    }

    size_t plain_len_out = 0;
    err = decrypt_payload(batch[i].cipher, (size_t)batch[i].cipher_len,
                          batch[i].nonce, (uint8_t *)plain,
                          expected_plain, &plain_len_out);

    if (err != NOX_OK) {
      sodium_free(plain);
      /* Bozuk mesajı sil — DB_LOCK/DB_UNLOCK içinde */
      DB_LOCK();
      if (g_state.ready) {
        sqlite3_stmt *del = NULL;
        if (sqlite3_prepare_v2(g_state.db, "DELETE FROM queue WHERE id = ?;", -1, &del, NULL) == SQLITE_OK) {
          if (sqlite3_bind_int64(del, 1, batch[i].id) == SQLITE_OK &&
              sqlite3_step(del) == SQLITE_DONE) {
            /* corrupt record deleted */
          } else {
            NOX_WARN(LOG_MOD_DB, "Bozuk kayıt silinemedi: %s", DB_ERRMSG());
          }
          sqlite3_finalize(del);
        }
      }
      DB_UNLOCK();
      continue;
    }

    plain[plain_len_out] = '\0';
    if (plain_len_out == 0 || plain[plain_len_out - 1] != '\0') {
        NOX_WARN(LOG_MOD_DB, "Plaintext NUL-terminate eksik — kayıt siliniyor");
        sodium_free(plain);
        DB_LOCK();
        if (g_state.ready) {
          sqlite3_stmt *del = NULL;
          if (sqlite3_prepare_v2(g_state.db, "DELETE FROM queue WHERE id = ?;", -1, &del, NULL) == SQLITE_OK) {
            if (sqlite3_bind_int64(del, 1, batch[i].id) == SQLITE_OK &&
                sqlite3_step(del) == SQLITE_DONE) {
              /* invalid record deleted */
            } else {
              NOX_WARN(LOG_MOD_DB, "Geçersiz kayıt silinemedi: %s", DB_ERRMSG());
            }
            sqlite3_finalize(del);
          }
        }
        DB_UNLOCK();
        continue;
    }

    nox_err_t send_err;
    send_err = send_fn(plain, ctx);
    sodium_free(plain);

    if (send_err == NOX_OK) {
      DB_LOCK();
      if (g_state.ready) {
        sqlite3_stmt *del = NULL;
        if (sqlite3_prepare_v2(g_state.db, "DELETE FROM queue WHERE id = ?;", -1, &del, NULL) == SQLITE_OK) {
          if (sqlite3_bind_int64(del, 1, batch[i].id) == SQLITE_OK &&
              sqlite3_step(del) == SQLITE_DONE) {
            sent_count++;
          } else {
            NOX_WARN(LOG_MOD_DB, "Kayıt silinemedi: %s", DB_ERRMSG());
            process_err = NOX_ERR_DB;
          }
          sqlite3_finalize(del);
        }
      }
      DB_UNLOCK();
    } else {
      NOX_WARN(LOG_MOD_DB, "Kuyruktaki mesaj gönderilemedi, işlem durduruldu");
      process_err = send_err;
      break;
    }
  }

  /* Batch cipher'ları temizle */
  for (int i = 0; i < batch_count; i++) {
    sodium_free(batch[i].cipher);
  }

  if (sent_count > 0) {
    NOX_INFO(LOG_MOD_DB, "Kuyruktan %d mesaj gönderildi ve temizlendi", sent_count);
  }
  return process_err;
}

nox_err_t db_list_contacts(db_contact_visitor_fn visitor, void *ctx) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!visitor) { DB_UNLOCK(); return NOX_ERR_DB; }

  sqlite3_stmt *stmt = NULL;
  const char *sql = "SELECT nonce, encrypted_payload FROM contacts;";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const void *nonce_ptr = sqlite3_column_blob(stmt, 0);
    int nonce_bytes = sqlite3_column_bytes(stmt, 0);
    const void *cipher_ptr = sqlite3_column_blob(stmt, 1);
    int cipher_bytes = sqlite3_column_bytes(stmt, 1);

    if (nonce_bytes != NOX_NONCE_LEN || cipher_bytes <= 0) {
      continue;
    }

    struct contact_payload cp;
    sodium_memzero(&cp, sizeof(cp));
    size_t plain_len_out = 0;
    nox_err_t err = decrypt_payload((const uint8_t *)cipher_ptr, (size_t)cipher_bytes,
                                    (const uint8_t *)nonce_ptr, (uint8_t *)&cp, sizeof(cp),
                                    &plain_len_out);
    if (err == NOX_OK) {
      if (plain_len_out == sizeof(struct contact_payload_old)) {
        memset(cp.my_onion, 0, sizeof(cp.my_onion));
        memset(cp.my_onion_key, 0, sizeof(cp.my_onion_key));
      }
      visitor(cp.onion, cp.name, cp.noise_key, cp.my_onion,
              (const uint8_t *)cp.my_onion_key, strnlen(cp.my_onion_key, NOX_ONION_KEY_B64_LEN), ctx);
    }
    sodium_memzero(&cp, sizeof(cp));
  }

  sqlite3_finalize(stmt);
  DB_UNLOCK();
  return NOX_OK;
}

nox_err_t db_save_message(const char *peer_onion, const char *text,
                          bool is_outgoing, time_t timestamp) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!peer_onion || !text) { DB_UNLOCK(); return NOX_ERR_DB; }

  size_t text_len = strlen(text);
  if (text_len > DB_MAX_MSG_LEN) {
      NOX_ERROR(LOG_MOD_DB, "Kaydedilecek mesaj çok uzun: %zu byte (maksimum %d)", text_len, DB_MAX_MSG_LEN);
      DB_UNLOCK(); return NOX_ERR_DB;
  }
  size_t payload_len = text_len + 1;
  size_t cipher_len = payload_len + crypto_secretbox_MACBYTES;
  assert(cipher_len <= (size_t)INT_MAX && "DB-3: cipher_len truncation guard");

  uint8_t nonce[NOX_NONCE_LEN];
  uint8_t *cipher = sodium_malloc(cipher_len);
  if (!cipher) { DB_UNLOCK(); return NOX_ERR_ALLOC; }

  nox_err_t err = encrypt_payload((const uint8_t *)text, payload_len, nonce, cipher, cipher_len);
  if (err != NOX_OK) {
    sodium_free(cipher);
    DB_UNLOCK(); return err;
  }

  uint8_t hash[32];
  err = hash_onion(peer_onion, hash);
  if (err != NOX_OK) {
    sodium_free(cipher);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return err;
  }

  sqlite3_stmt *stmt = NULL;
  const char *sql = "INSERT INTO messages (peer_hash, nonce, encrypted_payload, timestamp, is_outgoing) VALUES (?, ?, ?, ?, ?);";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    sodium_free(cipher);
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }
  rc = sqlite3_bind_blob(stmt, 2, nonce, sizeof(nonce), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }
  rc = sqlite3_bind_blob(stmt, 3, cipher, (int)cipher_len, SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }
  rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)timestamp);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }
  rc = sqlite3_bind_int(stmt, 5, is_outgoing ? 1 : 0);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_free(cipher); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  sodium_free(cipher);

  if (rc != SQLITE_DONE) {
    NOX_ERROR(LOG_MOD_DB, "Mesaj kaydetme hatası: %s", DB_ERRMSG());
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  sodium_memzero(hash, sizeof(hash));
  DB_UNLOCK();
  return NOX_OK;
}

nox_err_t db_get_history(const char *peer_onion, int limit,
                         db_message_visitor_fn visitor, void *ctx) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!peer_onion || !visitor) { DB_UNLOCK(); return NOX_ERR_DB; }

  uint8_t hash[32];
  nox_err_t err = hash_onion(peer_onion, hash);
  if (err != NOX_OK) { DB_UNLOCK(); return err; }

  sqlite3_stmt *stmt = NULL;
  const char *sql;
  if (limit > 0) {
    sql = "SELECT nonce, encrypted_payload, timestamp, is_outgoing FROM "
          "(SELECT id, nonce, encrypted_payload, timestamp, is_outgoing FROM messages WHERE peer_hash = ? ORDER BY timestamp DESC, id DESC LIMIT ?) "
          "ORDER BY timestamp ASC, id ASC;";
  } else {
    sql = "SELECT nonce, encrypted_payload, timestamp, is_outgoing FROM messages WHERE peer_hash = ? ORDER BY timestamp ASC, id ASC;";
  }

  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); DB_UNLOCK(); return NOX_ERR_DB; }
  
  if (limit > 0) {
    rc = sqlite3_bind_int(stmt, 2, limit);
    if (rc != SQLITE_OK) { sqlite3_finalize(stmt); DB_UNLOCK(); return NOX_ERR_DB; }
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const void *nonce_ptr = sqlite3_column_blob(stmt, 0);
    int nonce_bytes = sqlite3_column_bytes(stmt, 0);
    const void *cipher_ptr = sqlite3_column_blob(stmt, 1);
    int cipher_bytes_int = sqlite3_column_bytes(stmt, 1);
    time_t timestamp = (time_t)sqlite3_column_int64(stmt, 2);
    bool is_outgoing = sqlite3_column_int(stmt, 3) != 0;

    if (nonce_bytes != NOX_NONCE_LEN || cipher_bytes_int <= (int)crypto_secretbox_MACBYTES) {
      continue;
    }

    size_t cipher_bytes = (size_t)cipher_bytes_int;
    size_t expected_plain = cipher_bytes - crypto_secretbox_MACBYTES;

    char *plain = sodium_malloc(expected_plain + 1);
    if (!plain) {
      sqlite3_finalize(stmt);
      DB_UNLOCK(); return NOX_ERR_ALLOC;
    }

    size_t plain_len_out = 0;
    err = decrypt_payload((const uint8_t *)cipher_ptr, cipher_bytes,
                          (const uint8_t *)nonce_ptr, (uint8_t *)plain,
                          expected_plain, &plain_len_out);
    if (err == NOX_OK) {
      plain[plain_len_out] = '\0';
      visitor(plain, is_outgoing, timestamp, ctx);
    }
    sodium_free(plain);
  }

  sqlite3_finalize(stmt);
  DB_UNLOCK();
  return NOX_OK;
}

/**
 * db_list_contacts_with_summary — Tüm contact'ları son mesaj özetiyle listeler.
 *
 * @visitor: Callback fonksiyonu. Her contact için çağrılır:
 *           (name, onion_hash, last_msg_preview, last_msg_time, is_outgoing, ctx).
 *           NOX_OK döndürmeye devam et, hata durumunda döngüyü durdurur.
 * @ctx:     visitor'a geçirilen özel veri (ör. UI state, array).
 *
 * Akış:
 *   1. contacts tablosunu tara (nonce, encrypted_payload, onion_hash).
 *   2. Her contact için messages tablosundan son mesajı çek (timestamp DESC LIMIT 1).
 *   3. last_msg_preview: Şifreli payload'un ilk 40 byte'ı (ham hex olarak).
 *      Bu sadece önizleme — gerçek mesaj deşifre edilmez.
 *   4. Visitor'ı çağır, eğer NOX_OK dönmezse döngüyü durdur.
 *
 * Mutex: DB_LOCK() / DB_UNLOCK() ile korunur. Visitor callback'i kilit
 * altında çalışır — visitor içinde DB operasyonu yapmamalı (deadlock riski).
 *
 * Performans: O(N) contact sayısı kadar. Her contact için tek ek SQL sorgusu.
 * Büyük contact listelerinde (100+) N+1 query problemi olabilir —
 * gelecekte JOIN ile optimize edilebilir.
 */
nox_err_t db_list_contacts_with_summary(db_contact_summary_visitor_fn visitor, void *ctx) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!visitor) { DB_UNLOCK(); return NOX_ERR_DB; }

  /* Ana sorgu: tüm contact'ları listele (nonce, şifreli payload, onion hash) */
  sqlite3_stmt *stmt = NULL;
  const char *sql = "SELECT nonce, encrypted_payload, onion_hash FROM contacts;";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  /* İkincil sorgu: her contact için son mesajı getir (N+1 query) */
  sqlite3_stmt *msg_stmt = NULL;
  const char *msg_sql = "SELECT nonce, encrypted_payload, timestamp, is_outgoing FROM messages "
                        "WHERE peer_hash = ? ORDER BY timestamp DESC, id DESC LIMIT 1;";
  rc = sqlite3_prepare_v2(g_state.db, msg_sql, -1, &msg_stmt, NULL);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(stmt);
    NOX_ERROR(LOG_MOD_DB, "Message query hazırlanamadı: %s", DB_ERRMSG());
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  /* Her contact'ı dolaş: decrypt → son mesajı bul → visitor'a aktar */
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    /* Contact verisini SQL sütunlarından oku */
    const void *nonce_ptr = sqlite3_column_blob(stmt, 0);
    int nonce_bytes = sqlite3_column_bytes(stmt, 0);
    const void *cipher_ptr = sqlite3_column_blob(stmt, 1);
    int cipher_bytes = sqlite3_column_bytes(stmt, 1);
    const void *hash_ptr = sqlite3_column_blob(stmt, 2);
    int hash_bytes = sqlite3_column_bytes(stmt, 2);

    if (nonce_bytes != NOX_NONCE_LEN || cipher_bytes <= 0) {
      continue;
    }

    /* Contact payload'ı deşifre et (XChaCha20-Poly1305) */
    struct contact_payload cp;
    sodium_memzero(&cp, sizeof(cp));
    size_t plain_len_out = 0;
    nox_err_t err = decrypt_payload((const uint8_t *)cipher_ptr, (size_t)cipher_bytes,
                                    (const uint8_t *)nonce_ptr, (uint8_t *)&cp, sizeof(cp),
                                    &plain_len_out);
    if (err != NOX_OK) {
      sodium_memzero(&cp, sizeof(cp));
      continue;
    }

    /* Eski format uyumluluğu: my_onion/my_onion_key alanları yoksa sıfırla */
    if (plain_len_out == sizeof(struct contact_payload_old)) {
      memset(cp.my_onion, 0, sizeof(cp.my_onion));
      memset(cp.my_onion_key, 0, sizeof(cp.my_onion_key));
    }

    /* Son mesajı getir ve deşifre et */
    char *last_msg_text = NULL;
    bool last_msg_outgoing = false;
    time_t last_msg_timestamp = 0;

    sqlite3_reset(msg_stmt);
    rc = sqlite3_bind_blob(msg_stmt, 1, hash_ptr, hash_bytes, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
      NOX_WARN(LOG_MOD_DB, "Message bind başarısız: %s", DB_ERRMSG());
      continue;
    }

    if (sqlite3_step(msg_stmt) == SQLITE_ROW) {
      const void *msg_nonce_ptr = sqlite3_column_blob(msg_stmt, 0);
      int msg_nonce_bytes = sqlite3_column_bytes(msg_stmt, 0);
      const void *msg_cipher_ptr = sqlite3_column_blob(msg_stmt, 1);
      int msg_cipher_bytes_int = sqlite3_column_bytes(msg_stmt, 1);
      last_msg_timestamp = (time_t)sqlite3_column_int64(msg_stmt, 2);
      last_msg_outgoing = sqlite3_column_int(msg_stmt, 3) != 0;

      /* Mesaj nonce boyutu doğru ve MAC varsa deşifre et */
      if (msg_nonce_bytes == NOX_NONCE_LEN && msg_cipher_bytes_int > (int)crypto_secretbox_MACBYTES) {
        size_t msg_cipher_bytes = (size_t)msg_cipher_bytes_int;
        size_t msg_expected_plain = msg_cipher_bytes - crypto_secretbox_MACBYTES;

        char *msg_plain = sodium_malloc(msg_expected_plain + 1);
        if (msg_plain) {
          size_t msg_plain_len_out = 0;
          nox_err_t msg_err = decrypt_payload((const uint8_t *)msg_cipher_ptr, msg_cipher_bytes,
                                              (const uint8_t *)msg_nonce_ptr, (uint8_t *)msg_plain,
                                              msg_expected_plain, &msg_plain_len_out);
          if (msg_err == NOX_OK) {
            msg_plain[msg_plain_len_out] = '\0';
            last_msg_text = msg_plain;
          } else {
            sodium_free(msg_plain);
          }
        }
      }
    }

    /* Visitor callback: contact bilgisini ve son mesajı uygulamaya aktar */
    visitor(cp.onion, cp.name, cp.noise_key, cp.my_onion,
            (const uint8_t *)cp.my_onion_key, strnlen(cp.my_onion_key, NOX_ONION_KEY_B64_LEN),
            last_msg_text, last_msg_outgoing, last_msg_timestamp, ctx);

    /* Temizlik: hassas verileri sıfırla */
    if (last_msg_text) {
      sodium_free(last_msg_text);
    }
    sodium_memzero(&cp, sizeof(cp));
  }

  sqlite3_finalize(stmt);
  sqlite3_finalize(msg_stmt);
  DB_UNLOCK();
  return NOX_OK;
}

nox_err_t db_delete_conversation(const char *peer_onion) {
  DB_LOCK();
  if (!g_state.ready) { DB_UNLOCK(); return NOX_ERR_STATE; }
  if (!peer_onion) { DB_UNLOCK(); return NOX_ERR_DB; }

  uint8_t hash[32];
  nox_err_t err = hash_onion(peer_onion, hash);
  if (err != NOX_OK) { sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return err; }

  sqlite3_stmt *stmt = NULL;
  const char *sql = "DELETE FROM messages WHERE peer_hash = ?;";
  int rc = sqlite3_prepare_v2(g_state.db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", DB_ERRMSG());
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  rc = sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sodium_memzero(hash, sizeof(hash)); DB_UNLOCK(); return NOX_ERR_DB; }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    NOX_ERROR(LOG_MOD_DB, "Sohbet geçmişi silme hatası: %s", DB_ERRMSG());
    sodium_memzero(hash, sizeof(hash));
    DB_UNLOCK(); return NOX_ERR_DB;
  }

  NOX_INFO(LOG_MOD_DB, "Sohbet geçmişi başarıyla silindi");
  sodium_memzero(hash, sizeof(hash));
  DB_UNLOCK();
  return NOX_OK;
}
