/* SPDX-License-Identifier: GPL-3.0-or-later
 * database.c — SQLite tabanlı şifreli kontakt ve mesaj kuyruk yönetim sistemi
 */

#include "database.h"
#include "asm_utils.h"

#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ================================================================
 * STATİK VERİLER
 * ================================================================ */
static sqlite3 *g_db = NULL;
static const uint8_t *g_db_key = NULL;
static bool g_db_ready = false;

/* ================================================================
 * YARDIMCI GÜVENLİK FONKSİYONLARI
 * ================================================================ */

/* Onion adresi için keyed BLAKE2b hash hesapla (metadata sızıntısını önler) */
static nox_err_t hash_onion(const char *onion, uint8_t hash_out[32]) {
  if (crypto_generichash(hash_out, 32, (const uint8_t *)onion, strlen(onion),
                         g_db_key, NOX_KEY_LEN) != 0) {
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

  if (crypto_secretbox_easy(cipher_out, plain, plain_len, nonce, g_db_key) !=
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
                                 g_db_key) != 0) {
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
  if (g_db_ready)
    return NOX_OK;

  /* db_key pointer'ını sakla — secure arena'daki korumalı adrese işaret eder */
  g_db_key = db_key;

  char db_path[NOX_PATH_MAX];
  int n = snprintf(db_path, sizeof(db_path), "%s/contacts.db", config_dir);
  if (n < 0 || (size_t)n >= sizeof(db_path)) {
    g_db_key = NULL;
    return NOX_ERR_CONFIG;
  }

  /* SQLite bağlantısını aç */
  int rc = sqlite3_open_v2(
      db_path, &g_db,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Veritabanı açılamadı: %s", sqlite3_errmsg(g_db));
    if (g_db) {
      sqlite3_close(g_db);
      g_db = NULL;
    }
    g_db_key = NULL;
    return NOX_ERR_DB;
  }

  /* SQLite güvenlik optimizasyonları (WAL, Secure Delete) */
  char *err_msg = NULL;
  rc = sqlite3_exec(g_db,
                    "PRAGMA journal_mode=WAL;"
                    "PRAGMA synchronous=NORMAL;"
                    "PRAGMA secure_delete=ON;",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_WARN(LOG_MOD_DB, "PRAGMA ayarlanamadı: %s", err_msg);
    sqlite3_free(err_msg);
  }

  /* Rehber tablosu */
  rc = sqlite3_exec(g_db,
                    "CREATE TABLE IF NOT EXISTS contacts ("
                    "  onion_hash BLOB PRIMARY KEY,"
                    "  nonce BLOB NOT NULL,"
                    "  encrypted_payload BLOB NOT NULL"
                    ");",
                    NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "contacts tablosu oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(g_db);
    g_db = NULL;
    g_db_key = NULL;
    return NOX_ERR_DB;
  }

  /* Mesaj kuyruğu tablosu */
  rc = sqlite3_exec(g_db,
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
    sqlite3_close(g_db);
    g_db = NULL;
    g_db_key = NULL;
    return NOX_ERR_DB;
  }

  g_db_ready = true;
  NOX_INFO(LOG_MOD_DB, "Veritabanı başarıyla başlatıldı");
  return NOX_OK;
}

void db_close(void) {
  if (g_db) {
    sqlite3_close(g_db);
    g_db = NULL;
  }
  g_db_key = NULL;
  memory_barrier();
  g_db_ready = false;
  NOX_INFO(LOG_MOD_DB, "Veritabanı kapatıldı");
}

struct contact_payload {
  char onion[NOX_ONION_LEN + 1];
  char name[NOX_CONTACT_NAME_LEN + 1];
  uint8_t noise_key[NOX_KEY_LEN];
};

nox_err_t db_add_contact(const char *onion, const char *name,
                         const uint8_t noise_key[NOX_KEY_LEN]) {
  if (!g_db_ready)
    return NOX_ERR_STATE;
  if (!onion || !name || !noise_key)
    return NOX_ERR_DB;

  size_t onion_len = strlen(onion);
  size_t name_len = strlen(name);

  if (onion_len != NOX_ONION_LEN || name_len > NOX_CONTACT_NAME_LEN) {
    return NOX_ERR_DB;
  }

  /* Payload hazırla */
  struct contact_payload cp;
  explicit_bzero(&cp, sizeof(cp));
  strncpy(cp.onion, onion, NOX_ONION_LEN);
  strncpy(cp.name, name, NOX_CONTACT_NAME_LEN);
  memcpy(cp.noise_key, noise_key, NOX_KEY_LEN);

  /* Şifrele */
  uint8_t nonce[NOX_NONCE_LEN];
  uint8_t cipher[sizeof(struct contact_payload) + crypto_secretbox_MACBYTES];
  nox_err_t err = encrypt_payload((const uint8_t *)&cp, sizeof(cp), nonce,
                                  cipher, sizeof(cipher));
  explicit_bzero(&cp, sizeof(cp));
  if (err != NOX_OK)
    return err;

  /* Onion hash hesapla */
  uint8_t hash[32];
  err = hash_onion(onion, hash);
  if (err != NOX_OK)
    return err;

  /* Veritabanına yaz (INSERT OR REPLACE) */
  sqlite3_stmt *stmt = NULL;
  const char *sql = "INSERT OR REPLACE INTO contacts (onion_hash, nonce, "
                    "encrypted_payload) VALUES (?, ?, ?);";
  int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", sqlite3_errmsg(g_db));
    return NOX_ERR_DB;
  }

  sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 2, nonce, sizeof(nonce), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 3, cipher, sizeof(cipher), SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    NOX_ERROR(LOG_MOD_DB, "Kontakt ekleme hatası: %s", sqlite3_errmsg(g_db));
    return NOX_ERR_DB;
  }

  NOX_INFO(LOG_MOD_DB, "Kontakt başarıyla eklendi/güncellendi");
  return NOX_OK;
}

nox_err_t db_get_contact(const char *onion, char *name_out, size_t name_len,
                         uint8_t noise_key_out[NOX_KEY_LEN]) {
  if (!g_db_ready)
    return NOX_ERR_STATE;
  if (!onion || !name_out || !noise_key_out || name_len == 0)
    return NOX_ERR_DB;

  /* Hash hesapla */
  uint8_t hash[32];
  nox_err_t err = hash_onion(onion, hash);
  if (err != NOX_OK)
    return err;

  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "SELECT nonce, encrypted_payload FROM contacts WHERE onion_hash = ?;";
  int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", sqlite3_errmsg(g_db));
    return NOX_ERR_DB;
  }

  sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    return NOX_ERR_DB; /* Bulunamadı */
  }

  const void *nonce_ptr = sqlite3_column_blob(stmt, 0);
  int nonce_bytes = sqlite3_column_bytes(stmt, 0);
  const void *cipher_ptr = sqlite3_column_blob(stmt, 1);
  int cipher_bytes = sqlite3_column_bytes(stmt, 1);

  if (nonce_bytes != NOX_NONCE_LEN || cipher_bytes <= 0) {
    sqlite3_finalize(stmt);
    return NOX_ERR_DB;
  }

  /* Deşifre et */
  struct contact_payload cp;
  explicit_bzero(&cp, sizeof(cp));
  size_t plain_len_out = 0;

  err = decrypt_payload((const uint8_t *)cipher_ptr, (size_t)cipher_bytes,
                        (const uint8_t *)nonce_ptr, (uint8_t *)&cp, sizeof(cp),
                        &plain_len_out);
  sqlite3_finalize(stmt);

  if (err != NOX_OK)
    return err;
  if (plain_len_out != sizeof(cp))
    return NOX_ERR_DB;

  /* Çıktıları doldur */
  strncpy(name_out, cp.name, name_len - 1);
  name_out[name_len - 1] = '\0';
  memcpy(noise_key_out, cp.noise_key, NOX_KEY_LEN);

  explicit_bzero(&cp, sizeof(cp));
  return NOX_OK;
}

nox_err_t db_queue_message(const char *recipient_onion, const char *text) {
  if (!g_db_ready)
    return NOX_ERR_STATE;
  if (!recipient_onion || !text)
    return NOX_ERR_DB;

  size_t text_len = strlen(text) + 1; /* NUL dahil */
  if (text_len > 4096) {
    NOX_ERROR(LOG_MOD_DB, "Kuyruklanacak mesaj çok uzun (max 4096)");
    return NOX_ERR_DB;
  }

  /* Şifrele */
  uint8_t nonce[NOX_NONCE_LEN];
  /* 4096 + 16 MAC = 4112 byte en fazla yer kaplar */
  uint8_t cipher[4096 + crypto_secretbox_MACBYTES];
  nox_err_t err = encrypt_payload((const uint8_t *)text, text_len, nonce,
                                  cipher, text_len + crypto_secretbox_MACBYTES);
  if (err != NOX_OK)
    return err;

  /* Alıcı hash hesapla */
  uint8_t hash[32];
  err = hash_onion(recipient_onion, hash);
  if (err != NOX_OK)
    return err;

  /* Veritabanına yaz */
  sqlite3_stmt *stmt = NULL;
  const char *sql = "INSERT INTO queue (recipient_hash, nonce, "
                    "encrypted_payload) VALUES (?, ?, ?);";
  int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", sqlite3_errmsg(g_db));
    return NOX_ERR_DB;
  }

  sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 2, nonce, sizeof(nonce), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 3, cipher,
                    (int)(text_len + crypto_secretbox_MACBYTES),
                    SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    NOX_ERROR(LOG_MOD_DB, "Mesaj kuyruklama hatası: %s", sqlite3_errmsg(g_db));
    return NOX_ERR_DB;
  }

  NOX_INFO(LOG_MOD_DB, "Mesaj kuyruğa eklendi (%zu byte)", text_len - 1);
  return NOX_OK;
}

nox_err_t db_process_queue(const char *recipient_onion,
                           nox_err_t (*send_fn)(const char *text, void *ctx),
                           void *ctx) {
  if (!g_db_ready)
    return NOX_ERR_STATE;
  if (!recipient_onion || !send_fn)
    return NOX_ERR_DB;

  /* Hash hesapla */
  uint8_t hash[32];
  nox_err_t err = hash_onion(recipient_onion, hash);
  if (err != NOX_OK)
    return err;

  /* Kuyruktaki tüm kayıtları ID sırasına göre seç */
  sqlite3_stmt *stmt = NULL;
  const char *sql = "SELECT id, nonce, encrypted_payload FROM queue WHERE "
                    "recipient_hash = ? ORDER BY id ASC;";
  int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    NOX_ERROR(LOG_MOD_DB, "Statement hazırlanamadı: %s", sqlite3_errmsg(g_db));
    return NOX_ERR_DB;
  }

  sqlite3_bind_blob(stmt, 1, hash, sizeof(hash), SQLITE_TRANSIENT);

  /* Silinecek ID listesi */
  sqlite3_stmt *del_stmt = NULL;
  const char *del_sql = "DELETE FROM queue WHERE id = ?;";
  rc = sqlite3_prepare_v2(g_db, del_sql, -1, &del_stmt, NULL);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(stmt);
    NOX_ERROR(LOG_MOD_DB, "Silme statement hazırlanamadı");
    return NOX_ERR_DB;
  }

  nox_err_t process_err = NOX_OK;
  int sent_count = 0;

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    int64_t msg_id = sqlite3_column_int64(stmt, 0);
    const void *nonce_ptr = sqlite3_column_blob(stmt, 1);
    int nonce_bytes = sqlite3_column_bytes(stmt, 1);
    const void *cipher_ptr = sqlite3_column_blob(stmt, 2);
    int cipher_bytes = sqlite3_column_bytes(stmt, 2);

    if (nonce_bytes != NOX_NONCE_LEN || cipher_bytes <= 0) {
      continue;
    }

    /* Deşifre et */
    char plain[4096];
    size_t plain_len_out = 0;
    err = decrypt_payload((const uint8_t *)cipher_ptr, (size_t)cipher_bytes,
                          (const uint8_t *)nonce_ptr, (uint8_t *)plain,
                          sizeof(plain), &plain_len_out);
    if (err != NOX_OK) {
      /* Eğer deşifre edilemiyorsa bozuk kayıttır, silinip devam edilir */
      sqlite3_reset(del_stmt);
      sqlite3_bind_int64(del_stmt, 1, msg_id);
      sqlite3_step(del_stmt);
      continue;
    }

    /* Callback ile gönder */
    nox_err_t send_err = send_fn(plain, ctx);
    explicit_bzero(plain, sizeof(plain));

    if (send_err == NOX_OK) {
      /* Başarılı ise veritabanından sil */
      sqlite3_reset(del_stmt);
      sqlite3_bind_int64(del_stmt, 1, msg_id);
      rc = sqlite3_step(del_stmt);
      if (rc == SQLITE_DONE) {
        sent_count++;
      }
    } else {
      /* Gönderim başarısız olursa duruyoruz (peer kopmuş olabilir) */
      NOX_WARN(LOG_MOD_DB, "Kuyruktaki mesaj gönderilemedi, işlem durduruldu");
      process_err = send_err;
      break;
    }
  }

  sqlite3_finalize(stmt);
  sqlite3_finalize(del_stmt);

  if (sent_count > 0) {
    NOX_INFO(LOG_MOD_DB, "Kuyruktan %d mesaj gönderildi ve temizlendi",
             sent_count);
  }
  return process_err;
}
