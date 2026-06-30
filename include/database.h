/* SPDX-License-Identifier: GPL-3.0-or-later
 * database.h — SQLite tabanlı şifreli kontakt ve mesaj kuyruk yönetim API'si
 */

#ifndef PARANOID_DATABASE_H
#define PARANOID_DATABASE_H

#include "common.h"
#include "types.h"

/*
 * db_init — Veritabanını başlat ve tabloları oluştur
 *
 * @config_dir: Uygulamanın config dizin yolu (~/.config/paranoidcli)
 * @db_key:     Argon2id ile türetilmiş 32 byte veritabanı anahtarı
 *
 * Return: NOX_OK veya NOX_ERR_DB / NOX_ERR_CONFIG
 */
nox_err_t db_init(const char *config_dir, const uint8_t db_key[NOX_KEY_LEN]);

/*
 * db_close — Veritabanı bağlantısını güvenle kapat
 */
void db_close(void);

/*
 * db_add_contact — Yeni kontakt ekle veya mevcut olanı güncelle
 *
 * @onion:         Kontakt .onion adresi (56B + ".onion")
 * @name:          Kontakt ismi (maks 64 karakter)
 * @noise_key:     Noise static Curve25519 public key (32 byte)
 *
 * Not: Manuel eklemelerde noise_key sıfır (boş) olarak verilebilir.
 *
 * Return: NOX_OK veya NOX_ERR_DB
 */
nox_err_t db_add_contact(const char *onion, const char *name, const uint8_t noise_key[NOX_KEY_LEN]);

/*
 * db_get_contact — Kontakt bilgilerini ara ve çöz
 *
 * @onion:             Aranan .onion adresi
 * @name_out:          İsim çıktısı (buffer en az NOX_CONTACT_NAME_LEN + 1 olmalı)
 * @name_len:          İsim buffer boyutu
 * @noise_key_out:     Curve25519 public key çıktısı (32 byte)
 *
 * Return: NOX_OK (bulundu), NOX_ERR_DB (SQLite hatası veya bulunamadı)
 */
nox_err_t db_get_contact(const char *onion, char *name_out, size_t name_len, uint8_t noise_key_out[NOX_KEY_LEN]);

/*
 * db_queue_message — Çevrimdışı mesajı kuyruğa ekle (şifrelenmiş olarak)
 *
 * @recipient_onion: Alıcının .onion adresi
 * @text:            Gidecek mesaj metni (plain text)
 *
 * Return: NOX_OK veya NOX_ERR_DB
 */
nox_err_t db_queue_message(const char *recipient_onion, const char *text);

/*
 * db_process_queue — Kuyruktaki mesajları işleme sok (gönder ve sil)
 *
 * @recipient_onion: Alıcının .onion adresi
 * @send_fn:         Mesajı gönderecek callback fonksiyonu
 * @ctx:             Callback'e geçirilecek context (genelde app_state)
 *
 * Callback her başarılı gönderim için NOX_OK dönmelidir.
 * Başarılı gönderilen mesajlar veritabanından silinir.
 *
 * Return: NOX_OK veya NOX_ERR_DB
 */
nox_err_t db_process_queue(const char *recipient_onion,
                           nox_err_t (*send_fn)(const char *text, void *ctx),
                           void *ctx);

/* ── YENİ: Çoklu Oturum ve Mesaj Geçmişi API'leri ─────────────────── */

/* Rehberdeki tüm kişileri listele (şifre çözülmüş olarak) */
typedef void (*db_contact_visitor_fn)(const char *onion, const char *name,
                                      const uint8_t noise_key[NOX_KEY_LEN],
                                      void *ctx);
nox_err_t db_list_contacts(db_contact_visitor_fn visitor, void *ctx);

/* Mesaj geçmişi kaydetme */
nox_err_t db_save_message(const char *peer_onion, const char *text,
                          bool is_outgoing, time_t timestamp);

/* Mesaj geçmişi okuma */
typedef void (*db_message_visitor_fn)(const char *text, bool is_outgoing,
                                      time_t timestamp, void *ctx);
nox_err_t db_get_history(const char *peer_onion, int limit,
                         db_message_visitor_fn visitor, void *ctx);

/* Son mesaj özetiyle kişileri listeleme */
typedef void (*db_contact_summary_visitor_fn)(
    const char *onion,
    const char *name,
    const uint8_t noise_key[NOX_KEY_LEN],
    const char *last_msg_text,      /* NULL if no messages */
    bool last_msg_outgoing,
    time_t last_msg_timestamp,
    void *ctx
);
nox_err_t db_list_contacts_with_summary(db_contact_summary_visitor_fn visitor, void *ctx);

/* Konuşma geçmişini silme */
nox_err_t db_delete_conversation(const char *peer_onion);

#endif /* PARANOID_DATABASE_H */
