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
 * @onion:     Kontakt .onion adresi (56B + ".onion")
 * @name:      Kontakt ismi (maks 64 karakter)
 * @noise_key: Noise static Curve25519 public key (32 byte)
 *
 * Not: Manuel eklemelerde noise_key sıfır (boş) olarak verilebilir.
 *
 * Return: NOX_OK veya NOX_ERR_DB
 */
nox_err_t db_add_contact(const char *onion, const char *name, const uint8_t noise_key[NOX_KEY_LEN]);

/*
 * db_get_contact — Kontakt bilgilerini ara ve çöz
 *
 * @onion:         Aranan .onion adresi
 * @name_out:      İsim çıktısı (buffer en az NOX_CONTACT_NAME_LEN + 1 olmalı)
 * @name_len:      İsim buffer boyutu
 * @noise_key_out: Curve25519 public key çıktısı (32 byte)
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

#endif /* PARANOID_DATABASE_H */
