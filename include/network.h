/* SPDX-License-Identifier: GPL-3.0-or-later
 * network.h — Tor entegrasyonu ve ağ katmanı API
 *
 * Faz 3: Tor spawn, Control Protocol, Hidden Service, SOCKS5
 * Faz 4: TCP listener, epoll event loop yardımcıları
 *
 * Tüm fonksiyonlar blocking — epoll event loop bunları çağırır.
 */

#ifndef PARANOID_NETWORK_H
#define PARANOID_NETWORK_H

#include "common.h"
#include "types.h"

#include <stdint.h>
#include <stdbool.h>

/* ================================================================
 * TOR SPAWN & CONTROL PROTOCOL
 *
 * tor_spawn: fork + execvp("tor", ...) ile tor başlatır.
 *   - torrc üretir → config_dir/torrc
 *   - ControlSocket: AF_UNIX (control.sock)
 *   - SocksSocket: AF_UNIX (socks.sock)
 *   - CookieAuthentication 1
 *   - DataDirectory config_dir/tor_data/
 *
 * tor_authenticate: Cookie dosyasını okur, hex olarak gönderir + siler.
 * tor_wait_bootstrap: timeout ile %100 bootstrap bekler.
 * tor_create_new_hs: ADD_ONION ED25519-V3:<app-üretim rastgele seed> — ghost mod
 *                    (ephemeral, seed yalnızca bellekte — claim imzası için).
 * tor_create_derived_hs: ADD_ONION ED25519-V3:<derived key> — normal mod
 *                    (master_key'den deterministik türetme, dosya YOK).
 * tor_shutdown: SIGNAL SHUTDOWN + waitpid + dizin temizliği.
 * ================================================================ */

/* Tor process'ini başlat ve Control Port'a bağlan */
nox_err_t tor_spawn(struct app_state *state);

/* Cookie ile authenticate ol */
nox_err_t tor_authenticate(int ctrl_fd, const char *data_dir);

/* Control soketi peer doğrulaması (bulgu 2.1) — SO_PEERCRED ile karşı
 * ucun beklenen Tor süreci (expected_pid) ve aynı UID olduğunu kanıtlar.
 * connect() sonrası, cookie/ADD_ONION göndermeden ÖNCE çağrılır; peer
 * kimliği bağlantı boyunca sabittir. Hata: NOX_ERR_PEER (uyuşmazlık) |
 * NOX_ERR_NET (getsockopt hatası). */
nox_err_t tor_verify_peer(int fd, pid_t expected_pid);

/* Bootstrap %100 olana kadar bekle */
nox_err_t tor_wait_bootstrap(int ctrl_fd, int timeout_sec);

/* Ghost mod Hidden Service — ADD_ONION ED25519-V3:<app-üretim rastgele seed>.
 * (H-1/H-2: eski NEW:ED25519-V3 Flags=DiscardPK kaldırıldı — claim imzası
 * için onion private key client'ta bulunmalı. Her açılışta farklı rastgele
 * seed → farklı adres, eski ghost UX korunur.)
 * Detach YOK: control connection kapanınca hizmet otomatik silinir (D5).
 * listen_path: AF_UNIX socket yolu (ADD_ONION unix: prefix ile)
 * seed_out: 32 byte, SADECE BAŞARIDA yazılır (çağrıyan sodium_free ile
 *           temizler; hata yolunda içeriği yazılmamış olur)
 * onion_out: 63 byte (56 base32 + ".onion\0") */
__attribute__((strub)) nox_err_t tor_create_new_hs(int ctrl_fd, const char *listen_path,
                             uint8_t seed_out[32],
                             char *onion_out, size_t onion_len);

/* Normal mod Hidden Service — master_key'den deterministik türetme (D3/D10).
 * onion_seed → expanded key → ADD_ONION ED25519-V3:<b64>. Dosya okumak YOK.
 * master_key: PIN+salt → Argon2id çıktısı (state'ten bağımsız, birim test edilir)
 * onion_out: 63 byte (56 base32 + ".onion\0") */
__attribute__((strub)) nox_err_t tor_create_derived_hs(int ctrl_fd, const char *listen_path,
                                  const uint8_t master_key[NOX_KEY_LEN],
                                  char *onion_out, size_t onion_len);

/* Onion v3 adres doğrulaması — base32 + ".onion" suffix + v3 checksum
 * (H-2 FIX: SHA3-256 checksum zorunlu — zincir crypto_onion_pubkey'te).
 * 62 karakter tam v3 .onion adresi için true döner.
 * socks5_connect (peer) ve event_loop (handshake claim) tarafından
 * çağrılır. Kendi HS yolunda parse_service_id ayrıca adresin içindeki
 * pub'ı beklenen anahtarla sodium_memcmp eder. (hardened) */
nox_hardbool_t validate_onion_address(const char *addr);

/* Tor process'ini düzgün kapat */
void tor_shutdown(struct app_state *state);

/* ================================================================
 * SOCKS5 — Tor üzerinden .onion'a bağlan
 *
 * AF_UNIX SocksSocket üzerinden SOCKS5 CONNECT.
 * Onion adresi domain name olarak gönderilir (tip 0x03).
 *
 * expected_tor_pid: connect sonrası SO_PEERCRED doğrulaması (bulgu 2.1b).
 * socks.sock yolu Tor AYAKTAYKEN aynı-UID saldırgan tarafından
 * unlink/rebind edilebilir; peer spawn edilen tor_pid değilse SOCKS
 * greeting'i BİLE gönderilmeden fail-closed dönülür.
 * Hata: NOX_ERR_PEER (PID bilinmiyor veya peer uyuşmuyor).
 * ================================================================ */
nox_err_t socks5_connect(const char *onion_addr, uint16_t port,
                          const char *socks_path, pid_t expected_tor_pid,
                          int *fd_out);

/* ================================================================
 * UNIX DOMAIN LISTENER — Gelen peer bağlantıları
 *
 * AF_UNIX socket ile Tor Hidden Service üzerinden gelen
 * peer bağlantılarını dinler. Socket izinleri 0600 ile kısıtlanır.
 * ================================================================ */
nox_err_t listener_create(const char *tor_data_dir, char *listen_path_out,
                           int *listen_fd_out);

/* ================================================================
 * EPOLL YARDIMCILARI
 * ================================================================ */

/* epoll instance oluştur ve fd'leri kaydet */
nox_err_t epoll_setup(struct app_state *state, int listen_fd);

/* epoll'dan fd kaldır */
nox_err_t epoll_remove_fd(int epoll_fd, int fd);

/* epoll'a fd ekle */
nox_err_t epoll_add_fd(int epoll_fd, int fd);

/* epoll'daki fd olaylarını değiştir */
nox_err_t epoll_modify_fd(int epoll_fd, int fd, uint32_t events);

/* ================================================================
 * FRAME I/O — Wire format okuma/yazma
 *
 * frame_header (13 byte) + Noise-encrypted payload
 * Tüm multi-byte alanlar network byte order (big-endian).
 * ================================================================ */

/* Frame header'ı network byte order'a serialize et */
void frame_header_encode(const struct frame_header *hdr,
                         uint8_t *wire);

/* H2: AD'li transport gönderimlerinin tek header üreticisi.
 * frame_header_encode ile aynı 13 byte'ı üretir; receiver ham 13B'yi
 * AD olarak korur. Transport gönderim siteleri doğrudan encode yerine
 * bu fonksiyonu kullanır (handshake CTRL yazımları istisna). */
void frame_ad(const struct frame_header *hdr, uint8_t *wire);

/* Wire bytes'tan frame header'ı parse et */
nox_err_t frame_header_decode(const uint8_t *wire,
                               struct frame_header *hdr);

/* Frame boyutu sabitleri */
#define FRAME_HEADER_WIRE_SIZE  13U
#define FRAME_MAX_PAYLOAD       (4096U + NOX_MAC_LEN)

/* ================================================================
 * CONTROL PROTOCOL — satır okuma yardımcısı
 *
 * Tor Control Protocol satır tabanlı (\r\n).
 * ctrl_read_line: fd'den bir satır okur, timeout ile.
 * ================================================================ */
nox_err_t ctrl_read_line(int fd, char *buf, size_t buf_size,
                          int timeout_ms);

nox_err_t ctrl_send_command(int fd, const char *cmd);

/* I/O helpers — EINTR + partial read/write koruması */
nox_err_t write_full(int fd, const void *buf, size_t len);
nox_err_t read_full(int fd, void *buf, size_t len);

/* ================================================================
 * UNIT TEST ERİŞİMİ — production akışında da kullanılan iç
 * yardımcılar; sözleşmeleri testlerle kilitli (static kaldırıldı).
 * ================================================================ */

/* Tor Control çok satırlı yanıt okuma (250-/250 ayrımı, 64 satır
 * limiti H-2, toplam deadline B1). buf: birleşik satırlar + NUL. */
nox_err_t ctrl_read_response(int fd, char *buf, size_t buf_size,
                             int timeout_ms);

/* "tor_data_<pid>"/"torrc_<pid>" kalıntılarını süpürür — yalnız
 * ölü PID + bizim UID; symlink takibi yok (rm_rf O_NOFOLLOW). */
void cleanup_stale_tor_dirs(const char *config_dir);

/* strtol + ERANGE/endptr kontrolü; geçersiz → -1. */
long safe_parse_pid(const char *str);

#endif /* PARANOID_NETWORK_H */
