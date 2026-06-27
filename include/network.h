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
 * tor_create_new_hs: ADD_ONION NEW:ED25519-V3 — yeni HS + PrivateKey kaydet.
 * tor_create_persistent_hs: ADD_ONION ED25519-V3:<key> — kayıtlı key ile HS.
 * tor_shutdown: SIGNAL SHUTDOWN + waitpid + dizin temizliği.
 * ================================================================ */

/* Tor process'ini başlat ve Control Port'a bağlan */
nox_err_t tor_spawn(struct app_state *state);

/* Cookie ile authenticate ol */
nox_err_t tor_authenticate(int ctrl_fd, const char *data_dir);

/* Bootstrap %100 olana kadar bekle */
nox_err_t tor_wait_bootstrap(int ctrl_fd, int timeout_sec);

/* Yeni Hidden Service üret — ServiceID + PrivateKey döndür.
 * listen_path: AF_UNIX socket yolu (ADD_ONION unix: prefix ile)
 * onion_out: 63 byte (56 base32 + ".onion\0")
 * key_out: 89 byte (88 base64 + "\0") */
__attribute__((strub)) nox_err_t tor_create_new_hs(int ctrl_fd, const char *listen_path,
                             char *onion_out, size_t onion_len,
                             char *key_out, size_t key_len);

/* Kayıtlı ED25519-V3 private key ile Hidden Service oluştur.
 * onion_key_b64: 88 byte base64 key (ED25519-V3: prefix'siz)
 * onion_out: 63 byte (56 base32 + ".onion\0") */
__attribute__((strub)) nox_err_t tor_create_persistent_hs(int ctrl_fd, const char *listen_path,
                                    const char *onion_key_b64,
                                    char *onion_out, size_t onion_len);

/* Onion v3 adres doğrulaması — base32 + ".onion" suffix.
 * 62 karakter tam v3 .onion adresi için true döner.
 * socks5_connect (peer) ve tor_create_new_hs (S3 — kendi HS)
 * tarafından çağrılır. */
bool validate_onion_address(const char *addr);

/* Tor process'ini düzgün kapat */
void tor_shutdown(struct app_state *state);

/* ================================================================
 * SOCKS5 — Tor üzerinden .onion'a bağlan
 *
 * AF_UNIX SocksSocket üzerinden SOCKS5 CONNECT.
 * Onion adresi domain name olarak gönderilir (tip 0x03).
 * ================================================================ */
nox_err_t socks5_connect(const char *onion_addr, uint16_t port,
                          const char *socks_path, int *fd_out);

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

#endif /* PARANOID_NETWORK_H */
