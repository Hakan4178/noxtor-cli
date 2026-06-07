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
 *   - Control port 9051, SOCKS port 9050
 *   - CookieAuthentication 1
 *   - DataDirectory config_dir/tor_data/
 *
 * tor_authenticate: Cookie dosyasını okur, hex olarak gönderir.
 * tor_wait_bootstrap: 120s timeout ile %100 bootstrap bekler.
 * tor_create_hs: ADD_ONION ile Hidden Service oluşturur.
 * tor_shutdown: SIGNAL SHUTDOWN + waitpid.
 * ================================================================ */

/* Tor process'ini başlat ve Control Port'a bağlan */
nox_err_t tor_spawn(struct app_state *state);

/* Cookie ile authenticate ol */
nox_err_t tor_authenticate(int ctrl_fd, const char *data_dir);

/* Bootstrap %100 olana kadar bekle */
nox_err_t tor_wait_bootstrap(int ctrl_fd, int timeout_sec);

/* Hidden Service oluştur — onion adresini onion_out'a yaz */
nox_err_t tor_create_hidden_service(int ctrl_fd, uint16_t local_port,
                                     char *onion_out, size_t onion_len);

/* Onion v3 adres doğrulaması — base32 + ".onion" suffix.
 * 62 karakter tam v3 .onion adresi için true döner.
 * socks5_connect (peer) ve tor_create_hidden_service (S3 — kendi HS)
 * tarafından çağrılır. */
bool validate_onion_address(const char *addr);

/* Tor process'ini düzgün kapat */
void tor_shutdown(struct app_state *state);

/* SOCKS port'unu GETINFO ile öğren */
nox_err_t tor_get_socks_port(int ctrl_fd, uint16_t *port_out);

/* ================================================================
 * SOCKS5 — Tor üzerinden .onion'a bağlan
 *
 * 127.0.0.1:9050 üzerinden SOCKS5 CONNECT.
 * Onion adresi domain name olarak gönderilir (tip 0x03).
 * ================================================================ */
nox_err_t socks5_connect(const char *onion_addr, uint16_t port,
                          uint16_t socks_port, int *fd_out);

/* ================================================================
 * TCP LISTENER — Gelen peer bağlantıları
 *
 * 127.0.0.1 üzerinde rastgele port ile listen.
 * Port numarası port_out'a yazılır.
 * ================================================================ */
nox_err_t listener_create(uint16_t *port_out, int *listen_fd_out);

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
 * frame_header (37 byte) + Noise-encrypted payload
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
