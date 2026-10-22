/* SPDX-License-Identifier: GPL-3.0-or-later
 * stdin_handler.h — noxtor-cli terminal girdi yönetimi API
 */

#ifndef PARANOID_STDIN_HANDLER_H
#define PARANOID_STDIN_HANDLER_H

#include "types.h"

#include <stdbool.h>

/* Terminalden gelen her satırı (komut veya mesaj) işler */
void process_line(struct app_state *state, const char *line);

/* TOFU kullanıcı yanıtı — tek karar noktası. process_line 'y'/'n'
 * yolundan çağrılır; GTK geçişinde frontend callback'i (tofu_accept_request)
 * da AYNI fonksiyonu çağırır. C2 epoch+fp token kontrolü burada (ret +
 * re-arm); çoklu bekleyen varsa hiçbirine karar verilmez; pencere
 * kapanmışsa (async gecikme) no-op. */
void tofu_user_response(struct app_state *state, bool accept);

/* Non-blocking girdi okuma, tamponlama ve satır bölme işlemlerini yürütür */
void process_stdin_events(struct app_state *state);

/* Linenoise editörü başlatır (Faz E): TTY + linenoise olmayan modda no-op.
 * Event loop başlamadan hemen önce çağrılır; ln_buf'u sodium_malloc ile
 * ayırır (NOX_EDIT_CAP), allocator hook'larını sodium'a bağlar. */
void ln_edit_init(struct app_state *state);

/* Linenoise editörünü kapatır: raw mode geri, ln_buf sodium_free (zeroize). */
void ln_edit_deinit(struct app_state *state);

/* Uzun mesajları parçalara ayırıp peer'a gönderir */
nox_err_t send_segmented_message(struct app_state *state, const char *msg);

/* Belirli bir peer'a mesaj gönderir */
nox_err_t send_segmented_message_to(struct app_state *state,
                                    struct peer_session *ps,
                                    const char *msg);

/* Adım 4.5 — gönderim sırası koruması.
 * ps_tx_pending: peer'ın FILE chunk'ı tx_buf'ta bekliyor mu? (yazma yok)
 * peer_tx_flush_pending: chunk flush edildikten sonra ertelenen TEXT'i
 * gönderir. Slot boşsa veya hâlâ chunk bekliyorsa NOX_OK (no-op). */
bool ps_tx_pending(const struct peer_session *ps);
nox_err_t peer_tx_flush_pending(struct app_state *state,
                                struct peer_session *ps);

/* Çevrimdışı mesajları parçalara ayırıp kuyruğa alır */
nox_err_t queue_segmented_message(const char *recipient_onion, const char *msg);

/* D FIX: Sıradaki parça boyutunu UTF-8 sınırına göre hesaplar — kodpoint
 * bölünmez; offset >= total_len → 0; geçersiz UTF-8 garbage → 1 (progress).
 * Korpus: tests/test_chunk_size.c */
size_t nox_next_chunk_size(const char *msg, size_t offset, size_t total_len);

/* Veritabanı kuyruğundan mesaj gönderme callback fonksiyonu */
nox_err_t send_queued_callback(const char *text, void *ctx);

/* Kuyruk flush context — doğru peer'a gönderim için */
struct queue_flush_ctx {
  struct app_state *state;
  struct peer_session *ps;
};

/* Aktif peer sayısını say */
int active_peer_count(struct app_state *state);

#endif /* PARANOID_STDIN_HANDLER_H */
