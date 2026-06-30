/* SPDX-License-Identifier: GPL-3.0-or-later
 * stdin_handler.h — noxtor-cli terminal girdi yönetimi API
 */

#ifndef PARANOID_STDIN_HANDLER_H
#define PARANOID_STDIN_HANDLER_H

#include "types.h"

/* Terminalden gelen her satırı (komut veya mesaj) işler */
void process_line(struct app_state *state, const char *line);

/* Non-blocking girdi okuma, tamponlama ve satır bölme işlemlerini yürütür */
void process_stdin_events(struct app_state *state);

/* Uzun mesajları parçalara ayırıp peer'a gönderir */
nox_err_t send_segmented_message(struct app_state *state, const char *msg);

/* Belirli bir peer'a mesaj gönderir */
nox_err_t send_segmented_message_to(struct app_state *state,
                                    struct peer_session *ps,
                                    const char *msg);

/* Çevrimdışı mesajları parçalara ayırıp kuyruğa alır */
nox_err_t queue_segmented_message(const char *recipient_onion, const char *msg);

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
