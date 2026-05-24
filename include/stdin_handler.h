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

/* Çevrimdışı mesajları parçalara ayırıp kuyruğa alır */
nox_err_t queue_segmented_message(const char *recipient_onion, const char *msg);

/* Veritabanı kuyruğundan mesaj gönderme callback fonksiyonu */
nox_err_t send_queued_callback(const char *text, void *ctx);

#endif /* PARANOID_STDIN_HANDLER_H */
