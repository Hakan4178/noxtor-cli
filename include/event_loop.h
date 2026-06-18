/* SPDX-License-Identifier: GPL-3.0-or-later
 * event_loop.h — noxtor-cli epoll tabanlı olay döngüsü arayüzü
 */

#ifndef PARANOID_EVENT_LOOP_H
#define PARANOID_EVENT_LOOP_H

#include "types.h"

/* Epoll tabanlı asenkron I/O olay döngüsü.
 * STDIN_FILENO, listen_fd ve peer_fd (bağlantı aktifse) izlenir. */
void event_loop(struct app_state *state);

#endif /* PARANOID_EVENT_LOOP_H */
