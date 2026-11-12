/* SPDX-License-Identifier: GPL-3.0-or-later
 * frame_queue.c — C1: sıralı TX frame kuyruğu
 */

#include "frame_queue.h"
#include "frontend.h"
#include "network.h"
#include "state_machine.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <sodium.h>

uint8_t frame_queue_count(const struct peer_session *ps) {
  return ps ? ps->tx_frames.count : 0;
}

uint8_t frame_queue_free(const struct peer_session *ps) {
  if (!ps)
    return 0;
  if (ps->tx_frames.count >= FRAME_QUEUE_SLOTS)
    return 0;
  return (uint8_t)(FRAME_QUEUE_SLOTS - ps->tx_frames.count);
}

bool frame_queue_empty(const struct peer_session *ps) {
  return frame_queue_count(ps) == 0;
}

uint8_t *frame_queue_reserve(struct peer_session *ps) {
  if (!ps || ps->tx_frames.count >= FRAME_QUEUE_SLOTS)
    return NULL;
  return ps->tx_frames.slots[ps->tx_frames.tail].buf;
}

nox_err_t frame_queue_commit(struct peer_session *ps, size_t len) {
  if (!ps || len == 0 || len > (size_t)TX_BUF_CAPACITY)
    return NOX_ERR_OVERFLOW;

  struct frame_queue *q = &ps->tx_frames;
  if (q->count >= FRAME_QUEUE_SLOTS)
    return NOX_ERR_OVERFLOW;

  struct frame_queue_slot *s = &q->slots[q->tail];
  s->len = (uint16_t)len;
  s->off = 0;

  q->tail = (uint8_t)((q->tail + 1U) % FRAME_QUEUE_SLOTS);
  q->count = (uint8_t)(q->count + 1U);
  ps->tx_seq++;
  return NOX_OK;
}

nox_err_t frame_queue_flush(struct app_state *state, struct peer_session *ps) {
  if (!ps)
    return NOX_ERR_NET;

  struct frame_queue *q = &ps->tx_frames;

  while (q->count > 0) {
    if (ps->fd < 0)
      return NOX_ERR_NET;

    struct frame_queue_slot *s = &q->slots[q->head];
    size_t remaining = (size_t)s->len - (size_t)s->off;

    ssize_t w = send(ps->fd, s->buf + s->off, remaining,
                     MSG_DONTWAIT | MSG_NOSIGNAL);

    if (w > 0) {
      s->off = (uint16_t)((size_t)s->off + (size_t)w);
      clock_gettime(CLOCK_MONOTONIC, &ps->last_active);
      if (s->off < s->len)
        continue;

      /* Frame tamamlandı: ciphertext'i bırakmadan zeroize et. */
      sodium_memzero(s->buf, sizeof(s->buf));
      s->len = 0;
      s->off = 0;
      q->head = (uint8_t)((q->head + 1U) % FRAME_QUEUE_SLOTS);
      q->count = (uint8_t)(q->count - 1U);
      continue;
    }

#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
#else
    if (w < 0 && errno == EAGAIN)
#endif
    {
      /* Kısmi frame kuyrukta kalır; EPOLLOUT tekrar çağıracak.
       * İlgi kurulamazsa kuyruk sonsuza dek asılı kalır → fail-closed. */
      if (state && state->epoll_fd >= 0 &&
          epoll_modify_fd(state->epoll_fd, ps->fd,
                          EPOLLIN | EPOLLOUT) != NOX_OK) {
        NOX_WARN(LOG_MOD_NET,
                 "EPOLLOUT ilgisi kurulamadı — oturum kapatılıyor");
        if (state) {
          ui_print_error(state,
              "Soket olay ilgisi kurulamadı — oturum kapatılıyor.");
          (void)sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
        }
        return NOX_ERR_IO;
      }
      return NOX_ERR_AGAIN;
    }

    if (w < 0 && errno == EINTR)
      continue;

    /* w == 0 veya kalıcı hata. Nonce tüketilmiş olabilir; frame
     * düşürülemez, kısmi frame resync edilemez → oturum kapanır. */
    const char *why = (w == 0) ? "write 0 döndü" : strerror(errno);
    char reason[192];
    if (s->off == 0)
      snprintf(reason, sizeof(reason),
               "Frame gönderimi başarısız: %s (nonce tüketildi, frame yok)",
               why);
    else
      snprintf(reason, sizeof(reason),
               "Frame gönderimi koptu: %s (kısmi frame %u/%u)",
               why, (unsigned)s->off, (unsigned)s->len);

    NOX_WARN(LOG_MOD_NET, "%s", reason);
    if (state) {
      ui_print_error(state, "%s", reason);
      (void)sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
    }
    return NOX_ERR_IO;
  }

  return NOX_OK;
}

void frame_queue_reset(struct peer_session *ps) {
  if (!ps)
    return;
  sodium_memzero(&ps->tx_frames, sizeof(ps->tx_frames));
}

nox_err_t frame_queue_arm_tx(struct app_state *state,
                             struct peer_session *ps) {
  if (!ps || ps->fd < 0)
    return NOX_ERR_NET;
  if (!state || state->epoll_fd < 0)
    return NOX_OK; /* birim testi: epoll yok */

  if (epoll_modify_fd(state->epoll_fd, ps->fd, EPOLLIN | EPOLLOUT) != NOX_OK) {
    NOX_WARN(LOG_MOD_NET,
             "EPOLLOUT ilgisi kurulamadı — oturum kapatılıyor");
    ui_print_error(state,
                   "Soket olay ilgisi kurulamadı — oturum kapatılıyor.");
    (void)sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
    return NOX_ERR_IO;
  }
  return NOX_OK;
}
