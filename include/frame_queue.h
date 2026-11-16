/* SPDX-License-Identifier: GPL-3.0-or-later
 * frame_queue.h — C1: sıralı TX frame kuyruğu
 *
 * Kuyruk şifrelenmiş wire frame'leri tutar. Tek amaç, nonce sırasının
 * soket yazma sırasıyla birebir aynı kalmasını garanti etmektir:
 *
 *   encrypt(frame N) → commit(N) → socket write(N) → ... → write(N+1)
 *
 * Kuyruk doluysa frame şifrelenmez (nonce tüketilmez) ve NOX_ERR_AGAIN
 * döner. Şifrelenmiş bir frame asla düşürülmez; kısmi yazım offset ile
 * devam eder. Zero-byte veya kalıcı yazma hatası oturumu kapatır.
 */

#ifndef PARANOID_FRAME_QUEUE_H
#define PARANOID_FRAME_QUEUE_H

#include "common.h"
#include "types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Kuyruktaki dolu slot sayısı. NULL → 0. */
uint8_t frame_queue_count(const struct peer_session *ps);

/* Boş slot sayısı. NULL → 0 (güvenli taraf: yazma yok). */
uint8_t frame_queue_free(const struct peer_session *ps);

bool frame_queue_empty(const struct peer_session *ps);

/*
 * frame_queue_reserve — yazma için tail slotunu ayırır.
 *
 * Dönen alan TX_BUF_CAPACITY byte'tır; state DEĞİŞMEZ. Çağıran header'ı
 * ve ciphertext'i bu alana yazıp frame_queue_commit() çağırmalıdır.
 * Kuyruk doluysa NULL döner; bu durumda şifreleme yapılmamalıdır.
 * Tek thread: reserve ile commit arasına başka bir enqueue giremez.
 */
uint8_t *frame_queue_reserve(struct peer_session *ps);

/*
 * frame_queue_commit — reserve edilen frame'i kuyruğa alır.
 *
 * tx_seq burada ilerler: commit, wire sıra numarasının rezervasyon
 * noktasıdır. len 0 veya TX_BUF_CAPACITY'den büyükse NOX_ERR_OVERFLOW
 * döner ve state değişmez.
 */
nox_err_t frame_queue_commit(struct peer_session *ps, size_t len);

/*
 * frame_queue_flush — kuyruğu sırayla sokete yazar.
 *
 * NOX_OK:        kuyruk boş.
 * NOX_ERR_AGAIN: kısmi yazım/EAGAIN; offset ilerledi, EPOLLOUT açıldı.
 * NOX_ERR_IO:    zero-byte veya kalıcı hata; oturum kapatıldı.
 * NOX_ERR_NET:   geçersiz peer/fd.
 */
nox_err_t frame_queue_flush(struct app_state *state, struct peer_session *ps);

/* Kuyruğu zeroize eder (cleanup). */
void frame_queue_reset(struct peer_session *ps);

/*
 * frame_queue_arm_tx — peer fd'sini EPOLLIN | EPOLLOUT ilgisine geçirir.
 *
 * C2: FILE transferi METADATA commit'inden sonra ilk kez burada uyandırılır.
 * epoll yoksa (birim testleri) no-op NOX_OK döner. İlgi kurulamazsa
 * fail-closed: oturum kapatılır ve NOX_ERR_IO döner.
 */
nox_err_t frame_queue_arm_tx(struct app_state *state,
                             struct peer_session *ps);

#endif /* PARANOID_FRAME_QUEUE_H */
