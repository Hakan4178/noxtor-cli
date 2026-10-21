/* SPDX-License-Identifier: GPL-3.0-or-later
 * file_transfer.h — noxtor-cli dosya transferi yönetimi API
 */

#ifndef PARANOID_FILE_TRANSFER_H
#define PARANOID_FILE_TRANSFER_H

#include "types.h"
#include <stdbool.h>

/* Maksimum dosya boyutu sınırı — 100 GB */
#ifndef NOX_MAX_FILE_SIZE
#define NOX_MAX_FILE_SIZE (100ULL * 1024ULL * 1024ULL * 1024ULL)
#endif

/* Dosya adını temizleyerek path traversal açıklarını önler */
void sanitize_filename(char *name, size_t max_len);

/* Dosya gönderim sürecini (METADATA hazırlama, okuma, şifreleme ve iletim) başlatır */
void file_transfer_start(struct app_state *state, const char *filepath);

/* Peer soketi yazılabilir olduğunda (EPOLLOUT) sıradaki dosya parçasını gönderir */
void file_transfer_handle_tx(struct app_state *state, struct peer_session *ps);

/* Dosya paketlerini (Metadata veya chunk) işler ve diske yazar.
 * pt: event_loop'un çözdüğü düz metin — sahiplik çağıranda, burada free YOK.
 * pt_len == 0 → AEAD doğrulaması başarısız (eski decrypt fail yolu).
 * return: hardened true = tüketildi (veya hata sonrası temizlendi), false = kritik hata */
nox_hardbool_t file_transfer_handle_rx(struct app_state *state, struct peer_session *ps,
                                       uint8_t *pt, uint32_t pt_len);

/* Bağlantı koptuğunda yarım kalan transferlerin kaynaklarını temizler ve dosyaları siler */
void file_transfer_cleanup(struct app_state *state);

/* Chunk timeout predikati — saf ve saat enjekte edilebilir (A FIX):
 * now - last > timeout_sec. Caller CLOCK_MONOTONIC ile besler (M-12
 * kalıbı); duvar saati karşılaştırması YOK. NULL girdi → false
 * (fail-safe: sahipsiz veri aktif transferi öldürmesin). */
bool file_transfer_chunk_expired(const struct timespec *last,
                                 const struct timespec *now,
                                 long timeout_sec);

#endif /* PARANOID_FILE_TRANSFER_H */
