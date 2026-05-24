/* SPDX-License-Identifier: GPL-3.0-or-later
 * file_transfer.h — noxtor-cli dosya transferi yönetimi API
 */

#ifndef PARANOID_FILE_TRANSFER_H
#define PARANOID_FILE_TRANSFER_H

#include "types.h"

/* Maksimum dosya boyutu sınırı — 100 GB */
#ifndef NOX_MAX_FILE_SIZE
#define NOX_MAX_FILE_SIZE (100ULL * 1024ULL * 1024ULL * 1024ULL)
#endif

/* Dosya gönderim sürecini (METADATA hazırlama, okuma, şifreleme ve iletim) başlatır */
void file_transfer_start(struct app_state *state, const char *filepath);

/* Peer soketi yazılabilir olduğunda (EPOLLOUT) sıradaki dosya parçasını gönderir */
void file_transfer_handle_tx(struct app_state *state);

/* Dosya paketlerini (Metadata veya chunk) alır, şifresini çözer ve diske yazar */
void file_transfer_handle_rx(struct app_state *state, const uint8_t *payload, uint32_t len);

/* Bağlantı koptuğunda yarım kalan transferlerin kaynaklarını temizler ve dosyaları siler */
void file_transfer_cleanup(struct app_state *state);

#endif /* PARANOID_FILE_TRANSFER_H */
