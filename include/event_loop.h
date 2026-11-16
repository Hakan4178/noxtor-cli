/* SPDX-License-Identifier: GPL-3.0-or-later
 * event_loop.h — noxtor-cli epoll tabanlı olay döngüsü arayüzü
 */

#ifndef PARANOID_EVENT_LOOP_H
#define PARANOID_EVENT_LOOP_H

#include "types.h"

/* Epoll tabanlı asenkron I/O olay döngüsü.
 * STDIN_FILENO, listen_fd ve peer_fd (bağlantı aktifse) izlenir. */
void event_loop(struct app_state *state);

/* ================================================================
 * UNIT TEST ERİŞİMİ (test_event_frames) — davranış kilitleri.
 * Üretim akışında da kullanılan iç yardımcılar; static kaldırıldı.
 * ================================================================ */

#ifndef NOX_NO_LANDLOCK
/* F5 test seam: Landlock ön-kontrol kapısı. ops == NULL ise üretimdeki
 * gerçek Landlock fonksiyonları kullanılır; testler fake ops verir.
 * true → event loop devam eder; false → abort edildi ve
 * state->running=false yapıldı (çağıran return etmeli). */
struct nox_ll_gate_ops {
    int       (*abi_version)(void);
    int       (*open_socks)(const char *path);
    nox_err_t (*sandbox_init)(int config_dir_fd, int downloads_dir_fd,
                              int tor_data_fd, int socks_fd);
    nox_hardbool_t (*is_active)(void);
    int       (*close_fd)(int fd);
};

bool event_loop_landlock_gate(struct app_state *state,
                              const struct nox_ll_gate_ops *ops);
#endif /* !NOX_NO_LANDLOCK */

/* fd → peer eşlemesi (epoll dağıtımı). Bulunamazsa NULL. */
struct peer_session *find_peer_by_fd(struct app_state *state, int fd);

/* K-10: recv_buf gerçekten dolu mu? (drain sonrası yeniden değerlendirilir;
 * yalnız bu yüklem true iken tıkanma disconnect'i yapılır.) */
bool peer_recv_buf_full(const struct peer_session *ps);

/* B1: yarım frame / trickle deadline predikati — saf, saat enjekte
 * edilebilir. now - frame_start > timeout_sec. Caller CLOCK_MONOTONIC
 * ile besler; NULL girdi → false (fail-safe). */
bool frame_trickle_expired(const struct timespec *frame_start,
                           const struct timespec *now, long timeout_sec);

/* H-1/H-2 claim payload v1: [ver(1) | onion(62) | sig(64)] —
 * state->my_onion_seed/my_static_pub yoksa fail-closed. */
nox_err_t hs_build_claim_payload(uint8_t pl[NOX_HS_PAYLOAD_V1_LEN],
                                 const struct app_state *state);

/* recv_buf'taki tam frame'leri işler: header doğrula → (gerekirse
 * decrypt) → dağıt → seq ilerlet. Yarım frame bekletilir; bozuk
 * header/boyut buffer'ı sıfırlar. */
void process_peer_frames(struct peer_session *ps, struct app_state *state,
                         int fd);

#endif /* PARANOID_EVENT_LOOP_H */
