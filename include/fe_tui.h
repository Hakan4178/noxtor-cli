/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_tui.h — TUI (termbox2) backend arayüzü (Faz 1, commit 3)
 *
 * frontend.c içindeki tui_is_active() bloklarının ÇİZİM gövdeleri buraya
 * taşındı (davranış-değiştirmez — byte-identical çıktı).
 *
 * GEÇİŞ DURUMU (commit 3): dispatch henüz frontend_ops üzerinden DEĞİL.
 * frontend.c'deki ui_print_* hâlâ `if (tui_is_active())` ile dallanıp bu
 * fonksiyonları çağırır. Commit 4'te bu fonksiyonlar fe_tui_ops.emit'e
 * bağlanır, main.c registration akışı devreye girer ve bu ara katman
 * emit handler'ının içine iner.
 *
 * KURALLAR (tehdit modeli):
 *   - text pointer'ları SAHİPLENİLMEZ — backend sodium_memzero YAPMAZ
 *     (owner caller'dır; frontend.c kendi local msg[] buffer'larını
 *     kendisi sıfırlar)
 *   - Timestamp: fe_now_tm() ortak katmandan (tek clock_gettime +
 *     localtime_r) — backend'de kopya yok
 */

#ifndef PARANOID_FE_TUI_H
#define PARANOID_FE_TUI_H

#include "common.h"

/* Forward declaration — types.h'ye bağımlılık yok */
struct app_state;

/* ── Chat'e zaman damgalı mesaj ekle + panelleri tazele ──────────
 * Hepsi aynı kalıp: "[HH:MM:SS] <prefix><msg>" → tui_chat_append →
 * tui_refresh_all → tbuf scrub. Prefix'ler formatı byte-identical
 * tutar (eski inline snprintf'larla birebir aynı çıktı).
 */

/* "[TS] Peer: msg"  — gelen mesaj (ui_print_incoming) */
void fe_tui_msg_in(struct app_state *state, const char *msg);

/* "[TS] Sen: msg"   — giden mesaj (ui_print_outgoing) */
void fe_tui_msg_out(struct app_state *state, const char *msg);

/* "[TS] msg"        — sistem mesajı (ui_print_system) */
void fe_tui_msg_system(struct app_state *state, const char *msg);

/* "[TS] [!] msg"    — hata mesajı (ui_print_error) */
void fe_tui_msg_error(struct app_state *state, const char *msg);

/* Progress (ui_print_progress): TUI'da bar çizilmez — sadece panel
 * tazele. Mevcut davranışın aynısı (tui_refresh_all + return). */
void fe_tui_progress(struct app_state *state);

#endif /* PARANOID_FE_TUI_H */
