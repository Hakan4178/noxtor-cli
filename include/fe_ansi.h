/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_ansi.h — Atomic ANSI backend arayüzü (Faz 1, commit 4)
 *
 * fe_ansi.c: Atomic ANSI Terminal Output + linenoise yolu. frontend.c'deki
 * VARSAYILAN backend'dir (statik registration — §1.2: fuzz hedefleri
 * registration yapmaz, bugünün stderr davranışı korunur).
 *
 * Registration yaşam döngüsü (main.c):
 *   - başlangıç: frontend.c'de statik init → &fe_ansi_ops
 *   - tui_init() sonrası TUI aktifse: frontend_register(&fe_tui_ops, ...)
 *   - cleanup: tui_shutdown() + frontend_reset() → ANSI'ye dönüş
 *     (bugünkü `tui_is_active()` runtime kontrolünün karşılığı)
 *
 * CLI-only public API implementasyonları buradadır (prototipler
 * frontend.h'de kalır — 206 çağrı sitesi değişmez): clear_prompt_area*,
 * ui_line_*, ui_reset_sender. ui_print_prompt header'dan DÜŞTÜ (yalnız
 * redraw_input çağırır — dış çağrı 0).
 */

#ifndef PARANOID_FE_ANSI_H
#define PARANOID_FE_ANSI_H

#include "frontend.h"

extern const struct frontend_ops fe_ansi_ops;

#endif /* PARANOID_FE_ANSI_H */
