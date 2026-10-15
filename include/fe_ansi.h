/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_ansi.h — Atomic ANSI backend arayüzü
 *
 * Varsayılan dispatch backend'i (frontend.c statik registration —
 * fuzz/test registration yapmaz, stderr davranışı korunur).
 * main.c: TUI aktifse frontend_register(&fe_tui_ops) override;
 * cleanup'ta frontend_reset() → ANSI'ye dönüş.
 *
 * CLI-only API (prototipler frontend.h'de — imzalar değişmez):
 * clear_prompt_area*, ui_line_*, ui_reset_sender; ui_print_prompt
 * header'dan düştü (static, dış çağrı 0).
 *
 * Backend durumu: struct ansi_ctx (theme+last_label) — default yolda
 * ctx NULL → g_ansi fallback; tam ctx-erisim Faz 4 (GTK).
 */

#ifndef PARANOID_FE_ANSI_H
#define PARANOID_FE_ANSI_H

#include "frontend.h"

extern const struct frontend_ops fe_ansi_ops;

#endif /* PARANOID_FE_ANSI_H */
