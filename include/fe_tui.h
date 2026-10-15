/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_tui.h — TUI (termbox2) backend arayüzü
 *
 * main.c: tui_init() sonrası TUI aktifse frontend_register(&fe_tui_ops,
 * NULL); cleanup'ta tui_shutdown() + frontend_reset() → ANSI'ye dönüş.
 *
 * Sözleşme: senkron; text sahiplenilmez (scrub caller'da);
 * frontend_emit'e geri çağrı yok.
 */

#ifndef PARANOID_FE_TUI_H
#define PARANOID_FE_TUI_H

#include "frontend.h"

/* TUI backend — main.c registration + (test/fuzz doğrulaması) */
extern const struct frontend_ops fe_tui_ops;

#endif /* PARANOID_FE_TUI_H */
