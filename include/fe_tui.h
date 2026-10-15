/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_tui.h — TUI (termbox2) backend arayüzü (Faz 1, commit 4)
 *
 * fe_tui.c: tui_chat_append + tui_refresh_all tabanlı çizim. Dispatch
 * hedefidir — frontend.c'deki `if (tui_is_active())` dallanmaları
 * commit 4'te KALKTI, yerine registration geldi:
 *
 *   main.c: tui_init() sonrası TUI aktifse
 *           frontend_register(&fe_tui_ops, NULL)
 *           cleanup'ta tui_shutdown() + frontend_reset() → ANSI'ye dönüş
 *
 * KURALLAR (tehdit modeli):
 *   - text/filename pointer'ları SAHİPLENİLMEZ — backend sodium_memzero
 *     YAPMAZ (scrub sahibi caller / common katman)
 *   - Timestamp: ev->tm'den formatlar — backend'de clock kopyası YOK
 *   - frontend_emit'e GERİ ÇAĞRIŞ YOK (recursion yasağı)
 *   - SENKRON: emit dönüşünden sonra ev pointer'ları kullanılmaz
 */

#ifndef PARANOID_FE_TUI_H
#define PARANOID_FE_TUI_H

#include "frontend.h"

/* TUI backend — main.c registration + (test/fuzz doğrulaması) */
extern const struct frontend_ops fe_tui_ops;

#endif /* PARANOID_FE_TUI_H */
