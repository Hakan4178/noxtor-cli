/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_tui.c — TUI (termbox2) backend çizim yolları (Faz 1, commit 4)
 *
 * tui_chat_append + tui_refresh_all tabanlı render; fe_tui_ops.emit
 * dispatch hedefi. Eski inline TUI blokları (commit 3 split) buraya
 * taşınmıştı; commit 4'te fonksiyonlar ev.tabanlı hale getirildi —
 * timestamp ev->tm'den gelir (tek clock frontend.c'de, fe_fill_event).
 *
 * Çıktı byte-identical: "[HH:MM:SS] <prefix><msg>" — eski inline
 * snprintf'larla birebir aynı.
 *
 * !HAVE_TERMBOX derlemesinde tui.h inline no-op'lara düşer — bu dosya
 * her iki modda da derlenir; non-TUI modda emit çağrılmaz (backend
 * kaydı ANSI'de kalır) ve fonksiyonlar dead code'dur.
 *
 * KURALLAR:
 *   - text SAHİPLENİLMEZ — sodium_memzero YAPMAZ (owner caller)
 *   - clock kopyası YOK — ev->tm (fe_fill_event, tek clock_gettime)
 *   - frontend_emit'e GERİ ÇAĞRIŞ YOK (recursion yasağı)
 */

#include "fe_tui.h"
#include "frontend.h"   /* fe_event */
#include "common.h"
#include "tui.h"

#include <stdio.h>      /* snprintf */

/* Chat satırı ekle + tazele: "[HH:MM:SS] <prefix><text>"
 *
 * prefix: "Peer: " | "Sen: " | "[!] " | "" (sistem) — eski inline
 * snprintf formatlarıyla byte-identical çıktı üretir.
 *
 * tbuf[8192]: tek local; sahiplenme YOK ama stack scrub alışkanlığı
 * korunur (H-2 — stack zaten return'te temizlenir, defansif not).
 */
static void tui_append_line(struct app_state *state, const char *prefix,
                            const char *text, const struct tm *tm)
{
    char tbuf[8192];
    snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] %s%s",
             tm->tm_hour, tm->tm_min, tm->tm_sec, prefix, text);

    tui_chat_append(tbuf);
    tui_refresh_all(state);
}

/* ================================================================
 * DISPATCH HEDEFİ — fe_tui_ops
 * ================================================================ */
static void fe_tui_emit(void *ctx, const struct fe_event *ev)
{
    (void)ctx;   /* TUI backend-özel durumu yok (commit 5: gerekirse) */

    struct app_state *state = ev->state;

    switch (ev->type) {
    case FE_MSG_IN:
        tui_append_line(state, "Peer: ", ev->text, &ev->tm);
        break;
    case FE_MSG_OUT:
        tui_append_line(state, "Sen: ", ev->text, &ev->tm);
        break;
    case FE_SYSTEM:
        tui_append_line(state, "", ev->text, &ev->tm);
        break;
    case FE_ERROR:
        tui_append_line(state, "[!] ", ev->text, &ev->tm);
        break;
    case FE_PROGRESS:
        /* [F2] TUI'da progress bar çizilmez — sadece panel tazele.
         * total==0 kontrolü YOK: bugünkü davranışta TUI'da total==0'da
         * bile refresh vardır (ANSI'da erken dönüş var — fe_ansi'de). */
        tui_refresh_all(state);
        break;
    default:
        break;   /* bilinmeli tip → sessiz (strict koruma socket fazında) */
    }
}

const struct frontend_ops fe_tui_ops = {
    .name = "tui",
    .emit = fe_tui_emit,
};
