/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_tui.c — TUI (termbox2) backend çizimleri
 *
 * fe_tui_ops.emit: tui_chat_append + tui_refresh_all tabanlı render;
 * timestamp ev->tm'den (tek clock frontend.c'de). Çıktı byte-identical:
 * "[HH:MM:SS] <prefix><msg>". !HAVE_TERMBOX'da tui.h no-op inline'lara
 * düşer — dosya her iki modda derlenir.
 *
 * Sözleşme: senkron; text sahiplenilmez (scrub caller'da); clock
 * kopyası yok; frontend_emit'e geri çağrı yok.
 */

#include "fe_tui.h"
#include "frontend.h"   /* fe_event */
#include "common.h"
#include "tui.h"

#include <stdio.h>      /* snprintf */
#include <sodium.h>     /* sodium_memzero — tbuf scrub */

/* "[HH:MM:SS] <prefix><text>" ekle + tazele.
 * prefix: "Peer: " | "Sen: " | "[!] " | "" (sistem) */
static void tui_append_line(struct app_state *state, const char *prefix,
                            const char *text, const struct tm *tm)
{
    char tbuf[8192];
    snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] %s%s",
             tm->tm_hour, tm->tm_min, tm->tm_sec, prefix, text);

    tui_chat_append(tbuf);
    tui_refresh_all(state);
    /* H-2: formatted plaintext stack'te iz bırakmasın (eski ui.c ile birebir) */
    sodium_memzero(tbuf, sizeof(tbuf));
}

/* DISPATCH HEDEFİ — fe_tui_ops */
static void fe_tui_emit(void *ctx, const struct fe_event *ev)
{
    (void)ctx;   /* TUI backend-özel durumu yok */

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
        /* Bar çizilmez — sadece panel tazele (total==0'da bile refresh
         * var; erken dönüş yalnız ANSI kolunda) */
        tui_refresh_all(state);
        break;
    default:
        break;   /* bilinmeli tip → sessiz (strict socket fazında) */
    }
}

const struct frontend_ops fe_tui_ops = {
    .name = "tui",
    .emit = fe_tui_emit,
};
