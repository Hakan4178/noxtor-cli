/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_tui.c — TUI (termbox2) backend çizim yolları (Faz 1, commit 3)
 *
 * Eski adıyla frontend.c içindeki tui_is_active() bloklarının GÖVDELERİ
 * buraya taşındı. Davranış-değiştirmez: çıktı byte-identical, scrub
 * sıralaması aynı, truncation cap'leri (tbuf[8192]) aynı.
 *
 * GEÇİŞ DURUMU (commit 3): dispatch henüz frontend_ops üzerinden değil —
 * frontend.c'deki ui_print_* hâlâ `if (tui_is_active())` ile dallanıp bu
 * fonksiyonları çağırıyor. Commit 4'te registration akışı devreye girer
 * ve bu fonksiyonlar fe_tui_ops.emit handler'ının içine iner.
 *
 * !HAVE_TERMBOX derlemesinde tui.h inline no-op'lara düşer — bu dosya
 * her iki modda da derlenir; non-TUI modda fonksiyonlar dead code kalır
 * (çağrılmaz çünkü tui_is_active() hep false).
 *
 * KURALLAR:
 *   - text SAHİPLENİLMEZ — sodium_memzero YAPMAZ (owner caller)
 *   - Timestamp: fe_now_tm() ortak katmandan — kopya yok
 *   - frontend_emit'e GERİ ÇAĞRIŞ YOK (recursion yasağı)
 */

#include "fe_tui.h"
#include "frontend.h"   /* fe_now_tm — ortak zaman damgası */
#include "tui.h"

#include <sodium.h>     /* sodium_memzero — tbuf scrub */
#include <stdio.h>      /* snprintf */

/* Chat satırı ekle + tazele: "[HH:MM:SS] <prefix><msg>"
 *
 * prefix: "Peer: " | "Sen: " | "[!] " | "" (sistem) — eski inline
 * snprintf formatlarıyla byte-identical çıktı üretir.
 *
 * tbuf[8192]: plaintext barındıran tek local — döndükten önce
 * sodium_memzero ile temizlenir (H-2, dead-store elimination'a dayanıklı).
 */
static void tui_append_line(struct app_state *state,
                            const char *prefix, const char *msg)
{
    struct tm tm_buf;
    fe_now_tm(&tm_buf);

    char tbuf[8192];
    snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] %s%s",
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
             prefix, msg);

    tui_chat_append(tbuf);
    tui_refresh_all(state);

    /* H-2: tbuf heap değil ama scrub alışkanlığı korunur (stack). */
    sodium_memzero(tbuf, sizeof(tbuf));
}

void fe_tui_msg_in(struct app_state *state, const char *msg)
{
    tui_append_line(state, "Peer: ", msg);
}

void fe_tui_msg_out(struct app_state *state, const char *msg)
{
    tui_append_line(state, "Sen: ", msg);
}

void fe_tui_msg_system(struct app_state *state, const char *msg)
{
    tui_append_line(state, "", msg);
}

void fe_tui_msg_error(struct app_state *state, const char *msg)
{
    tui_append_line(state, "[!] ", msg);
}

void fe_tui_progress(struct app_state *state)
{
    /* [F2] TUI'da progress bar çizilmez — mevcut davranış:
     * yalnız panel tazele (bar'ı ANSI backend yönetir). */
    tui_refresh_all(state);
}
