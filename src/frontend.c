/* SPDX-License-Identifier: GPL-3.0-or-later
 * frontend.c — noxtor-cli ortak frontend katmanı (eski adıyla ui.c)
 *
 * Bu dosya ORTAK KATMAN'dır (§1.1):
 *   - ui_print_* public sarmalayıcılar — filtre/vsnprintf + fe_event
 *     doldurma + TEK dispatch (frontend_emit)
 *   - ui_strip_ansi — ESC/C0 temizliğinin tek doğruluk kaynağı
 *     (korpus: tests/test_ansi_strip.c)
 *   - fe_now_tm — tek clock_gettime + localtime_r (ts + tm birlikte)
 *   - dispatch durumu: varsayılan backend ANSI (statik registration)
 *
 * Asıl çizim (render) fe_ansi.c / fe_tui.c backend'lerine aittir —
 * bkz. struct frontend_ops. Bu dosyada tui_is_active() KALMAZ (commit 4):
 * backend seçimi registration ile.
 *
 * KURALLAR (tehdit modeli):
 *   - Event SENKRON + kopyasız: fe_event caller'ın buffer'ına pointer
 *     taşır, frontend_emit anında döner. Kuyruk YOK, plaintext beklemez.
 *   - Backend emit'ten sonra ev pointer'larını KULLANAMAZ.
 *   - Backend frontend_emit'i GERİ ÇAĞIRMAZ (özyineleme tuzağı).
 *   - text/filename sahiplenilmez — scrub sahibi caller'dır (burası).
 */

#include "frontend.h"
#include "common.h"
#include "types.h"
#include "fe_ansi.h"    /* varsayılan backend (statik registration) */

#include <stdarg.h>     /* vsnprintf — ui_print_system/error */
#include <sodium.h>     /* sodium_memzero — msg scrub */
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ================================================================
 * ORTAK ZAMAN DAMGASI — tek clock_gettime + localtime_r (commit 2/4)
 *
 * ts ve tm AYNI kaynaktan (tek clock_gettime) doldurulur — fe_event
 * alanlarının tutarlılığı için (commit 4).
 *
 * Hata davranışı korundu: clock_gettime başarısızsa epoch'a (ts=0)
 * düşülür, localtime_r hatası → sıfır tm (00:00:00).
 *
 * ts_out NULL olabilir (sadece tm isteyen çağrılar — testler).
 * ================================================================ */
void fe_now_tm(time_t *ts_out, struct tm *tm_out)
{
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        ts.tv_sec = 0;   /* korunmuş davranış: hata → epoch */

    memset(tm_out, 0, sizeof(*tm_out));
    if (!localtime_r(&ts.tv_sec, tm_out))
        memset(tm_out, 0, sizeof(*tm_out)); /* hata → sıfır tm (00:00:00) */

    if (ts_out)
        *ts_out = ts.tv_sec;
}

/* ================================================================
 * UI-1/B FIX: Terminal ANSI injection koruması — tek doğruluk kaynağı.
 * Daha önce İKİ static kopya vardı (frontend + stdin_handler) ve drift
 * başlamıştı: stdin kopyasında OSC/DCS tarama limiti (256) vardı.
 * Kanonik = limitli versiyon; korpus: tests/test_ansi_strip.c.
 *
 * Yer: ORTAK katman (§1.4). Backend'ler (fe_ansi atomic_message /
 * render_progress) bu public fonksiyonu çağırır. Faz 1b'de C0/DEL
 * kapsamı + UTF-8 doğrulama bu noktaya gelecek.
 *
 * // Real attack surface in practice: terminal injection (CSI/OSC/DCS)
 * ================================================================ */
void ui_strip_ansi(char *str) {
  if (!str) return;
  char *dst = str;
  const char *src = str;
  while (*src) {
    if ((unsigned char)*src == 0x1b) {
      if (src[1] == '[') {
        /* CSI: ESC [ <params> <final> */
        src += 2;
        while (*src && ((*src >= '0' && *src <= '?') ||
                        (*src >= ' ' && *src <= '/')))
          src++;
        if (*src) src++;
      } else if (src[1] == ']') {
        /* OSC: ESC ] <cmd> ; <data> BEL or ESC \ — max 256 byte tara */
        src += 2;
        int osc_limit = 256;
        while (*src && osc_limit-- > 0 && (unsigned char)*src != 0x07 &&
               !(src[0] == 0x1b && src[1] == '\\'))
          src++;
        if ((unsigned char)*src == 0x07) src++;
        else if (src[0] == 0x1b && src[1] == '\\') src += 2;
      } else if (src[1] == 'P') {
        /* DCS: ESC P <data> ESC \ — max 256 byte tara */
        src += 2;
        int dcs_limit = 256;
        while (*src && dcs_limit-- > 0 && !(src[0] == 0x1b && src[1] == '\\'))
          src++;
        if (src[0] == 0x1b && src[1] == '\\') src += 2;
      } else {
        /* Diğer tüm ESC sequence'leri (ST, tek ESC, vs.) — atla */
        if (src[1] != '\0')
          src += 2;
        else
          src++;  /* bare ESC — NUL'a kadar atla */
      }
    } else if ((unsigned char)*src < 32 && *src != '\t' && *src != '\n' && *src != '\r') {
      /* LN-1: C0 control (except TAB/LF/CR) — drop, UTF-8 continuation korunur */
      src++;
    } else if ((unsigned char)*src == 0x7F) {
      src++;
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

/* ================================================================
 * EVENT DOLDURMA — tüm sarmalayıcılar bunu kullanır
 *
 * type + state + text/len + tek kaynaktan ts/tm. memset(0) ile geri
 * kalan alanlar (filename/done/total/is_upload) temizlenir.
 * text: senkron, sahiplenilmez — backend okur, biz scrub ederiz.
 * ================================================================ */
static void fe_fill_event(struct fe_event *ev, enum fe_event_type type,
                          struct app_state *state,
                          const char *text, size_t len)
{
    memset(ev, 0, sizeof(*ev));
    ev->type  = type;
    ev->state = state;
    ev->text  = text;
    ev->len   = len;
    fe_now_tm(&ev->ts, &ev->tm);   /* tek clock — ts+tm tutarlı */
}

/* ================================================================
 * PUBLIC BİLDİRİM SARMALAYICILAR — 206 çağrı sitesi bu imzaları
 * kullanır (Faz 1'de imzalar DEĞİŞMEZ).
 *
 * commit 4: eski `if (tui_is_active())` dallanmaları KALKTI —
 * dispatch registration ile backend'i seçer.
 * ================================================================ */

/* Geçerlilik filtresi ortak (§1.4.5): boş/beyaz-only gelen mesaj atılır */
void ui_print_incoming(struct app_state *state, const char *msg)
{
    if (!msg || !*msg || strspn(msg, " \t") == strlen(msg))
        return;
    struct fe_event ev;
    fe_fill_event(&ev, FE_MSG_IN, state, msg, strlen(msg));
    frontend_emit(&ev);
}

/* Dikkat: outgoing'te boş filtre YOK — bugünkü davranış korunur
 * (atılan tek yer incoming). */
void ui_print_outgoing(struct app_state *state, const char *msg)
{
    struct fe_event ev;
    fe_fill_event(&ev, FE_MSG_OUT, state, msg, strlen(msg));
    frontend_emit(&ev);
}

/* ================================================================
 * SİSTEM VE HATA MESAJLARI
 * ================================================================ */

void ui_print_system(struct app_state *state, const char *fmt, ...)
{
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);   /* §1.4.1: msg[4096] korunur */
    va_end(ap);

    struct fe_event ev;
    fe_fill_event(&ev, FE_SYSTEM, state, msg, strlen(msg));
    frontend_emit(&ev);

    /* H-2: local buffer — emit senkron, backend döndükten sonra scrub
     * (backend text'i sahiplenmez, kopyalama YOK). */
    sodium_memzero(msg, sizeof(msg));
}

void ui_print_error(struct app_state *state, const char *fmt, ...)
{
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    struct fe_event ev;
    fe_fill_event(&ev, FE_ERROR, state, msg, strlen(msg));
    frontend_emit(&ev);

    sodium_memzero(msg, sizeof(msg));
}

/* ================================================================
 * DOSYA TRANSFERİ PROGRESS BAR — bkz. fe_ansi.c render_progress
 * (toplam/çizim/backend işi; burada sadece dispatch)
 * ================================================================ */
void ui_print_progress(struct app_state *state, const char *filename,
                       uint64_t done, uint64_t total, bool is_upload)
{
    /* total==0 erken dönüşü ORTAK DEĞİL — ANSI backend'inde
     * (render_progress). TUI'da total==0'da bile refresh vardır;
     * davranış birebir korunur (commit 4 notu). */
    struct fe_event ev;
    fe_fill_event(&ev, FE_PROGRESS, state, NULL, 0);
    ev.filename  = filename;
    ev.done      = done;
    ev.total     = total;
    ev.is_upload = is_upload;
    frontend_emit(&ev);
}

/* ================================================================
 * STRUCTURED EVENT + OPS — dispatch durumu (commit 1 iskeleti,
 * commit 4'te canlıya alındı)
 *
 * VARSAYILAN backend ANSI (statik registration, §1.2): fuzz hedefleri
 * ve birim testleri registration yapmaz → bugünün stderr davranışı
 * korunur. main.c sadece TUI devreye girerse override eder
 * (frontend_register(&fe_tui_ops)) ve cleanup'ta frontend_reset()
 * ile ANSI'ye döner.
 * ================================================================ */

static const struct frontend_ops *g_fe_ops = &fe_ansi_ops;
static void *g_fe_ctx = NULL;

void frontend_register(const struct frontend_ops *ops, void *ctx)
{
    /* Son çağran kazanır — TUI devreye girerse ANSI'ın yerini alır.
     * NULL ile unregister da mümkün (geçici/special test). */
    g_fe_ops = ops;
    g_fe_ctx = ctx;
}

void frontend_reset(void)
{
    /* Varsayılan (ANSI) backend'e dön — tui_shutdown sonrası cleanup
     * bunu çağırır; bugünkü `tui_is_active()` runtime kontrolünün
     * registration karşılığı. */
    g_fe_ops = &fe_ansi_ops;
    g_fe_ctx = NULL;
}

void frontend_emit(const struct fe_event *ev)
{
    if (!ev || !g_fe_ops || !g_fe_ops->emit)
        return;   /* kayıt yok → no-op (unregister senaryosu) */

    /* SENKRON: backend, ev'deki pointer'ları emit dönüşünde
     * kullanamaz. Kuyruk/copy YOK — plaintext beklemez (tehdit modeli).
     * Recursion yasağı: backend bu fonksiyonu geri çağırmaz. */
    g_fe_ops->emit(g_fe_ctx, ev);
}
