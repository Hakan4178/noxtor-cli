/* SPDX-License-Identifier: GPL-3.0-or-later
 * frontend.c — ortak frontend katmanı (eski adıyla ui.c)
 *
 *   ui_print_* sarmalayıcılar: filtre/vsnprintf + fe_event + tek dispatch
 *   ui_strip_ansi: ESC/C0 temizliği (korpus: tests/test_ansi_strip.c)
 *   fe_now_tm: tek clock_gettime + localtime_r (ts + tm birlikte)
 *
 * Render backend'de (fe_ansi.c / fe_tui.c); backend registration ile
 * seçilir — varsayılan ANSI (fuzz/test registration yapmaz → stderr
 * davranışı korunur).
 *
 * Sözleşme: event senkron + kopyasız; backend emit'ten sonra ev
 * pointer'larını kullanamaz; frontend_emit'e geri çağrılmaz; text
 * sahiplenilmez — scrub sahibi caller (burası).
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

/* Tek clock — ts + tm aynı clock_gettime'den (commit 2/4).
 * ts_out NULL olabilir; clock/localtime hatası → epoch / sıfır tm. */
void fe_now_tm(time_t *ts_out, struct tm *tm_out)
{
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        ts.tv_sec = 0;   /* hata → epoch */

    memset(tm_out, 0, sizeof(*tm_out));
    if (!localtime_r(&ts.tv_sec, tm_out))
        memset(tm_out, 0, sizeof(*tm_out)); /* hata → 00:00:00 */

    if (ts_out)
        *ts_out = ts.tv_sec;
}

/* K-33: görünmez/yon saptırıcı kod noktaları — C1 (U+0080..U+009F),
 * LRM/RLM (U+200E/200F), bidi embedding/override (U+202A..202E),
 * bidi isolate (U+2066..2069) ve ALM (U+061C). Peer kontrollü metinde
 * bunlar terminal satırı/yonü sahteleştirebilir; sessizce düşürülür.
 * Dönüş: eşleşen UTF-8 dizisinin bayt uzunluğu (yoksa 0). */
static size_t utf8_deceptive_cp(const unsigned char *s) {
  if (s[0] == 0xC2 && s[1] >= 0x80 && s[1] <= 0x9F) return 2; /* C1 */
  if (s[0] == 0xD8 && s[1] == 0x9C) return 2;                 /* U+061C ALM */
  if (s[0] == 0xE2 && s[1] == 0x80 &&
      ((s[2] >= 0x8E && s[2] <= 0x8F) ||
       (s[2] >= 0xAA && s[2] <= 0xAE))) return 3;              /* LRM/RLM + bidi */
  if (s[0] == 0xE2 && s[1] == 0x81 &&
      s[2] >= 0xA6 && s[2] <= 0xA9) return 3;                  /* bidi isolates */
  return 0;
}

/* Ortak sanitizer — ANSI injection koruması (tek doğruluk kaynağı;
 * eski iki static kopya drift olmuştu, kanonik = limitli OSC/DCS tarama).
 * C0/DEL + C1 + bidi kontrol kodları düşürülür. `keep_eol` true iken
 * CR/LF aynen korunur (stdin satır çerçevelemesi için); false iken
 * boşluğa çevrilir (K-33: çıktıda peer metni sahte satır üretemez). */
static void strip_ansi_impl(char *str, bool keep_eol) {
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
        /* Diğer ESC sequence'leri — atla (bare ESC → NUL'a kadar) */
        if (src[1] != '\0')
          src += 2;
        else
          src++;
      }
    } else if (*src == '\r' || *src == '\n') {
      if (keep_eol) {
        *dst++ = *src++;
      } else {
        /* K-33: çıktıda CR/LF satır sahteciliği üretmesin — katla. */
        *dst++ = ' ';
        src++;
      }
    } else if ((unsigned char)*src < 32 && *src != '\t') {
      /* LN-1: C0 control (TAB hariç) — drop, UTF-8 continuation korunur */
      src++;
    } else if ((unsigned char)*src == 0x7F) {
      src++;
    } else {
      size_t cp_len = utf8_deceptive_cp((const unsigned char *)src);
      if (cp_len > 0) {
        src += cp_len;
      } else {
        *dst++ = *src++;
      }
    }
  }
  *dst = '\0';
}

/* Çıktı sanitizer'ı: CR/LF satır sahteciliğini boşluğa katlar. */
void ui_strip_ansi(char *str) {
  strip_ansi_impl(str, false);
}

/* Girdi sanitizer'ı: aynı ESC/C0/C1/bidi temizliği, fakat CR/LF korunur.
 * stdin_handler satırları '\n' ile bölüp Enter'ı işler; burada CR/LF
 * düşürülürse hiçbir komut çalışmaz (K-33 regresyonu). */
void ui_strip_input(char *str) {
  strip_ansi_impl(str, true);
}

/* fe_event doldur — text sahiplenilmez, scrub emit dönüşünde (caller) */
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

/* Public sarmalayıcılar — 206 çağrı sitesi, imzalar Faz 1'de değişmez.
 * Eski `if (tui_is_active())` dallanmaları KALKTI (commit 4):
 * backend seçimi registration ile. */

/* Geçerlilik filtresi ortak (§1.4.5): boş/beyaz-only gelen mesaj atılır */
void ui_print_incoming(struct app_state *state, const char *msg)
{
    if (!msg || !*msg || strspn(msg, " \t") == strlen(msg))
        return;
    struct fe_event ev;
    fe_fill_event(&ev, FE_MSG_IN, state, msg, strlen(msg));
    frontend_emit(&ev);
}

/* Outgoing'te boş filtre YOK — bugünkü davranış korunur (atılan tek
 * yer incoming). NULL guard: strlen(NULL) crash'i önler. */
void ui_print_outgoing(struct app_state *state, const char *msg)
{
    if (!msg)
        return;
    struct fe_event ev;
    fe_fill_event(&ev, FE_MSG_OUT, state, msg, strlen(msg));
    frontend_emit(&ev);
}

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

    /* H-2: emit senkron — backend döndükten sonra scrub */
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

/* Çizim backend'in işi (fe_ansi render_progress) — burada sadece dispatch.
 * total==0 erken dönüşü ANSI kolunda; TUI'da total==0'da bile refresh var
 * (davranış birebir korunur). */
void ui_print_progress(struct app_state *state, const char *filename,
                       uint64_t done, uint64_t total, bool is_upload)
{
    struct fe_event ev;
    fe_fill_event(&ev, FE_PROGRESS, state, NULL, 0);
    ev.filename  = filename;
    ev.done      = done;
    ev.total     = total;
    ev.is_upload = is_upload;
    frontend_emit(&ev);
}

/* Varsayılan backend ANSI (statik registration, §1.2) — main.c TUI'de
 * override eder (frontend_register(&fe_tui_ops)) ve cleanup'ta
 * frontend_reset() ile ANSI'ye döner. */
static const struct frontend_ops *g_fe_ops = &fe_ansi_ops;
static void *g_fe_ctx = NULL;

void frontend_register(const struct frontend_ops *ops, void *ctx)
{
    /* Son kayıt kazanır; NULL = unregister (test/special) */
    g_fe_ops = ops;
    g_fe_ctx = ctx;
}

void frontend_reset(void)
{
    /* Varsayılan ANSI'ye dön — tui_shutdown sonrası cleanup çağırır */
    g_fe_ops = &fe_ansi_ops;
    g_fe_ctx = NULL;
}

void frontend_emit(const struct fe_event *ev)
{
    if (!ev || !g_fe_ops || !g_fe_ops->emit)
        return;   /* kayıt yok → no-op */

    /* Senkron + kopyasız — plaintext beklemez; recursion yasağı:
     * backend bu fonksiyonu geri çağırmaz. */
    g_fe_ops->emit(g_fe_ctx, ev);
}
