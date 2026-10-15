/* SPDX-License-Identifier: GPL-3.0-or-later
 * frontend.h — ortak frontend arayüzü (eski adıyla ui.h)
 *
 *   1. Public UI API (ui_print_*, tema, CLI-only satır sahipliği) —
 *      206 çağrı sitesi; fazlarda imzalar DEĞİŞMEZ.
 *   2. Structured event + ops — ui_print_* → frontend_emit → kayıtlı
 *      backend (varsayılan fe_ansi; TUI override). CLI-only API
 *      implementasyonları fe_ansi.c'dedir.
 */

#ifndef PARANOID_FRONTEND_H
#define PARANOID_FRONTEND_H

#include "common.h"
#include <stdarg.h>
#include <time.h>   /* time_t + struct tm — fe_event timestamp alanı */

/* Forward declaration — types.h'yi include etmeye gerek yok */
struct app_state;

/* TEMA — her alan bir ANSI escape sequence (ileride config'ten okunabilir) */
struct nox_theme {
    const char *clr_self;       /* [Sen] etiketi ve mesaj rengi     */
    const char *clr_peer;       /* [Akran] etiketi ve mesaj rengi   */
    const char *clr_system;     /* sistem bilgi mesajları           */
    const char *clr_error;      /* hata mesajları                   */
    const char *clr_prompt;     /* prompt metni rengi               */
    const char *clr_timestamp;  /* zaman damgası rengi              */
    const char *clr_progress;   /* progress bar rengi               */
    const char *clr_reset;      /* ANSI reset sekansı               */
};

/* Varsayılan tema — fe_ansi.c'de tanımlı */
extern const struct nox_theme nox_theme_default;

/* UI FONKSİYONLARI */

/* Tema ayarla (NULL = varsayılan) */
void ui_init(const struct nox_theme *theme);

/* Gelen/giden mesaj: atomik ANSI — cursor hide → clear → print →
 * redraw → show */
void ui_print_incoming(struct app_state *state, const char *msg);
void ui_print_outgoing(struct app_state *state, const char *msg);

/* Sistem/hata mesajı — atomik ANSI blok */
void ui_print_system(struct app_state *state, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void ui_print_error(struct app_state *state, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ANSI escape temizleyici: CSI/OSC/DCS/bare-ESC, C0 drop (\t\n\r
 * hariç), DEL drop; UTF-8 continuation korunur; OSC/DCS tarama 256
 * ile sınırlı. Korpus: tests/test_ansi_strip.c */
void ui_strip_ansi(char *str);

/* Prompt / satır sahipliği */

/* Sender durumunu sıfırla (yeni bağlantıda) */
void ui_reset_sender(void);

/* Prompt alanını temizle (cursor yukarı + sil) — TOFU promptları için */
void clear_prompt_area(struct app_state *state);

/* Belirli satır sayısını temizle (saved prompt wrap için) */
void clear_prompt_area_lines(int lines);

/* ui_print_prompt: header'dan DÜŞTÜ (§1.3) — dış çağrı 0 (static) */

/* G-2: Terminal satır sahipliği — YALNIZCA event_loop.c top-level
 * handler'larından çağrılır; ui_print_* veya log.c içine eklenmez
 * (refcount nesting'i kırar). */
void ui_line_suspend(struct app_state *state);      /* ln_active && depth++==0 → Hide */
void ui_line_resume(struct app_state *state);       /* --depth==0 → Show */
void ui_line_force_resume(struct app_state *state); /* acil kurtarma: depth→0, Show (yalnızca ln_edit_deinit'te) */

/* Dosya transferi — in-place progress bar (aynı satırı günceller) */
void ui_print_progress(struct app_state *state,
                       const char *filename,
                       uint64_t done, uint64_t total,
                       bool is_upload);

/* ORTAK ZAMAN DAMGASI — tek clock_gettime + tek localtime_r (ts+tm
 * birlikte). ts_out NULL olabilir. Backend'ler timestamp'i ev->tm'den
 * alır; kendi kopyası TUTMAZ. Hata: clock → epoch, localtime → 00:00:00 */
void fe_now_tm(time_t *ts_out, struct tm *tm_out);

/* STRUCTURED EVENT + OPS
 *
 * Akış: ui_print_* (filtre/vsnprintf + fe_fill_event) → frontend_emit
 * → kayıtlı backend (varsayılan ANSI; TUI override).
 *
 * KURALLAR (tehdit modeli):
 *   - Event SENKRON + kopyasız: frontend_emit anında döner; kuyruk
 *     YOK, RAM'de plain text beklemez.
 *   - Backend emit'ten sonra event pointer'larını KULLANAMAZ.
 *   - Backend frontend_emit'i GERİ ÇAĞIRMAZ.
 *   - text/filename sahiplenilmez; scrub sahibi caller (common). */

enum fe_event_type {
    FE_MSG_IN = 1,      /* gelen sohbet mesajı   */
    FE_MSG_OUT,         /* giden sohbet mesajı  */
    FE_SYSTEM,          /* sistem bilgi mesajı  */
    FE_ERROR,           /* hata mesajı          */
    FE_PROGRESS,        /* dosya transferi bar'ı */
};

struct fe_event {
    enum fe_event_type type;

    /* sanitize edilmiş UTF-8, NUL-terminated; senkron, sahiplenilmez.
     * Faz 1'de yalnızca escape/C0 strip (backend'de); Faz 1b'de UTF-8
     * doğrulama + ortak katman öncesi strip. */
    const char *text;
    size_t      len;

    /* Tek clock'tan ts+tm (fe_fill_event doldurur) */
    time_t      ts;
    struct tm   tm;

    /* Render kimi — dispatch'in tek state kaynağı
     * (ctx registration'da backend-özel durum içindir) */
    struct app_state *state;

    /* FE_PROGRESS alanları (diğer tiplerde kullanılmaz) */
    const char *filename;   /* senkron, sahiplenilmez — backend strip eder */
    uint64_t    done;
    uint64_t    total;
    bool        is_upload;
};

/* Backend arayüzü — her backend tek emit fonksiyonu sağlar */
struct frontend_ops {
    const char *name;
    void (*emit)(void *ctx, const struct fe_event *ev);
};

/* Son kayıt kazanır. ctx backend-özel durum: ANSI'de `struct ansi_ctx`
 * (fe_ansi.c iç — production'da NULL, g_ansi fallback); TUI'de NULL.
 * ctx sahiplenilmez; son kayıt eskisini ezer. */
void frontend_register(const struct frontend_ops *ops, void *ctx);

/* Varsayılan ANSI'ye dön — tui_shutdown sonrası cleanup çağırır */
void frontend_reset(void);

/* Tek dispatch — senkron, kopyasız; kayıt yoksa no-op */
void frontend_emit(const struct fe_event *ev);

#endif /* PARANOID_FRONTEND_H */
