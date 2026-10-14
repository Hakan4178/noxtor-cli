/* SPDX-License-Identifier: GPL-3.0-or-later
 * frontend.h — noxtor-cli ortak frontend arayüzü (eski adıyla ui.h)
 *
 * Bu header İKİ katmanı tanımlar:
 *   1. Public UI API (ui_print_*, tema, CLI-only satır sahipliği) — 206
 *      çağrı sitesi bu imzaları kullanır; fazlarda imzalar DEĞİŞMEZ.
 *   2. Structured event + ops — dispatch noktası (commit 4'te canlı:
 *      ui_print_* → frontend_emit → kayıtlı backend fe_ansi/fe_tui).
 *      CLI-only API implementasyonları fe_ansi.c'dedir.
 *
 * Tema değiştirmek için tek yapılması gereken nox_theme struct'ını
 * güncellemek — tüm çıktılar otomatik olarak yeni paleti kullanır.
 */

#ifndef PARANOID_FRONTEND_H
#define PARANOID_FRONTEND_H

#include "common.h"
#include <stdarg.h>
#include <time.h>   /* time_t + struct tm — fe_event timestamp alanı */

/* Forward declaration — types.h'yi include etmeye gerek yok */
struct app_state;

/* ================================================================
 * TEMA YAPISI — ileride config dosyasından okunabilir
 *
 * Her alan bir ANSI escape sequence string'i tutar.
 * Örn: "\033[38;2;38;162;105m" (24-bit truecolor yeşil)
 * ================================================================ */
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

/* Varsayılan tema — ui.c'de tanımlı */
extern const struct nox_theme nox_theme_default;

/* ================================================================
 * UI FONKSİYONLARI
 * ================================================================ */

/* Tema ayarla (NULL = varsayılan) */
void ui_init(const struct nox_theme *theme);

/* ── Mesaj çıktıları ─────────────────────────────────────── */

/* Gelen mesaj: atomik ANSI — cursor hide → clear → print → redraw → show */
void ui_print_incoming(struct app_state *state, const char *msg);

/* Giden mesaj: atomik ANSI — cursor hide → clear → print → redraw → show */
void ui_print_outgoing(struct app_state *state, const char *msg);

/* ── Bildirimler ─────────────────────────────────────────── */

/* Sistem bilgi mesajı — atomik ANSI */
void ui_print_system(struct app_state *state, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Hata mesajı — atomik ANSI */
void ui_print_error(struct app_state *state, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Tek ESC kaçış temizleyici (B FIX): CSI/OSC/DCS/bare-ESC, C0 drop
 * (\t\n\r hariç), DEL drop; UTF-8 continuation korunur. OSC/DCS tarama
 * 256 ile sınırlı (bounded). Korpus: tests/test_ansi_strip.c. */
void ui_strip_ansi(char *str);

/* ── Prompt ──────────────────────────────────────────────── */

/* Sender durumunu sıfırla (yeni bağlantıda) */
void ui_reset_sender(void);

/* Prompt alanını temizle (cursor yukarı + sil) — TOFU promptları için */
void clear_prompt_area(struct app_state *state);

/* Belirli satır sayısını temizle (saved prompt wrap için) */
void clear_prompt_area_lines(int lines);

/* ui_print_prompt: header'dan DÜŞTÜ (commit 4, §1.3) — dış çağrı 0;
 * yalnız fe_ansi.c'deki redraw_input çağırır (static). */

/* G-2: Terminal satır sahipliği — YALNIZCA event_loop.c top-level
 * handler'larından çağrılır. ui_print_* veya log.c gibi yardımcılar içine
 * asla eklenmemeli (refcount nesting'i kırar, kuraldan sapma riskini geri getirir). */
void ui_line_suspend(struct app_state *state);      /* ln_active && depth++==0 → Hide */
void ui_line_resume(struct app_state *state);       /* --depth==0 → Show */
void ui_line_force_resume(struct app_state *state); /* acil kurtarma: depth→0, Show (yalnızca ln_edit_deinit'te) */

/* ── Dosya Transferi ─────────────────────────────────────── */

/* In-place progress bar (aynı satırı günceller) */
void ui_print_progress(struct app_state *state,
                       const char *filename,
                       uint64_t done, uint64_t total,
                       bool is_upload);

/* ================================================================
 * ORTAK YARDIMCI — zaman damgası (commit 2'de tekelleşti, commit 3'te
 * backend kullanımı için public yapıldı)
 *
 * Tek clock_gettime(CLOCK_REALTIME) + tek localtime_r. Backend'ler
 * (fe_tui.c) timestamp'i buradan alır; kendi kopyası TUTMAZ.
 * Hata davranışı: clock_gettime hatası → epoch (ts=0), localtime_r
 * hatası → sıfır tm (00:00:00) — mevcut davranışın aynısı.
 * ================================================================ */
void fe_now_tm(struct tm *tm_out);

/* ================================================================
 * STRUCTURED EVENT + OPS (Faz 1 iskeleti)
 *
 * Amaç: dispatch'i tek noktaya indirmek. Mevcut ui_print_* imzaları bu
 * fazda KORUNUR ve henüz bu sisteme bağlanmaz — iskelet önce kurulur,
 * dönüşüm sonraki commit'lerde tek tek yapılır (davranış-değiştirmez).
 *
 * KURALLAR (tehdit modelinden):
 *   - Event SENKRON kullanılır: fe_event caller'ın buffer'ına pointer
 *     taşır, frontend_emit anında döner. Hiçbir yerde kuyruğa alınmaz,
 *     RAM'de plain text bekletilmez.
 *   - Backend emit'ten sonra event'teki pointer'ları KULLANAMAZ.
 *   - Backend frontend_emit'i GERİ ÇAĞIRMAZ (özyineleme tuzağı).
 * ================================================================ */

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
     * Faz 1'de yalnızca escape/C0 strip; Faz 1b'de UTF-8 doğrulama eklenir. */
    const char *text;
    size_t      len;

    /* Core'dan timestamp — tek clock_gettime + localtime_r (faz 2'de
     * doldurulacak; backend'ler kendi kopyalarını silmek üzere buna geçer). */
    time_t      ts;
    struct tm   tm;

    /* FE_PROGRESS alanları (diğer tiplerde kullanılmaz) */
    const char *filename;   /* sanitize edilmiş; senkron */
    uint64_t    done;
    uint64_t    total;
    bool        is_upload;
};

/* Backend arayüzü — her backend tek emit fonksiyonu sağlar */
struct frontend_ops {
    const char *name;
    void (*emit)(void *ctx, const struct fe_event *ev);
};

/* Aktif backend'i set eder (son çağran kazanır). ctx backend'in kendi
 * durumudur (g_theme, g_last_label gibi — faz 4/5'te taşınacak). */
void frontend_register(const struct frontend_ops *ops, void *ctx);

/* Tek dispatch noktası — senkron, kopyasız. Backend kayıtlı değilse
 * no-op (fuzz hedefleri registration yapmaz, stderr davranışı korunur). */
void frontend_emit(const struct fe_event *ev);

#endif /* PARANOID_FRONTEND_H */
