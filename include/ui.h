/* SPDX-License-Identifier: GPL-3.0-or-later
 * ui.h — noxtor-cli terminal UI katmanı
 *
 * Tüm kullanıcı arayüzü çıktıları bu modül üzerinden geçer.
 * Tema değiştirmek için tek yapılması gereken nox_theme struct'ını
 * güncellemek — tüm çıktılar otomatik olarak yeni paleti kullanır.
 */

#ifndef PARANOID_UI_H
#define PARANOID_UI_H

#include "common.h"
#include <stdarg.h>

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

/* Gelen mesaj: save → print → restore */
void ui_print_incoming(struct app_state *state, const char *msg);

/* Giden mesaj: üst satırı sil → yeniden yaz */
void ui_print_outgoing(struct app_state *state, const char *msg);

/* ── Bildirimler ─────────────────────────────────────────── */

/* Sistem bilgi mesajı — save/restore ile güvenli */
void ui_print_system(struct app_state *state, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Hata mesajı — save/restore ile güvenli */
void ui_print_error(struct app_state *state, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ── Prompt ──────────────────────────────────────────────── */

/* Bağlam duyarlı prompt bas (bağlantı durumu + onion kısaltma) */
void ui_print_prompt(struct app_state *state);

/* ── Dosya Transferi ─────────────────────────────────────── */

/* In-place progress bar (aynı satırı günceller) */
void ui_print_progress(struct app_state *state,
                       const char *filename,
                       uint64_t done, uint64_t total,
                       bool is_upload);

/* ── stdin Buffer Save/Restore ───────────────────────────── */

/* Kullanıcının yarım kalan girdisini kaydet ve satırı temizle */
void ui_save_input(struct app_state *state);

/* Prompt + yarım girdiyi geri yaz */
void ui_restore_input(struct app_state *state);

#endif /* PARANOID_UI_H */
