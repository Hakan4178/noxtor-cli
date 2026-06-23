/* SPDX-License-Identifier: GPL-3.0-or-later
 * tui.h — noxtor-cli termbox2 TUI katmanı
 *
 * HAVE_TERMBOX tanımlıysa derlenir.
 * Tanımlı değilse tüm fonksiyonlar no-op inline olarak kalır.
 *
 * 3-Panel Düzen:
 *   ┌──────────┬──────────────────────────────┐
 *   │ SIDEBAR  │         CHAT                  │
 *   │          │                              │
 *   │          ├──────────────────────────────┤
 *   │          │ INPUT                         │
 *   └──────────┴──────────────────────────────┘
 */

#ifndef PARANOID_TUI_H
#define PARANOID_TUI_H

#include "common.h"

/* Forward declaration */
struct app_state;

#ifdef HAVE_TERMBOX

/* ── Sabitler ─────────────────────────────── */
#define TUI_SIDEBAR_WIDTH   22
#define TUI_INPUT_HEIGHT     3
#define TUI_CHAT_SCROLLBACK 512

#define TUI_FOCUS_INPUT     0
#define TUI_FOCUS_SIDEBAR   1

#define TUI_MAX_CONTACTS    64

struct tui_contact {
    char name[NOX_CONTACT_NAME_LEN + 1];
    char onion[NOX_ONION_LEN + 1];
    bool online;
};

/* ── TUI Durumu ───────────────────────────── */
struct tui_state {
    /* Chat scrollback buffer */
    char   *chat_lines[TUI_CHAT_SCROLLBACK];
    unsigned chat_line_colors[TUI_CHAT_SCROLLBACK]; /* 0 = otomatik */
    int     chat_line_count;
    int     chat_scroll_offset;

    /* Input buffer */
    char    input_buf[4096];
    int     input_len;
    int     input_cursor;

    /* Focus and selection */
    int     focus;              /* TUI_FOCUS_INPUT or TUI_FOCUS_SIDEBAR */
    struct tui_contact contacts[TUI_MAX_CONTACTS];
    int     contact_count;
    int     selected_idx;

    /* Boyutlar */
    int     cols;
    int     rows;

    bool    active;
};

/* Extern — main.c'de tanımlanır */
extern struct tui_state g_tui;

static inline bool tui_is_active(void) { return g_tui.active; }

/* ── Yaşam Döngüsü ───────────────────────── */

void tui_init(void);

/* TUI açılış bilgilendirmesi */
void tui_print_welcome(struct app_state *state);

/* termbox2 kapat, terminali geri yükle */
void tui_shutdown(void);

/* Terminal boyutu değiştiğinde yeniden çiz (SIGWINCH) */
void tui_resize(void);

/* ── Çizim ────────────────────────────────── */

/* Sidebar'ı yeniden çiz (peer listesi) */
void tui_draw_sidebar(struct app_state *state);

/* Chat paneline mesaj ekle */
void tui_chat_append(const char *line);

/* Chat paneline belirli renkle mesaj ekle */
void tui_chat_append_colored(const char *line, unsigned fg);

/* Chat panelini yeniden çiz */
void tui_draw_chat(void);

/* Input panelini yeniden çiz */
void tui_draw_input(void);

/* Tüm panelleri yeniden çiz */
void tui_refresh_all(struct app_state *state);

/* ── Girdi İşleme ─────────────────────────── */

/* termbox2 event'ini işle.
 * Return: tamamlanmış satır (Enter'a basıldı) veya NULL */
const char *tui_handle_input(struct app_state *state, int ch);

#else /* !HAVE_TERMBOX */

/* termbox2 yokken tüm fonksiyonlar no-op */
struct tui_state { bool active; };
static inline bool tui_is_active(void) { return false; }
static inline void tui_init(void) {}
static inline void tui_print_welcome(struct app_state *s) { (void)s; }
static inline void tui_shutdown(void) {}
static inline void tui_resize(void) {}
static inline void tui_draw_sidebar(struct app_state *s) { (void)s; }
static inline void tui_chat_append(const char *l) { (void)l; }
static inline void tui_chat_append_colored(const char *l, unsigned c) { (void)l; (void)c; }
static inline void tui_draw_chat(void) {}
static inline void tui_draw_input(void) {}
static inline void tui_refresh_all(struct app_state *s) { (void)s; }
static inline const char *tui_handle_input(struct app_state *s, int ch) { (void)s; (void)ch; return NULL; }

#endif /* HAVE_TERMBOX */

#endif /* PARANOID_TUI_H */
