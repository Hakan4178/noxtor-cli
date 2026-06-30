/* SPDX-License-Identifier: GPL-3.0-or-later
 * tui.c — noxtor-cli termbox2 TUI implementasyonu
 *
 * Yalnızca HAVE_TERMBOX tanımlıysa derlenir (Makefile: TUI=1).
 *
 * 3-Panel Düzen:
 *   Sidebar (22 karakter) | Chat + Input
 *
 * Renk paleti (truecolor 0xRRGGBB):
 *   [Sen]     → yeşil    0x26A269
 *   [Peer]    → mor      0x853C99
 *   Sistem    → amber    0xC9970F
 *   [!] Hata  → kırmızı  0xD21826
 *   Sidebar   → teal     0x226979
 *   Zaman     → koyu mavi 0x1F4175
 */

#ifdef HAVE_TERMBOX

#define TB_IMPL
#include "tui.h"
#include "common.h"
#include "types.h"
#include "database.h"
#include "ui.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "termbox2.h"
#pragma GCC diagnostic pop

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

/* ── Global TUI State ─────────────────────── */
struct tui_state g_tui;

/* ── Truecolor Renkler (0xRRGGBB) ─────────── */
#define TC_SELF       0x26A269
#define TC_PEER       0x853C99
#define TC_SYSTEM     0xC9970F
#define TC_ERROR      0xD21826
#define TC_SIDEBAR    0x226979
#define TC_TIMESTAMP  0x1F4175
#define TC_ACTIVE_BG  0x226979

/* ── Yardımcılar ──────────────────────────── */
static void tui_load_contacts(struct app_state *state);

/* Unicode codepoint'i UTF-8 byte dizisine çevir.
 * buf: en az 5 byte (4 data + null). Return: byte sayısı (1-4). */
static int utf8_encode(uint32_t cp, char *buf) {
    if (cp < 0x80) {
        buf[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        buf[0] = (char)(0xC0 | (cp >> 6));
        buf[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        buf[0] = (char)(0xE0 | (cp >> 12));
        buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else {
        buf[0] = (char)(0xF0 | (cp >> 18));
        buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
}

/* input_buf'da byte offset'indeki character'in byte sayısını bul (1-4) */
static int utf8_char_bytes(const char *buf, int byte_pos, int buf_len) {
    if (byte_pos >= buf_len) return 0;
    unsigned char b = (unsigned char)buf[byte_pos];
    int len;
    if (b < 0x80)          len = 1;
    else if (b < 0xE0)     len = 2;
    else if (b < 0xF0)     len = 3;
    else                    len = 4;
    if (byte_pos + len > buf_len) return 1;
    return len;
}

/* Byte offset'inden önceki karakterin byte sayısını bul (backspace için) */
static int utf8_prev_char_bytes(const char *buf, int byte_pos) {
    if (byte_pos <= 0) return 0;
    int i = byte_pos - 1;
    while (i > 0 && ((unsigned char)buf[i] & 0xC0) == 0x80)
        i--;
    return byte_pos - i;
}

/* Byte offset'inden itibaren ekran genişliğini hesapla (cursor için) */
#include <wchar.h>
static int input_display_width_up_to(int byte_pos) {
    mbstate_t ps;
    memset(&ps, 0, sizeof(ps));
    int width = 0;
    const char *p = g_tui.input_buf;
    int remaining = byte_pos;
    while (remaining > 0) {
        wchar_t wc;
        size_t consumed = mbrtowc(&wc, p, (size_t)remaining, &ps);
        if (consumed == 0 || consumed == (size_t)-1 || consumed == (size_t)-2)
            break;
        int w = wcwidth(wc);
        width += (w > 0) ? w : 1;
        p += consumed;
        remaining -= (int)consumed;
    }
    return width;
}

/* Düz çizgi */
static void hline(int x, int y, int len, uintattr_t fg) {
    for (int i = 0; i < len; i++)
        tb_set_cell(x + i, y, 0x2500, fg, 0);  /* ─ */
}

/* Kutu çerçeve çiz */
static void draw_box(int x, int y, int w, int h, uintattr_t fg) {
    if (w < 2 || h < 2) return;

    /* Köşeler */
    tb_set_cell(x, y, 0x250C, fg, 0);              /* ┌ */
    tb_set_cell(x + w - 1, y, 0x2510, fg, 0);      /* ┐ */
    tb_set_cell(x, y + h - 1, 0x2514, fg, 0);      /* └ */
    tb_set_cell(x + w - 1, y + h - 1, 0x2518, fg, 0); /* ┘ */

    /* Yatay kenarlar */
    for (int i = 1; i < w - 1; i++) {
        tb_set_cell(x + i, y, 0x2500, fg, 0);          /* ─ */
        tb_set_cell(x + i, y + h - 1, 0x2500, fg, 0);  /* ─ */
    }

    /* Dikey kenarlar */
    for (int i = 1; i < h - 1; i++) {
        tb_set_cell(x, y + i, 0x2502, fg, 0);              /* │ */
        tb_set_cell(x + w - 1, y + i, 0x2502, fg, 0);      /* │ */
    }
}

/* Başlık yazısı (kutu içinde) */
static void draw_title(int x, int y, const char *title, uintattr_t fg) {
    tb_print(x + 2, y, fg, 0, title);
}

/* ================================================================
 * YAŞAM DÖNGÜSÜ
 * ================================================================ */

void tui_init(void)
{
    setlocale(LC_ALL, "");

    memset(&g_tui, 0, sizeof(g_tui));
    for (int i = 0; i < TUI_CHAT_SCROLLBACK; i++)
        g_tui.chat_lines[i] = NULL;

    int rc = tb_init();
    if (rc != TB_OK) {
        fprintf(stderr, "tui: termbox init başarısız: %s\n", tb_strerror(rc));
        return;
    }

    tb_set_output_mode(TB_OUTPUT_TRUECOLOR);
    tb_set_cursor(-1, -1);  /* İmleci gizle */

    g_tui.cols = tb_width();
    g_tui.rows = tb_height();
    g_tui.active = true;
    g_tui.focus = TUI_FOCUS_INPUT;
    g_tui.selected_idx = 0;

    tui_draw_chat();
    tui_draw_input();
    tb_present();
}

void tui_print_welcome(struct app_state *state)
{
    if (!g_tui.active)
        return;

    tui_load_contacts(state);

    ui_print_system(state, "╔══════════════════════════════════════╗");
    ui_print_system(state, "║       Noxtor — Anonymous Messenger   ║");
    ui_print_system(state, "╚══════════════════════════════════════╝");
    ui_print_system(state, "");
    ui_print_system(state, " Komutlar:");
    ui_print_system(state, "   /addr               — .onion adresini göster");
    ui_print_system(state, "   /connect <onion>    — peer'a bağlan");
    ui_print_system(state, "   /add <onion> <isim> — rehbere kişi ekle");
    ui_print_system(state, "   /msg <onion> <msj>  — kuyruklu mesaj gönder");
    ui_print_system(state, "   /file <dosya_yolu>  — dosya gönder");
    ui_print_system(state, "   /list               — rehberi listele");
    ui_print_system(state, "   /switch <isim>      — aktif sohbeti değiştir");
    ui_print_system(state, "   /disconnect         — bağlantıyı kes");
    ui_print_system(state, "   Ctrl+P              — çıkış");
    ui_print_system(state, "");
    ui_print_system(state, " Gezinti: Tab=panel geçişi  ↑↓=seçim  PgUp/PgDn=kaydır");

    if (g_tui.contact_count == 0) {
        ui_print_system(state, "");
        ui_print_system(state, " [!] Rehberinizde kayıtlı akran yok.");
        ui_print_system(state, "     /add <onion> <isim> ile ilk akranınızı ekleyin.");
    }
}

void tui_shutdown(void)
{
    if (!g_tui.active)
        return;

    g_tui.active = false;

    for (int i = 0; i < TUI_CHAT_SCROLLBACK; i++) {
        free(g_tui.chat_lines[i]);
        g_tui.chat_lines[i] = NULL;
    }

    tb_shutdown();
}

void tui_resize(void)
{
    if (!g_tui.active)
        return;

    g_tui.cols = tb_width();
    g_tui.rows = tb_height();
    tb_clear();
}

/* ================================================================
 * SIDEBAR ÇİZİMİ
 * ================================================================ */
static void contact_visitor(const char *onion, const char *name,
                            const uint8_t noise_key[NOX_KEY_LEN],
                            void *ctx)
{
    (void)noise_key;
    struct app_state *state = (struct app_state *)ctx;
    if (g_tui.contact_count < TUI_MAX_CONTACTS) {
        struct tui_contact *tc = &g_tui.contacts[g_tui.contact_count];
        snprintf(tc->name, sizeof(tc->name), "%s", name);
        snprintf(tc->onion, sizeof(tc->onion), "%s", onion);
        tc->online = false;
        for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
            if (state->peers[i].fd >= 0 &&
                strcmp(state->peers[i].peer_onion, onion) == 0) {
                tc->online = true;
                break;
            }
        }
        g_tui.contact_count++;
    }
}

static void tui_load_contacts(struct app_state *state)
{
    g_tui.contact_count = 0;
    if (!state->ghost_mode) {
        db_list_contacts(contact_visitor, state);
    }

    struct peer_session *ps_load = ACTIVE_PEER(state);
    if (ps_load && state->active_peer_onion[0] != '\0') {
        bool found = false;
        for (int i = 0; i < g_tui.contact_count; i++) {
            if (strcmp(g_tui.contacts[i].onion, state->active_peer_onion) == 0) {
                g_tui.contacts[i].online = true;
                found = true;
                break;
            }
        }
        if (!found && g_tui.contact_count < TUI_MAX_CONTACTS) {
            struct tui_contact *tc = &g_tui.contacts[g_tui.contact_count];
            snprintf(tc->name, sizeof(tc->name), "%.12s", state->active_peer_onion);
            snprintf(tc->onion, sizeof(tc->onion), "%s", state->active_peer_onion);
            tc->online = true;
            g_tui.contact_count++;
        }
    }
}

void tui_draw_sidebar(struct app_state *state)
{
    if (!g_tui.active)
        return;

    tui_load_contacts(state);

    int sidebar_w = TUI_SIDEBAR_WIDTH;
    int chat_w = g_tui.cols - sidebar_w;
    if (chat_w < 20) chat_w = 20;

    /* Border */
    draw_box(0, 0, sidebar_w, g_tui.rows, TC_SIDEBAR);
    draw_title(0, 0, " Rehber ", TC_SIDEBAR);

    /* İçerik bölgesi: x=1..sidebar_w-2, y=1..rows-2 */
    int content_w = sidebar_w - 2;
    int content_h = g_tui.rows - 2;
    int name_w = content_w - 2;  /* ● için yer bırak */
    int row = 0;

    for (int i = 0; i < g_tui.contact_count && row < content_h; i++) {
        struct tui_contact *tc = &g_tui.contacts[i];

        char display_name[128];
        if (tc->name[0] != '\0') {
            snprintf(display_name, sizeof(display_name), "%s", tc->name);
        } else {
            size_t olen = strlen(tc->onion);
            if (olen >= 12) {
                snprintf(display_name, sizeof(display_name), "%.4s..%.4s",
                         tc->onion, tc->onion + olen - 10);
            } else {
                snprintf(display_name, sizeof(display_name), "%s", tc->onion);
            }
        }

        bool is_selected = (g_tui.focus == TUI_FOCUS_SIDEBAR && g_tui.selected_idx == i);
        struct peer_session *ps_active = ACTIVE_PEER(state);
        bool is_active_chat = (ps_active && strcmp(state->active_peer_onion, tc->onion) == 0);

        uintattr_t fg = TC_SIDEBAR;
        uintattr_t bg = 0;
        if (is_selected) {
            fg = 0xFFFFFF;
            bg = TC_ACTIVE_BG;
        } else if (is_active_chat) {
            fg = TC_SIDEBAR | TB_BOLD;
        }

        /* İsim yaz — tb_print UTF-8 destekler */
        tb_printf(1, 1 + row, fg, bg, "%-*.*s", name_w, name_w, display_name);

        /* Online göstergesi */
        if (tc->online) {
            tb_set_cell(1 + name_w, 1 + row, 0x25CF, TC_SELF, 0);  /* ● */
        }

        row++;
    }

    /* Ayırıcı çizgi */
    if (row > 0 && row < content_h) {
        hline(1, 1 + row, content_w, TC_SIDEBAR);
        row++;
    }

    /* "+ /connect" seçeneği */
    if (row < content_h) {
        uintattr_t fg = TC_SIDEBAR;
        uintattr_t bg = 0;
        bool is_plus_selected = (g_tui.focus == TUI_FOCUS_SIDEBAR &&
                                 g_tui.selected_idx == g_tui.contact_count);
        if (is_plus_selected) {
            fg = 0xFFFFFF;
            bg = TC_ACTIVE_BG;
        }
        const char *label = "+ /connect";
        tb_printf(1, 1 + row, fg, bg, "%-*s", content_w, label);
    }
}

/* ================================================================
 * CHAT PANELİ
 * ================================================================ */
void tui_chat_append(const char *line)
{
    tui_chat_append_colored(line, 0);
}

void tui_chat_append_colored(const char *line, uintattr_t fg)
{
    if (!g_tui.active || !line || !*line)
        return;

    int sidebar_w = TUI_SIDEBAR_WIDTH;
    int content_w = g_tui.cols - sidebar_w - 2;
    if (content_w < 10) content_w = 10;

    /* Prefix uzunluğunu hesapla */
    size_t prefix_len = 0;
    const char *msg_start = NULL;

    const char *last_bracket = NULL;
    const char *search = line;
    while ((search = strstr(search, "] ")) != NULL) {
        last_bracket = search;
        search += 2;
    }

    if (last_bracket) {
        msg_start = last_bracket + 2;
        prefix_len = (size_t)(msg_start - line);
    }

    if (prefix_len == 0 || !msg_start) {
        prefix_len = strlen(line);
        msg_start = line;
    }

    size_t msg_len = strlen(msg_start);
    size_t wrap_width = (content_w > 1) ? (size_t)(content_w - 1) : (size_t)content_w;
    if (prefix_len >= wrap_width) wrap_width = prefix_len + 1;

    /* Tek satır */
    if (msg_len == 0 || prefix_len + msg_len <= wrap_width) {
        if (g_tui.chat_line_count >= TUI_CHAT_SCROLLBACK) {
            free(g_tui.chat_lines[0]);
            memmove(&g_tui.chat_lines[0], &g_tui.chat_lines[1],
                    (size_t)(TUI_CHAT_SCROLLBACK - 1) * sizeof(char *));
            memmove(&g_tui.chat_line_colors[0], &g_tui.chat_line_colors[1],
                    (size_t)(TUI_CHAT_SCROLLBACK - 1) * sizeof(g_tui.chat_line_colors[0]));
            g_tui.chat_line_count = TUI_CHAT_SCROLLBACK - 1;
        }
        g_tui.chat_lines[g_tui.chat_line_count] = strdup(line);
        if (!g_tui.chat_lines[g_tui.chat_line_count]) return;
        g_tui.chat_line_colors[g_tui.chat_line_count] = fg;
        g_tui.chat_line_count++;
        return;
    }

    /* Uzun mesaj — word wrap */
    char indent[64];
    size_t indent_len = prefix_len;
    if (indent_len > sizeof(indent) - 1) indent_len = sizeof(indent) - 1;
    memset(indent, ' ', indent_len);
    indent[indent_len] = '\0';

    size_t chunk = (wrap_width > prefix_len) ? (wrap_width - prefix_len) : 1;
    const char *p = msg_start;
    size_t remaining = msg_len;
    int first = 1;

    while (remaining > 0) {
        size_t take = (remaining > chunk) ? chunk : remaining;

        if (take < remaining) {
            size_t ws = take;
            while (ws > 0 && p[ws - 1] != ' ' && p[ws - 1] != '\n')
                ws--;
            if (ws > 0) take = ws;
        }

        if (take == 0) break;

        char row[1024];
        if (first) {
            snprintf(row, sizeof(row), "%.*s%.*s",
                     (int)prefix_len, line, (int)take, p);
            first = 0;
        } else {
            snprintf(row, sizeof(row), "%s%.*s", indent, (int)take, p);
        }

        if (row[0]) {
            if (g_tui.chat_line_count >= TUI_CHAT_SCROLLBACK) {
                free(g_tui.chat_lines[0]);
                memmove(&g_tui.chat_lines[0], &g_tui.chat_lines[1],
                        (size_t)(TUI_CHAT_SCROLLBACK - 1) * sizeof(char *));
                memmove(&g_tui.chat_line_colors[0], &g_tui.chat_line_colors[1],
                        (size_t)(TUI_CHAT_SCROLLBACK - 1) * sizeof(g_tui.chat_line_colors[0]));
                g_tui.chat_line_count = TUI_CHAT_SCROLLBACK - 1;
            }
            g_tui.chat_lines[g_tui.chat_line_count] = strdup(row);
            g_tui.chat_line_colors[g_tui.chat_line_count] = fg;
            g_tui.chat_line_count++;
        }

        if (take < remaining && p[take] == ' ')
            take++;
        p += take;
        remaining -= take;
        if (remaining == 0 || take == 0) break;
    }

    g_tui.chat_scroll_offset = 0;
}

void tui_draw_chat(void)
{
    if (!g_tui.active)
        return;

    int sidebar_w = TUI_SIDEBAR_WIDTH;
    int chat_w = g_tui.cols - sidebar_w;
    int chat_h = g_tui.rows - TUI_INPUT_HEIGHT;
    if (chat_w < 20) chat_w = 20;
    if (chat_h < 5) chat_h = 5;

    /* Border */
    draw_box(sidebar_w, 0, chat_w, chat_h, TC_SIDEBAR);
    draw_title(sidebar_w, 0, " Sohbet ", TC_SIDEBAR);

    /* İçerik */
    int content_w = chat_w - 2;
    int content_h = chat_h - 2;

    int max_scroll = g_tui.chat_line_count - content_h;
    if (max_scroll < 0) max_scroll = 0;
    if (g_tui.chat_scroll_offset > max_scroll)
        g_tui.chat_scroll_offset = max_scroll;
    if (g_tui.chat_scroll_offset < 0)
        g_tui.chat_scroll_offset = 0;

    int start = g_tui.chat_line_count - content_h - g_tui.chat_scroll_offset;
    if (start < 0) start = 0;
    int end = start + content_h;
    if (end > g_tui.chat_line_count) end = g_tui.chat_line_count;

    for (int i = start; i < end; i++) {
        int row = i - start;
        const char *line = g_tui.chat_lines[i];
        if (!line) continue;

        uintattr_t fg = (uintattr_t)g_tui.chat_line_colors[i];
        if (fg == 0) {
            fg = TC_SYSTEM;
            if (strstr(line, "[Sen]"))         fg = TC_SELF;
            else if (strstr(line, "[Peer]"))   fg = TC_PEER;
            else if (strstr(line, "[!]"))      fg = TC_ERROR | TB_BOLD;
        }

        /* tb_print UTF-8 dizilerini otomatik çözer */
        tb_printf(sidebar_w + 1, 1 + row, fg, 0, "%.*s", content_w, line);
    }
}

/* ================================================================
 * INPUT PANELİ
 * ================================================================ */
void tui_draw_input(void)
{
    if (!g_tui.active)
        return;

    int sidebar_w = TUI_SIDEBAR_WIDTH;
    int chat_w = g_tui.cols - sidebar_w;
    int chat_h = g_tui.rows - TUI_INPUT_HEIGHT;
    if (chat_w < 20) chat_w = 20;

    /* Border */
    draw_box(sidebar_w, chat_h, chat_w, TUI_INPUT_HEIGHT, TC_SIDEBAR);

    /* Prompt */
    int px = sidebar_w + 1;
    int py = chat_h + 1;
    tb_set_cell(px, py, '>', TC_SIDEBAR, 0);
    tb_set_cell(px + 1, py, ' ', TC_SIDEBAR, 0);

    /* Kullanıcı girdisi — tb_printf UTF-8 destekler */
    int input_x = px + 2;
    int max_input_w = chat_w - 4;
    if (g_tui.input_len > 0) {
        tb_printf(input_x, py, 0xFFFFFF, 0, "%.*s", max_input_w, g_tui.input_buf);
    }

    /* İmleci göster — Unicode display width ile */
    if (g_tui.focus == TUI_FOCUS_INPUT) {
        int cursor_col = input_display_width_up_to(g_tui.input_cursor);
        tb_set_cursor(input_x + cursor_col, py);
    } else {
        tb_hide_cursor();
    }
}

/* ================================================================
 * TOPLU YENİLEME
 * ================================================================ */
void tui_refresh_all(struct app_state *state)
{
    if (!g_tui.active)
        return;

    g_tui.cols = tb_width();
    g_tui.rows = tb_height();
    tb_clear();

    tui_draw_sidebar(state);
    tui_draw_chat();
    tui_draw_input();
    tb_present();
}

/* ================================================================
 * GİRDİ İŞLEME
 * ================================================================ */
const char *tui_handle_input(struct app_state *state, int ch)
{
    if (!g_tui.active)
        return NULL;

    switch (ch) {
    case TB_KEY_CTRL_C:
    case TB_KEY_CTRL_P:
        g_shutdown = 1;
        break;

    case '\t':
    case TB_KEY_BACK_TAB:
        g_tui.focus = (g_tui.focus == TUI_FOCUS_INPUT) ? TUI_FOCUS_SIDEBAR : TUI_FOCUS_INPUT;
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            tb_set_cursor(g_tui.cols - 4, g_tui.rows - 2);
        } else {
            tb_hide_cursor();
        }
        break;

    case TB_KEY_PGUP:
        g_tui.chat_scroll_offset += 10;
        tui_draw_chat();
        break;

    case TB_KEY_PGDN:
        g_tui.chat_scroll_offset -= 10;
        if (g_tui.chat_scroll_offset < 0) g_tui.chat_scroll_offset = 0;
        tui_draw_chat();
        break;

    case TB_KEY_ARROW_UP:
        if (g_tui.focus == TUI_FOCUS_SIDEBAR) {
            if (g_tui.selected_idx > 0) {
                g_tui.selected_idx--;
            } else {
                g_tui.selected_idx = g_tui.contact_count;
            }
        } else {
            g_tui.chat_scroll_offset += 1;
            tui_draw_chat();
        }
        break;

    case TB_KEY_ARROW_DOWN:
        if (g_tui.focus == TUI_FOCUS_SIDEBAR) {
            if (g_tui.selected_idx < g_tui.contact_count) {
                g_tui.selected_idx++;
            } else {
                g_tui.selected_idx = 0;
            }
        } else {
            g_tui.chat_scroll_offset -= 1;
            if (g_tui.chat_scroll_offset < 0) g_tui.chat_scroll_offset = 0;
            tui_draw_chat();
        }
        break;

    case TB_KEY_ARROW_LEFT:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor > 0) {
                g_tui.input_cursor--;
            } else {
                g_tui.focus = TUI_FOCUS_SIDEBAR;
                tb_hide_cursor();
            }
        }
        break;

    case TB_KEY_ARROW_RIGHT:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor < g_tui.input_len)
                g_tui.input_cursor++;
        } else {
            g_tui.focus = TUI_FOCUS_INPUT;
            tb_set_cursor(g_tui.cols - 4, g_tui.rows - 2);
        }
        break;

    case '\n':
    case TB_KEY_ENTER:
        if (g_tui.focus == TUI_FOCUS_SIDEBAR) {
            if (g_tui.selected_idx < g_tui.contact_count) {
                /* Eski chat satırlarını temizle */
                for (int i = 0; i < g_tui.chat_line_count; i++) {
                    free(g_tui.chat_lines[i]);
                    g_tui.chat_lines[i] = NULL;
                }
                g_tui.chat_line_count = 0;
                g_tui.chat_scroll_offset = 0;

                struct tui_contact *tc = &g_tui.contacts[g_tui.selected_idx];
                snprintf(g_tui.input_buf, sizeof(g_tui.input_buf), "/connect %s", tc->onion);
                g_tui.input_len = 0;
                g_tui.input_cursor = 0;
                g_tui.focus = TUI_FOCUS_INPUT;
                tb_set_cursor(g_tui.cols - 4, g_tui.rows - 2);
                return g_tui.input_buf;
            } else {
                snprintf(g_tui.input_buf, sizeof(g_tui.input_buf), "/connect ");
                g_tui.input_len = (int)strlen(g_tui.input_buf);
                g_tui.input_cursor = g_tui.input_len;
                g_tui.focus = TUI_FOCUS_INPUT;
                tb_set_cursor(g_tui.cols - 4, g_tui.rows - 2);
                tui_draw_input();
            }
        } else {
            if (g_tui.input_len == 0)
                return NULL;
            g_tui.input_buf[g_tui.input_len] = '\0';
            g_tui.input_len = 0;
            g_tui.input_cursor = 0;
            g_tui.chat_scroll_offset = 0;
            return g_tui.input_buf;
        }
        break;

    case TB_KEY_BACKSPACE:
    case 127:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor > 0 && g_tui.input_len > 0) {
                int del = utf8_prev_char_bytes(g_tui.input_buf, g_tui.input_cursor);
                memmove(&g_tui.input_buf[g_tui.input_cursor - del],
                        &g_tui.input_buf[g_tui.input_cursor],
                        (size_t)(g_tui.input_len - g_tui.input_cursor));
                g_tui.input_len -= del;
                g_tui.input_cursor -= del;
            }
        }
        break;

    case TB_KEY_DELETE:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor < g_tui.input_len) {
                int del = utf8_char_bytes(g_tui.input_buf,
                                          g_tui.input_cursor,
                                          g_tui.input_len);
                memmove(&g_tui.input_buf[g_tui.input_cursor],
                        &g_tui.input_buf[g_tui.input_cursor + del],
                        (size_t)(g_tui.input_len - g_tui.input_cursor - del));
                g_tui.input_len -= del;
            }
        }
        break;

    case TB_KEY_HOME:
        if (g_tui.focus == TUI_FOCUS_INPUT)
            g_tui.input_cursor = 0;
        break;

    case TB_KEY_END:
        if (g_tui.focus == TUI_FOCUS_INPUT)
            g_tui.input_cursor = g_tui.input_len;
        break;

    default:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            uint32_t c = 0;
            if (ch >= 32 && ch < 127)
                c = (uint32_t)ch;
            else if (ch > 127 && ch < 0x110000)
                c = (uint32_t)ch;
            else if (ch == 0)
                return NULL;

            if (c == 0) return NULL;

            char utf8[5];
            int nbytes = utf8_encode(c, utf8);
            if (g_tui.input_len + nbytes <= (int)sizeof(g_tui.input_buf) - 1) {
                memmove(&g_tui.input_buf[g_tui.input_cursor + nbytes],
                        &g_tui.input_buf[g_tui.input_cursor],
                        (size_t)(g_tui.input_len - g_tui.input_cursor));
                memcpy(&g_tui.input_buf[g_tui.input_cursor], utf8, (size_t)nbytes);
                g_tui.input_len += nbytes;
                g_tui.input_cursor += nbytes;
            }
        }
        break;
    }

    tui_draw_input();
    tui_draw_sidebar(state);
    tb_present();
    return NULL;
}

#endif /* HAVE_TERMBOX */

/* ISO C forbids an empty translation unit — pedantic guard */
typedef int tui_empty_tu_guard;
