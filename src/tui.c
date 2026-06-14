/* SPDX-License-Identifier: GPL-3.0-or-later
 * tui.c — noxtor-cli ncurses TUI implementasyonu
 *
 * Yalnızca HAVE_NCURSES tanımlıysa derlenir (Makefile: TUI=1).
 *
 * 3-Panel Düzen:
 *   Sidebar (22 karakter) | Chat + Input
 *
 * Renk paleti nox_theme ile uyumlu:
 *   PAIR 1: [Sen]     → yeşil    (38, 162, 105)
 *   PAIR 2: [Peer]    → mor      (133, 60, 153)
 *   PAIR 3: Sistem    → amber    (202, 151, 15)
 *   PAIR 4: Hata      → kırmızı  (210, 24, 38)
 *   PAIR 5: Sidebar   → teal     (34, 105, 121)
 *   PAIR 6: Zaman     → koyu mavi(31, 65, 117)
 *   PAIR 7: Aktif peer→ beyaz/bg
 */

#ifdef HAVE_NCURSES

#include "tui.h"
#include "common.h"
#include "types.h"
#include "database.h"
#include "ui.h"

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Global TUI State ─────────────────────── */
struct tui_state g_tui;

/* ── ncurses Renk Çiftleri ────────────────── */
enum {
    CLR_SELF = 1,
    CLR_PEER,
    CLR_SYSTEM,
    CLR_ERROR,
    CLR_SIDEBAR,
    CLR_TIMESTAMP,
    CLR_ACTIVE_PEER,
    CLR_BORDER,
};

/* ── Yardımcılar ──────────────────────────── */
static int g_rows, g_cols;
static void tui_load_contacts(struct app_state *state);

static void get_dimensions(void)
{
    getmaxyx(stdscr, g_rows, g_cols);
}

/* Renkleri başlat — true color destekleniyorsa extended, yoksa basic */
static void init_colors(void)
{
    start_color();
    use_default_colors();

    if (can_change_color() && COLORS >= 256) {
        /* Tema renklerini custom tanımla (RGB 0-1000 scale) */
        init_color(10, 149, 635, 412);   /* yeşil  (38,162,105) */
        init_color(11, 522, 235, 600);   /* mor    (133,60,153) */
        init_color(12, 792, 592, 59);    /* amber  (202,151,15) */
        init_color(13, 824, 94, 149);    /* kırmızı(210,24,38)  */
        init_color(14, 133, 412, 475);   /* teal   (34,105,121) */
        init_color(15, 122, 255, 459);   /* koyu mavi(31,65,117)*/

        init_pair(CLR_SELF,        10, -1);
        init_pair(CLR_PEER,        11, -1);
        init_pair(CLR_SYSTEM,      12, -1);
        init_pair(CLR_ERROR,       13, -1);
        init_pair(CLR_SIDEBAR,     14, -1);
        init_pair(CLR_TIMESTAMP,   15, -1);
        init_pair(CLR_ACTIVE_PEER, COLOR_BLACK, 14);
        init_pair(CLR_BORDER,      14, -1);
    } else {
        /* Fallback: temel 8 renk */
        init_pair(CLR_SELF,        COLOR_GREEN,   -1);
        init_pair(CLR_PEER,        COLOR_MAGENTA, -1);
        init_pair(CLR_SYSTEM,      COLOR_YELLOW,  -1);
        init_pair(CLR_ERROR,       COLOR_RED,     -1);
        init_pair(CLR_SIDEBAR,     COLOR_CYAN,    -1);
        init_pair(CLR_TIMESTAMP,   COLOR_BLUE,    -1);
        init_pair(CLR_ACTIVE_PEER, COLOR_BLACK,   COLOR_CYAN);
        init_pair(CLR_BORDER,      COLOR_CYAN,    -1);
    }
}

/* Alt pencere boyutlarını hesapla ve oluştur */
static void create_windows(void)
{
    get_dimensions();

    int sidebar_w = TUI_SIDEBAR_WIDTH;
    int chat_w    = g_cols - sidebar_w;
    int chat_h    = g_rows - TUI_INPUT_HEIGHT;
    int input_h   = TUI_INPUT_HEIGHT;

    /* Minimum boyut koruması */
    if (chat_w < 20) chat_w = 20;
    if (chat_h < 5)  chat_h = 5;

    /* Border pencereler (çerçeve çizimi için) */
    g_tui.sidebar_border = newwin(g_rows, sidebar_w, 0, 0);
    g_tui.chat_border    = newwin(chat_h, chat_w, 0, sidebar_w);
    g_tui.input_border   = newwin(input_h, chat_w, chat_h, sidebar_w);

    /* İç pencereler (içerik yazımı için — border'ın 1 px içinde) */
    g_tui.sidebar_win = derwin(g_tui.sidebar_border, g_rows - 2, sidebar_w - 2, 1, 1);
    g_tui.chat_win    = derwin(g_tui.chat_border, chat_h - 2, chat_w - 2, 1, 1);
    g_tui.input_win   = derwin(g_tui.input_border, input_h - 2, chat_w - 2, 1, 1);

    /* Scroll aktif */
    scrollok(g_tui.chat_win, TRUE);

    /* Renk ve border ayarları */
    wattron(g_tui.sidebar_border, COLOR_PAIR(CLR_BORDER));
    box(g_tui.sidebar_border, 0, 0);
    mvwprintw(g_tui.sidebar_border, 0, 2, " Rehber ");
    wattroff(g_tui.sidebar_border, COLOR_PAIR(CLR_BORDER));

    wattron(g_tui.chat_border, COLOR_PAIR(CLR_BORDER));
    box(g_tui.chat_border, 0, 0);
    mvwprintw(g_tui.chat_border, 0, 2, " Sohbet ");
    wattroff(g_tui.chat_border, COLOR_PAIR(CLR_BORDER));

    wattron(g_tui.input_border, COLOR_PAIR(CLR_BORDER));
    box(g_tui.input_border, 0, 0);
    wattroff(g_tui.input_border, COLOR_PAIR(CLR_BORDER));
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

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);   /* Non-blocking getch — epoll uyumu */
    curs_set(1);

    init_colors();
    create_windows();

    g_tui.active = true;
    g_tui.focus = TUI_FOCUS_INPUT;
    g_tui.selected_idx = 0;

    tui_draw_chat();
    tui_draw_input();
}

void tui_print_welcome(struct app_state *state)
{
    if (!g_tui.active)
        return;

    tui_load_contacts(state);

    ui_print_system(state, "=== Noxtor TUI'ya Hoş Geldiniz ===");
    ui_print_system(state, "[*] Odak Değiştirme: Tab tuşuna basarak (veya Giriş satırında en soldayken Sol yön tuşuyla) Rehber ve Giriş panelleri arasında geçiş yapabilirsiniz.");
    ui_print_system(state, "[*] Rehber Gezintisi: Yukarı/Aşağı yön tuşlarıyla gezip Enter tuşuna basarak bağlantı başlatabilirsiniz.");
    ui_print_system(state, "[*] Sohbet Kaydırma: Sohbeti yukarı/aşağı kaydırmak için Page Up / Page Down tuşlarını veya Giriş odağındayken Yukarı/Aşağı yön tuşlarını kullanabilirsiniz.");

    if (g_tui.contact_count == 0) {
        ui_print_system(state, "[!] Rehberinizde kayıtlı akran yok. '+ /connect' seçeneğini seçip Enter'a basarak veya '/add <onion> <isim>' yazarak ilk akranınızı ekleyebilirsiniz.");
    }
}

void tui_shutdown(void)
{
    if (!g_tui.active)
        return;

    g_tui.active = false;

    /* Scrollback buffer temizliği */
    for (int i = 0; i < TUI_CHAT_SCROLLBACK; i++) {
        free(g_tui.chat_lines[i]);
        g_tui.chat_lines[i] = NULL;
    }

    /* Alt pencereleri sil (derwin -> delwin önce) */
    if (g_tui.sidebar_win)  delwin(g_tui.sidebar_win);
    if (g_tui.chat_win)     delwin(g_tui.chat_win);
    if (g_tui.input_win)    delwin(g_tui.input_win);
    if (g_tui.sidebar_border) delwin(g_tui.sidebar_border);
    if (g_tui.chat_border)    delwin(g_tui.chat_border);
    if (g_tui.input_border)   delwin(g_tui.input_border);

    endwin();
}

void tui_resize(void)
{
    if (!g_tui.active)
        return;

    /* Eski pencereleri temizle */
    if (g_tui.sidebar_win)  delwin(g_tui.sidebar_win);
    if (g_tui.chat_win)     delwin(g_tui.chat_win);
    if (g_tui.input_win)    delwin(g_tui.input_win);
    if (g_tui.sidebar_border) delwin(g_tui.sidebar_border);
    if (g_tui.chat_border)    delwin(g_tui.chat_border);
    if (g_tui.input_border)   delwin(g_tui.input_border);

    endwin();
    refresh();
    create_windows();
}

/* ================================================================
 * SIDEBAR ÇİZİMİ
 * ================================================================ */
static void contact_visitor(const char *onion, const char *name,
                            const uint8_t noise_key[NOX_KEY_LEN],
                            const char *my_onion,
                            const uint8_t *my_onion_key,
                            size_t onion_key_len,
                            void *ctx)
{
    (void)noise_key; (void)my_onion; (void)my_onion_key; (void)onion_key_len;
    struct app_state *state = (struct app_state *)ctx;
    if (g_tui.contact_count < TUI_MAX_CONTACTS) {
        struct tui_contact *tc = &g_tui.contacts[g_tui.contact_count];
        snprintf(tc->name, sizeof(tc->name), "%s", name);
        snprintf(tc->onion, sizeof(tc->onion), "%s", onion);
        tc->online = (state->peer_fd >= 0 && strcmp(state->active_peer_onion, onion) == 0);
        g_tui.contact_count++;
    }
}

static void tui_load_contacts(struct app_state *state)
{
    g_tui.contact_count = 0;
    if (!state->ghost_mode) {
        db_list_contacts(contact_visitor, state);
    }

    /* Eğer aktif peer listede yoksa geçici olarak ekleyelim */
    if (state->peer_fd >= 0 && state->active_peer_onion[0] != '\0') {
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

/* ================================================================
 * SIDEBAR ÇİZİMİ
 * ================================================================ */
void tui_draw_sidebar(struct app_state *state)
{
    if (!g_tui.active)
        return;

    tui_load_contacts(state);

    werase(g_tui.sidebar_win);

    int max_y, max_x;
    getmaxyx(g_tui.sidebar_win, max_y, max_x);
    (void)max_x;

    int row = 0;

    for (int i = 0; i < g_tui.contact_count; i++) {
        struct tui_contact *tc = &g_tui.contacts[i];
        
        char display_name[128];
        if (tc->name[0] != '\0') {
            snprintf(display_name, sizeof(display_name), "%s", tc->name);
        } else {
            size_t olen = strlen(tc->onion);
            if (olen >= 12) {
                snprintf(display_name, sizeof(display_name), "%.4s..%.4s", tc->onion, tc->onion + olen - 12);
            } else {
                snprintf(display_name, sizeof(display_name), "%s", tc->onion);
            }
        }

        bool is_selected = (g_tui.focus == TUI_FOCUS_SIDEBAR && g_tui.selected_idx == i);
        bool is_active_chat = (state->peer_fd >= 0 && strcmp(state->active_peer_onion, tc->onion) == 0);

        if (is_selected) {
            wattron(g_tui.sidebar_win, COLOR_PAIR(CLR_ACTIVE_PEER) | A_BOLD);
        } else if (is_active_chat) {
            wattron(g_tui.sidebar_win, COLOR_PAIR(CLR_SIDEBAR) | A_BOLD);
        }

        mvwprintw(g_tui.sidebar_win, row, 0, " %-*.*s", TUI_SIDEBAR_WIDTH - 5, TUI_SIDEBAR_WIDTH - 5, display_name);

        if (is_selected) {
            wattroff(g_tui.sidebar_win, COLOR_PAIR(CLR_ACTIVE_PEER) | A_BOLD);
        } else if (is_active_chat) {
            wattroff(g_tui.sidebar_win, COLOR_PAIR(CLR_SIDEBAR) | A_BOLD);
        }

        if (tc->online) {
            wattron(g_tui.sidebar_win, COLOR_PAIR(CLR_SELF));
            wprintw(g_tui.sidebar_win, " ●");
            wattroff(g_tui.sidebar_win, COLOR_PAIR(CLR_SELF));
        } else {
            wprintw(g_tui.sidebar_win, "  ");
        }

        row++;
        if (row >= max_y - 2) break;
    }

    /* Ayırıcı çizgi */
    if (row > 0 && row < max_y - 2) {
        mvwhline(g_tui.sidebar_win, row, 0, ACS_HLINE, TUI_SIDEBAR_WIDTH - 2);
        row++;
    }

    /* "+ /connect" seçeneği */
    if (row < max_y) {
        bool is_plus_selected = (g_tui.focus == TUI_FOCUS_SIDEBAR && g_tui.selected_idx == g_tui.contact_count);
        if (is_plus_selected) {
            wattron(g_tui.sidebar_win, COLOR_PAIR(CLR_ACTIVE_PEER) | A_BOLD);
        } else {
            wattron(g_tui.sidebar_win, COLOR_PAIR(CLR_SIDEBAR));
        }

        mvwprintw(g_tui.sidebar_win, row, 0, " %-*s", TUI_SIDEBAR_WIDTH - 2, "+ /connect");

        if (is_plus_selected) {
            wattroff(g_tui.sidebar_win, COLOR_PAIR(CLR_ACTIVE_PEER) | A_BOLD);
        } else {
            wattroff(g_tui.sidebar_win, COLOR_PAIR(CLR_SIDEBAR));
        }
    }

    /* Border'ı güncelle */
    wattron(g_tui.sidebar_border, COLOR_PAIR(CLR_BORDER));
    box(g_tui.sidebar_border, 0, 0);
    mvwprintw(g_tui.sidebar_border, 0, 2, " Rehber ");
    wattroff(g_tui.sidebar_border, COLOR_PAIR(CLR_BORDER));

    wnoutrefresh(g_tui.sidebar_border);
    wnoutrefresh(g_tui.sidebar_win);
}

/* ================================================================
 * CHAT PANELİ
 * ================================================================ */
void tui_chat_append(const char *line)
{
    if (!g_tui.active || !line)
        return;

    /* Circular buffer — en eski satırı sil */
    if (g_tui.chat_line_count >= TUI_CHAT_SCROLLBACK) {
        free(g_tui.chat_lines[0]);
        memmove(&g_tui.chat_lines[0], &g_tui.chat_lines[1],
                (size_t)(TUI_CHAT_SCROLLBACK - 1) * sizeof(char *));
        g_tui.chat_line_count = TUI_CHAT_SCROLLBACK - 1;
    }

    g_tui.chat_lines[g_tui.chat_line_count] = strdup(line);
    if (!g_tui.chat_lines[g_tui.chat_line_count]) {
        return;
    }
    g_tui.chat_line_count++;
}

void tui_draw_chat(void)
{
    if (!g_tui.active)
        return;

    werase(g_tui.chat_win);

    int max_y, max_x;
    getmaxyx(g_tui.chat_win, max_y, max_x);

    /* chat_scroll_offset'i sınırla (clamp) */
    int max_scroll = g_tui.chat_line_count - max_y;
    if (max_scroll < 0) max_scroll = 0;
    if (g_tui.chat_scroll_offset > max_scroll) {
        g_tui.chat_scroll_offset = max_scroll;
    }
    if (g_tui.chat_scroll_offset < 0) {
        g_tui.chat_scroll_offset = 0;
    }

    int start = g_tui.chat_line_count - max_y - g_tui.chat_scroll_offset;
    if (start < 0) start = 0;
    int end = start + max_y;
    if (end > g_tui.chat_line_count) end = g_tui.chat_line_count;

    for (int i = start; i < end; i++) {
        int row = i - start;
        if (row >= max_y) break;

        const char *line = g_tui.chat_lines[i];
        if (!line) continue;

        /* Renk tespiti: [Sen] veya [Peer] veya sistem */
        if (strstr(line, "[Sen]")) {
            wattron(g_tui.chat_win, COLOR_PAIR(CLR_SELF));
            mvwprintw(g_tui.chat_win, row, 0, "%.*s", max_x, line);
            wattroff(g_tui.chat_win, COLOR_PAIR(CLR_SELF));
        } else if (strstr(line, "[Peer]")) {
            wattron(g_tui.chat_win, COLOR_PAIR(CLR_PEER));
            mvwprintw(g_tui.chat_win, row, 0, "%.*s", max_x, line);
            wattroff(g_tui.chat_win, COLOR_PAIR(CLR_PEER));
        } else if (strstr(line, "[!]")) {
            wattron(g_tui.chat_win, COLOR_PAIR(CLR_ERROR) | A_BOLD);
            mvwprintw(g_tui.chat_win, row, 0, "%.*s", max_x, line);
            wattroff(g_tui.chat_win, COLOR_PAIR(CLR_ERROR) | A_BOLD);
        } else {
            wattron(g_tui.chat_win, COLOR_PAIR(CLR_SYSTEM));
            mvwprintw(g_tui.chat_win, row, 0, "%.*s", max_x, line);
            wattroff(g_tui.chat_win, COLOR_PAIR(CLR_SYSTEM));
        }
    }

    /* Border güncelle */
    wattron(g_tui.chat_border, COLOR_PAIR(CLR_BORDER));
    box(g_tui.chat_border, 0, 0);
    mvwprintw(g_tui.chat_border, 0, 2, " Sohbet ");
    wattroff(g_tui.chat_border, COLOR_PAIR(CLR_BORDER));

    wnoutrefresh(g_tui.chat_border);
    wnoutrefresh(g_tui.chat_win);
}

/* ================================================================
 * INPUT PANELİ
 * ================================================================ */
void tui_draw_input(void)
{
    if (!g_tui.active)
        return;

    werase(g_tui.input_win);

    /* Prompt */
    wattron(g_tui.input_win, COLOR_PAIR(CLR_SIDEBAR));
    mvwprintw(g_tui.input_win, 0, 0, "> ");
    wattroff(g_tui.input_win, COLOR_PAIR(CLR_SIDEBAR));

    /* Kullanıcı girdisi */
    if (g_tui.input_len > 0) {
        wprintw(g_tui.input_win, "%.*s", g_tui.input_len, g_tui.input_buf);
    }

    /* Input border */
    wattron(g_tui.input_border, COLOR_PAIR(CLR_BORDER));
    box(g_tui.input_border, 0, 0);
    wattroff(g_tui.input_border, COLOR_PAIR(CLR_BORDER));

    /* İmleci göster */
    wmove(g_tui.input_win, 0, 2 + g_tui.input_cursor);

    wnoutrefresh(g_tui.input_border);
    wnoutrefresh(g_tui.input_win);
}

/* ================================================================
 * TOPLU YENİLEME
 * ================================================================ */
void tui_refresh_all(struct app_state *state)
{
    if (!g_tui.active)
        return;

    tui_draw_sidebar(state);
    tui_draw_chat();
    tui_draw_input();
    doupdate();
}

/* ================================================================
 * GİRDİ İŞLEME
 *
 * Return: Enter'a basıldığında tamamlanmış satır, yoksa NULL.
 * ================================================================ */
const char *tui_handle_input(struct app_state *state, int ch)
{
    if (!g_tui.active)
        return NULL;

    switch (ch) {
    case '\t':
    case KEY_BTAB:
        /* Odak değiştir */
        g_tui.focus = (g_tui.focus == TUI_FOCUS_INPUT) ? TUI_FOCUS_SIDEBAR : TUI_FOCUS_INPUT;
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            curs_set(1);
        } else {
            curs_set(0);
        }
        break;

    case KEY_PPAGE: /* Page Up */
        g_tui.chat_scroll_offset += 10;
        tui_draw_chat();
        break;

    case KEY_NPAGE: /* Page Down */
        g_tui.chat_scroll_offset -= 10;
        if (g_tui.chat_scroll_offset < 0) g_tui.chat_scroll_offset = 0;
        tui_draw_chat();
        break;

    case KEY_UP:
        if (g_tui.focus == TUI_FOCUS_SIDEBAR) {
            if (g_tui.contact_count >= 0) {
                if (g_tui.selected_idx > 0) {
                    g_tui.selected_idx--;
                } else {
                    g_tui.selected_idx = g_tui.contact_count;
                }
            }
        } else {
            g_tui.chat_scroll_offset += 1;
            tui_draw_chat();
        }
        break;

    case KEY_DOWN:
        if (g_tui.focus == TUI_FOCUS_SIDEBAR) {
            if (g_tui.contact_count >= 0) {
                if (g_tui.selected_idx < g_tui.contact_count) {
                    g_tui.selected_idx++;
                } else {
                    g_tui.selected_idx = 0;
                }
            }
        } else {
            g_tui.chat_scroll_offset -= 1;
            if (g_tui.chat_scroll_offset < 0) g_tui.chat_scroll_offset = 0;
            tui_draw_chat();
        }
        break;

    case KEY_LEFT:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor > 0) {
                g_tui.input_cursor--;
            } else {
                g_tui.focus = TUI_FOCUS_SIDEBAR;
                curs_set(0);
            }
        }
        break;

    case KEY_RIGHT:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor < g_tui.input_len)
                g_tui.input_cursor++;
        } else {
            g_tui.focus = TUI_FOCUS_INPUT;
            curs_set(1);
        }
        break;

    case '\n':
    case KEY_ENTER:
        if (g_tui.focus == TUI_FOCUS_SIDEBAR) {
            if (g_tui.selected_idx < g_tui.contact_count) {
                /* Seçili kişiye bağlan */
                struct tui_contact *tc = &g_tui.contacts[g_tui.selected_idx];
                snprintf(g_tui.input_buf, sizeof(g_tui.input_buf), "/connect %s", tc->onion);
                g_tui.input_len = 0;
                g_tui.input_cursor = 0;
                g_tui.focus = TUI_FOCUS_INPUT;
                curs_set(1);
                g_tui.chat_scroll_offset = 0;
                return g_tui.input_buf;
            } else {
                /* "+ /connect" seçeneği: komutu yaz ve odağı input'a al */
                snprintf(g_tui.input_buf, sizeof(g_tui.input_buf), "/connect ");
                g_tui.input_len = (int)strlen(g_tui.input_buf);
                g_tui.input_cursor = g_tui.input_len;
                g_tui.focus = TUI_FOCUS_INPUT;
                curs_set(1);
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

    case KEY_BACKSPACE:
    case 127:
    case '\b':
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (g_tui.input_cursor > 0 && g_tui.input_len > 0) {
                memmove(&g_tui.input_buf[g_tui.input_cursor - 1],
                        &g_tui.input_buf[g_tui.input_cursor],
                        (size_t)(g_tui.input_len - g_tui.input_cursor));
                g_tui.input_len--;
                g_tui.input_cursor--;
            }
        }
        break;

    case KEY_HOME:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            g_tui.input_cursor = 0;
        }
        break;

    case KEY_END:
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            g_tui.input_cursor = g_tui.input_len;
        }
        break;

    default:
        /* Yazdırılabilir karakter ekle */
        if (g_tui.focus == TUI_FOCUS_INPUT) {
            if (ch >= 32 && ch < 127 && g_tui.input_len < (int)sizeof(g_tui.input_buf) - 2) {
                memmove(&g_tui.input_buf[g_tui.input_cursor + 1],
                        &g_tui.input_buf[g_tui.input_cursor],
                        (size_t)(g_tui.input_len - g_tui.input_cursor));
                g_tui.input_buf[g_tui.input_cursor] = (char)ch;
                g_tui.input_len++;
                g_tui.input_cursor++;
            }
        }
        break;
    }

    tui_draw_input();
    tui_draw_sidebar(state);
    doupdate();
    return NULL;
}

#endif /* HAVE_NCURSES */

/* ISO C forbids an empty translation unit — pedantic guard */
typedef int tui_empty_tu_guard;
