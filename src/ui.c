/* SPDX-License-Identifier: GPL-3.0-or-later
 * ui.c — noxtor-cli merkezi terminal UI katmanı
 *
 * Tüm kullanıcıya görünen çıktılar bu dosyadan geçer.
 * Tema renkleri tek bir struct'ta tanımlı, ileride config'den okunabilir.
 *
 * Tasarım: Atomic ANSI Terminal Output
 *   - Her ui_print_* kendi kendine yeterli atomik çıkış üretir
 *   - Save/restore statefulness yok — her fonksiyon state'ten hesaplar
 *   - RAM'de plain text depolanmaz — fprintf + fflush + scrub
 *   - Cursor hide/show ile flicker engellenir
 *   - Prompt her zaman state'ten yeniden çizilir
 *
 * Audit fix'leri:
 *   [F1] g_theme global — thread-unsafe, şu an single-thread (nota eklendi)
 *   [F2] ui_print_progress — save/restore kaldırıldı, progress bar karışıyordu
 *   [F3] ui_print_outgoing — wrap kırılganlığı düzeltildi (TIOCGWINSZ + multi-line clear)
 *   [F4] format_size — uint64_t → PRIu64, 32-bit taşma giderildi
 *   [F6] Atomic ANSI — save/restore kaldırıldı, her mesaj atomik
 *   [F7] Plain text scrub — local buffer'lar sodium_memzero ile temizleniyor
 */

#include "ui.h"
#include "common.h"
#include "types.h"
#include "tui.h"

#include <assert.h>
#include <inttypes.h>  /* PRIu64 — [F4] */
#include <stdarg.h>
#include <sodium.h>    /* [F7] sodium_memzero — plain text scrub */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ── Magic number sabitleri ───────────────────── */
#define SHORT_ID_SIZE       12
#define PROGRESS_BAR_WIDTH  16

/* ================================================================
 * VARSAYILAN TEMA — Kullanıcı paleti (truecolor 24-bit)
 *
 * [Sen]     → yeşil    rgb(38, 162, 105)
 * [Peer]    → mor      rgb(133, 60, 153)
 * Sistem    → amber    rgb(202, 151, 15)
 * Hata      → kırmızı  rgb(210, 24, 38)
 * Prompt    → teal     rgb(34, 105, 121)
 * Zaman     → koyu mavi rgb(31, 65, 117)
 * Progress  → teal     rgb(34, 105, 121)
 * ================================================================ */
const struct nox_theme nox_theme_default = {
    .clr_self      = "\033[38;2;38;162;105m",
    .clr_peer      = "\033[38;2;133;60;153m",
    .clr_system    = "\033[38;2;202;151;15m",
    .clr_error     = "\033[1;38;2;210;24;38m",  /* bold + kırmızı */
    .clr_prompt    = "\033[38;2;34;105;121m",
    .clr_timestamp = "\033[38;2;31;65;117m",
    .clr_progress  = "\033[38;2;34;105;121m",
    .clr_reset     = "\033[0m",
};

/*
 * [F1] g_theme — global pointer, şu an single-thread olduğu için güvenli.
 *
 * ⚠️  GELECEK UYARI: Multi-peer (Phase 6.3+) veya GTK UI thread'i
 *     eklendiğinde bu pointer'a eşzamanlı erişim race condition yaratır.
 *     O zaman ya app_state içine taşı ya da _Atomic/_Thread_local kullan.
 */
static const struct nox_theme *g_theme = &nox_theme_default;

/* ================================================================
 * TEMA BAŞLATMA
 * ================================================================ */
void ui_init(const struct nox_theme *theme)
{
    g_theme = theme ? theme : &nox_theme_default;
}

/* ================================================================
 * YARDIMCI: Terminal genişliği ve wrap satır hesabı
 * ================================================================ */
static int get_terminal_cols(void)
{
    struct winsize ws;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80; /* fallback */
}

/* Prompt display uzunluğunu hesapla (ANSI kodları hariç) */
static size_t calc_prompt_display_len(struct app_state *state)
{
    if (state->peer_fd < 0 || state->active_peer_onion[0] == '\0')
        return 5; /* "nox> " */

    size_t olen = strlen(state->active_peer_onion);
    size_t id_len;
    if (olen > 10) {
        size_t hash_len = olen;
        if (strcmp(state->active_peer_onion + olen - 6, ".onion") == 0)
            hash_len = olen - 6;
        id_len = (hash_len >= 8) ? 10 : hash_len;
    } else {
        id_len = olen;
    }

    /* [id] > = 1 + id_len + 1 + 3 */
    size_t base = 1 + id_len + 1 + 3;

    /* Dosya transferi progress: " ⬆XX%" veya " ⬇XX%" = 7 byte display */
    if ((state->tx_file.active && state->tx_file.total_size > 0) ||
        (state->rx_file.active && state->rx_file.expected_size > 0))
        base += 7;

    return base;
}

/* Prompt + stdin_len için wrap satır sayısını hesapla */
static int calc_input_lines(struct app_state *state)
{
    int cols = get_terminal_cols();
    size_t total = state->prompt_display_len + state->stdin_len;
    if (total == 0) return 1;
    return (int)((total + (size_t)cols - 1) / (size_t)cols);
}

/* Wrap edilmiş tüm satırları temizle (cursor yukarı + sil) */
void clear_prompt_area(struct app_state *state)
{
    if (tui_is_active())
        return;
    if (state->tofu_pending)
        return;  /* TOFU interaktif modunda temizleme yapma */

    int lines = calc_input_lines(state);
    if (lines < 1) lines = 1;
    /* N satır yukarı git, hepsini temizle */
    fprintf(stderr, "\033[%dA\033[J", lines);
}

/* Belirli satır sayısını temizle (saved prompt için) */
void clear_prompt_area_lines(int lines)
{
    if (tui_is_active())
        return;
    if (lines < 1) lines = 1;
    /* Git yukarı → sütun 1'e git → cursor'dan ekran sonuna sil */
    if (lines > 1)
        fprintf(stderr, "\033[%dA", lines - 1);
    fprintf(stderr, "\033[1G\033[J");
}

/* Mevcut input'un wrap satır sayısını dinamik hesapla */
static int calc_current_input_lines(struct app_state *state)
{
    int cols = get_terminal_cols();
    size_t total = state->prompt_display_len + state->stdin_len;
    if (total == 0) return 1;
    return (int)((total + (size_t)cols - 1) / (size_t)cols);
}

/* Cursor altındaki her şeyi temizle */
static void clear_below_cursor(void)
{
    fprintf(stderr, "\033[J");
}

/* Prompt'u ve mevcut input'u state'ten yeniden çiz */
static void redraw_input(struct app_state *state)
{
    if (tui_is_active())
        return;
    if (state->tofu_pending)
        return;

    /* Cursor altındaki her şeyi temizle — eski wrap satırlarını siler */
    clear_below_cursor();

    ui_print_prompt(state);

    /* Kullanıcının mevcut girdisini yeniden yaz — TOCTOU korumalı */
    if (state->stdin_len > 0 && state->stdin_buf != NULL) {
        char buf[1024];
        size_t len = state->stdin_len;
        if (len > sizeof(buf) - 1) len = sizeof(buf) - 1;
        memcpy(buf, state->stdin_buf, len);
        buf[len] = '\0';
        fwrite(buf, 1, len, stderr);
        /* [F7] Local buffer scrub */
        sodium_memzero(buf, sizeof(buf));
    }
    fflush(stderr);
}

/* Mesaj label'ı yaz */
enum ui_label {
    UI_LABEL_NONE,
    UI_LABEL_SELF,
    UI_LABEL_PEER,
    UI_LABEL_ERROR,
};

static enum ui_label g_last_label = UI_LABEL_NONE;

static void print_label(enum ui_label label)
{
    switch (label) {
    case UI_LABEL_SELF:
        fprintf(stderr, "%sSen:%s", g_theme->clr_self, g_theme->clr_reset);
        break;
    case UI_LABEL_PEER:
        fprintf(stderr, "%sPeer:%s", g_theme->clr_peer, g_theme->clr_reset);
        break;
    case UI_LABEL_ERROR:
        fprintf(stderr, "%s!:%s", g_theme->clr_error, g_theme->clr_reset);
        break;
    case UI_LABEL_NONE:
        break;
    }
}

/* Sender durumunu sıfırla (yeni bağlantıda) */
void ui_reset_sender(void)
{
    g_last_label = UI_LABEL_NONE;
}

/* ================================================================
 * BAĞLAM DUYARLI PROMPT
 *
 * Bağlantı yok:          nox>
 * Bağlı:                 [peer:abcd..wxyz] >
 * Dosya gönderiliyor:    [peer:abcd..wxyz ⬆45%] >
 * ================================================================ */
void ui_print_prompt(struct app_state *state)
{
    if (tui_is_active())
        return;

    /* Display uzunluğunu hesapla ve kaydet (wrap hesabı için gerekli) */
    state->prompt_display_len = calc_prompt_display_len(state);

    fprintf(stderr, "%s", g_theme->clr_prompt);

    if (state->peer_fd >= 0 && state->active_peer_onion[0] != '\0') {

        /* Onion kısaltma: ilk 4 + ".." + son 4 (toplam 10 karakter) */
        size_t olen = strlen(state->active_peer_onion);
        char   short_id[SHORT_ID_SIZE];

        /* CodeQL #24 cpp/comparison-is-always-the-same: olen dinamik strlen sonucu */
        assert(olen <= NOX_ONION_LEN);
        assert(olen <= NOX_ONION_LEN && "onion length bounded"); /* CodeQL hint */
        if (olen > 10) {
            size_t hash_len = olen;
            if (olen > 6 &&
                strcmp(state->active_peer_onion + olen - 6, ".onion") == 0)
                hash_len = olen - 6;

            /* underflow koruması: en az 8 karakter (4 baş + 4 son) */
            if (hash_len >= 8) {
                snprintf(short_id, sizeof(short_id), "%.4s..%.4s",
                         state->active_peer_onion,
                         state->active_peer_onion + hash_len - 4);
            } else {
                snprintf(short_id, sizeof(short_id), "%.*s",
                         (int)hash_len, state->active_peer_onion);
            }
        } else {
            snprintf(short_id, sizeof(short_id), "%.11s",
                     state->active_peer_onion);
        }

        /* Dosya transferi progress göstergesi */
        if (state->tx_file.active && state->tx_file.total_size > 0) {
            unsigned pct = (unsigned)((state->tx_file.sent_bytes * 100ULL) /
                                       state->tx_file.total_size);
            if (pct > 100) pct = 100;
            fprintf(stderr, "[%s \xe2\xac\x86%u%%]", short_id, pct);
        } else if (state->rx_file.active && state->rx_file.expected_size > 0) {
            unsigned pct = (unsigned)((state->rx_file.received_bytes * 100ULL) /
                                       state->rx_file.expected_size);
            if (pct > 100) pct = 100;
            fprintf(stderr, "[%s \xe2\xac\x87%u%%]", short_id, pct);
        } else {
            fprintf(stderr, "[%s]", short_id);
        }

        fprintf(stderr, " > %s", g_theme->clr_reset);

    } else {
        fprintf(stderr, "nox> %s", g_theme->clr_reset);
    }

    fflush(stderr);
}

/* ================================================================
 * MESAJ ÇIKTILARI — İki Satır Formatı
 *
 *   [21:14:39] Sen:
 *     pejfoooooooooooooooooooooooooooooooooooo
 *     ooooooooooooooooooooooooooooooooooooooo
 *
 *   [21:14:39] Peer:
 *     r3nhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
 *     hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
 *
 * [F8] Dinamik satır hesabı — peer mesajı gelirken input bozulmaz
 * ================================================================ */

/* UI-1 FIX: Terminal ANSI injection koruması —peer mesajlarını temizle */
static void strip_ansi_escape(char *str) {
  if (!str) return;
  char *dst = str;
  const char *src = str;
  while (*src) {
    if ((unsigned char)*src == 0x1b && src[1] == '[') {
      src += 2;
      while (*src && ((*src >= '0' && *src <= '?') ||
                      (*src >= ' ' && *src <= '/')))
        src++;
      if (*src) src++;
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

static void print_timestamp_short(void)
{
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        ts.tv_sec = 0;
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));
    localtime_r(&ts.tv_sec, &tm_buf);
    fprintf(stderr, "%s[%02d:%02d:%02d]%s ",
            g_theme->clr_timestamp,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
            g_theme->clr_reset);
}

/* Atomik mesaj çıkışı — tek satır format
 *
 *   [22:29:17] Sen: jeyyheyyo
 *   [22:29:22] Peer: heyo
 *   [22:29:33] Sen: uhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
 *               hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
 *
 * Uzun mesajlar terminal genişliğine göre otomatik sarılır.
 * Sender değişince boşluk eklenir.
 */

static void atomic_message(struct app_state *state, enum ui_label label,
                           const char *msg)
{
    if (tui_is_active())
        return;

    /* UI-1 FIX: ANSI injection koruması — mutable kopya oluştur */
    size_t msg_len = strlen(msg);
    char *safe_msg = malloc(msg_len + 1);
    if (!safe_msg) return;
    memcpy(safe_msg, msg, msg_len + 1);
    strip_ansi_escape(safe_msg);

    int clear_lines = calc_current_input_lines(state);

    fprintf(stderr, "\033[?25l");
    clear_prompt_area_lines(clear_lines);

    /* Sender değişince boşluk ekle */
    if (g_last_label != UI_LABEL_NONE && g_last_label != label)
        fprintf(stderr, "\n");

    print_timestamp_short();
    print_label(label);
    fprintf(stderr, " %s\n", safe_msg);
    free(safe_msg);
    fflush(stderr);

    g_last_label = label;

    redraw_input(state);
    fprintf(stderr, "\033[?25h");
    fflush(stderr);
}

void ui_print_incoming(struct app_state *state, const char *msg)
{
    if (!msg || !*msg || strspn(msg, " \t") == strlen(msg))
        return;
    if (tui_is_active()) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) ts.tv_sec = 0;
        struct tm tm_buf;
        localtime_r(&ts.tv_sec, &tm_buf);
        char tbuf[8192];
        snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] Peer: %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, msg);
        tui_chat_append(tbuf);
        tui_refresh_all(state);
        sodium_memzero(tbuf, sizeof(tbuf));
        return;
    }
    atomic_message(state, UI_LABEL_PEER, msg);
}

void ui_print_outgoing(struct app_state *state, const char *msg)
{
    if (tui_is_active()) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) ts.tv_sec = 0;
        struct tm tm_buf;
        localtime_r(&ts.tv_sec, &tm_buf);
        char tbuf[8192];
        snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] Sen: %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, msg);
        tui_chat_append(tbuf);
        tui_refresh_all(state);
        sodium_memzero(tbuf, sizeof(tbuf));
        return;
    }
    atomic_message(state, UI_LABEL_SELF, msg);
}

/* ================================================================
 * SİSTEM VE HATA MESAJLARI
 * ================================================================ */

void ui_print_system(struct app_state *state, const char *fmt, ...)
{
    if (tui_is_active()) {
        char msg[4096];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) ts.tv_sec = 0;
        struct tm tm_buf;
        localtime_r(&ts.tv_sec, &tm_buf);
        char tbuf[8192];
        snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, msg);
        tui_chat_append(tbuf);
        tui_refresh_all(state);
        sodium_memzero(tbuf, sizeof(tbuf));
        sodium_memzero(msg, sizeof(msg));
        return;
    }

    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    int clear_lines = calc_current_input_lines(state);

    fprintf(stderr, "\033[?25l");
    clear_prompt_area_lines(clear_lines);
    print_timestamp_short();
    fprintf(stderr, "  %s%s%s\n", g_theme->clr_system, msg, g_theme->clr_reset);
    fflush(stderr);
    sodium_memzero(msg, sizeof(msg));
    redraw_input(state);
    fprintf(stderr, "\033[?25h");
    fflush(stderr);
}

void ui_print_error(struct app_state *state, const char *fmt, ...)
{
    if (tui_is_active()) {
        char msg[4096];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) ts.tv_sec = 0;
        struct tm tm_buf;
        localtime_r(&ts.tv_sec, &tm_buf);
        char tbuf[8192];
        snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d] [!] %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, msg);
        tui_chat_append(tbuf);
        tui_refresh_all(state);
        sodium_memzero(tbuf, sizeof(tbuf));
        sodium_memzero(msg, sizeof(msg));
        return;
    }

    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    int clear_lines = calc_current_input_lines(state);

    fprintf(stderr, "\033[?25l");
    clear_prompt_area_lines(clear_lines);
    print_timestamp_short();
    fprintf(stderr, "  %s[!] %s%s\n", g_theme->clr_error, msg, g_theme->clr_reset);
    fflush(stderr);
    sodium_memzero(msg, sizeof(msg));
    redraw_input(state);
    fprintf(stderr, "\033[?25h");
    fflush(stderr);
}

/* ================================================================
 * DOSYA TRANSFERİ PROGRESS BAR
 *
 * ASCII stili: [========--------] 45% 1.2/2.6 MB
 * Aynı satırı günceller (\r\033[K ile).
 *
 * [F2] save/restore KALDIRILDI:
 *   Progress bar sürekli aynı satırı \r ile günceller.
 *   Önceki sürümde her güncellemede ui_restore_input çağrılıyor,
 *   prompt yeniden basılıyordu → progress bar + prompt iç içe geçiyordu.
 *   Çözüm: progress bar kendi satırını yönetir, prompt basmaz.
 *   Transfer bitince caller ui_print_system ile sonucu bildirir,
 *   o da save/restore ile prompt'u düzgün geri getirir.
 * ================================================================ */

/* [F4] format_size — PRIu64 ile 32-bit taşma giderildi */
static void format_size(uint64_t bytes, char *buf, size_t buf_sz)
{
    if (bytes >= 1073741824ULL) {
        snprintf(buf, buf_sz, "%.1f GB", (double)bytes / 1073741824.0);
    } else if (bytes >= 1048576ULL) {
        snprintf(buf, buf_sz, "%.1f MB", (double)bytes / 1048576.0);
    } else if (bytes >= 1024ULL) {
        snprintf(buf, buf_sz, "%.1f KB", (double)bytes / 1024.0);
    } else {
        /* [F4] unsigned long yerine PRIu64 — 32-bit sistemde taşma yok */
        snprintf(buf, buf_sz, "%" PRIu64 " B", bytes);
    }
}

void ui_print_progress(struct app_state *state, const char *filename,
                       uint64_t done, uint64_t total, bool is_upload)
{
    if (tui_is_active()) {
        tui_refresh_all(state);
        return;
    }
    if (total == 0)
        return;

    /*
     * [F2] save/restore YOK — kasıtlı.
     * Bu fonksiyon \r ile aynı satırı günceller, prompt basmaz.
     * ui_save_input/ui_restore_input çağrılırsa prompt iç içe geçer.
     * Transfer tamamlanınca caller ui_print_system çağırır,
     * o da save/restore ile prompt'u düzgün geri getirir.
     */
    (void)state;  /* şu an kullanılmıyor — ileride tema için gerekebilir */

    unsigned pct = (unsigned)((done * 100ULL) / total);
    if (pct > 100) pct = 100;

    /* Progress bar dolgu */
    int  filled = (int)(pct * PROGRESS_BAR_WIDTH / 100);
    char bar[PROGRESS_BAR_WIDTH + 1];
    for (int i = 0; i < PROGRESS_BAR_WIDTH; i++)
        bar[i] = (i < filled) ? '=' : '-';
    bar[PROGRESS_BAR_WIDTH] = '\0';

    char done_str[32], total_str[32];
    format_size(done,  done_str,  sizeof(done_str));
    format_size(total, total_str, sizeof(total_str));

    /* UTF-8 ok karakterleri: ⬆ = \xe2\xac\x86, ⬇ = \xe2\xac\x87 */
    const char *arrow = is_upload ? "\xe2\xac\x86" : "\xe2\xac\x87";

    fprintf(stderr, "\r\033[K  %s%s %s [%s] %u%% %s/%s%s",
            g_theme->clr_progress,
            arrow, filename, bar, pct,
            done_str, total_str,
            g_theme->clr_reset);
    fflush(stderr);
}
