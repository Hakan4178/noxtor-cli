/* SPDX-License-Identifier: GPL-3.0-or-later
 * ui.c — noxtor-cli merkezi terminal UI katmanı
 *
 * Tüm kullanıcıya görünen çıktılar bu dosyadan geçer.
 * Tema renkleri tek bir struct'ta tanımlı, ileride config'den okunabilir.
 *
 * Kritik tasarım: ui_save_input / ui_restore_input çifti sayesinde
 * gelen mesajlar kullanıcının yarım kalan girdisini ezmez.
 *
 * Audit fix'leri:
 *   [F1] g_theme global — thread-unsafe, şu an single-thread (nota eklendi)
 *   [F2] ui_print_progress — save/restore kaldırıldı, progress bar karışıyordu
 *   [F3] ui_print_outgoing — terminal wrap kırılganlığı yorumda belirtildi
 *   [F4] format_size — uint64_t → PRIu64, 32-bit taşma giderildi
 *   [F5] print_timestamp — ms eklendi, log sistemiyle tutarlı hale getirildi
 */

#include "ui.h"
#include "common.h"
#include "types.h"
#include "tui.h"

#include <assert.h>
#include <inttypes.h>  /* PRIu64 — [F4] */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
 * [F5] ZAMAN DAMGASI — [HH:MM:SS.mmm] formatında
 *
 * Önceki sürümde milisaniye yoktu, log sistemiyle tutarsızdı.
 * Şimdi log.c ile aynı format: HH:MM:SS.mmm
 * ================================================================ */
static void print_timestamp(void)
{
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        ts.tv_sec = 0;

    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));
    localtime_r(&ts.tv_sec, &tm_buf);

    /* [F5] Milisaniye eklendi — log sistemiyle tutarlı */
    long ms = ts.tv_nsec / 1000000L;

    fprintf(stderr, "%s[%02d:%02d:%02d.%03ld]%s ",
            g_theme->clr_timestamp,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ms,
            g_theme->clr_reset);
}

/* ================================================================
 * STDIN BUFFER SAVE / RESTORE
 *
 * Gelen mesaj yazılmadan önce kullanıcının yarım girdisi kaydedilir.
 * Mesaj basıldıktan sonra prompt + yarım girdi geri yazılır.
 *
 * İç içe çağrı koruması: input_saved flag'i ile kontrol edilir.
 * ================================================================ */
void ui_save_input(struct app_state *state)
{
    if (tui_is_active())
        return;
    if (state->input_saved)
        return;  /* zaten kaydedilmiş */
    state->input_saved = true;

    /* Mevcut satırı sil: imleci satır başına al, satırı temizle */
    fprintf(stderr, "\r\033[K");
    fflush(stderr);
}

void ui_restore_input(struct app_state *state)
{
    if (tui_is_active())
        return;
    if (!state->input_saved)
        return;  /* kaydedilmemiş, restore gereksiz */
    state->input_saved = false;

    /* Prompt'u yeniden bas */
    ui_print_prompt(state);

    /*
     * Kullanıcının yarım kalan girdisini geri yaz.
     * TOCTOU koruması: önce pointer + len kopyala, sonra kullan.
     */
    const char *buf = state->stdin_buf;
    size_t      len = state->stdin_len;
    if (len > 0 && buf != NULL)
        fwrite(buf, 1, len, stderr);

    fflush(stderr);
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
    fprintf(stderr, "%s", g_theme->clr_prompt);

    if (state->peer_fd >= 0 && state->active_peer_onion[0] != '\0') {

        /* Onion kısaltma: ilk 4 + ".." + son 4 (toplam 10 karakter) */
        size_t olen = strlen(state->active_peer_onion);
        char   short_id[SHORT_ID_SIZE];

        /* CodeQL #24: "Comparison result is always the same"
         * olen dinamik strlen sonucu, herhangi bir uzunlukta olabilir. */
        assert(olen <= NOX_ONION_LEN);
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
 * MESAJ ÇIKTILARI
 * ================================================================ */

void ui_print_incoming(struct app_state *state, const char *msg)
{
    if (tui_is_active()) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) ts.tv_sec = 0;
        struct tm tm_buf;
        localtime_r(&ts.tv_sec, &tm_buf);
        char buf[8192];
        snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03ld] [Peer] %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                 ts.tv_nsec / 1000000L, msg);
        tui_chat_append(buf);
        tui_refresh_all(state);
        return;
    }
    ui_save_input(state);
    print_timestamp();
    fprintf(stderr, "%s[Peer]%s %s\n",
            g_theme->clr_peer, g_theme->clr_reset, msg);
    ui_restore_input(state);
}

void ui_print_outgoing(struct app_state *state, const char *msg)
{
    if (tui_is_active()) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) ts.tv_sec = 0;
        struct tm tm_buf;
        localtime_r(&ts.tv_sec, &tm_buf);
        char buf[8192];
        snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03ld] [Sen] %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                 ts.tv_nsec / 1000000L, msg);
        tui_chat_append(buf);
        tui_refresh_all(state);
        return;
    }
    /*
     * [F3] Terminal wrap kırılganlığı:
     *
     * "\033[1A\r\033[K" yalnızca TEK satırı siler.
     * Kullanıcı uzun mesaj yazdıysa terminal satır kaydırdıysa
     * (wrap), yalnızca son satır silinir, önceki satır(lar) kalır.
     *
     * Gerçek çözüm ncurses (Phase 8) — o gelene kadar bu
     * kırılganlık kabul edilmiş bir tradeoff'tur.
     * İyileştirme: terminal genişliğini (TIOCGWINSZ) okuyup
     * kaç satır kaydığını hesaplamak mümkün ama kompleks.
     */
    fprintf(stderr, "\033[1A\r\033[K");

    print_timestamp();
    fprintf(stderr, "%s[Sen]%s %s\n",
            g_theme->clr_self, g_theme->clr_reset, msg);

    ui_print_prompt(state);
    fflush(stderr);
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
        char buf[8192];
        snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03ld] %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                 ts.tv_nsec / 1000000L, msg);
        tui_chat_append(buf);
        tui_refresh_all(state);
        return;
    }
    ui_save_input(state);

    fprintf(stderr, "  %s", g_theme->clr_system);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", g_theme->clr_reset);

    ui_restore_input(state);
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
        char buf[8192];
        snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03ld] [!] %s",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                 ts.tv_nsec / 1000000L, msg);
        tui_chat_append(buf);
        tui_refresh_all(state);
        return;
    }
    ui_save_input(state);

    fprintf(stderr, "  %s[!] ", g_theme->clr_error);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", g_theme->clr_reset);

    ui_restore_input(state);
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
