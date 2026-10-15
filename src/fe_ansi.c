/* SPDX-License-Identifier: GPL-3.0-or-later
 * fe_ansi.c — Atomic ANSI Terminal Output backend (Faz 1, commit 4)
 *
 * frontend.c'den taşındı (eski: ui.c içindeydi). Bu dosya sahip olduğu:
 *   - Tema (nox_theme_default, g_theme, ui_init)
 *   - Prompt çizimi (ui_print_prompt — static), redraw_input,
 *     clear_prompt_area(_lines), ui_line_* (G-2), ui_reset_sender
 *   - Atomic ANSI mesaj çıkışı (atomic_message + strip)
 *   - Sistem/hata bloğu (block_message), progress bar (render_progress)
 *   - Label state (g_last_label — commit 5'te ctx'e taşınacak)
 *
 * Tasarım: Atomic ANSI Terminal Output
 *   - Her çizim fonksiyonu kendi kendine yeterli atomik çıkış üretir
 *   - Save/restore statefulness yok — her fonksiyon state'ten hesaplar
 *   - RAM'de plain text depolanmaz — fprintf + fflush + scrub
 *   - Cursor hide/show ile flicker engellenir
 *   - Prompt her zaman state'ten yeniden çizilir
 *
 * DISPATCH (commit 4): bu backend fe_ansi_ops.emit ile kayıtlıdır;
 * tui_is_active() dallanması çizim yollarından KALKTI — backend seçimi
 * registration ile. CLI-only fonksiyonlarda (clear_prompt_area*,
 * redraw_input, ui_print_prompt) guard KALIR — onlar dispatch dışı.
 *
 * Audit fix'leri:
 *   [F1] g_theme global — thread-unsafe, şu an single-thread (nota eklendi)
 *   [F2] ui_print_progress — save/restore kaldırıldı, progress bar karışıyordu
 *   [F3] ui_print_outgoing — wrap kırılganlığı düzeltildi (TIOCGWINSZ + multi-line clear)
 *   [F4] format_size — uint64_t → PRIu64, 32-bit taşma giderildi
 *   [F6] Atomic ANSI — save/restore kaldırıldı, her mesaj atomik
 *   [F7] Plain text scrub — local buffer'lar sodium_memzero ile temizleniyor
 */

#include "fe_ansi.h"
#include "frontend.h"
#include "common.h"
#include "types.h"
#include "tui.h"

#include <assert.h>
#include <inttypes.h>  /* PRIu64 — [F4] */

/* İleri bildirim — ui_print_prompt tanımı (satır ~279) çağrıdan (redraw_input)
 * sonra geliyor; derleyici implicit-declaration veriyordu (WIP build fix) */
static void ui_print_prompt(struct app_state *state);
#include <sodium.h>    /* [F7] sodium_memzero — plain text scrub */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ── Magic number sabitleri ───────────────────── */
#define SHORT_ID_SIZE       12
#define PROGRESS_BAR_WIDTH  16

/* ================================================================
 * VARSAYILAN TEMA — Kullanıcı paleti (truecolor 24-bit)
 *
 * [Sen]     → yeşil    rgb(38, 162, 105)
 * [Peer]    → mor      rgb(112, 60, 153)
 * Sistem    → amber    rgb(202, 151, 15)
 * Hata      → kırmızı  rgb(210, 24, 38)
 * Prompt    → teal     rgb(38, 105, 121)
 * Zaman     → koyu mavi rgb(31, 65, 117)
 * Progress  → teal     rgb(38, 105, 121)
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
 *     (commit 5: ansi_ctx'e taşınacak — fe_ansi_emit ctx parametresi hazır)
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
    struct peer_session *ps = ACTIVE_PEER(state);
    if (!ps || state->active_peer_onion[0] == '\0')
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
    if (ps && ((ps->tx_file.active && ps->tx_file.total_size > 0) ||
        (ps->rx_file.active && ps->rx_file.expected_size > 0)))
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

/* Wrap edilmiş tüm satırları temizle (cursor yukarı + sil)
 *
 * CLI-only (dispatch dışı): TUI aktifken no-op — guard KALIR (commit 4:
 * çizim yollarındaki tui_is_active dalları kalktı, bunlar kalmaz). */
void clear_prompt_area(struct app_state *state)
{
    if (tui_is_active())
        return;
    struct peer_session *ps = ACTIVE_PEER(state);
    if (ps && ps->tofu_pending)
        return;  /* TOFU interaktif modunda temizleme yapma */
    if (state->ln_active)
        return;  /* G-2: linenoise satır sahibi — clear suspend altında yapılır */

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

/* G-2: Linenoise satır sahipliği — refcount suspend/resume.
 * YALNIZCA event_loop.c top-level handler'larından çağrılır. */
void ui_line_suspend(struct app_state *state) {
    if (!state->ln_active) return;
    if (state->ln_suspend_depth++ == 0) {
        linenoiseHide(&state->ln_state);
    }
}
void ui_line_resume(struct app_state *state) {
    if (!state->ln_active) return;
    if (state->ln_suspend_depth == 0) return;
    if (--state->ln_suspend_depth == 0) {
        linenoiseShow(&state->ln_state);
    }
}
void ui_line_force_resume(struct app_state *state) {
    if (!state->ln_active) return;
    if (state->ln_suspend_depth > 0) {
        state->ln_suspend_depth = 0;
        linenoiseShow(&state->ln_state);
    }
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
// Real attack surface in practice: local stdin re-draw (pipe fallback)
static void redraw_input(struct app_state *state)
{
    if (tui_is_active())
        return;
    struct peer_session *ps = ACTIVE_PEER(state);
    if (ps && ps->tofu_pending)
        return;

    /* Cursor altındaki her şeyi temizle — eski wrap satırlarını siler */
    clear_below_cursor();

    ui_print_prompt(state);

    /* Kullanıcının mevcut girdisini yeniden yaz — doğrudan flush, 1023 cap kaldırıldı (A) */
    if (state->stdin_len > 0 && state->stdin_buf != NULL) {
        size_t len = state->stdin_len; /* TOCTOU snap */
        fwrite(state->stdin_buf, 1, len, stderr);
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

/* commit 5: ctx'e taşınacak (fe_ansi_emit ctx parametresi hazır) */
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
    default:
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
 *
 * header'dan düştü (§1.3): dış çağrı 0 — yalnız redraw_input çağırır.
 * ================================================================ */
static void ui_print_prompt(struct app_state *state)
{
    if (tui_is_active())
        return;

    /* Display uzunluğunu hesapla ve kaydet (wrap hesabı için gerekli) */
    state->prompt_display_len = calc_prompt_display_len(state);

    fprintf(stderr, "%s", g_theme->clr_prompt);

    struct peer_session *ps = ACTIVE_PEER(state);

    if (ps && state->active_peer_onion[0] != '\0') {

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
        if (ps && ps->tx_file.active && ps->tx_file.total_size > 0) {
            unsigned pct = (unsigned)((ps->tx_file.sent_bytes * 100ULL) /
                                       ps->tx_file.total_size);
            if (pct > 100) pct = 100;
            fprintf(stderr, "[%s \xe2\xac\x86%u%%]", short_id, pct);
        } else if (ps && ps->rx_file.active && ps->rx_file.expected_size > 0) {
            unsigned pct = (unsigned)((ps->rx_file.received_bytes * 100ULL) /
                                       ps->rx_file.expected_size);
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

/* Timestamp bas — tm event'ten gelir (commit 4: tek clock frontend.c'de) */
static void print_timestamp_short(const struct tm *tm)
{
    fprintf(stderr, "%s[%02d:%02d:%02d]%s ",
            g_theme->clr_timestamp,
            tm->tm_hour, tm->tm_min, tm->tm_sec,
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
 *
 * commit 4: tui_is_active guard KALKTI (dispatch registration ile korur),
 * tm event'ten parametre olarak gelir.
 */

// Real attack surface in practice: attacker plaintext → terminal (strip_ansi)
static void atomic_message(struct app_state *state, enum ui_label label,
                           const char *msg, const struct tm *tm)
{
    /* UI-1 FIX: ANSI injection koruması — mutable kopya oluştur */
    size_t msg_len = strlen(msg);
    char *safe_msg = malloc(msg_len + 1);
    if (!safe_msg) return;
    memcpy(safe_msg, msg, msg_len + 1);
    ui_strip_ansi(safe_msg);

    if (state->ln_active) {
        /* Linenoise modu (Faz G-1): terminal satırının sahibi linenoise'dır
         * (Hide/Show/EditStart). Eski input-satır mekanizması burada
         * prompt'u silip kendi prompt'unu bastığı için atlanır — yalnız
         * içerik yazılır. */
        if (g_last_label != UI_LABEL_NONE && g_last_label != label)
            fprintf(stderr, "\n");
        print_timestamp_short(tm);
        print_label(label);
        fprintf(stderr, " %s\n", safe_msg);
        /* H-2: mesaj kopyası heap'te iz bırakmasın (sodium_memzero:
         * dead-store elimination'a dayanıklı) */
        sodium_memzero(safe_msg, msg_len + 1);
        free(safe_msg);
        fflush(stderr);
        g_last_label = label;
        return;
    }

    int clear_lines = calc_current_input_lines(state);

    fprintf(stderr, "\033[?25l");
    clear_prompt_area_lines(clear_lines);

    /* Sender değişince boşluk ekle */
    if (g_last_label != UI_LABEL_NONE && g_last_label != label)
        fprintf(stderr, "\n");

    print_timestamp_short(tm);
    print_label(label);
    fprintf(stderr, " %s\n", safe_msg);
    /* H-2: mesaj kopyası heap'te iz bırakmasın */
    sodium_memzero(safe_msg, msg_len + 1);
    free(safe_msg);
    fflush(stderr);

    g_last_label = label;

    redraw_input(state);
    fprintf(stderr, "\033[?25h");
    fflush(stderr);
}

/* Sistem/hata bloğu — eski ui_print_system/ui_print_error ANSI yolu
 *
 *   [22:29:17]   sistem mesajı
 *   [22:29:18]   [!] hata mesajı
 *
 * tag: "" (system) veya "[!] " (error) — çıktı byte-identical
 * (eski formatlar: "  %s%s%s\n" / "  %s[!] %s%s\n").
 *
 * scrub YOK: msg sahipliği caller'da (frontend.c emit dönüşünde
 * sodium_memzero). H-2 sahiplik kuralı: backend text'i sahiplenmez.
 */
static void block_message(struct app_state *state, const struct tm *tm,
                          const char *color, const char *tag,
                          const char *text)
{
    if (state->ln_active) {
        /* Linenoise modu (Faz G-1): yalnız içerik — satır yönetimi
         * linenoise'da (bkz. atomic_message notu). */
        print_timestamp_short(tm);
        fprintf(stderr, "  %s%s%s%s\n", color, tag, text, g_theme->clr_reset);
        fflush(stderr);
        return;
    }

    int clear_lines = calc_current_input_lines(state);

    fprintf(stderr, "\033[?25l");
    clear_prompt_area_lines(clear_lines);
    print_timestamp_short(tm);
    fprintf(stderr, "  %s%s%s%s\n", color, tag, text, g_theme->clr_reset);
    fflush(stderr);
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

/* Progress bar çiz — commit 4: dispatch hedefi (eski ui_print_progress gövdesi).
 *
 * total==0 erken dönüşü BURADA (ANSI kolunda) — TUI'da bugün total==0'da
 * bile refresh var, o yüzden kontrol ortak katmana alınmadı (davranış
 * birebir korunur). */
static void render_progress(struct app_state *state, const char *filename,
                            uint64_t done, uint64_t total, bool is_upload)
{
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

    /* M-24 FIX: ANSI injection koruması — filename strip */
    size_t fn_len = strlen(filename);
    char *safe_fn = malloc(fn_len + 1);
    if (!safe_fn) return;
    memcpy(safe_fn, filename, fn_len + 1);
    ui_strip_ansi(safe_fn);

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
            arrow, safe_fn, bar, pct,
            done_str, total_str,
            g_theme->clr_reset);
    fflush(stderr);
    /* H-2: dosya adı kopyası heap'te iz bırakmasın */
    sodium_memzero(safe_fn, fn_len + 1);
    free(safe_fn);
}

/* ================================================================
 * DISPATCH HEDEFİ — fe_ansi_ops
 *
 * Senkron: ev dönüşünde geçersiz; text sahiplenilmez (scrup caller yapar).
 * Recursion yasağı: frontend_emit'e geri çağrılmaz.
 *
 * label mapping: FE_MSG_IN→Peer, FE_MSG_OUT→Sen, FE_ERROR→blok "[!] ",
 * FE_SYSTEM→blok tag "" — eski çağrı ağaçlarıyla birebir aynı çıktı.
 * ================================================================ */
static void fe_ansi_emit(void *ctx, const struct fe_event *ev)
{
    (void)ctx;   /* commit 5: g_theme/g_last_label ansi_ctx'e taşınacak */

    struct app_state *state = ev->state;

    switch (ev->type) {
    case FE_MSG_IN:
        atomic_message(state, UI_LABEL_PEER, ev->text, &ev->tm);
        break;
    case FE_MSG_OUT:
        atomic_message(state, UI_LABEL_SELF, ev->text, &ev->tm);
        break;
    case FE_SYSTEM:
        block_message(state, &ev->tm, g_theme->clr_system, "", ev->text);
        break;
    case FE_ERROR:
        block_message(state, &ev->tm, g_theme->clr_error, "[!] ", ev->text);
        break;
    case FE_PROGRESS:
        render_progress(state, ev->filename, ev->done,
                        ev->total, ev->is_upload);
        break;
    default:
        break;   /* bilinmeli tip → sessiz (strict koruma socket fazında) */
    }
}

const struct frontend_ops fe_ansi_ops = {
    .name = "ansi",
    .emit = fe_ansi_emit,
};
