/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_frontend.c — ortak frontend katmanı birim testi (Faz 1, commit 1-3)
 *
 * Kilitlenen davranışlar:
 *   A. Dispatch iskeleti (commit 1):
 *      - backend yokken emit no-op (fuzz hedefleri registration yapmaz)
 *      - NULL ev no-op; son registration kazanır; NULL ile unregister
 *      - emit SENKRON + KOPYASIZ: backend aynı ev pointer'ını alır,
 *        ctx aynen geçer (struct kopyası yok — tehdit modeli kuralı)
 *   B. fe_now_tm (commit 2): alan aralıkları + mktime round-trip
 *      (tek clock_gettime + localtime_r kaynağı — 5 kopyanın kilit testi)
 *   C. Bildirim yolları (commit 3 sonrası davranış — stderr'e capture):
 *      - ui_print_incoming boş/beyaz-only filtre (erken return, çıktı YOK)
 *      - incoming/outgoing/system/error içerik + label formatı
 *      - ANSI strip atomic_message yolunda (attacker mesaj temizliği)
 *      - vsnprintf truncation (4096 cap) crash'siz
 *      - ui_print_progress: total==0 erken dönüş; render çıktısı
 *   D. fe_tui.c split (commit 3): !HAVE_TERMBOX'da no-op — link ve
 *      crash-sağlam (TUI=1 modunda test edilmez: init'siz termbox'a
 *      dokunulmaz, o yol pty smoke ile doğrulanır)
 *
 * Not: timestamp değerleri duyarlı değildir — sadece aralık/tutarlılık
 * kontrol edilir (determinizm testi DEĞİL).
 */

#include "common.h"
#include "types.h"
#include "frontend.h"
#include "fe_tui.h"
#include "tui.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ================================================================
 * TEST MAKROLARI (şablon: test_ansi_strip.c / test_onion_bind.c)
 * ================================================================ */
static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond) do {                                      \
    if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL %s:%d: %s\n",                        \
                __FILE__, __LINE__, #cond);                         \
        return 1;                                                   \
    }                                                               \
} while (0)

#define RUN_TEST(test_fn) do {                                      \
    tests_run++;                                                    \
    fprintf(stderr, "  [%d] %-45s ", tests_run, #test_fn);          \
    if (test_fn() == 0) {                                           \
        tests_passed++;                                             \
        fprintf(stderr, "\033[32mOK\033[0m\n");                     \
    } else {                                                        \
        fprintf(stderr, "\033[31mFAIL\033[0m\n");                   \
    }                                                               \
} while (0)

/* ================================================================
 * PROBE BACKEND — dispatch iskeleti testi (kısım A)
 * ================================================================ */
struct probe_ctx {
    int                calls;
    void              *seen_ctx;    /* ctx aynen geçti mi (kimlik) */
    const struct fe_event *seen_ev; /* ev pointer'ı aynen mi (kopyasız) */
};

static struct probe_ctx g_probe1;
static struct probe_ctx g_probe2;

static void probe1_emit(void *ctx, const struct fe_event *ev)
{
    g_probe1.calls++;
    g_probe1.seen_ctx = ctx;
    g_probe1.seen_ev  = ev;
}

static void probe2_emit(void *ctx, const struct fe_event *ev)
{
    g_probe2.calls++;
    g_probe2.seen_ctx = ctx;
    g_probe2.seen_ev  = ev;
}

static const struct frontend_ops probe1_ops = { "probe1", probe1_emit };
static const struct frontend_ops probe2_ops = { "probe2", probe2_emit };

/* ── A1: backend yokken emit no-op (crash yok) ─────────────────── */
static int test_emit_noop_without_backend(void)
{
    frontend_register(NULL, NULL);   /* temiz garantili başlangıç */

    struct fe_event ev = { .type = FE_MSG_IN, .text = "x", .len = 1 };
    frontend_emit(&ev);              /* crash yoksa ve sessizse OK */
    return 0;
}

/* ── A2: NULL ev — backend çağrılmaz ───────────────────────────── */
static int test_emit_null_event(void)
{
    memset(&g_probe1, 0, sizeof(g_probe1));
    frontend_register(&probe1_ops, &g_probe1);

    frontend_emit(NULL);
    TEST_ASSERT(g_probe1.calls == 0);

    frontend_register(NULL, NULL);
    return 0;
}

/* ── A3: round-trip — SENKRON + KOPYASIZ + ctx kimliği ─────────── */
static int test_emit_roundtrip_fields(void)
{
    memset(&g_probe1, 0, sizeof(g_probe1));
    frontend_register(&probe1_ops, &g_probe1);

    struct fe_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = FE_MSG_IN;
    ev.text = "abc";
    ev.len  = 3;

    frontend_emit(&ev);

    TEST_ASSERT(g_probe1.calls == 1);
    /* Kopyasızlık: backend AYNI ev pointer'ını aldı — kuyruk/kopya yok,
     * emit dönüşünde caller struct'ı serbest (senkron sözleşme) */
    TEST_ASSERT(g_probe1.seen_ev == &ev);
    /* ctx aynen geçti — backend kendi durumunu pointer kimliğiyle korur */
    TEST_ASSERT(g_probe1.seen_ctx == &g_probe1);
    /* Alanlar backend'e bozulmadan ulaştı */
    TEST_ASSERT(g_probe1.seen_ev->type == FE_MSG_IN);
    TEST_ASSERT(g_probe1.seen_ev->text == ev.text);
    TEST_ASSERT(g_probe1.seen_ev->len  == 3);

    frontend_register(NULL, NULL);
    return 0;
}

/* ── A4: son registration kazanır ──────────────────────────────── */
static int test_register_last_wins(void)
{
    memset(&g_probe1, 0, sizeof(g_probe1));
    memset(&g_probe2, 0, sizeof(g_probe2));

    frontend_register(&probe1_ops, &g_probe1);
    frontend_register(&probe2_ops, &g_probe2);

    struct fe_event ev = { .type = FE_SYSTEM, .text = "s", .len = 1 };
    frontend_emit(&ev);

    TEST_ASSERT(g_probe2.calls == 1);   /* son kayıt kazanır */
    TEST_ASSERT(g_probe1.calls == 0);   /* eski backend ezilir */

    frontend_register(NULL, NULL);
    return 0;
}

/* ── A5: NULL ile unregister → no-op'a dönüş ───────────────────── */
static int test_unregister_resets(void)
{
    memset(&g_probe1, 0, sizeof(g_probe1));
    frontend_register(&probe1_ops, &g_probe1);
    frontend_register(NULL, NULL);

    struct fe_event ev = { .type = FE_ERROR, .text = "e", .len = 1 };
    frontend_emit(&ev);

    TEST_ASSERT(g_probe1.calls == 0);
    return 0;
}

/* ================================================================
 * fe_now_tm — ortak zaman damgası (kısım B)
 * ================================================================ */

/* ── B1: alan aralıkları geçerli ────────────────────────────────── */
static int test_now_tm_valid_fields(void)
{
    struct tm tm_buf;
    memset(&tm_buf, 0xAA, sizeof(tm_buf));   /* dolgu — her alan yazılmalı */

    fe_now_tm(&tm_buf);

    TEST_ASSERT(tm_buf.tm_year >= 70);       /* >= 1970 (epoch) */
    TEST_ASSERT(tm_buf.tm_year <= 300);      /* <= 2200 (saçma değer yok) */
    TEST_ASSERT(tm_buf.tm_mon  >= 0 && tm_buf.tm_mon  <= 11);
    TEST_ASSERT(tm_buf.tm_mday >= 1 && tm_buf.tm_mday <= 31);
    TEST_ASSERT(tm_buf.tm_hour >= 0 && tm_buf.tm_hour <= 23);
    TEST_ASSERT(tm_buf.tm_min  >= 0 && tm_buf.tm_min  <= 59);
    TEST_ASSERT(tm_buf.tm_sec  >= 0 && tm_buf.tm_sec  <= 60);
    return 0;
}

/* ── B2: mktime round-trip — tm gerçek saate tutarlı ─────────────
 * fe_now_tm → mktime → |epoch - time(NULL)| küçük olmalı. localtime_r
 * bozuksa (ör. /etc/localtime EACCES → sıfır tm) round-trip patlar. */
static int test_now_tm_mktime_roundtrip(void)
{
    struct tm tm_buf;
    fe_now_tm(&tm_buf);

    time_t roundtrip = mktime(&tm_buf);
    TEST_ASSERT(roundtrip != (time_t)-1);

    time_t now = time(NULL);
    long diff = (long)(roundtrip - now);
    TEST_ASSERT(diff >= -5 && diff <= 5);   /* timezone dönüşümü toleransı */
    return 0;
}

/* ================================================================
 * stderr capture yardımcıları (kısım C)
 * ================================================================ */

/* fn(st, msg) çağrısının stderr çıktısını buf'a yakala.
 * Return: yakalanan uzunluk (hata: -1). */
typedef void (*fe_msg_fn)(struct app_state *, const char *);

static int capture_msg(char *buf, size_t cap, fe_msg_fn fn,
                       struct app_state *st, const char *msg)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    if (saved < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (dup2(pipefd[1], STDERR_FILENO) < 0) {
        close(saved); close(pipefd[0]); close(pipefd[1]); return -1;
    }

    fn(st, msg);

    fflush(stderr);
    dup2(saved, STDERR_FILENO);   /* stderr'i geri al */
    close(saved);
    close(pipefd[1]);

    ssize_t n = read(pipefd[0], buf, cap - 1);
    close(pipefd[0]);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

/* ── C1: incoming boş/beyaz-only filtre — çıktı YOK ────────────── */
static int test_incoming_empty_filtered(void)
{
    static struct app_state st;   /* {0} — çizim yolları güvenli */
    char buf[512];

    TEST_ASSERT(capture_msg(buf, sizeof(buf), ui_print_incoming,
                            &st, "") >= 0);
    TEST_ASSERT(buf[0] == '\0');                 /* "" atıldı */

    TEST_ASSERT(capture_msg(buf, sizeof(buf), ui_print_incoming,
                            &st, "  \t   ") >= 0);
    TEST_ASSERT(buf[0] == '\0');                 /* beyaz-only atıldı */
    return 0;
}

/* ── C2: incoming — Peer label + içerik ────────────────────────── */
static int test_incoming_content(void)
{
    static struct app_state st;
    char buf[512];

    TEST_ASSERT(capture_msg(buf, sizeof(buf), ui_print_incoming,
                            &st, "merhaba") > 0);
    TEST_ASSERT(strstr(buf, "Peer:") != NULL);
    TEST_ASSERT(strstr(buf, "merhaba") != NULL);
    return 0;
}

/* ── C3: outgoing — Sen label + içerik ─────────────────────────── */
static int test_outgoing_content(void)
{
    static struct app_state st;
    char buf[512];

    TEST_ASSERT(capture_msg(buf, sizeof(buf), ui_print_outgoing,
                            &st, "selam") > 0);
    TEST_ASSERT(strstr(buf, "Sen:") != NULL);
    TEST_ASSERT(strstr(buf, "selam") != NULL);
    return 0;
}

/* ── C4: incoming — ANSI strip atomic_message yolunda ────────────
 * attacker mesajı escape'siz çıkmalı (UI-1 / terminal injection). */
static int test_incoming_strips_ansi(void)
{
    static struct app_state st;
    char buf[512];

    TEST_ASSERT(capture_msg(buf, sizeof(buf), ui_print_incoming,
                            &st, "temiz\033[31mkirmizi\033[0m") > 0);
    TEST_ASSERT(strstr(buf, "\033[31m") == NULL);   /* escape düştü */
    TEST_ASSERT(strstr(buf, "temizkirmizi") != NULL);
    return 0;
}

/* ── C5: system — format + içerik ──────────────────────────────── */
static int test_system_content(void)
{
    static struct app_state st;
    char buf[512];

    int pipefd[2];
    if (pipe(pipefd) != 0) return 1;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    TEST_ASSERT(saved >= 0);
    TEST_ASSERT(dup2(pipefd[1], STDERR_FILENO) >= 0);

    ui_print_system(&st, "sistem %d", 42);

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    TEST_ASSERT(n > 0);
    buf[n] = '\0';

    TEST_ASSERT(strstr(buf, "sistem 42") != NULL);
    return 0;
}

/* ── C6: error — [!] label + içerik ────────────────────────────── */
static int test_error_content(void)
{
    static struct app_state st;
    char buf[512];

    int pipefd[2];
    if (pipe(pipefd) != 0) return 1;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    TEST_ASSERT(saved >= 0);
    TEST_ASSERT(dup2(pipefd[1], STDERR_FILENO) >= 0);

    ui_print_error(&st, "hata %s", "oldu");

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    TEST_ASSERT(n > 0);
    buf[n] = '\0';

    TEST_ASSERT(strstr(buf, "[!]") != NULL);
    TEST_ASSERT(strstr(buf, "hata oldu") != NULL);
    return 0;
}

/* ── C7: vsnprintf truncation — 4096 cap, crash'siz ────────────── */
static int test_system_truncation(void)
{
    static struct app_state st;
    char huge[8001];
    memset(huge, 'A', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';

    char *buf = malloc(16384);
    TEST_ASSERT(buf != NULL);

    int pipefd[2];
    if (pipe(pipefd) != 0) { free(buf); return 1; }
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    TEST_ASSERT(saved >= 0);
    TEST_ASSERT(dup2(pipefd[1], STDERR_FILENO) >= 0);

    ui_print_system(&st, "%s", huge);   /* msg[4096] → 4095 + NUL */

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], buf, 16383);
    close(pipefd[0]);
    TEST_ASSERT(n > 0);
    buf[n] = '\0';

    /* timestamp + renk escape'leri + cursor/prompt ≈ <128 byte ek;
     * içerik 4095'te kesildi (msg[4096] cap) — 4096+ ardışık A YOK */
    TEST_ASSERT(n < 4096 + 128);
    TEST_ASSERT(strstr(buf, "AAAA") != NULL);
    free(buf);
    return 0;
}

/* ── C8: progress — total==0 erken dönüş (çıktı YOK) ───────────── */
static int test_progress_zero_total(void)
{
    static struct app_state st;
    char buf[256];

    int pipefd[2];
    if (pipe(pipefd) != 0) return 1;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    TEST_ASSERT(saved >= 0);
    TEST_ASSERT(dup2(pipefd[1], STDERR_FILENO) >= 0);

    ui_print_progress(&st, "dosya", 0, 0, false);   /* total=0 → erken */

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    TEST_ASSERT(n <= 0);   /* erken return: hiçbir çıktı yok */
    return 0;
}

/* ── C9: progress — render: \r + yüzde + dosya adı ─────────────── */
static int test_progress_renders(void)
{
    static struct app_state st;
    char buf[512];

    int pipefd[2];
    if (pipe(pipefd) != 0) return 1;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    TEST_ASSERT(saved >= 0);
    TEST_ASSERT(dup2(pipefd[1], STDERR_FILENO) >= 0);

    ui_print_progress(&st, "rapor.txt", 100, 200, false);   /* %50 */

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    TEST_ASSERT(n > 0);
    buf[n] = '\0';

    TEST_ASSERT(strstr(buf, "\r") != NULL);        /* aynı satır güncellemesi */
    TEST_ASSERT(strstr(buf, "50%") != NULL);
    TEST_ASSERT(strstr(buf, "rapor.txt") != NULL);
    return 0;
}

/* ================================================================
 * fe_tui split — link + no-op (kısım D)
 * ================================================================ */

#ifndef HAVE_TERMBOX
/* ── D1: !TUI'da fe_tui_* no-op — crash/çıktı yok ───────────────
 * inline no-op'lar devrede; asıl amaç: fe_tui.c her iki modda da
 * derlenip linklenir, non-TUI'da ölü kod kalır. */
static int test_fe_tui_noop_no_termbox(void)
{
    static struct app_state st;
    char buf[256];

    int pipefd[2];
    if (pipe(pipefd) != 0) return 1;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    TEST_ASSERT(saved >= 0);
    TEST_ASSERT(dup2(pipefd[1], STDERR_FILENO) >= 0);

    fe_tui_msg_in(&st, "gelen");
    fe_tui_msg_out(&st, "giden");
    fe_tui_msg_system(&st, "sistem");
    fe_tui_msg_error(&st, "hata");
    fe_tui_progress(&st);

    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);
    TEST_ASSERT(n <= 0);   /* no-op: stderr'e hiçbir şey yazılmadı */
    return 0;
}
#endif /* !HAVE_TERMBOX */

/* ================================================================ */
int main(void)
{
    fprintf(stderr, "=== test_frontend.c — ortak frontend katmanı ===\n");

    /* ── A: dispatch iskeleti ── */
    RUN_TEST(test_emit_noop_without_backend);
    RUN_TEST(test_emit_null_event);
    RUN_TEST(test_emit_roundtrip_fields);
    RUN_TEST(test_register_last_wins);
    RUN_TEST(test_unregister_resets);

    /* ── B: fe_now_tm ── */
    RUN_TEST(test_now_tm_valid_fields);
    RUN_TEST(test_now_tm_mktime_roundtrip);

    /* ── C: bildirim yolları ── */
    RUN_TEST(test_incoming_empty_filtered);
    RUN_TEST(test_incoming_content);
    RUN_TEST(test_outgoing_content);
    RUN_TEST(test_incoming_strips_ansi);
    RUN_TEST(test_system_content);
    RUN_TEST(test_error_content);
    RUN_TEST(test_system_truncation);
    RUN_TEST(test_progress_zero_total);
    RUN_TEST(test_progress_renders);

    /* ── D: fe_tui split (yalnız non-TUI modda anlamlı) ── */
#ifdef HAVE_TERMBOX
    fprintf(stderr, "  [D] fe_tui no-op testi TUI modunda atlandı"
                    " (init'siz termbox'a dokunulmaz)\n");
#else
    RUN_TEST(test_fe_tui_noop_no_termbox);
#endif

    frontend_register(NULL, NULL);   /* kayıt bırakma */

    fprintf(stderr, "=== %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return (tests_run == tests_passed) ? 0 : 1;
}
