/* SPDX-License-Identifier: GPL-3.0-or-later
 * ui.c — noxtor-cli merkezi terminal UI katmanı
 *
 * Tüm kullanıcıya görünen çıktılar bu dosyadan geçer.
 * Tema renkleri tek bir struct'ta tanımlı ileride config'den okunabilir.
 *
 * Kritik tasarım: ui_save_input / ui_restore_input çifti sayesinde
 * gelen mesajlar kullanıcının yarım kalan girdisini ezmez.
 */

#include "ui.h"
#include "common.h"
#include "types.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ================================================================
 * VARSAYILAN TEMA — Kullanıcı paleti (truecolor 24-bit)
 *
 * [Sen]     → yeşil    rgb(38, 162, 105)
 * [Peer]   → mor      rgb(133, 60, 153)
 * Sistem    → amber    rgb(202, 151, 15)
 * Hata      → kırmızı  rgb(210, 24, 38)
 * Prompt    → teal     rgb(34, 105, 121)
 * Zaman     → koyu mavi rgb(31, 65, 117)
 * Progress  → teal     rgb(34, 105, 121)
 * ================================================================ */
const struct nox_theme nox_theme_default = {
    .clr_self = "\033[38;2;38;162;105m",
    .clr_peer = "\033[38;2;133;60;153m",
    .clr_system = "\033[38;2;202;151;15m",
    .clr_error = "\033[1;38;2;210;24;38m", /* bold + kırmızı */
    .clr_prompt = "\033[38;2;34;105;121m",
    .clr_timestamp = "\033[38;2;31;65;117m",
    .clr_progress = "\033[38;2;34;105;121m",
    .clr_reset = "\033[0m",
};

/* Aktif tema — ui_init() ile değiştirilebilir */
static const struct nox_theme *g_theme = &nox_theme_default;

/* ================================================================
 * TEMA BAŞLATMA
 * ================================================================ */
void ui_init(const struct nox_theme *theme) {
  g_theme = theme ? theme : &nox_theme_default;
}

/* ================================================================
 * ZAMAN DAMGASI — [HH:MM:SS] formatında (orta)
 * ================================================================ */
static void print_timestamp(void) {
  struct timespec ts;
memset(&ts, 0, sizeof(ts));

if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
  ts.tv_sec = 0;
}

struct tm tm_buf;
memset(&tm_buf, 0, sizeof(tm_buf));

localtime_r(&ts.tv_sec, &tm_buf);

  fprintf(stderr, "%s[%02d:%02d:%02d]%s ", g_theme->clr_timestamp,
          tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, g_theme->clr_reset);
}

/* ================================================================
 * STDIN BUFFER SAVE / RESTORE
 *
 * Gelen mesaj yazılmadan önce kullanıcının yarım girdisi kaydedilir.
 * Mesaj basıldıktan sonra prompt + yarım girdi geri yazılır.
 *
 * İç içe çağrı koruması: input_saved flag'i ile kontrol edilir.
 * ================================================================ */
void ui_save_input(struct app_state *state) {
  if (state->input_saved)
    return; /* zaten kaydedilmiş */
  state->input_saved = true;

  /* Mevcut satırı sil: imleci satır başına al, satırı temizle */
  fprintf(stderr, "\r\033[K");
  fflush(stderr);
}

void ui_restore_input(struct app_state *state) {
  if (!state->input_saved)
    return; /* kaydedilmemiş, restore gereksiz */
  state->input_saved = false;

  /* Prompt'u yeniden bas */
  ui_print_prompt(state);

  /* Kullanıcının yarım kalan girdisini geri yaz */
  if (state->stdin_len > 0 && state->stdin_buf) {
    fwrite(state->stdin_buf, 1, state->stdin_len, stderr);
  }
  fflush(stderr);
}

/* ================================================================
 * BAĞLAM DUYARLI PROMPT
 *
 * Bağlantı yok:       nox>
 * Bağlı:              [peer:abcd..wxyz] >
 * Dosya gönderiliyor:  [peer:abcd..wxyz ⬆45%] >
 * ================================================================ */
void ui_print_prompt(struct app_state *state) {
  fprintf(stderr, "%s", g_theme->clr_prompt);

  if (state->peer_fd >= 0 && state->active_peer_onion[0] != '\0') {
    /* Onion kısaltma: ilk 4 + ".." + son 4 (toplam 10 karakter) */
    size_t olen = strlen(state->active_peer_onion);
    /* .onion kısmını çıkar — sadece hash'in ilk/son 4'ü */
    char short_id[12];
    if (olen > 10) {
      /* onion adresinden .onion'u çıkar */
      size_t hash_len = olen;
      if (olen > 6 &&
          strcmp(state->active_peer_onion + olen - 6, ".onion") == 0) {
        hash_len = olen - 6;
      }
      snprintf(short_id, sizeof(short_id), "%.4s..%.4s",
               state->active_peer_onion,
               state->active_peer_onion + hash_len - 4);
    } else {
      snprintf(short_id, sizeof(short_id), "%.11s", state->active_peer_onion);
    }

    /* Dosya transferi progress göstergesi */
    if (state->tx_file.active && state->tx_file.total_size > 0) {
      unsigned pct = (unsigned)((state->tx_file.sent_bytes * 100) /
                                state->tx_file.total_size);
      fprintf(stderr, "[%s ⬆%u%%]", short_id, pct);
    } else if (state->rx_file.active && state->rx_file.expected_size > 0) {
      unsigned pct = (unsigned)((state->rx_file.received_bytes * 100) /
                                state->rx_file.expected_size);
      fprintf(stderr, "[%s ⬇%u%%]", short_id, pct);
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

void ui_print_incoming(struct app_state *state, const char *msg) {
  ui_save_input(state);

  print_timestamp();
  fprintf(stderr, "%s[Peer]%s %s\n", g_theme->clr_peer, g_theme->clr_reset,
          msg);

  ui_restore_input(state);
}

void ui_print_outgoing(struct app_state *state, const char *msg) {
  /* Kullanıcının girdiği ham satırı sil (zaten Enter'a bastı) */
  fprintf(stderr, "\033[1A\r\033[K");

  print_timestamp();
  fprintf(stderr, "%s[Sen]%s %s\n", g_theme->clr_self, g_theme->clr_reset, msg);

  ui_print_prompt(state);
  fflush(stderr);
}

/* ================================================================
 * SİSTEM VE HATA MESAJLARI
 * ================================================================ */

void ui_print_system(struct app_state *state, const char *fmt, ...) {
  ui_save_input(state);

  fprintf(stderr, "  %s", g_theme->clr_system);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "%s\n", g_theme->clr_reset);

  ui_restore_input(state);
}

void ui_print_error(struct app_state *state, const char *fmt, ...) {
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
 * ================================================================ */
static void format_size(uint64_t bytes, char *buf, size_t buf_sz) {
  if (bytes >= 1073741824ULL) {
    snprintf(buf, buf_sz, "%.1f GB", (double)bytes / 1073741824.0);
  } else if (bytes >= 1048576ULL) {
    snprintf(buf, buf_sz, "%.1f MB", (double)bytes / 1048576.0);
  } else if (bytes >= 1024ULL) {
    snprintf(buf, buf_sz, "%.1f KB", (double)bytes / 1024.0);
  } else {
    snprintf(buf, buf_sz, "%lu B", (unsigned long)bytes);
  }
}

void ui_print_progress(struct app_state *state, const char *filename,
                       uint64_t done, uint64_t total, bool is_upload) {
  (void)state; /* ileride save/restore gerekirse kullanılır */

  if (total == 0)
    return;

  unsigned pct = (unsigned)((done * 100ULL) / total);
  if (pct > 100)
    pct = 100;

  /* 16 karakterlik ASCII bar */
  int filled = (int)(pct * 16 / 100);
  char bar[17];
  for (int i = 0; i < 16; i++) {
    bar[i] = (i < filled) ? '=' : '-';
  }
  bar[16] = '\0';

  char done_str[32], total_str[32];
  format_size(done, done_str, sizeof(done_str));
  format_size(total, total_str, sizeof(total_str));

  const char *arrow = is_upload ? "⬆" : "⬇";

  fprintf(stderr, "\r\033[K  %s%s %s [%s] %u%% %s/%s%s", g_theme->clr_progress,
          arrow, filename, bar, pct, done_str, total_str, g_theme->clr_reset);
  fflush(stderr);
}
