/* SPDX-License-Identifier: GPL-3.0-or-later
 * stdin_handler.c — Terminal girdi ve komut yönetimi implementasyonu
 */

#include "stdin_handler.h"
#include "file_transfer.h"
#include "arena.h"
#include "common.h"
#include "database.h"
#include "network.h"
#include "noise.h"
#include "ui.h"
#include "tui.h"
#include "state_machine.h"

#ifdef HAVE_TERMBOX
#include "termbox2.h"
#endif

#include <errno.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sodium.h>
#include <stdbool.h>

/* ================================================================
 * YARDIMCI METOTLAR
 * ================================================================ */

/* UTF-8 multi-byte karakter sınırına göre bir sonraki güvenli bölme boyutunu bulur */
static size_t get_next_chunk_size(const char *msg, size_t offset, size_t total_len) {
  /* Underflow koruması */
  if (offset >= total_len) return 0;

  const size_t chunk_limit = 4000U;
  size_t remaining = total_len - offset;

  if (remaining <= chunk_limit) return remaining;

  /* Overflow koruması: offset + chunk_limit */
  if (offset > SIZE_MAX - chunk_limit) return chunk_limit;

  size_t size = chunk_limit;
  while (size > 0 && ((uint8_t)msg[offset + size] & 0xC0) == 0x80) {
    size--;
  }

  return (size == 0) ? 1 : size;
}

/* ================================================================
 * ONION ADRES DOĞRULAMA
 * ================================================================ */

static bool validate_onion_input(const char *onion, size_t len) {
  if (len != NOX_ONION_LEN) return false;   /* 56 + ".onion" = 62 */

  /* 56 base32 karakter — sadece lowercase (validate_onion_address ile uyumlu) */
  for (size_t i = 0; i < 56; i++) {
    char c = onion[i];
    bool ok = (c >= 'a' && c <= 'z') ||
              (c >= '2' && c <= '7');
    if (!ok) return false;
  }

  /* .onion suffix */
  return memcmp(onion + 56, ".onion", 6) == 0;
}

/* Ham terminal modunda ANSI kaçış dizilerini temizle.
 * ^[[A (Up), ^[[B (Down), ^[[C (Right), ^[[D (Left) gibi escape
 * sequence'leri stdin buffer'a girer ve metin olarak gönderilir.
 * Bu dizi: ESC '[' param final_char biçimindeki ANSI sequence'leri siler. */
static void strip_ansi_escape(char *str) {
  if (!str) return;
  char *dst = str;
  const char *src = str;
  while (*src) {
    if ((unsigned char)*src == 0x1b && src[1] == '[') {
      /* ANSI CSI sequence: ESC [ <params> <final char> */
      src += 2; /* ESC [ atla */
      while (*src && ((*src >= '0' && *src <= '?') ||
                      (*src >= ' ' && *src <= '/')))
        src++; /* parametreleri atla (n; m; vs.) */
      if (*src) src++; /* final char'ı atla (A-Z, a-z, `) */
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

/* ================================================================
 * MESAJ GÖNDERME VE KUYRUK YARDIMCILARI
 * ================================================================ */

nox_err_t send_queued_callback(const char *text, void *ctx) {
  struct app_state *state = (struct app_state *)ctx;
  if (!state || state->peer_fd < 0 || !state->session)
    return NOX_ERR_NET;

  size_t pt_len = strlen(text) + 1;

  /* Boyut kontrolü */
  if (pt_len > 4096) {
    NOX_WARN(LOG_MOD_MAIN,
             "queued mesaj çok uzun (%zu), atlanıyor", pt_len);
    return NOX_ERR_PROTO;
  }

  /* sodium_malloc — swap koruması */
  uint8_t *payload = sodium_malloc(4096 + NOX_MAC_LEN);
  if (!payload) return NOX_ERR_ALLOC;

  ssize_t ct_len = noise_encrypt(state->session,
                                 (const uint8_t *)text,
                                 pt_len, payload);
  if (ct_len < 0) {
    sodium_free(payload);
    return NOX_ERR_CRYPTO;
  }

  struct frame_header fh = {
      .magic = NOX_FRAME_MAGIC,
      .type = NOX_MSG_TEXT,
      .seq = state->tx_seq,
      .len = (uint32_t)ct_len,
  };
  uint8_t wire[FRAME_HEADER_WIRE_SIZE];
  frame_header_encode(&fh, wire);

  struct iovec iov[2] = {
      { .iov_base = (void *)wire,   .iov_len = FRAME_HEADER_WIRE_SIZE },
      { .iov_base = (void *)payload, .iov_len = (size_t)ct_len },
  };
  ssize_t written = writev(state->peer_fd, iov, 2);

  nox_err_t err = NOX_OK;
  if (written != (ssize_t)(FRAME_HEADER_WIRE_SIZE + (size_t)ct_len)) {
    err = NOX_ERR_IO;
  } else {
    state->tx_seq++;
  }

  sodium_free(payload);   /* her durumda, otomatik sıfırlar */
  return err;
}

/* Uzun bir mesajı güvenli chunk'lara ayırıp sırayla şifreleyerek sokete yazar */
nox_err_t send_segmented_message(struct app_state *state, const char *msg) {
  if (!state->session || state->peer_fd < 0)
    return NOX_ERR_NET;

  size_t total_len = strlen(msg);
  size_t offset = 0;

  uint8_t *ct    = sodium_malloc(4096 + NOX_MAC_LEN);
  char    *chunk = sodium_malloc(4096 + 1);   /* NUL için +1 */
  if (!ct || !chunk) {
    sodium_free(ct);
    sodium_free(chunk);
    return NOX_ERR_ALLOC;
  }

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    size_t pt_len = chunk_len + 1;
    ssize_t ct_len =
        noise_encrypt(state->session, (const uint8_t *)chunk, pt_len, ct);
    if (ct_len < 0) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_CRYPTO;
    }

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_TEXT,
        .seq = state->tx_seq,
        .len = (uint32_t)ct_len,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&fh, wire);

    struct iovec iov[2] = {
        { .iov_base = (void *)wire, .iov_len = FRAME_HEADER_WIRE_SIZE },
        { .iov_base = (void *)ct,   .iov_len = (size_t)ct_len },
    };
    ssize_t written = writev(state->peer_fd, iov, 2);
    if (written != (ssize_t)(FRAME_HEADER_WIRE_SIZE + (size_t)ct_len)) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_IO;
    }
    state->tx_seq++;

    offset += chunk_len;
  }

  sodium_free(chunk);
  sodium_free(ct);
  return NOX_OK;
}

/* Uzun bir mesajı güvenli chunk'lara ayırıp SQLite veritabanı kuyruğuna yazar */
nox_err_t queue_segmented_message(const char *recipient_onion, const char *msg) {
  size_t total_len = strlen(msg);
  size_t offset = 0;

  char *chunk = sodium_malloc(4096 + 1);   /* NUL için +1 */
  if (!chunk)
    return NOX_ERR_ALLOC;

  nox_err_t first_err = NOX_OK;

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    nox_err_t err = db_queue_message(recipient_onion, chunk);
    if (err != NOX_OK) {
      if (first_err == NOX_OK) {
        NOX_WARN(LOG_MOD_MAIN, "chunk %zu/%zu kuyruğa eklenemedi — kalan parça atlanıyor",
                 offset / 4096 + 1, (total_len + 4095) / 4096);
        first_err = err;
      }
      break; /* kısmi kuyruklama veri bütünlüğünü bozar */
    }

    offset += chunk_len;
  }

  sodium_free(chunk);
  return first_err;
}

/* ================================================================
 * ÇEKİRDEK GİRDİ İŞLEME
 * ================================================================ */

void process_line(struct app_state *state, const char *line) {
  /* ── TOFU Onay Modu ─────────────────── */
  if (state->peer_state == ST_TOFU_PENDING) {
    if (strcasecmp(line, "y") == 0 || strcasecmp(line, "yes") == 0) {
      if (sm_dispatch(state, EV_TOFU_ACCEPTED) != NOX_OK) {
        /* Session oluşturma başarısız — temizle */
        sm_dispatch(state, EV_PEER_DISCONNECTED);
      }
    } else if (strcasecmp(line, "n") == 0 || strcasecmp(line, "no") == 0) {
      ui_print_system(state, "[*] Bağlantı reddedildi.");
      sm_dispatch(state, EV_TOFU_REJECTED);
    } else {
      fprintf(
          stderr,
          "  [?] Lütfen 'y' veya 'n' giriniz (y/n): "); /* raw — prompt değil */
    }
    return;
  }

  /* ── Session aktifken: her satır mesaj ─── */
  if (state->session && state->peer_fd >= 0) {
    if (line[0] == '\0')
      return; /* boş satır gönderme */
    nox_err_t err = send_segmented_message(state, line);
    if (err == NOX_OK) {
      ui_print_outgoing(state, line);
    } else {
      ui_print_error(state, "Şifreleme/Gönderim hatası");
    }
    return;
  }

  /* ── Session yokken: komut modu ─────── */
  if (state->peer_fd < 0 && line[0] != '/') {
    if (state->ghost_mode) {
      ui_print_error(state, "bağlantı yok — önce /connect kullan");
    } else {
      ui_print_error(state, "bağlantı yok — önce /connect kullan veya çevrimdışı "
                            "mesaj için /msg kullan");
    }
    return;
  }

  if (strcmp(line, "/addr") == 0) {
    ui_print_system(state, "%s", state->onion_addr);
    return;
  }

  if (strncmp(line, "/add ", 5) == 0) {
    if (state->ghost_mode) {
      ui_print_error(state, "ghost mod aktif — rehbere kişi eklenemez");
      return;
    }
    const char *p = line + 5;
    while (*p == ' ')
      p++;

    const char *onion_start = p;
    while (*p && *p != ' ')
      p++;
    size_t onion_len = (size_t)(p - onion_start);

    if (onion_len != NOX_ONION_LEN || *p == '\0') {
      ui_print_error(state, "Geçersiz kullanım. Örnek: /add <onion> <isim>");
      return;
    }

    /* Onion adres format doğrulaması */
    if (!validate_onion_input(onion_start, onion_len)) {
      ui_print_error(state,
          "Geçersiz onion adresi formatı (56 base32 karakter + .onion)");
      return;
    }

    char onion[NOX_ONION_LEN + 1];
    memcpy(onion, onion_start, NOX_ONION_LEN);
    onion[NOX_ONION_LEN] = '\0';

    while (*p == ' ')
      p++;
    const char *name_start = p;
    if (*name_start == '\0') {
      ui_print_error(state, "Geçersiz kullanım. Örnek: /add <onion> <isim>");
      return;
    }

    char name[NOX_CONTACT_NAME_LEN + 1];
    snprintf(name, sizeof(name), "%s", name_start);

    uint8_t zero_key[NOX_KEY_LEN];
    sodium_memzero(zero_key, sizeof(zero_key));

    nox_err_t err = db_add_contact(onion, name, zero_key, NULL, NULL, 0);
    if (err == NOX_OK) {
      ui_print_system(state, "[✓] Rehbere kaydedildi: %s (%s)", name, onion);
    } else {
      ui_print_error(state, "Veritabanı hatası");
    }
    return;
  }

  if (strncmp(line, "/msg ", 5) == 0) {
    const char *p = line + 5;
    while (*p == ' ')
      p++;

    const char *onion_start = p;
    while (*p && *p != ' ')
      p++;
    size_t onion_len = (size_t)(p - onion_start);

    if (onion_len != NOX_ONION_LEN || *p == '\0') {
      ui_print_error(state, "Geçersiz kullanım. Örnek: /msg <onion> <mesaj>");
      return;
    }

    /* Onion adres format doğrulaması */
    if (!validate_onion_input(onion_start, onion_len)) {
      ui_print_error(state,
          "Geçersiz onion adresi (56 base32 karakter + .onion)");
      return;
    }

    char onion[NOX_ONION_LEN + 1];
    memcpy(onion, onion_start, NOX_ONION_LEN);
    onion[NOX_ONION_LEN] = '\0';

    while (*p == ' ')
      p++;
    const char *msg_start = p;
    if (*msg_start == '\0') {
      ui_print_error(state, "Geçersiz kullanım. Örnek: /msg <onion> <mesaj>");
      return;
    }

    if (state->session && state->peer_fd >= 0 &&
        strcmp(state->active_peer_onion, onion) == 0) {
      nox_err_t err = send_segmented_message(state, msg_start);
      if (err == NOX_OK) {
        ui_print_outgoing(state, msg_start);
      } else {
        ui_print_error(state, "Şifreleme/Gönderim hatası");
      }
    } else {
      if (state->ghost_mode) {
        ui_print_error(state, "ghost mod aktif — çevrimdışı mesaj kuyruğa alınamaz");
        return;
      }
      nox_err_t err = queue_segmented_message(onion, msg_start);
      if (err == NOX_OK) {
        ui_print_system(state, "[*] Mesaj kuyruğa eklendi (akran çevrimdışı)");
      } else {
        ui_print_error(state, "Kuyruğa ekleme başarısız");
      }
    }
    return;
  }

  if (strncmp(line, "/connect ", 9) == 0) {
    const char *target = line + 9;
    while (*target == ' ')
      target++;

    if (state->peer_state != ST_IDLE) {
      ui_print_error(state, "zaten bağlı veya handshake devam ediyor");
      return;
    }

    /* Onion adres doğrulaması */
    size_t target_len = strlen(target);
    if (!validate_onion_input(target, target_len)) {
      ui_print_error(state,
          "Geçersiz onion adresi (sadece .onion adresleri desteklenir)");
      return;
    }

    NOX_INFO(LOG_MOD_MAIN, "bağlanılıyor: %s", target);
    int peer_fd = -1;
    nox_err_t err =
        socks5_connect(target, NOX_VIRTUAL_PORT, state->socks_path, &peer_fd);
    if (err != NOX_OK) {
      ui_print_error(state, "bağlantı başarısız");
      return;
    }

    state->peer_fd = peer_fd;
    if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
      NOX_ERROR(LOG_MOD_MAIN, "epoll_ctl ADD başarısız — bağlantı iptal");
      close(peer_fd);
      state->peer_fd = -1;
      ui_print_error(state, "bağlantı kayıt hatası");
      return;
    }
    NOX_INFO(LOG_MOD_MAIN, "peer bağlandı");

    /* Noise handshake — initiator */
    state->session_arena_mark = arena_save(&state->arena);
    state->hs = arena_alloc(&state->arena, sizeof(struct noise_handshake));
    if (!state->hs) {
      ui_print_error(state, "arena dolu");
      close(peer_fd);
      state->peer_fd = -1;
      return;
    }

    handshake_init(state->hs, true,
               state->my_static_priv,
               state->my_static_pub);
    clock_gettime(CLOCK_MONOTONIC, &state->handshake_start);

    /* State geçişi: IDLE → HANDSHAKE_INIT
     * Rate limit kontrolünden ÖNCE yapılmalı — aksi halde
     * sm_dispatch(EV_RATE_LIMIT) ST_IDLE'da geçiş bulamaz. */
    state->peer_state = ST_HANDSHAKE_INIT;

    /* Handshake rate limiting — outbound connect */
    {
      time_t now = time(NULL);
      if (now - state->hs_window_start >= 60) {
        state->hs_attempt_count = 0;
        state->hs_window_start = now;
      }
      if (state->hs_attempt_count >= 5) {
        NOX_WARN(LOG_MOD_NOISE,
                 "Handshake rate limit aşıldı (5/60s) — outbound connect engellendi");
        ui_print_error(state, "Çok fazla handshake denemesi — biraz bekleyin.");
        sm_dispatch(state, EV_RATE_LIMIT);
        return;
      }
    }
    state->hs_attempt_count++;

    uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
    size_t hslen = sizeof(hsbuf);
    nox_err_t hs_err = handshake_write(state->hs, NULL, 0, hsbuf, &hslen);
    if (hs_err != NOX_OK) {
      NOX_ERROR(LOG_MOD_NOISE, "handshake_write hatası: %s",
                nox_strerror(hs_err));
      ui_print_error(state, "Handshake başlatılamadı — bağlantı kesildi");
      sm_dispatch(state, EV_HANDSHAKE_ERROR);
      return;
    }

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_CTRL,
        .seq = state->tx_seq,
        .len = (uint32_t)hslen,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&fh, wire);
    struct iovec iov[2] = {
        { .iov_base = (void *)wire,  .iov_len = FRAME_HEADER_WIRE_SIZE },
        { .iov_base = (void *)hsbuf, .iov_len = hslen },
    };
    ssize_t written = writev(peer_fd, iov, 2);
    if (written != (ssize_t)(FRAME_HEADER_WIRE_SIZE + hslen)) {
      NOX_ERROR(LOG_MOD_NOISE, "handshake msg0 gönderilemedi");
      ui_print_error(state, "Handshake başlatılamadı — bağlantı kesildi");
      sm_dispatch(state, EV_HANDSHAKE_ERROR);
      return;
    }
    state->tx_seq++;

    NOX_INFO(LOG_MOD_NOISE, "handshake msg0 gönderildi (tx_seq→%u)", state->tx_seq);
    ui_print_system(state, "[*] handshake başlatıldı");
    return;
  }

  /* ── /file <path> — Güvenli dosya gönderimi ── */
  if (strncmp(line, "/file ", 6) == 0) {
    const char *filepath = line + 6;
    while (*filepath == ' ')
      filepath++;

    file_transfer_start(state, filepath);
    return;
  }

  ui_print_system(state, "komutlar: /addr  /connect <onion>  /add <onion> "
                         "<isim>  /msg <onion> <mesaj>  /file <dosya>  Ctrl+P");
}

void process_stdin_events(struct app_state *state) {
  if (tui_is_active()) {
#ifdef HAVE_TERMBOX
    for (;;) {
      struct tb_event ev;
      int rc = tb_peek_event(&ev, 0);
      if (rc == TB_ERR_NO_EVENT)
        break;
      if (rc != TB_OK)
        break;
      if (ev.type == TB_EVENT_RESIZE) {
        tui_resize();
        tui_refresh_all(state);
        continue;
      }
      if (ev.type == TB_EVENT_KEY) {
        /* termbox2 key → int ch mapping */
        int ch;
        if (ev.ch)
          ch = (int)ev.ch;
        else
          ch = (int)ev.key;
        const char *line = tui_handle_input(state, ch);
        if (line) {
          process_line(state, line);
          /* Komut işlendi — input buffer'ı temizle */
          sodium_memzero(g_tui.input_buf, sizeof(g_tui.input_buf));
        }
      }
    }
#endif
    return;
  }

#define STDIN_BUF_MAX  (64 * 1024U)   /* 64 KB üst sınır */
#define STDIN_BUF_INIT 512U

  for (;;) {
    if (state->stdin_len + 512 >= state->stdin_cap) {
      /* Overflow koruması ve üst sınır */
      if (state->stdin_cap > STDIN_BUF_MAX / 2) {
        if (state->stdin_cap >= STDIN_BUF_MAX) {
          NOX_WARN(LOG_MOD_MAIN,
                   "stdin buffer limit aşıldı (%u KB), satır bekleniyor",
                   STDIN_BUF_MAX / 1024);
          sodium_memzero(state->stdin_buf, state->stdin_cap);
          state->stdin_len = 0;
          return;
        }
      }

      size_t new_cap = state->stdin_cap == 0
                       ? STDIN_BUF_INIT
                       : state->stdin_cap * 2;

      if (new_cap > STDIN_BUF_MAX) new_cap = STDIN_BUF_MAX;

      char *new_buf = sodium_malloc(new_cap);
      if (!new_buf) {
        NOX_ERROR(LOG_MOD_MAIN, "stdin buffer genişletme başarısız");
        return;
      }

      if (state->stdin_buf && state->stdin_len > 0) {
        memcpy(new_buf, state->stdin_buf, state->stdin_len);
      }
      new_buf[state->stdin_len] = '\0';

      if (state->stdin_buf) {
        sodium_free(state->stdin_buf);   /* otomatik sıfırlar */
      }

      state->stdin_buf = new_buf;
      state->stdin_cap = new_cap;
    }

    ssize_t r = read(STDIN_FILENO, state->stdin_buf + state->stdin_len,
                     state->stdin_cap - state->stdin_len - 1);
    if (r < 0) {
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
#else
      if (errno == EAGAIN) {
        break;
      }
#endif
      if (errno == EINTR) {
        continue;
      }
      NOX_ERROR(LOG_MOD_MAIN, "stdin read error: %s", strerror(errno));
      return;
    }

    if (r == 0) {
      if (state->stdin_len > 0) {
        process_line(state, state->stdin_buf);
        sodium_memzero(state->stdin_buf, state->stdin_cap);
        state->stdin_len = 0;
      }
      return;
    }

    state->stdin_len += (size_t)r;
    state->stdin_buf[state->stdin_len] = '\0';

    /* Echo: terminal raw mode'da echo kapalı, program kendi yazacak
     * Sadece son okunan byte'ları echo et (önceki döngüde zaten yazıldı)
     * NOT: strip_ansi_escape'dan ÖNCE hesapla — escape temizlenince
     * echo_start underflow olmasın */
    size_t old_len = state->stdin_len - (size_t)r;
    {
      /* Escape sequence temizle — ok tuşları, vb. */
      strip_ansi_escape(state->stdin_buf);
      state->stdin_len = strlen(state->stdin_buf);

      size_t echo_start = (state->stdin_len > old_len) ? old_len : state->stdin_len;
      for (size_t i = echo_start; i < state->stdin_len; i++) {
        unsigned char c = (unsigned char)state->stdin_buf[i];
        if (c == '\n' || c == '\r') {
          fprintf(stderr, "\n");
        } else if (c == '\x7f' || c == '\b') {
          /* Backspace: buffer'dan sil, ekrandan sil */
          if (state->stdin_len > 0) {
            state->stdin_len--;
            state->stdin_buf[state->stdin_len] = '\0';
            fprintf(stderr, "\b \b");
          }
        } else if (c >= 0x20 && c < 0x7f) {
          /* Yazdırılabilir karakter — echo et */
          fputc(c, stderr);
        }
        /* Diğer kontrol karakterleri (escape, vb.) — sessizce atla */
      }
      fflush(stderr);
    }

    /* Backspace işlendiyse newline kontrolünü atla */
    if (state->stdin_len == 0 || state->stdin_buf[state->stdin_len - 1] == '\0')
      continue;

    char *newline;
    while ((newline = memchr(state->stdin_buf, '\n', state->stdin_len)) != NULL) {
      size_t line_len = (size_t)(newline - state->stdin_buf);
      char *line = sodium_malloc(line_len + 1);
      if (!line) {
        NOX_ERROR(LOG_MOD_MAIN, "line buffer alloc başarısız — satır atlanıyor");
        size_t consumed = line_len + 1;
        size_t remaining = state->stdin_len - consumed;
        if (remaining > 0)
          memmove(state->stdin_buf, state->stdin_buf + consumed, remaining);
        state->stdin_len = remaining;
        state->stdin_buf[state->stdin_len] = '\0';
        continue;
      }
      memcpy(line, state->stdin_buf, line_len);
      line[line_len] = '\0';

      size_t consumed = line_len + 1;
      size_t remaining = state->stdin_len - consumed;
      if (remaining > 0) {
        memmove(state->stdin_buf, state->stdin_buf + consumed, remaining);
      }
      state->stdin_len = remaining;
      state->stdin_buf[state->stdin_len] = '\0';

      /* Satır sonundaki satır başı karakterini (\r) temizle */
      if (line_len > 0 && line[line_len - 1] == '\r') {
        line[line_len - 1] = '\0';
      }

      process_line(state, line);

      sodium_free(line);
    }
  }
}
