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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
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

  /* 56 base32 karakter */
  for (size_t i = 0; i < 56; i++) {
    char c = onion[i];
    bool ok = (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '2' && c <= '7');
    if (!ok) return false;
  }

  /* .onion suffix */
  return memcmp(onion + 56, ".onion", 6) == 0;
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
      .seq = state->tx_seq++,
      .len = (uint32_t)ct_len,
  };
  uint8_t wire[FRAME_HEADER_WIRE_SIZE];
  frame_header_encode(&fh, wire);

  nox_err_t err = NOX_OK;
  if (write_full(state->peer_fd, wire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
      write_full(state->peer_fd, payload, (size_t)ct_len) != NOX_OK) {
    err = NOX_ERR_IO;
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
        .seq = state->tx_seq++,
        .len = (uint32_t)ct_len,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&fh, wire);

    if (write_full(state->peer_fd, wire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
        write_full(state->peer_fd, ct, (size_t)ct_len) != NOX_OK) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_IO;
    }

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

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    nox_err_t err = db_queue_message(recipient_onion, chunk);
    if (err != NOX_OK) {
      sodium_free(chunk);
      return err;
    }

    offset += chunk_len;
  }

  sodium_free(chunk);
  return NOX_OK;
}

/* ================================================================
 * ÇEKİRDEK GİRDİ İŞLEME
 * ================================================================ */

void process_line(struct app_state *state, const char *line) {
  /* ── TOFU Onay Modu ─────────────────── */
  if (state->tofu_pending) {
    if (strcasecmp(line, "y") == 0 || strcasecmp(line, "yes") == 0) {
      /* hs geçerlilik kontrolü */
      if (!state->hs) {
        ui_print_error(state,
            "Handshake durumu geçersiz (peer ayrılmış olabilir)");
        state->tofu_pending = false;
        state->peer_fd = -1;
        return;
      }

      /* db_add_contact dönüş kontrolü */
      if (!state->ghost_mode) {
        nox_err_t db_err = db_add_contact(
            state->tofu_onion, state->tofu_name, state->tofu_new_key, NULL, NULL, 0);
        if (db_err != NOX_OK) {
          ui_print_error(state, "Rehbere kaydetme başarısız");
          /* devam et — session yine kurulabilir */
        }
      } else {
        NOX_INFO(LOG_MOD_MAIN, "ghost mod aktif — rehber kaydı atlandı");
      }

      state->session = arena_alloc(&state->arena, sizeof(struct noise_session));
      if (state->session) {
        handshake_split(state->hs, state->session);
        state->tx_seq = 0;
        state->rx_seq = 0;
        snprintf(state->active_peer_onion, sizeof(state->active_peer_onion), "%s", state->tofu_onion);

        NOX_INFO(LOG_MOD_NOISE, "session kuruldu — mesajlaşma hazır");
        ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)",
                        state->tofu_name);

        /* Kuyruktaki bekleyen mesajları gönder */
        if (!state->ghost_mode) {
          db_process_queue(state->active_peer_onion, send_queued_callback, state);
        }
      } else {
        ui_print_error(state, "Arena bellek hatası");
        close(state->tofu_peer_fd);
        state->peer_fd = -1;
        state->hs = NULL;
        arena_restore(&state->arena, state->tofu_arena_mark);
      }
      state->tofu_pending = false;
    } else if (strcasecmp(line, "n") == 0 || strcasecmp(line, "no") == 0) {
      ui_print_system(state, "[*] Bağlantı reddedildi.");
      close(state->tofu_peer_fd);
      state->peer_fd = -1;
      state->hs = NULL;
      state->session = NULL;
      arena_restore(&state->arena, state->tofu_arena_mark);
      state->tofu_pending = false;
    } else {
      fprintf(
          stderr,
          "  [?] Lütfen 'y' veya 'n' giriniz (y/n): "); /* raw — prompt değil */
    }
    return;
  }

  /* ── Session aktifken: her satır mesaj ─── */
  if (state->session && state->peer_fd >= 0) {
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

    if (state->peer_fd >= 0) {
      ui_print_error(state, "zaten bağlı");
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
        socks5_connect(target, NOX_VIRTUAL_PORT, state->socks_port, &peer_fd);
    if (err != NOX_OK) {
      ui_print_error(state, "bağlantı başarısız");
      return;
    }

    state->peer_fd = peer_fd;
    if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
      /* S2: epoll_ctl başarısız — fd + state sızıntısını engelle. */
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
      /* S2: arena_alloc başarısız — fd + peer_fd + epoll kaydını temizle.
       * Linux close() fd'yi epoll'den otomatik çıkarır, ayrıca
       * epoll_remove_fd gerekmez. */
      ui_print_error(state, "arena dolu");
      close(peer_fd);
      state->peer_fd = -1;
      return;
    }

    handshake_init(state->hs, true,
               state->my_static_priv,
               state->my_static_pub);
    state->handshake_start = time(NULL);

    uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
    size_t hslen = sizeof(hsbuf);
    handshake_write(state->hs, NULL, 0, hsbuf, &hslen);

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_CTRL,
        .seq = state->tx_seq++,
        .len = (uint32_t)hslen,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&fh, wire);
    write_full(peer_fd, wire, FRAME_HEADER_WIRE_SIZE);
    write_full(peer_fd, hsbuf, hslen);

    NOX_INFO(LOG_MOD_NOISE, "handshake msg0 gönderildi");
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
#ifdef HAVE_NCURSES
    for (;;) {
      int ch = wgetch(g_tui.input_win);
      if (ch == ERR) {
        break;
      }
      if (ch == KEY_RESIZE) {
        tui_resize();
        tui_refresh_all(state);
        continue;
      }
      const char *line = tui_handle_input(state, ch);
      if (line) {
        process_line(state, line);
        tui_refresh_all(state);
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

    char *newline;
    while ((newline = memchr(state->stdin_buf, '\n', state->stdin_len)) != NULL) {
      size_t line_len = (size_t)(newline - state->stdin_buf);
      char *line = sodium_malloc(line_len + 1);
      if (!line) {
        NOX_ERROR(LOG_MOD_MAIN, "line buffer alloc başarısız");
        return;
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

      /* TOFU veya normal girdi koruması */
      if (!state->tofu_pending) {
        ui_save_input(state);
      }

      process_line(state, line);

      if (!state->tofu_pending) {
        ui_restore_input(state);
      }

      sodium_free(line);
    }
  }
}
