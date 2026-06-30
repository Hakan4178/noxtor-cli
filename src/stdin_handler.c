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

/* ================================================================
 * PER-PEER YARDIMCI FONKSİYONLAR
 * ================================================================ */

/* /list callback — her contact'ı listele */
static void list_visitor_cb(const char *onion, const char *name,
                            const uint8_t noise_key[NOX_KEY_LEN],
                            void *ctx) {
  (void)noise_key;
  struct app_state *state = (struct app_state *)ctx;

  /* Çevrimiçi durumunu kontrol et */
  bool online = false;
  for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
    if (state->peers[i].fd >= 0 &&
        strcmp(state->peers[i].peer_onion, onion) == 0) {
      online = true;
      break;
    }
  }

  char short_onion[12];
  snprintf(short_onion, sizeof(short_onion), "%.11s", onion);
  ui_print_system(state, "  %s %s %s",
                  online ? "●" : "○",
                  name[0] ? name : short_onion,
                  online ? "(çevrimiçi)" : "");
}

/* Aktif peer sayısını say */
int active_peer_count(struct app_state *state) {
  int count = 0;
  for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
    if (state->peers[i].fd >= 0)
      count++;
  }
  return count;
}

/* İsim veya onion ile peer bul */
static struct peer_session *find_peer_by_name_or_onion(struct app_state *state,
                                                        const char *arg) {
  for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
    struct peer_session *ps = &state->peers[i];
    if (ps->fd < 0 && ps->state == ST_IDLE)
      continue;
    if ((ps->name[0] && strcmp(ps->name, arg) == 0) ||
        strcmp(ps->peer_onion, arg) == 0) {
      return ps;
    }
  }
  /* Rehberde de ara — connect edilmemiş olabilir */
  if (!state->ghost_mode) {
    static char db_name_buf[NOX_CONTACT_NAME_LEN + 1];
    static uint8_t db_key_buf[NOX_KEY_LEN];
    if (db_get_contact(arg, db_name_buf, sizeof(db_name_buf), db_key_buf) == NOX_OK) {
      for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        struct peer_session *ps = &state->peers[i];
        if (ps->fd >= 0 && strcmp(ps->peer_onion, arg) == 0)
          return ps;
      }
    }
  }
  return NULL;
}

/* Ham terminal modunda ANSI kaçış dizilerini temizle — tüm türler:
 * CSI (ESC [), OSC (ESC ]), DCS (ESC P), tek ESC */
static void strip_ansi_escape(char *str) {
  if (!str) return;
  char *dst = str;
  const char *src = str;
  while (*src) {
    if ((unsigned char)*src == 0x1b) {
      if (src[1] == '[') {
        /* CSI: ESC [ <params> <final> */
        src += 2;
        while (*src && ((*src >= '0' && *src <= '?') ||
                        (*src >= ' ' && *src <= '/')))
          src++;
        if (*src) src++;
      } else if (src[1] == ']') {
        /* OSC: ESC ] <cmd> ; <data> BEL or ESC \ */
        src += 2;
        while (*src && (unsigned char)*src != 0x07 &&
               !(src[0] == 0x1b && src[1] == '\\'))
          src++;
        if ((unsigned char)*src == 0x07) src++;
        else if (src[0] == 0x1b && src[1] == '\\') src += 2;
      } else if (src[1] == 'P') {
        /* DCS: ESC P <data> ESC \ */
        src += 2;
        while (*src && !(src[0] == 0x1b && src[1] == '\\'))
          src++;
        if (src[0] == 0x1b && src[1] == '\\') src += 2;
      } else {
        /* Diğer tüm ESC sequence'leri — atla */
        if (src[1] != '\0')
          src += 2;
        else
          src++;  /* bare ESC — NUL'a kadar atla */
      }
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

/* ================================================================
 * MESAJ GÖNDERME VE KUYRUK YARDIMCILARI
 * ================================================================ */

/* Kuyruk flush context — doğru peer'a gönderim için */
struct queue_flush_ctx {
  struct app_state *state;
  struct peer_session *ps;
};

nox_err_t send_queued_callback(const char *text, void *ctx) {
  struct queue_flush_ctx *qctx = (struct queue_flush_ctx *)ctx;
  struct app_state *state = qctx->state;
  struct peer_session *ps = qctx->ps;
  if (!state || !ps || ps->fd < 0 || !ps->session)
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

  ssize_t ct_len = noise_encrypt(ps->session,
                                 (const uint8_t *)text,
                                 pt_len, payload);
  if (ct_len < 0) {
    sodium_free(payload);
    return NOX_ERR_CRYPTO;
  }

  struct frame_header fh = {
      .magic = NOX_FRAME_MAGIC,
      .type = NOX_MSG_TEXT,
      .seq = ps->tx_seq,
      .len = (uint32_t)ct_len,
  };
  uint8_t wire[FRAME_HEADER_WIRE_SIZE];
  frame_header_encode(&fh, wire);

  struct iovec iov[2] = {
      { .iov_base = (void *)wire,   .iov_len = FRAME_HEADER_WIRE_SIZE },
      { .iov_base = (void *)payload, .iov_len = (size_t)ct_len },
  };
  ssize_t written = writev(ps->fd, iov, 2);

  nox_err_t err = NOX_OK;
  if (written != (ssize_t)(FRAME_HEADER_WIRE_SIZE + (size_t)ct_len)) {
    err = NOX_ERR_IO;
  } else {
    ps->tx_seq++;
  }

  sodium_free(payload);   /* her durumda, otomatik sıfırlar */
  return err;
}

/* Uzun bir mesajı güvenli chunk'lara ayırıp sırayla şifreleyerek sokete yazar */
nox_err_t send_segmented_message(struct app_state *state, const char *msg) {
  struct peer_session *ps = ACTIVE_PEER(state);
  return send_segmented_message_to(state, ps, msg);
}

nox_err_t send_segmented_message_to(struct app_state *state,
                                    struct peer_session *ps,
                                    const char *msg) {
  (void)state;
  if (!ps || !ps->session || ps->fd < 0)
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
        noise_encrypt(ps->session, (const uint8_t *)chunk, pt_len, ct);
    if (ct_len < 0) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_CRYPTO;
    }

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_TEXT,
        .seq = ps->tx_seq,
        .len = (uint32_t)ct_len,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&fh, wire);

    struct iovec iov[2] = {
        { .iov_base = (void *)wire, .iov_len = FRAME_HEADER_WIRE_SIZE },
        { .iov_base = (void *)ct,   .iov_len = (size_t)ct_len },
    };
    ssize_t written = writev(ps->fd, iov, 2);
    if (written != (ssize_t)(FRAME_HEADER_WIRE_SIZE + (size_t)ct_len)) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_IO;
    }
    ps->tx_seq++;

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
  struct peer_session *ps = ACTIVE_PEER(state);

  /* ── TOFU Onay Modu ─────────────────── */
  if (ps && ps->state == ST_TOFU_PENDING) {
    if (strcasecmp(line, "y") == 0 || strcasecmp(line, "yes") == 0) {
      if (sm_dispatch(ps, state, EV_TOFU_ACCEPTED) != NOX_OK) {
        /* Session oluşturma başarısız — temizle */
        sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
      }
    } else if (strcasecmp(line, "n") == 0 || strcasecmp(line, "no") == 0) {
      ui_print_system(state, "[*] Bağlantı reddedildi.");
      sm_dispatch(ps, state, EV_TOFU_REJECTED);
    } else {
      fprintf(
          stderr,
          "  [?] Lütfen 'y' veya 'n' giriniz (y/n): "); /* raw — prompt değil */
    }
    return;
  }

  /* ── Komut modu — her zaman kontrol et (session aktif olsa bile) ─── */
  if (line[0] == '/') {
    if (strcmp(line, "/quit") == 0 || strcmp(line, "/exit") == 0) {
      state->running = false;
      return;
    }

    if (strcmp(line, "/help") == 0) {
      ui_print_system(state,
          "Komutlar:\n"
          "  /help               — bu yardımı göster\n"
          "  /quit               — uygulamadan çık\n"
          "  /addr               — .onion adresini göster\n"
          "  /connect <onion>    — peer'a bağlan\n"
          "  /disconnect         — aktif peer bağlantısını kes\n"
          "  /add <onion> <isim> — rehbere kişi ekle\n"
          "  /list               — rehberi ve çevrimiçi durumu listele\n"
          "  /switch <isim|onion>— aktif peer'ı değiştir\n"
          "  /msg <onion> <msj>  — mesaj gönder (çevrimdışıysa kuyruğa ekler)\n"
          "  /file <dosya_yolu>  — peer'a dosya gönder\n"
          "  /status             — bağlantı durumunu göster\n"
          "  /history            — mesaj geçmişini göster\n"
          "  Ctrl+P              — çıkış\n\n"
          "Bağlantı kurulduktan sonra yazdığınız her şey mesaj olarak gönderilir.");
      return;
    }

    if (strcmp(line, "/addr") == 0) {
      ui_print_system(state, "%s", state->onion_addr);
      return;
    }
  }

  /* ── Session aktifken: her satır mesaj ─── */
  if (ps && ps->session && ps->fd >= 0) {
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
  if ((!ps || ps->fd < 0) && line[0] != '/') {
    if (state->ghost_mode) {
      ui_print_error(state, "bağlantı yok — önce /connect kullan");
    } else {
      ui_print_error(state, "bağlantı yok — önce /connect kullan veya çevrimdışı "
                            "mesaj için /msg kullan");
    }
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

    nox_err_t err = db_add_contact(onion, name, zero_key);
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

    /* Tüm bağlı peer'larda aktif oturum ara */
    struct peer_session *target_ps = find_peer_by_name_or_onion(state, onion);
    if (target_ps && target_ps->session && target_ps->fd >= 0) {
      nox_err_t err = send_segmented_message_to(state, target_ps, msg_start);
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

    if (ps && ps->state != ST_IDLE) {
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

    /* Self-connection koruması */
    if (target_len == NOX_ONION_LEN &&
        memcmp(target, state->onion_addr, NOX_ONION_LEN) == 0) {
      ui_print_error(state, "kendi adresinize bağlanamazsınız");
      return;
    }

    /* Boş peer slotu bul */
    struct peer_session *target_ps = NULL;
    unsigned target_idx = 0;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
      if (state->peers[i].fd == -1 && state->peers[i].state == ST_IDLE) {
        target_ps = &state->peers[i];
        target_idx = i;
        break;
      }
    }
    if (!target_ps) {
      ui_print_error(state, "maksimum peer sayısına ulaşıldı");
      return;
    }

    /* Duplicate bağlantı kontrolü */
    for (unsigned j = 0; j < NOX_MAX_PEERS; j++) {
      if (j != target_idx && state->peers[j].fd >= 0 &&
          strcmp(state->peers[j].peer_onion, target) == 0) {
        ui_print_error(state, "Bu peer'a zaten bağlı");
        return;
      }
    }

    /* BUG-6 FIX: Rate limit kontrolü SOCKS5 öncesi */
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
        return;
      }
    }

    NOX_INFO(LOG_MOD_MAIN, "bağlanılıyor: %s", target);
    int peer_fd = -1;
    nox_err_t err =
        socks5_connect(target, NOX_VIRTUAL_PORT, state->socks_path, &peer_fd);
    if (err != NOX_OK) {
      ui_print_error(state, "bağlantı başarısız");
      return;
    }

    target_ps->fd = peer_fd;
    snprintf(target_ps->peer_onion, sizeof(target_ps->peer_onion),
             "%s", target);

    if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
      NOX_ERROR(LOG_MOD_MAIN, "epoll_ctl ADD başarısız — bağlantı iptal");
      close(peer_fd);
      target_ps->fd = -1;
      sodium_memzero(target_ps->peer_onion, sizeof(target_ps->peer_onion));
      ui_print_error(state, "bağlantı kayıt hatası");
      return;
    }
    NOX_INFO(LOG_MOD_MAIN, "peer bağlandı");

    /* Noise handshake — initiator */
    target_ps->hs = sodium_malloc(sizeof(struct noise_handshake));
    if (!target_ps->hs) {
      ui_print_error(state, "arena dolu");
      close(peer_fd);
      target_ps->fd = -1;
      sodium_memzero(target_ps->peer_onion, sizeof(target_ps->peer_onion));
      return;
    }

    handshake_init(target_ps->hs, true,
               state->my_static_priv,
               state->my_static_pub);
    clock_gettime(CLOCK_MONOTONIC, &target_ps->handshake_start);

    /* State geçişi: IDLE → HANDSHAKE_INIT */
    sm_dispatch(target_ps, state, EV_CONNECT_CMD);

    state->hs_attempt_count++;

    uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
    size_t hslen = sizeof(hsbuf);
    nox_err_t hs_err = handshake_write(target_ps->hs, NULL, 0, hsbuf, &hslen);
    if (hs_err != NOX_OK) {
      NOX_ERROR(LOG_MOD_NOISE, "handshake_write hatası: %s",
                nox_strerror(hs_err));
      ui_print_error(state, "Handshake başlatılamadı — bağlantı kesildi");
      sm_dispatch(target_ps, state, EV_HANDSHAKE_ERROR);
      return;
    }

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_CTRL,
        .seq = target_ps->tx_seq,
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
      sm_dispatch(target_ps, state, EV_HANDSHAKE_ERROR);
      return;
    }
    target_ps->tx_seq++;

    NOX_INFO(LOG_MOD_NOISE, "handshake msg0 gönderildi (tx_seq→%u)", target_ps->tx_seq);
    ui_print_system(state, "[*] handshake başlatıldı");
    state->active_peer_idx = (int)target_idx;
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

  /* ── /list — Rehberdeki kişileri listele ── */
  if (strcmp(line, "/list") == 0) {
    if (state->ghost_mode) {
      ui_print_error(state, "ghost mod — rehber kullanılamaz");
      return;
    }
    ui_print_system(state, "── Rehber ──");
    db_list_contacts(list_visitor_cb, state);
    ui_print_system(state, "── (%d bağlı) ──",
                    active_peer_count(state));
    return;
  }

  /* ── /switch <isim|onion> — Aktif peer'ı değiştir ── */
  if (strncmp(line, "/switch ", 8) == 0) {
    const char *arg = line + 8;
    while (*arg == ' ')
      arg++;
    if (*arg == '\0') {
      ui_print_error(state, "Kullanım: /switch <isim|onion>");
      return;
    }

    struct peer_session *found = find_peer_by_name_or_onion(state, arg);
    if (!found) {
      ui_print_error(state, "Peer bulunamadı: %s", arg);
      return;
    }

    /* active_peer_idx'yi güncelle */
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
      if (&state->peers[i] == found) {
        state->active_peer_idx = (int)i;
        strncpy(state->active_peer_onion, found->peer_onion, NOX_ONION_LEN);
        state->active_peer_onion[NOX_ONION_LEN] = '\0';
        ui_print_system(state, "Aktif peer: %s (%s)",
                        found->name[0] ? found->name : found->peer_onion,
                        sm_state_name(found->state));
        return;
      }
    }
    return;
  }

  /* ── /disconnect — Aktif peer'ın bağlantısını kes ── */
  if (strcmp(line, "/disconnect") == 0) {
    struct peer_session *ps_disconnect = ACTIVE_PEER(state);
    if (!ps_disconnect) {
      ui_print_error(state, "Aktif peer yok");
      return;
    }
    char name_buf[NOX_CONTACT_NAME_LEN + 1];
    strncpy(name_buf, ps_disconnect->name[0] ? ps_disconnect->name : "bilinmeyen",
            sizeof(name_buf) - 1);
    name_buf[sizeof(name_buf) - 1] = '\0';
    sm_dispatch(ps_disconnect, state, EV_PEER_DISCONNECTED);
    ui_print_system(state, "Bağlantı kesildi: %s", name_buf);
    return;
  }

  ui_print_system(state, "  /addr               — .onion adresini göster");
  ui_print_system(state, "  /connect <onion>    — peer'a bağlan");
  ui_print_system(state, "  /add <onion> <isim> — rehbere kişi ekle");
  ui_print_system(state, "  /msg <onion> <msj>  — kuyruklu mesaj gönder");
  ui_print_system(state, "  /file <dosya_yolu>  — dosya gönder (aktif bağlantı)");
  ui_print_system(state, "  /list               — rehberi listele");
  ui_print_system(state, "  /switch <isim>      — aktif sohbeti değiştir");
  ui_print_system(state, "  /disconnect         — bağlantıyı kes");
  ui_print_system(state, "  Ctrl+P              — çıkış");
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
