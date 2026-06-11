/* SPDX-License-Identifier: GPL-3.0-or-later
 * main.c — noxtor-cli giriş noktası
 *
 * Init sırası:
 *   1. Log sistemi 
 *   2. libsodium init
 *   3. Config dizin kontrolü / bootstrap
 *   4. PIN oku (echo kapalı)
 *   5. Secure arena init
 *   6. Key derivation 
 *   7. Tor spawn 
 *   8. epoll event loop 
 *   9. Cleanup: arena_destroy, tor kill, exit
 *
 * Signal handling:
 *   SIGINT/SIGTERM → g_shutdown = 1 (async-signal-safe flag)
 *   epoll loop kontrol eder → cleanup → exit(0)
 */

#include "arena.h"
#include "asm_utils.h"
#include "common.h"
#include "crypto.h"
#include "database.h"
#include "network.h"
#include "noise.h"
#include "types.h"
#include "ui.h"
#include "stdin_handler.h"
#include "file_transfer.h"
#include "tui.h"
#include "seccomp_policy.h"

#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h> /* nanosleep, struct timespec */
#include <unistd.h>

#include <errno.h>
#include <libgen.h> /* basename */
#include <sodium.h>
#include <sys/epoll.h>
#include <assert.h>
#include <sys/socket.h>

/* ================================================================
 * GLOBAL SHUTDOWN FLAG — async-signal-safe
 *
 * g_shutdown tanımı log.c'de yaşar (test build'lerde main.c
 * hariç tutulduğundan). extern types.h'de bildirilmiş.
 * ================================================================ */

static struct termios g_orig_termios;
static bool g_termios_saved = false;

static void signal_handler(int sig) {
  (void)sig;
  g_shutdown = 1; /* sadece flag, başka hiçbir şey */
}

static void setup_signal_handlers(void) {
  struct sigaction sa = {
      .sa_handler = signal_handler,
      .sa_flags = 0,
  };
  sigemptyset(&sa.sa_mask);

  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL); /* Ctrl+P → temiz çıkış */

  /* SIGPIPE → ignore (broken pipe'da crash olmasın) */
  struct sigaction sa_ign = {
      .sa_handler = SIG_IGN,
      .sa_flags = 0,
  };
  sigemptyset(&sa_ign.sa_mask);
  sigaction(SIGPIPE, &sa_ign, NULL);
}

/* Ctrl+P (0x10) → SIGQUIT eşlemesi */
static void setup_terminal(void) {
  if (!isatty(STDIN_FILENO))
    return;

  if (tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
    g_termios_saved = true;

    struct termios raw = g_orig_termios;
    raw.c_cc[VQUIT] = 0x10; /* Ctrl+P → SIGQUIT */
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
  }
}

static void restore_terminal(void) {
  if (g_termios_saved) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
    g_termios_saved = false;
  }
}

/* ================================================================
 * CONFIG DİZİN YÖNETİMİ
 *
 * ~/.config/paranoidcli/ dizini ve alt dosyalarının yolu.
 * İlk çalıştırmada dizin oluşturulur.
 * ================================================================ */
static nox_err_t resolve_config_paths(struct app_state *state) {
  /* HOME dizinini bul */
  const char *home = getenv("HOME");
  if (!home || home[0] == '\0') {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
      NOX_ERROR(LOG_MOD_MAIN, "HOME dizini belirlenemedi");
      return NOX_ERR_CONFIG;
    }
    home = pw->pw_dir;
  }

  /* Config dizin yolu */
  int ret = snprintf(state->config_dir, sizeof(state->config_dir), "%s/%s",
                     home, PARANOID_CONFIG_DIR);
  if (ret < 0 || (size_t)ret >= sizeof(state->config_dir)) {
    NOX_ERROR(LOG_MOD_MAIN, "config dizin yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  /* HOME'u realpath ile normalize et, symlink traversal'i engelle */
  char resolved_home[PATH_MAX];
  if (realpath(home, resolved_home) == NULL) {
    NOX_ERROR(LOG_MOD_MAIN, "HOME dizini resolve edilemedi: %s", strerror(errno));
    return NOX_ERR_CONFIG;
  }
  ret = snprintf(state->config_dir, sizeof(state->config_dir), "%s/%s",
                 resolved_home, PARANOID_CONFIG_DIR);
  if (ret < 0 || (size_t)ret >= sizeof(state->config_dir)) {
    NOX_ERROR(LOG_MOD_MAIN, "config dizin yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  /*
   * Alt dosya yolları config_dir + "/identity.key" (en uzun: 13 char).
   * config_dir 498 byte'tan uzunsa alt yollar sığmaz.
   */
  size_t dir_len = strlen(state->config_dir);
  if (dir_len + 14 >= sizeof(state->identity_path)) {
    NOX_ERROR(LOG_MOD_MAIN, "config dizin yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  /* identity.key yolu — taşma yukarıda kontrol edildi */
  memcpy(state->identity_path, state->config_dir, dir_len);
  memcpy(state->identity_path + dir_len, "/identity.key", 14);

  /* contacts.db yolu */
  memcpy(state->contacts_path, state->config_dir, dir_len);
  memcpy(state->contacts_path + dir_len, "/contacts.db", 13);

  /* downloads dizini yolu */
  memcpy(state->downloads_dir, state->config_dir, dir_len);
  memcpy(state->downloads_dir + dir_len, "/downloads", 11);

  state->downloads_dir_fd = -1;

  return NOX_OK;
}

static nox_err_t ensure_config_dir(struct app_state *state) {
  struct stat st;

  if (stat(state->config_dir, &st) == 0) {
    /* Dizin zaten var */
    if (!S_ISDIR(st.st_mode)) {
      NOX_ERROR(LOG_MOD_MAIN, "%s bir dizin değil", state->config_dir);
      return NOX_ERR_CONFIG;
    }
    NOX_INFO(LOG_MOD_MAIN, "config dizini mevcut: %s", state->config_dir);
  } else {
    /* İlk çalıştırma — dizin oluştur */
    NOX_INFO(LOG_MOD_MAIN, "ilk çalıştırma tespit edildi");

    if (mkdir(state->config_dir, 0700) != 0) {
      /* Üst dizin (.config) olmayabilir — onu da oluştur */
      const char *home = getenv("HOME");
      if (!home || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "";
      }
      
      char parent[NOX_PATH_MAX];
      int r = snprintf(parent, sizeof(parent), "%s/.config", home);
      if (r < 0 || (size_t)r >= sizeof(parent)) {
        NOX_ERROR(LOG_MOD_MAIN, "parent dizin yolu çok uzun veya hatalı");
        return NOX_ERR_CONFIG;
      }
      mkdir(parent, 0700); /* zaten varsa hata önemsiz */

      if (mkdir(state->config_dir, 0700) != 0) {
        NOX_ERROR(LOG_MOD_MAIN, "config dizini oluşturulamadı: %s",
                  strerror(errno));
        return NOX_ERR_CONFIG;
      }
    }
    NOX_INFO(LOG_MOD_MAIN, "config dizini oluşturuldu: %s", state->config_dir);
  }

  if (mkdir(state->downloads_dir, 0700) != 0 && errno != EEXIST) {
    NOX_ERROR(LOG_MOD_MAIN, "downloads dizini oluşturulamadı: %s", strerror(errno));
    return NOX_ERR_CONFIG;
  }
  
  /* CodeQL #14 cpp/path-injection: downloads_dir config_dir + "/downloads" */
  assert(strncmp(state->downloads_dir, state->config_dir, strlen(state->config_dir)) == 0);
  state->downloads_dir_fd = open(state->downloads_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (state->downloads_dir_fd < 0) {
    NOX_ERROR(LOG_MOD_MAIN, "downloads dizini açılamadı: %s", strerror(errno));
    return NOX_ERR_CONFIG;
  }

  /*
   * first_run: identity.key dosyasına bak, dizine DEĞİL.
   *
   * Edge case'ler:
   *   - Dizin var ama identity.key yok (yarıda kesilmiş init)
   *     → first_run = true → yeniden üret
   *   - Dizin var + identity.key var
   *     → first_run = false → yükle
   *   - salt var ama identity.key yok
   *     → salt yeniden üretilir (idempotent), identity de üretilir
   */
  if (stat(state->identity_path, &st) == 0 && S_ISREG(st.st_mode)) {
    state->first_run = false;
    NOX_INFO(LOG_MOD_MAIN, "mevcut identity.key bulundu");
  } else {
    state->first_run = true;
    NOX_INFO(LOG_MOD_MAIN, "identity.key bulunamadı — ilk çalıştırma modu");
  }

  return NOX_OK;
}

/* validate_pin() — log.c'de tanımlı, common.h'de prototipi var */

/* ================================================================
 * PIN OKUMA — echo kapalı, güvenli
 *
 * Terminal echo'su kapatılır → PIN ekranda görünmez.
 * Interrupt gelirse echo geri açılır (cleanup).
 * ================================================================ */
static nox_err_t read_pin(char *pin_buf, size_t buf_size, bool confirm) {
  struct termios old_term;
  bool is_terminal = (tcgetattr(STDIN_FILENO, &old_term) == 0);

  if (is_terminal) {
    /* Terminal modu — echo kapat */
    struct termios new_term = old_term;
    new_term.c_lflag &= ~((tcflag_t)ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
  } else {
    NOX_DEBUG(LOG_MOD_MAIN, "stdin terminal değil — pipe modu");
  }

  fprintf(stderr, "[%s] PIN: ", PARANOID_APP_NAME);
  fflush(stderr);

  /* PIN oku */
  if (!fgets(pin_buf, (int)buf_size, stdin)) {
    if (is_terminal)
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    fprintf(stderr, "\n");
    return NOX_ERR_PIN;
  }
  fprintf(stderr, "\n");

  /* Truncation tespiti — fgets buffer'ı doldurmuşsa PIN kesilmiş */
  size_t len = strlen(pin_buf);
  if (len == buf_size - 1 && pin_buf[len - 1] != '\n') {
    if (is_terminal)
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    NOX_ERROR(LOG_MOD_MAIN, "PIN çok uzun: buffer aşıldı (maksimum %u byte)",
              NOX_PIN_MAX_LEN);
    sodium_memzero(pin_buf, buf_size);
    return NOX_ERR_PIN;
  }

  /* Newline'ı kaldır */
  if (len > 0 && pin_buf[len - 1] == '\n') {
    pin_buf[len - 1] = '\0';
    len--;
  }

  /* Doğrulama — test edilebilir fonksiyon */
  nox_err_t err = validate_pin(pin_buf, len);
  if (err != NOX_OK) {
    if (is_terminal)
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    sodium_memzero(pin_buf, buf_size);
    return err;
  }

  /* İlk çalıştırmada onay iste */
  if (confirm) {
    char confirm_buf[NOX_PIN_MAX_LEN + 2];

    fprintf(stderr, "[%s] PIN tekrar: ", PARANOID_APP_NAME);
    fflush(stderr);

    if (!fgets(confirm_buf, (int)sizeof(confirm_buf), stdin)) {
      if (is_terminal)
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
      sodium_memzero(pin_buf, buf_size);
      sodium_memzero(confirm_buf, sizeof(confirm_buf));
      fprintf(stderr, "\n");
      return NOX_ERR_PIN;
    }
    fprintf(stderr, "\n");

    /* Truncation tespiti — confirm_buf için */
    size_t clen = strlen(confirm_buf);
    if (clen == sizeof(confirm_buf) - 1 && confirm_buf[clen - 1] != '\n') {
      if (is_terminal)
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
      NOX_ERROR(LOG_MOD_MAIN, "Onay PIN çok uzun: buffer aşıldı");
      sodium_memzero(pin_buf, buf_size);
      sodium_memzero(confirm_buf, sizeof(confirm_buf));
      return NOX_ERR_PIN;
    }

    /* Newline kaldır */
    if (clen > 0 && confirm_buf[clen - 1] == '\n')
      confirm_buf[clen - 1] = '\0';

    /*
     * Sabit zamanlı karşılaştırma — her iki PIN'i de
     * buf_size kadar karşılaştır (uzunluk leak'i yok).
     *
     * Önce her ikisini de aynı boyutta buffer'a kopyala,
     * sonra sodium_memcmp ile karşılaştır.
     */
    char pad_a[NOX_PIN_MAX_LEN + 2];
    char pad_b[NOX_PIN_MAX_LEN + 2];
    sodium_memzero(pad_a, sizeof(pad_a));
    sodium_memzero(pad_b, sizeof(pad_b));
    memcpy(pad_a, pin_buf, len);
    memcpy(pad_b, confirm_buf, strlen(confirm_buf));

    int match = sodium_memcmp(pad_a, pad_b, sizeof(pad_a));

    sodium_memzero(pad_a, sizeof(pad_a));
    sodium_memzero(pad_b, sizeof(pad_b));
    sodium_memzero(confirm_buf, sizeof(confirm_buf));

    if (match != 0) {
      if (is_terminal)
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
      NOX_ERROR(LOG_MOD_MAIN, "PIN'ler eşleşmiyor");
      sodium_memzero(pin_buf, buf_size);
      return NOX_ERR_PIN;
    }
  }

  /* Terminal ayarlarını geri yükle */
  if (is_terminal)
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

  return NOX_OK;
}

/* ================================================================
 * CLEANUP — Güvenli çıkış
 * ================================================================ */
static void cleanup(struct app_state *state) {
  NOX_INFO(LOG_MOD_MAIN, "temizlik başlıyor...");
  tui_shutdown();
  restore_terminal();
  if (!state->ghost_mode) {
    db_close();
  }

  /* Key materyali — arena'da yaşar, arena_destroy sıfırlar */
  state->master_key = NULL;
  state->db_key = NULL;
  state->session_key = NULL;
  state->session = NULL;
  state->hs = NULL;

  /* Secure arena — explicit_bzero + munmap */
  arena_destroy(&state->arena);

  /* Async stdin buffer scrubbing and free */
  if (state->stdin_buf) {
    sodium_memzero(state->stdin_buf, state->stdin_cap);
    sodium_free(state->stdin_buf);
    state->stdin_buf = NULL;
    state->stdin_len = 0;
    state->stdin_cap = 0;
  }

  /* Tor — temiz kapanma (SIGNAL SHUTDOWN + waitpid) */
  tor_shutdown(state);

  /* File descriptor'ları kapat */
  if (state->listen_fd >= 0) {
    close(state->listen_fd);
    state->listen_fd = -1;
  }
  if (state->peer_fd >= 0) {
    close(state->peer_fd);
    state->peer_fd = -1;
  }
  if (state->epoll_fd >= 0) {
    close(state->epoll_fd);
    state->epoll_fd = -1;
  }
  if (state->downloads_dir_fd >= 0) {
    close(state->downloads_dir_fd);
    state->downloads_dir_fd = -1;
  }

  NOX_INFO(LOG_MOD_MAIN, "temizlik tamamlandı");
}


/* ================================================================
 * EVENT LOOP — epoll tabanlı async I/O
 *
 * Ayrı fonksiyon — stack frame'i main()'den izole.
 * 3+ fd izler: stdin, listen_fd, peer_fd (varsa).
 * ================================================================ */
static void event_loop(struct app_state *state) {
  struct epoll_event events[4];

  while (state->running && !g_shutdown) {
    /* Handshake timeout kontrolü (slot yorulması ve kilitlenmeyi önler) */
    if (state->hs && state->peer_fd >= 0) {
      if (time(NULL) - state->handshake_start > 30) {
        NOX_WARN(LOG_MOD_NOISE, "Handshake zaman aşımına uğradı");
        ui_print_error(state, "Akran ile handshake zaman aşımına uğradı.");
        int fd = state->peer_fd;
        epoll_remove_fd(state->epoll_fd, fd);
        close(fd);
        state->peer_fd = -1;
        state->hs = NULL;
        state->active_peer_onion[0] = '\0';
        arena_restore(&state->arena, state->session_arena_mark);
      }
    }

    int nfds = epoll_wait(state->epoll_fd, events, 4, 2000);

    if (nfds < 0) {
      if (errno == EINTR)
        continue;
      NOX_ERROR(LOG_MOD_MAIN, "epoll_wait: %s", strerror(errno));
      break;
    }

    for (int i = 0; i < nfds; i++) {
      int fd = events[i].data.fd;

      if (fd == STDIN_FILENO) {
        process_stdin_events(state);
      } else if (fd == state->listen_fd) {
        /* ── Gelen peer bağlantısı ───────── */
        int peer_fd =
            accept4(state->listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (peer_fd < 0)
          continue;

        if (state->peer_fd >= 0) {
          NOX_WARN(LOG_MOD_MAIN, "zaten peer var — reddedildi");
          close(peer_fd);
          continue;
        }

        state->peer_fd = peer_fd;
        if (epoll_add_fd(state->epoll_fd, peer_fd) != NOX_OK) {
          /* S2: epoll_ctl başarısız (örn. EMFILE) — fd sızıntısını
           * engelle, "bağlandı" yanılsamasını kır. */
          NOX_ERROR(LOG_MOD_MAIN, "epoll_ctl ADD başarısız — bağlantı reddedildi");
          close(peer_fd);
          state->peer_fd = -1;
          continue;
        }

        state->session_arena_mark = arena_save(&state->arena);
        state->hs = arena_alloc(&state->arena, sizeof(struct noise_handshake));
        if (!state->hs) {
          close(peer_fd);
          state->peer_fd = -1;
          continue;
        }

        handshake_init(state->hs, false,
               state->my_static_priv,
               state->my_static_pub);    
        state->handshake_start = time(NULL);

        NOX_INFO(LOG_MOD_MAIN, "gelen peer kabul edildi");
        ui_print_system(state, "[*] gelen bağlantı — handshake bekleniyor");

      } else if (fd == state->peer_fd) {
        /* ── Peer'a Veri Gönderimi (EPOLLOUT) ────── */
        if (events[i].events & EPOLLOUT) {
          if (state->tx_file.active) {
            file_transfer_handle_tx(state);
          } else {
            epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
          }
        }

        /* ── Peer'dan Veri Alımı (EPOLLIN) ───────── */
        if (events[i].events & EPOLLIN) {
          uint8_t wire[FRAME_HEADER_WIRE_SIZE];

          /* İlk byte'ı oku — bağlantı durumunu kontrol et */
          ssize_t r = read(fd, wire, 1);
          if (r <= 0) {
            if (errno == EINTR)
              continue;
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
              break;
#else
            if (r < 0 && (errno == EAGAIN))
              break;
#endif

            NOX_INFO(LOG_MOD_MAIN, "peer bağlantısı kapandı");
            epoll_remove_fd(state->epoll_fd, fd);
            close(fd);
            state->peer_fd = -1;
            state->session = NULL;
            state->hs = NULL;
            state->active_peer_onion[0] = '\0';
            arena_restore(&state->arena, state->session_arena_mark);

            /* Faz 6.2 Step 7: Aktif dosya transferlerini temizle */
            file_transfer_cleanup(state);

            ui_print_system(state, "[*] peer ayrıldı");
            continue;
          }

          /* Kalan header byte'larını tam oku (partial read koruması) */
          if (read_full(fd, wire + 1, FRAME_HEADER_WIRE_SIZE - 1) != NOX_OK) {
            NOX_ERROR(LOG_MOD_NET, "frame header eksik okundu");
            continue;
          }

          struct frame_header fh;
          if (frame_header_decode(wire, &fh) != NOX_OK)
            continue;

          /* A-1 FIX: Boyut sınırı kontrolü */
          if (fh.len == 0 || fh.len > 4096 + NOX_MAC_LEN) {
            NOX_WARN(LOG_MOD_NET, "geçersiz frame boyutu: %u", fh.len);
            continue;
          }

          /* A-1 FIX: sodium_malloc — swap koruması + guard page
           * fh.len zaten 0 < fh.len <= 4096+NOX_MAC_LEN olarak sınırlandırıldı */
          uint8_t *payload = sodium_malloc(fh.len);
          if (!payload)
            continue;

          /* Payload'u tam oku (partial read koruması) */
          if (read_full(fd, payload, fh.len) != NOX_OK) {
            NOX_ERROR(LOG_MOD_NET, "frame payload eksik okundu");
            sodium_free(payload);
            continue;
          }

          if (fh.type == NOX_MSG_CTRL && state->hs) {
            uint8_t pl[64];
            size_t pl_len = sizeof(pl);
            nox_err_t hs_err =
                handshake_read(state->hs, payload, fh.len, pl, &pl_len);
            if (hs_err != NOX_OK) {
              NOX_ERROR(LOG_MOD_NOISE, "Handshake okuma hatası: %s",
                        nox_strerror(hs_err));
              ui_print_error(
                  state, "Akran ile handshake el sıkışması başarısız oldu.");
              close(fd);
              state->peer_fd = -1;
              state->hs = NULL;
              state->active_peer_onion[0] = '\0';
              arena_restore(&state->arena, state->session_arena_mark);
              sodium_free(payload);
              continue;
            }

            if (state->hs->msg_index < 3) {
              uint8_t hsbuf[NOISE_MAX_HANDSHAKE_LEN];
              size_t hslen = sizeof(hsbuf);
              handshake_write(state->hs, (const uint8_t *)state->onion_addr,
                              NOX_ONION_LEN + 1, hsbuf, &hslen);

              struct frame_header rfh = {
                  .magic = NOX_FRAME_MAGIC,
                  .type = NOX_MSG_CTRL,
                  .seq = state->tx_seq++,
                  .len = (uint32_t)hslen,
              };
              uint8_t rwire[FRAME_HEADER_WIRE_SIZE];
              frame_header_encode(&rfh, rwire);
              if (write_full(fd, rwire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
                  write_full(fd, hsbuf, hslen) != NOX_OK) {
                NOX_ERROR(LOG_MOD_NOISE, "handshake yanıtı gönderilemedi");
                ui_print_error(state, "Handshake yanıtı gönderilemedi");
                close(fd);
                state->peer_fd = -1;
                state->hs = NULL;
                state->active_peer_onion[0] = '\0';
                arena_restore(&state->arena, state->session_arena_mark);
                continue;
              }
              NOX_INFO(LOG_MOD_NOISE, "handshake yanıt");
            }

            if (state->hs->msg_index >= 3) {
              char peer_onion[NOX_ONION_LEN + 1];
              sodium_memzero(peer_onion, sizeof(peer_onion));

              if (pl_len == NOX_ONION_LEN + 1 && pl[NOX_ONION_LEN] == '\0') {
                memcpy(peer_onion, pl, NOX_ONION_LEN + 1);
              } else {
                NOX_ERROR(LOG_MOD_NOISE,
                          "Handshake payload geçersiz veya eksik");
                ui_print_error(state, "Akran geçerli bir adres iletmedi");
                close(fd);
                state->peer_fd = -1;
                state->hs = NULL;
                state->active_peer_onion[0] = '\0';
                arena_restore(&state->arena, state->session_arena_mark);
                sodium_free(payload);
                continue;
              }

              char name[NOX_CONTACT_NAME_LEN + 1];
              uint8_t stored_key[NOX_KEY_LEN];
              sodium_memzero(name, sizeof(name));
              sodium_memzero(stored_key, sizeof(stored_key));

              nox_err_t db_err = NOX_ERR_DB;
              if (!state->ghost_mode) {
                db_err = db_get_contact(peer_onion, name, sizeof(name), stored_key, NULL, 0, NULL, NULL);
              }
              uint8_t remote_pub[NOX_KEY_LEN];
              memcpy(remote_pub, state->hs->rs, NOX_KEY_LEN);

              char fp_str[NOX_KEY_LEN * 2 + 1];
              for (size_t k = 0; k < NOX_KEY_LEN; k++) {
                snprintf(&fp_str[k * 2], sizeof(fp_str) - (k * 2), "%02x", remote_pub[k]);
              }

              bool zero_key = true;
              for (size_t k = 0; k < NOX_KEY_LEN; k++) {
                if (stored_key[k] != 0) {
                  zero_key = false;
                  break;
                }
              }

              if (db_err == NOX_OK && !zero_key) {
                /* E-1 FIX: sodium_memcmp — sabit zamanlı karşılaştırma, timing saldırısı koruması */
                if (sodium_memcmp(stored_key, remote_pub, NOX_KEY_LEN) == 0) {
                  state->session =
                      arena_alloc(&state->arena, sizeof(struct noise_session));
                  if (state->session) {
                    handshake_split(state->hs, state->session);
                    state->tx_seq = 0;
                    state->rx_seq = 0;
                    strncpy(state->active_peer_onion, peer_onion,
                            NOX_ONION_LEN);
                    state->active_peer_onion[NOX_ONION_LEN] = '\0';

                    NOX_INFO(LOG_MOD_NOISE,
                             "session kuruldu — mesajlaşma hazır");
                    ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)",
                                    name);

                    if (!state->ghost_mode) {
                      db_process_queue(state->active_peer_onion,
                                       send_queued_callback, state);
                    }
                  } else {
                    ui_print_error(state, "Arena bellek hatası");
                    close(fd);
                    state->peer_fd = -1;
                    state->active_peer_onion[0] = '\0';
                    state->hs = NULL;
                    arena_restore(&state->arena, state->session_arena_mark);
                  }
                } else {
                  ui_save_input(state);
                  fprintf(stderr, "\n\033[31m  [!] UYARI: AKRANIN ANAHTARI "
                                  "DEĞİŞMİŞ! (MITM RİSKİ)\033[0m\n");
                  fprintf(stderr, "      Adres: %s\n", peer_onion);
                  fprintf(stderr, "      Kayıtlı İsim: %s\n", name);
                  fprintf(stderr, "      \033[1;31mYeni Fingerprint: %s\033[0m\n", fp_str);
                  fprintf(stderr,
                          "  [?] Yeni anahtarı onaylıyor musunuz? (y/n): ");
                  fflush(stderr);
                  ui_restore_input(state);

                  state->tofu_pending = true;
                  state->tofu_peer_fd = fd;
                  strncpy(state->tofu_onion, peer_onion, NOX_ONION_LEN);
                  state->tofu_onion[NOX_ONION_LEN] = '\0';
                  strncpy(state->tofu_name, name, NOX_CONTACT_NAME_LEN);
                  state->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
                  memcpy(state->tofu_new_key, remote_pub, NOX_KEY_LEN);
                  state->tofu_arena_mark = state->session_arena_mark;
                }
               } else {
                ui_save_input(state);
                fprintf(stderr,
                        "\n\033[33m  [!] TOFU: Yeni peer bağlantısı\033[0m\n");
                fprintf(stderr, "      Adres: %s\n", peer_onion);
                fprintf(stderr, "      \033[1;36mFingerprint: %s\033[0m\n", fp_str);
                fprintf(stderr, "  [?] Bu bağlantıyı onaylıyor ve rehbere "
                                "kaydediyor musunuz? (y/n): ");
                fflush(stderr);
                ui_restore_input(state);

                char default_name[NOX_CONTACT_NAME_LEN + 1];
                if (db_err == NOX_OK && zero_key && name[0] != '\0') {
                  snprintf(default_name, sizeof(default_name), "%s", name);
                } else {
                  snprintf(default_name, sizeof(default_name), "peer_%.8s",
                           peer_onion);
                }
                default_name[NOX_CONTACT_NAME_LEN] = '\0';

                state->tofu_pending = true;
                state->tofu_peer_fd = fd;
                strncpy(state->tofu_onion, peer_onion, NOX_ONION_LEN);
                state->tofu_onion[NOX_ONION_LEN] = '\0';
                strncpy(state->tofu_name, default_name, NOX_CONTACT_NAME_LEN);
                state->tofu_name[NOX_CONTACT_NAME_LEN] = '\0';
                memcpy(state->tofu_new_key, remote_pub, NOX_KEY_LEN);
                state->tofu_arena_mark = state->session_arena_mark;
              }
            }
          } else if ((fh.type == NOX_MSG_TEXT || fh.type == NOX_MSG_FILE) &&
                     state->session) {
            /* Sequence Number Doğrulaması (Y1) */
            if (fh.seq != state->rx_seq) {
              NOX_WARN(LOG_MOD_NET,
                       "Beklenmeyen seq: %u (beklenen: %u). Bağlantı "
                       "sonlandırılıyor.",
                       fh.seq, state->rx_seq);
              ui_print_error(state,
                             "Hata: Akran bağlantısında geçersiz sıra numarası "
                             "algılandı (Replay Attack veya paket kaybı)!");
              close(fd);
              state->peer_fd = -1;
              state->session = NULL;
              state->active_peer_onion[0] = '\0';
              arena_restore(&state->arena, state->session_arena_mark);
              sodium_free(payload);
              continue;
            }
            state->rx_seq++;

            if (fh.type == NOX_MSG_TEXT) {
              /* A-1 FIX: sodium_malloc ile swap koruması */
              size_t max_pt = fh.len; /* MAC çıkarılmadan üst sınır */
              uint8_t *pt = sodium_malloc(max_pt + 1);
              if (pt) {
                ssize_t pt_len =
                    noise_decrypt(state->session, payload, fh.len, pt);
                /* A-1 FIX: pt_len overflow kontrolü */
                if (pt_len > 0 && (size_t)pt_len <= max_pt) {
                  pt[pt_len] = '\0';
                  ui_print_incoming(state, (const char *)pt);
                }
                sodium_free(pt); /* otomatik sıfırlar */
              }
            } else if (fh.type == NOX_MSG_FILE) {
              file_transfer_handle_rx(state, payload, fh.len);
            }
          }

          /* Payload Cleanup — Tüm mesaj tipleri için çalışır */
          sodium_free(payload);
        }
      }
    }
  }
}

/* ================================================================
 * TRANSPORT SEÇİMİ — Pluggable Transport (Faz 6.2)
 * ================================================================ */
static void prompt_transport_selection(struct app_state *state) {
    fprintf(stderr, "\n[?] Bağlantı yöntemi seçin:\n"
                    "    [D] Direct (Doğrudan Tor bağlantısı)\n"
                    "    [S] Snowflake (Sansür delme - WebRTC)\n"
                    "    [O] OBFS4 (Sansür delme - Gizlenmiş Köprü)\n"
                    "Seçiminiz [D/S/O] (Varsayılan: D): ");
    fflush(stderr);

    char choice[16];
    if (fgets(choice, sizeof(choice), stdin) == NULL) {
      state->transport_type = TRANSPORT_DIRECT;
      return;
    }

    /* Strip newline/whitespaces */
    char c = 'D';
    for (int i = 0; choice[i] != '\0'; i++) {
      if (choice[i] != ' ' && choice[i] != '\t' && choice[i] != '\n' &&
          choice[i] != '\r') {
        c = choice[i];
        break;
      }
    }

    if (c == 's' || c == 'S') {
      state->transport_type = TRANSPORT_SNOWFLAKE;
      /* Binary varlığını denetle */
      if (access("/usr/bin/snowflake-client", X_OK) != 0 &&
          access("/usr/local/bin/snowflake-client", X_OK) != 0) {
        NOX_WARN(LOG_MOD_TOR,
                 "snowflake-client belirtilen yollarda bulunamadı "
                 "(/usr/bin/snowflake-client). Bağlantı başarısız olabilir.");
      }
    } else if (c == 'o' || c == 'O') {
      state->transport_type = TRANSPORT_OBFS4;
      /* Binary varlığını denetle */
      if (access("/usr/bin/obfs4proxy", X_OK) != 0 &&
          access("/usr/local/bin/obfs4proxy", X_OK) != 0) {
        NOX_WARN(LOG_MOD_TOR,
                 "obfs4proxy belirtilen yollarda bulunamadı "
                 "(/usr/bin/obfs4proxy). Bağlantı başarısız olabilir.");
      }

      fprintf(stderr, "[?] OBFS4 Köprü satırını girin (Yerleşik köprüler için "
                      "boş bırakın):\n> ");
      fflush(stderr);

      memset(state->obfs4_bridge_line, 0, sizeof(state->obfs4_bridge_line));
      if (fgets(state->obfs4_bridge_line, sizeof(state->obfs4_bridge_line),
                stdin) != NULL) {
        /* Trim trailing newline and spaces */
        size_t len = strlen(state->obfs4_bridge_line);
        while (len > 0 && (state->obfs4_bridge_line[len - 1] == '\n' ||
                           state->obfs4_bridge_line[len - 1] == '\r' ||
                           state->obfs4_bridge_line[len - 1] == ' ' ||
                           state->obfs4_bridge_line[len - 1] == '\t')) {
          state->obfs4_bridge_line[len - 1] = '\0';
          len--;
        }

        /* Sanitize input: no control characters, printable ASCII only */
        for (size_t i = 0; i < len; i++) {
          char ch = state->obfs4_bridge_line[i];
          if (ch < 32 || ch > 126) {
            fprintf(stderr, "[!] HATA: Geçersiz karakterler tespit edildi. "
                            "Yerleşik köprülere dönülüyor.\n");
            memset(state->obfs4_bridge_line, 0,
                   sizeof(state->obfs4_bridge_line));
            break;
          }
        }
      }
    } else {
      state->transport_type = TRANSPORT_DIRECT;
    }
  }

  /* ================================================================
   * ANA GİRİŞ NOKTASI
   * ================================================================ */
  int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /* Struct'ı sıfırla — tüm fd'ler -1 olmalı */
    struct app_state state = {
        .tor_ctrl_fd = -1,
        .tor_pid = 0,
        .epoll_fd = -1,
        .listen_fd = -1,
        .peer_fd = -1,
        .running = true,
        .first_run = false,
        .tx_file = { .fd = -1, .active = false },  /* G-2 FIX */
        .rx_file = { .fd = -1, .active = false },  /* G-2 FIX */
    };

    nox_err_t err;

    /* ── 0. Komut satırı argümanları ───────────────────── */
    bool ghost_mode = false;
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--ghost") == 0 || strcmp(argv[i], "-ghost") == 0) {
        ghost_mode = true;
      }
    }
    state.ghost_mode = ghost_mode;

    if (argc >= 2 && strcmp(argv[1], "--full_cleankeys") == 0) {
      /*
       * Hesap silme — tüm key materyalini güvenli şekilde yok et.
       *
       * 1. Config yollarını çöz
       * 2. Her dosyayı sıfırla (overwrite) + sil
       * 3. Dizini kaldır
       */
      err = resolve_config_paths(&state);
      if (err != NOX_OK) {
        fprintf(stderr, "[!] config yolları çözülemedi\n");
        return 1;
      }

      /* Güvenli silme: dosya içeriğini sıfırla, sonra unlink */
      const char *files[] = {
          state.identity_path, NULL /* sentinel */
      };

      /* Salt dosyası yolunu oluştur */
      size_t dir_len = strlen(state.config_dir);
      if (dir_len + 14 >= NOX_PATH_MAX) {
        fprintf(stderr, "[!] config yolu çok uzun\n");
        return 1;
      }

      char salt_path[NOX_PATH_MAX];
      memcpy(salt_path, state.config_dir, dir_len);
      memcpy(salt_path + dir_len, "/salt", 6); /* 5 + NUL */

      /* contacts.db */
      char db_path[NOX_PATH_MAX];
      memcpy(db_path, state.config_dir, dir_len);
      memcpy(db_path + dir_len, "/contacts.db", 13); /* 12 + NUL */

      const char *all_files[] = {state.identity_path, salt_path, db_path,
                                 state.contacts_path, NULL};

      int wiped = 0;
      for (int i = 0; all_files[i] != NULL; i++) {
        /* CodeQL #11 cpp/path-injection: tüm dosya yolları config_dir'den türetilmiştir */
        assert(strncmp(all_files[i], state.config_dir, dir_len) == 0);
        struct stat st;
        if (stat(all_files[i], &st) != 0)
          continue; /* dosya yok — sorun değil */

        /* Dosyayı sıfırlarla üzerine yaz */
        int fd = open(all_files[i], O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
          uint8_t zeros[256];
          memset(zeros, 0, sizeof(zeros));
          off_t remaining = st.st_size;
          while (remaining > 0) {
            size_t chunk = (size_t)remaining < sizeof(zeros) ? (size_t)remaining
                                                             : sizeof(zeros);
            if (write(fd, zeros, chunk) <= 0)
              break;
            remaining -= (off_t)chunk;
          }
          fsync(fd);
          close(fd);
        }

        /* Sil */
        if (unlink(all_files[i]) == 0) {
          fprintf(stderr, "[*] silindi: %s\n", all_files[i]);
          wiped++;
        }
      }

      /* Dizini kaldır */
      if (rmdir(state.config_dir) == 0) {
        fprintf(stderr, "[*] dizin kaldırıldı: %s\n", state.config_dir);
      }

      fprintf(stderr,
              "\n[✓] %d dosya güvenli şekilde silindi.\n"
              "[!] Tüm key materyali yok edildi. Geri alınamaz.\n",
              wiped);

      (void)files; /* unused warning suppress */
      return 0;
    }

    /* ── 1. Log sistemi ────────────────────────────────── */
    NOX_INFO(LOG_MOD_MAIN, "%s v%s başlatılıyor", PARANOID_APP_NAME,
             PARANOID_VERSION);

    /* ── 2. Signal handler'lar ─────────────────────────── */
    setup_signal_handlers();
    setup_terminal();

    /* ── 3. libsodium init ─────────────────────────────── */
    if (sodium_init() < 0) {
      NOX_FATAL(LOG_MOD_MAIN, "libsodium başlatılamadı");
      return 1;
    }
    NOX_INFO(LOG_MOD_MAIN, "libsodium başlatıldı");

    /* ── 4. CPU yetenek kontrolü ───────────────────────── */
    NOX_INFO(LOG_MOD_HARD, "shadow stack (CET-SS): %s",
             cpu_has_shstk() ? "destekleniyor" : "desteklenmiyor");
    NOX_INFO(LOG_MOD_HARD, "IBT (CET-IBT): %s",
             cpu_has_ibt() ? "destekleniyor" : "desteklenmiyor");

    /* ── 5. Config dizin ───────────────────────────────── */
    err = resolve_config_paths(&state);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "config yolları çözülemedi: %s",
                nox_strerror(err));
      return 1;
    }

    err = ensure_config_dir(&state);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "config dizin hatası: %s", nox_strerror(err));
      return 1;
    }

    /* ── 6. PIN oku ────────────────────────────────────── */
    char pin_buf[NOX_PIN_MAX_LEN + 2];
    err = read_pin(pin_buf, sizeof(pin_buf), state.first_run);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "PIN hatası: %s", nox_strerror(err));
      sodium_memzero(pin_buf, sizeof(pin_buf));
      return 1;
    }

    /* ── 7. Secure arena init ──────────────────────────── */
    err = arena_init(&state.arena, NOX_ARENA_DEFAULT_SIZE);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "arena başlatılamadı: %s", nox_strerror(err));
      sodium_memzero(pin_buf, sizeof(pin_buf));
      return 1;
    }

    /* ── 8. Salt yükle veya oluştur ───────────────────── */
    uint8_t salt[NOX_SALT_LEN];
    /* CodeQL #12 cpp/path-injection: config_dir realpath($HOME)'den türetilmiştir */
    assert(state.config_dir[0] != '\0');
    err = crypto_load_or_create_salt(salt, state.config_dir);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "salt hatası: %s", nox_strerror(err));
      sodium_memzero(pin_buf, sizeof(pin_buf));
      arena_destroy(&state.arena);
      return 1;
    }

    /* ── 9. Key derivation: PIN → master_key ──────────── */
    state.master_key = arena_alloc(&state.arena, NOX_KEY_LEN);
    if (!state.master_key) {
      NOX_FATAL(LOG_MOD_MAIN, "arena alloc başarısız (master_key)");
      sodium_memzero(pin_buf, sizeof(pin_buf));
      arena_destroy(&state.arena);
      return 1;
    }

    err = crypto_derive_master_key(state.master_key, pin_buf, strlen(pin_buf),
                                   salt);

    /* PIN artık gerekli değil — hemen sil */
    sodium_memzero(pin_buf, sizeof(pin_buf));
    sodium_memzero(salt, sizeof(salt));
    memory_barrier();
    NOX_INFO(LOG_MOD_MAIN, "PIN ve salt bellekten silindi");

    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "key derivation başarısız: %s",
                nox_strerror(err));
      arena_destroy(&state.arena);
      return 1;
    }

    /* ── 10. Subkey türetimi ─────────────────────────── */
    state.db_key = arena_alloc(&state.arena, NOX_KEY_LEN);
    uint8_t *identity_unlock = arena_alloc(&state.arena, NOX_KEY_LEN);
    state.session_key = arena_alloc(&state.arena, NOX_KEY_LEN);

    if (!state.db_key || !identity_unlock || !state.session_key) {
      NOX_FATAL(LOG_MOD_MAIN, "arena alloc başarısız (subkeys)");
      arena_destroy(&state.arena);
      return 1;
    }

    err = crypto_derive_subkeys(state.master_key, state.db_key, identity_unlock,
                                state.session_key);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "subkey türetimi başarısız: %s",
                nox_strerror(err));
      arena_destroy(&state.arena);
      return 1;
    }

    /* ── 11. Identity key yükle, oluştur ve Curve25519'a dönüştür ── */
    state.my_static_priv = arena_alloc(&state.arena, NOX_KEY_LEN);
    state.my_static_pub = arena_alloc(&state.arena, NOX_KEY_LEN);
    if (!state.my_static_priv || !state.my_static_pub) {
      NOX_FATAL(LOG_MOD_MAIN, "arena alloc başarısız (static keys)");
      arena_destroy(&state.arena);
      return 1;
    }

    /* Geçici Ed25519 tamponları */
    uint8_t *ed_pub = sodium_malloc(32);
    uint8_t *ed_sk = sodium_malloc(64);
    if (!ed_pub || !ed_sk) {
      NOX_FATAL(LOG_MOD_MAIN, "bellek tahsisi başarısız (Ed25519 buffers)");
      sodium_free(ed_pub);
      sodium_free(ed_sk);
      arena_destroy(&state.arena);
      return 1;
    }
    memset(ed_pub, 0, 32);
    memset(ed_sk, 0, 64);

    if (state.first_run) {
      /* İlk çalıştırma: yeni key pair üret ve kaydet */
      err = crypto_generate_identity(state.identity_path, identity_unlock,
                                     ed_pub);
      if (err != NOX_OK) {
        NOX_FATAL(LOG_MOD_MAIN, "identity key üretimi başarısız: %s",
                  nox_strerror(err));
        sodium_free(ed_pub);
        sodium_free(ed_sk);
        arena_destroy(&state.arena);
        return 1;
      }
      NOX_INFO(LOG_MOD_MAIN, "yeni identity key oluşturuldu");
    }

    /* Diskten şifreli anahtarı yükle */
    /* CodeQL #13 cpp/path-injection: identity_path config_dir + "/identity.key" */
    assert(strncmp(state.identity_path, state.config_dir, strlen(state.config_dir)) == 0);
    err = crypto_load_identity(state.identity_path, identity_unlock, ed_sk,
                               ed_pub);
    if (err == NOX_ERR_AUTH) {
      NOX_FATAL(LOG_MOD_MAIN, "yanlış PIN — identity key çözülemedi");
      sodium_free(ed_pub);
      sodium_free(ed_sk);
      arena_destroy(&state.arena);
      return 1;
    }
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "identity key yükleme hatası: %s",
                nox_strerror(err));
      sodium_free(ed_pub);
      sodium_free(ed_sk);
      arena_destroy(&state.arena);
      return 1;
    }
    NOX_INFO(LOG_MOD_MAIN, "identity key yüklendi");

    /* Ed25519 anahtar çiftini Curve25519 (X25519) formatına dönüştür */
    err = crypto_ed25519_to_curve25519(state.my_static_pub,
                                       state.my_static_priv, ed_pub, ed_sk);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "anahtar dönüştürme başarısız");
      sodium_free(ed_pub);
      sodium_free(ed_sk);
      arena_destroy(&state.arena);
      return 1;
    }

    /* Hassas geçici Ed25519 verileri sıfırla */
    sodium_free(ed_pub);
    sodium_free(ed_sk);
    memory_barrier();

    /*
     * identity_unlock artık gerekli değil — hemen sil.
     * Bu en hassas subkey: identity.key'i açan anahtar.
     */
    sodium_memzero(identity_unlock, NOX_KEY_LEN);
    memory_barrier();
    identity_unlock = NULL;
    NOX_DEBUG(LOG_MOD_MAIN, "identity_unlock bellekten silindi");

    /* ── Pluggable Transport Seçimi (Faz 6.2) ── */
    prompt_transport_selection(&state);
    if (g_shutdown) {
      cleanup(&state);
      return 0;
    }

    /* SQLite veritabanını başlat */
    if (!state.ghost_mode) {
      err = db_init(state.config_dir, state.db_key);
      if (err != NOX_OK) {
        NOX_FATAL(LOG_MOD_MAIN, "veritabanı başlatılamadı: %s",
                  nox_strerror(err));
        arena_destroy(&state.arena);
        return 1;
      }
    } else {
      NOX_INFO(LOG_MOD_MAIN, "ghost mod aktif — veritabanı başlatılmadı");
    }

    NOX_INFO(LOG_MOD_MAIN, "public key hazır");
    NOX_DEBUG(
        LOG_MOD_MAIN, "arena: %zu byte / %zu KB kullanımda",
        arena_bytes_used(&state.arena),
        (arena_bytes_used(&state.arena) + arena_bytes_free(&state.arena)) /
            1024);

#ifdef DEBUG
    /* ── 12. Noise XX loopback demo (geçici — Tor gelince kalkacak) ── */
    NOX_INFO(LOG_MOD_MAIN, "=== Noise XX loopback demo ===");
    {
      /* Curve25519 keypair'ler — Ed25519 ile karıştırma! */
      uint8_t alice_priv[NOX_KEY_LEN], alice_pub[NOX_KEY_LEN];
      uint8_t bob_priv[NOX_KEY_LEN], bob_pub[NOX_KEY_LEN];
      crypto_box_keypair(alice_pub, alice_priv);
      crypto_box_keypair(bob_pub, bob_priv);

      struct noise_handshake hs_a, hs_b;
      handshake_init(&hs_a, true, alice_priv, alice_pub);
      handshake_init(&hs_b, false, bob_priv, bob_pub);

      uint8_t msg_buf[NOISE_MAX_HANDSHAKE_LEN];
      uint8_t pl_buf[64];
      size_t msg_len, pl_len;

      /* msg0: Alice → Bob */
      msg_len = sizeof(msg_buf);
      handshake_write(&hs_a, NULL, 0, msg_buf, &msg_len);
      NOX_INFO(LOG_MOD_NOISE, "msg0 gönderildi (%zu byte)", msg_len);

      pl_len = sizeof(pl_buf);
      handshake_read(&hs_b, msg_buf, msg_len, pl_buf, &pl_len);
      NOX_INFO(LOG_MOD_NOISE, "msg0 alındı");

      /* msg1: Bob → Alice */
      msg_len = sizeof(msg_buf);
      handshake_write(&hs_b, NULL, 0, msg_buf, &msg_len);
      NOX_INFO(LOG_MOD_NOISE, "msg1 gönderildi (%zu byte)", msg_len);

      pl_len = sizeof(pl_buf);
      handshake_read(&hs_a, msg_buf, msg_len, pl_buf, &pl_len);
      NOX_INFO(LOG_MOD_NOISE, "msg1 alındı");

      /* msg2: Alice → Bob */
      msg_len = sizeof(msg_buf);
      handshake_write(&hs_a, NULL, 0, msg_buf, &msg_len);
      NOX_INFO(LOG_MOD_NOISE, "msg2 gönderildi (%zu byte)", msg_len);

      pl_len = sizeof(pl_buf);
      handshake_read(&hs_b, msg_buf, msg_len, pl_buf, &pl_len);
      NOX_INFO(LOG_MOD_NOISE, "msg2 alındı");

      /* Split → transport */
      struct noise_session sa, sb;
      handshake_split(&hs_a, &sa);
      handshake_split(&hs_b, &sb);

      /* Transport test: Alice → Bob */
      const char *test_msg = "merhaba noise!";
      uint8_t ct[64 + NOX_MAC_LEN];
      uint8_t pt[64];

      ssize_t ct_len = noise_encrypt(&sa, (const uint8_t *)test_msg,
                                     strlen(test_msg) + 1, ct);
      NOX_INFO(LOG_MOD_NOISE, "şifrelendi: %zd byte", ct_len);

      ssize_t pt_len = noise_decrypt(&sb, ct, (size_t)ct_len, pt);
      NOX_INFO(LOG_MOD_NOISE, "çözüldü: \"%s\" (%zd byte)", (const char *)pt,
               pt_len);

      /* Temizle */
      sodium_memzero(&sa, sizeof(sa));
      sodium_memzero(&sb, sizeof(sb));
      sodium_memzero(alice_priv, sizeof(alice_priv));
      sodium_memzero(bob_priv, sizeof(bob_priv));
      
    }
    NOX_INFO(LOG_MOD_MAIN, "=== Noise demo tamamlandı ===");
#endif

    /* ── 13. Tor spawn → bootstrap → HS ─────────────── */
    err = tor_spawn(&state);
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "Tor başlatılamadı: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    if (g_shutdown) goto shutdown_clean;

    err = tor_authenticate(state.tor_ctrl_fd, state.tor_data_dir);
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "Tor auth başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    if (g_shutdown) goto shutdown_clean;

    err = tor_wait_bootstrap(state.tor_ctrl_fd, 120);
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "Tor bootstrap başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    if (g_shutdown) goto shutdown_clean;

    /* SOCKS port'unu öğren (auto port) */
    err = tor_get_socks_port(state.tor_ctrl_fd, &state.socks_port);
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "SOCKS port öğrenilemedi: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    if (g_shutdown) goto shutdown_clean;

    /* ── 14. TCP listener + Hidden Service ─────────── */
    err = listener_create(&state.listen_port, &state.listen_fd);
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "listener başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    if (g_shutdown) goto shutdown_clean;

    err = tor_create_hidden_service(state.tor_ctrl_fd, state.listen_port,
                                    state.onion_addr, sizeof(state.onion_addr));
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "Hidden Service başarısız: %s",
                nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    NOX_INFO(LOG_MOD_MAIN, "adresiniz: %s", state.onion_addr);

    /* ── 14b. Seccomp blacklist yükle ────────────────
     * Tor ve Hidden Service hazır. Bundan sonra tehlikeli
     * syscall'lar SIGSYS ile öldürmeli. */
    if (seccomp_policy_load() != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "seccomp yüklenemedi — abort");
      cleanup(&state);
      return 1;
    }

    if (g_shutdown) goto shutdown_clean;

    /* ── 15. epoll event loop ─────────────────────────── */
    err = epoll_setup(&state, state.listen_fd);
    if (err != NOX_OK) {
      if (g_shutdown) goto shutdown_clean;
      NOX_FATAL(LOG_MOD_MAIN, "epoll setup başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    NOX_INFO(LOG_MOD_MAIN, "init tamamlandı — event loop başlıyor");
    NOX_INFO(LOG_MOD_MAIN, "arena: %zu byte / %zu KB kullanımda",
             arena_bytes_used(&state.arena),
             (arena_bytes_used(&state.arena) + arena_bytes_free(&state.arena)) /
                 1024);

    tui_init();
    tui_print_welcome(&state);
    tui_refresh_all(&state);

    if (!tui_is_active()) {
        if (state.ghost_mode) {
          fprintf(
              stderr,
              "\n  [👻] GHOST MOD — hiçbir veri kaydedilmez, rehber ve kuyruk devre dışı\n\n"
              "  Komutlar:\n"
              "    \033[38;2;210;24;38m/addr               — .onion adresini "
              "göster\033[0m\n"
              "    \033[38;2;224;126;20m/connect <onion>    — peer'a bağlan\033[0m\n"
              "    \033[38;2;31;65;117m/file <dosya_yolu>  — peer'a dosya gönder "
              "(aktif bağlantı gerektirir)\033[0m\n"
              "    \033[38;2;133;60;153mCtrl+P              — çıkış\033[0m\n"
              "  Bağlantı kurulduktan sonra yazdığınız her şey doğrudan mesaj olarak "
              "gönderilir.\n\n"
              "> ");
        } else {
          fprintf(
              stderr,
              "\n  Komutlar:\n"
              "    \033[38;2;210;24;38m/addr               — .onion adresini "
              "göster\033[0m\n"
              "    \033[38;2;224;126;20m/connect <onion>    — peer'a bağlan\033[0m\n"
              "    \033[38;2;202;151;15m/add <onion> <isim> — rehbere kişi "
              "ekle\033[0m\n"
              "    \033[38;2;38;162;105m/msg <onion> <msj>  — çevrimdışı/kuyruklu "
              "mesaj gönder\033[0m\n"
              "    \033[38;2;31;65;117m/file <dosya_yolu>  — peer'a dosya gönder "
              "(aktif bağlantı gerektirir)\033[0m\n"
              "    \033[38;2;133;60;153mCtrl+P              — çıkış\033[0m\n"
              "  Bağlantı kurulduktan sonra yazdığınız her şey doğrudan mesaj olarak "
              "gönderilir.\n\n"
              "> ");
        }
    }

    event_loop(&state);

    NOX_INFO(LOG_MOD_MAIN, "shutdown sinyali alındı");

shutdown_clean:
    /* ── Cleanup ───────────────────────────────────────── */
    cleanup(&state);

    NOX_INFO(LOG_MOD_MAIN, "%s kapatıldı", PARANOID_APP_NAME);
    return 0;
  }
