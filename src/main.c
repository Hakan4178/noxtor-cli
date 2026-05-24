/* SPDX-License-Identifier: GPL-3.0-or-later
 * main.c — noxtor-cli giriş noktası
 *
 * Init sırası:
 *   1. Log sistemi (ilk — geri kalan her şey log'a bağlı)
 *   2. libsodium init
 *   3. Config dizin kontrolü / bootstrap
 *   4. PIN oku (echo kapalı)
 *   5. Secure arena init
 *   6. Key derivation (Faz 2'de doldurulacak)
 *   7. Tor spawn (Faz 3'te)
 *   8. epoll event loop (Faz 4'te)
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
#include <sys/socket.h>

/* ================================================================
 * GLOBAL SHUTDOWN FLAG — async-signal-safe
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
      char parent[NOX_PATH_MAX];
      snprintf(parent, sizeof(parent), "%s/.config",
               getenv("HOME") ? getenv("HOME") : "");
      mkdir(parent, 0700); /* zaten varsa hata önemsiz */

      if (mkdir(state->config_dir, 0700) != 0) {
        NOX_ERROR(LOG_MOD_MAIN, "config dizini oluşturulamadı: %s",
                  strerror(errno));
        return NOX_ERR_CONFIG;
      }
    }
    NOX_INFO(LOG_MOD_MAIN, "config dizini oluşturuldu: %s", state->config_dir);
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

  /* Newline'ı kaldır */
  size_t len = strlen(pin_buf);
  if (len > 0 && pin_buf[len - 1] == '\n') {
    pin_buf[len - 1] = '\0';
    len--;
  }

  /* Truncation tespiti — fgets buffer'ı doldurmuşsa PIN kesilmiş */
  if (len == buf_size - 1 && pin_buf[len - 1] != '\n') {
    if (is_terminal)
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    NOX_ERROR(LOG_MOD_MAIN, "PIN çok uzun: buffer aşıldı (maksimum %u byte)",
              NOX_PIN_MAX_LEN);
    explicit_bzero(pin_buf, buf_size);
    return NOX_ERR_PIN;
  }

  /* Doğrulama — test edilebilir fonksiyon */
  nox_err_t err = validate_pin(pin_buf, len);
  if (err != NOX_OK) {
    if (is_terminal)
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    explicit_bzero(pin_buf, buf_size);
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
      explicit_bzero(pin_buf, buf_size);
      explicit_bzero(confirm_buf, sizeof(confirm_buf));
      fprintf(stderr, "\n");
      return NOX_ERR_PIN;
    }
    fprintf(stderr, "\n");

    /* Newline kaldır */
    size_t clen = strlen(confirm_buf);
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
    explicit_bzero(pad_a, sizeof(pad_a));
    explicit_bzero(pad_b, sizeof(pad_b));
    memcpy(pad_a, pin_buf, len);
    memcpy(pad_b, confirm_buf, strlen(confirm_buf));

    int match = sodium_memcmp(pad_a, pad_b, sizeof(pad_a));

    explicit_bzero(pad_a, sizeof(pad_a));
    explicit_bzero(pad_b, sizeof(pad_b));
    explicit_bzero(confirm_buf, sizeof(confirm_buf));

    if (match != 0) {
      if (is_terminal)
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
      NOX_ERROR(LOG_MOD_MAIN, "PIN'ler eşleşmiyor");
      explicit_bzero(pin_buf, buf_size);
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
  restore_terminal();
  db_close();

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
    explicit_bzero(state->stdin_buf, state->stdin_cap);
    free(state->stdin_buf);
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

  NOX_INFO(LOG_MOD_MAIN, "temizlik tamamlandı");
}

static nox_err_t send_queued_callback(const char *text, void *ctx) {
  struct app_state *state = (struct app_state *)ctx;
  if (state->peer_fd < 0 || !state->session)
    return NOX_ERR_NET;

  size_t pt_len = strlen(text) + 1;
  uint8_t payload[4096 + NOX_MAC_LEN];
  ssize_t ct_len =
      noise_encrypt(state->session, (const uint8_t *)text, pt_len, payload);
  if (ct_len < 0)
    return NOX_ERR_CRYPTO;

  struct frame_header fh = {
      .magic = NOX_FRAME_MAGIC,
      .type = NOX_MSG_TEXT,
      .seq = state->tx_seq++,
      .len = (uint32_t)ct_len,
  };
  uint8_t wire[FRAME_HEADER_WIRE_SIZE];
  frame_header_encode(&fh, wire);

  if (write_full(state->peer_fd, wire, FRAME_HEADER_WIRE_SIZE) != NOX_OK)
    return NOX_ERR_IO;
  if (write_full(state->peer_fd, payload, (size_t)ct_len) != NOX_OK)
    return NOX_ERR_IO;

  return NOX_OK;
}

/* UTF-8 multi-byte karakter sınırına göre bir sonraki güvenli bölme boyutunu
 * bulur */
static size_t get_next_chunk_size(const char *msg, size_t offset,
                                  size_t total_len) {
  size_t chunk_limit = 4000;
  if (total_len - offset <= chunk_limit) {
    return total_len - offset;
  }

  size_t size = chunk_limit;
  /* UTF-8 devam byte'ları 10xxxxxx (0x80 - 0xBF) formatındadır */
  while (size > 0 && ((uint8_t)msg[offset + size] & 0xC0) == 0x80) {
    size--;
  }

  /* Fallback safety guard */
  if (size == 0) {
    return chunk_limit;
  }
  return size;
}

/* Uzun bir mesajı güvenli chunk'lara ayırıp sırayla şifreleyerek sokete yazar
 */
static nox_err_t send_segmented_message(struct app_state *state,
                                        const char *msg) {
  if (!state->session || state->peer_fd < 0)
    return NOX_ERR_NET;

  size_t total_len = strlen(msg);
  size_t offset = 0;

  uint8_t *ct = malloc(4096 + NOX_MAC_LEN);
  char *chunk = malloc(4096);
  if (!ct || !chunk) {
    free(ct);
    free(chunk);
    return NOX_ERR_CONFIG;
  }

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    size_t pt_len = chunk_len + 1;
    ssize_t ct_len =
        noise_encrypt(state->session, (const uint8_t *)chunk, pt_len, ct);
    if (ct_len < 0) {
      explicit_bzero(chunk, 4096);
      explicit_bzero(ct, 4096 + NOX_MAC_LEN);
      free(chunk);
      free(ct);
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
      explicit_bzero(chunk, 4096);
      explicit_bzero(ct, 4096 + NOX_MAC_LEN);
      free(chunk);
      free(ct);
      return NOX_ERR_IO;
    }

    offset += chunk_len;
  }

  explicit_bzero(chunk, 4096);
  explicit_bzero(ct, 4096 + NOX_MAC_LEN);
  free(chunk);
  free(ct);
  return NOX_OK;
}

/* Uzun bir mesajı güvenli chunk'lara ayırıp SQLite veritabanı kuyruğuna yazar
 */
static nox_err_t queue_segmented_message(const char *recipient_onion,
                                         const char *msg) {
  size_t total_len = strlen(msg);
  size_t offset = 0;

  char *chunk = malloc(4096);
  if (!chunk)
    return NOX_ERR_CONFIG;

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    nox_err_t err = db_queue_message(recipient_onion, chunk);
    if (err != NOX_OK) {
      explicit_bzero(chunk, 4096);
      free(chunk);
      return err;
    }

    offset += chunk_len;
  }

  explicit_bzero(chunk, 4096);
  free(chunk);
  return NOX_OK;
}

/* ================================================================
 * DOSYA ADI SANİTİZASYONU — Path Traversal Koruması (K2)
 *
 * Saldırgan "../../etc/cron.d/backdoor" gibi dosya adı gönderebilir.
 * Whitelist yaklaşımı: sadece [a-zA-Z0-9._-] karakterlere izin verilir.
 * Birden fazla ardışık nokta ("..") engellenir.
 * Sonuç boş veya tehlikeli ise rastgele hex ID atanır.
 * ================================================================ */
static void sanitize_filename(char *name, size_t max_len) {
  if (!name || max_len == 0)
    return;

  /* 1. Yol ayırıcılarını kes — sadece basename'i al */
  char *slash = strrchr(name, '/');
  if (slash) {
    size_t remain = strlen(slash + 1) + 1;
    memmove(name, slash + 1, remain);
  }

  /* 2. Whitelist filtresi — izin verilmeyen her karakter '_' olur */
  size_t len = strlen(name);
  for (size_t i = 0; i < len; i++) {
    char c = name[i];
    bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!allowed) {
      name[i] = '_';
    }
  }

  /* 3. Ardışık nokta ("..") engelle — her ".." → "__" */
  for (size_t i = 0; i + 1 < len; i++) {
    if (name[i] == '.' && name[i + 1] == '.') {
      name[i] = '_';
      name[i + 1] = '_';
    }
  }

  /* 4. Baştaki nokta ("gizli dosya" veya "." / "..") engelle */
  if (len > 0 && name[0] == '.') {
    name[0] = '_';
  }

  /* 5. Boş ad kontrolü — rastgele hex ID ata */
  len = strlen(name);
  if (len == 0) {
    uint32_t rnd = randombytes_random();
    snprintf(name, max_len, "file_%08x", rnd);
  }
}

static void process_line(struct app_state *state, const char *line) {
  /* ── TOFU Onay Modu ─────────────────── */
  if (state->tofu_pending) {
    if (strcasecmp(line, "y") == 0 || strcasecmp(line, "yes") == 0) {
      db_add_contact(state->tofu_onion, state->tofu_name, state->tofu_new_key);
      ui_print_system(state, "[✓] Akran onaylandı ve kaydedildi: %s",
                      state->tofu_name);

      state->session = arena_alloc(&state->arena, sizeof(struct noise_session));
      if (state->session) {
        handshake_split(state->hs, state->session);
        state->tx_seq = 0;
        state->rx_seq = 0;
        strncpy(state->active_peer_onion, state->tofu_onion, NOX_ONION_LEN);
        state->active_peer_onion[NOX_ONION_LEN] = '\0';

        NOX_INFO(LOG_MOD_NOISE, "session kuruldu — mesajlaşma hazır");
        ui_print_system(state, "[✓] şifreli kanal kuruldu (%s)",
                        state->tofu_name);

        /* Kuyruktaki bekleyen mesajları gönder */
        db_process_queue(state->active_peer_onion, send_queued_callback, state);
      } else {
        ui_print_error(state, "Arena bellek hatası");
        close(state->tofu_peer_fd);
        state->peer_fd = -1;
        arena_restore(&state->arena, state->tofu_arena_mark);
      }
      state->hs = NULL;
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
    ui_print_error(state, "bağlantı yok — önce /connect kullan veya çevrimdışı "
                          "mesaj için /msg kullan");
    return;
  }

  if (strcmp(line, "/addr") == 0) {
    ui_print_system(state, "%s", state->onion_addr);
    return;
  }

  if (strncmp(line, "/add ", 5) == 0) {
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
    strncpy(name, name_start, NOX_CONTACT_NAME_LEN);
    name[NOX_CONTACT_NAME_LEN] = '\0';

    uint8_t zero_key[NOX_KEY_LEN];
    explicit_bzero(zero_key, sizeof(zero_key));

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

    NOX_INFO(LOG_MOD_MAIN, "bağlanılıyor: %s", target);
    int peer_fd = -1;
    nox_err_t err =
        socks5_connect(target, NOX_VIRTUAL_PORT, state->socks_port, &peer_fd);
    if (err != NOX_OK) {
      ui_print_error(state, "bağlantı başarısız");
      return;
    }

    state->peer_fd = peer_fd;
    epoll_add_fd(state->epoll_fd, peer_fd);
    NOX_INFO(LOG_MOD_MAIN, "peer bağlandı");

    /* Noise handshake — initiator */
    state->session_arena_mark = arena_save(&state->arena);
    state->hs = arena_alloc(&state->arena, sizeof(struct noise_handshake));
    if (!state->hs) {
      ui_print_error(state, "arena dolu");
      return;
    }

    uint8_t cpriv[NOX_KEY_LEN], cpub[NOX_KEY_LEN];
    handshake_init(state->hs, true,
               state->my_static_priv,
               state->my_static_pub);    
    explicit_bzero(cpriv, sizeof(cpriv));

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

  /* ── /file <path> — Güvenli dosya gönderimi (Faz 6.2) ── */
  if (strncmp(line, "/file ", 6) == 0) {
    const char *filepath = line + 6;
    while (*filepath == ' ')
      filepath++;

    /* Çevrimdışı dosya gönderimi desteklenmiyor */
    if (state->peer_fd < 0 || !state->session) {
      ui_print_error(
          state,
          "Çevrimdışı dosyalar kuyruğa alınamaz. Aktif bir bağlantı gerekir.");
      return;
    }

    /* Zaten aktif bir dosya transferi var mı? */
    if (state->tx_file.active) {
      ui_print_error(state, "Zaten aktif bir dosya transferi var.");
      return;
    }

    /* Dosya path kopyası oluştur (basename mutate edebilir) */
    char path_copy[NOX_PATH_MAX];
    size_t path_len = strlen(filepath);
    if (path_len == 0 || path_len >= sizeof(path_copy)) {
      ui_print_error(state, "Geçersiz dosya yolu.");
      return;
    }
    memcpy(path_copy, filepath, path_len + 1);

    /* Dosya var mı, okunabilir mi? */
    struct stat st;
    if (stat(path_copy, &st) != 0) {
      ui_print_error(state, "Dosya bulunamadı: %s", strerror(errno));
      return;
    }
    if (!S_ISREG(st.st_mode)) {
      ui_print_error(state, "Düzenli dosya değil.");
      return;
    }
    if (st.st_size == 0) {
      ui_print_error(state, "Boş dosya gönderilemez.");
      return;
    }

    /* Dosyayı aç */
    int file_fd = open(path_copy, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
      ui_print_error(state, "Dosya açılamadı: %s", strerror(errno));
      return;
    }

    /* basename al, sonra mutlak yolu hemen sil (crash/coredump koruması) */
    char *bname = basename(path_copy);
    char safe_name[256];
    size_t bname_len = strlen(bname);
    if (bname_len >= sizeof(safe_name))
      bname_len = sizeof(safe_name) - 1;
    memcpy(safe_name, bname, bname_len);
    safe_name[bname_len] = '\0';
    explicit_bzero(path_copy, sizeof(path_copy));

    /* Streaming BLAKE2b hash — dosyayı 4KB parçalarla hash'le */
    crypto_generichash_state hash_st;
    crypto_generichash_init(&hash_st, NULL, 0, 32);

    uint8_t hash_buf[4096];
    for (;;) {
      ssize_t r = read(file_fd, hash_buf, sizeof(hash_buf));
      if (r < 0) {
        if (errno == EINTR)
          continue;
        ui_print_error(state, "Dosya okuma hatası: %s", strerror(errno));
        explicit_bzero(hash_buf, sizeof(hash_buf));
        close(file_fd);
        return;
      }
      if (r == 0)
        break;
      crypto_generichash_update(&hash_st, hash_buf, (size_t)r);
    }
    explicit_bzero(hash_buf, sizeof(hash_buf));

    uint8_t file_hash[32];
    crypto_generichash_final(&hash_st, file_hash, 32);

    /* Dosya başına geri sar */
    if (lseek(file_fd, 0, SEEK_SET) != 0) {
      ui_print_error(state, "lseek başarısız.");
      close(file_fd);
      return;
    }

    /* tx_file state'ini kur */
    explicit_bzero(&state->tx_file, sizeof(state->tx_file));
    state->tx_file.active = true;
    state->tx_file.fd = file_fd;
    state->tx_file.total_size = (uint64_t)st.st_size;
    state->tx_file.sent_bytes = 0;
    memcpy(state->tx_file.hash, file_hash, 32);
    memcpy(state->tx_file.filename, safe_name, bname_len + 1);

    /*
     * METADATA frame gönder:
     *   "METADATA\0" (9) + filename (256) + size (8) + hash (32) = 305 byte
     */
    uint8_t meta[305];
    memset(meta, 0, sizeof(meta));
    memcpy(meta, "METADATA", 9);
    memcpy(meta + 9, safe_name, bname_len + 1);
    uint64_t net_size = state->tx_file.total_size;
    /* Big-endian encode */
    meta[265] = (uint8_t)(net_size >> 56);
    meta[266] = (uint8_t)(net_size >> 48);
    meta[267] = (uint8_t)(net_size >> 40);
    meta[268] = (uint8_t)(net_size >> 32);
    meta[269] = (uint8_t)(net_size >> 24);
    meta[270] = (uint8_t)(net_size >> 16);
    meta[271] = (uint8_t)(net_size >> 8);
    meta[272] = (uint8_t)(net_size);
    memcpy(meta + 273, file_hash, 32);

    /* Şifrele ve gönder */
    uint8_t meta_ct[305 + NOX_MAC_LEN];
    ssize_t meta_ct_len =
        noise_encrypt(state->session, meta, sizeof(meta), meta_ct);
    explicit_bzero(meta, sizeof(meta));
    if (meta_ct_len < 0) {
      ui_print_error(state, "Metadata şifreleme hatası.");
      close(file_fd);
      explicit_bzero(&state->tx_file, sizeof(state->tx_file));
      return;
    }

    struct frame_header mfh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_FILE,
        .seq = state->tx_seq++,
        .len = (uint32_t)meta_ct_len,
    };
    uint8_t mwire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&mfh, mwire);

    if (write_full(state->peer_fd, mwire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
        write_full(state->peer_fd, meta_ct, (size_t)meta_ct_len) != NOX_OK) {
      ui_print_error(state, "Metadata gönderim hatası.");
      close(file_fd);
      explicit_bzero(&state->tx_file, sizeof(state->tx_file));
      return;
    }

    /* peer_fd'yi EPOLLIN | EPOLLOUT olarak değiştir */
    epoll_modify_fd(state->epoll_fd, state->peer_fd, EPOLLIN | EPOLLOUT);

    ui_print_system(state, "[*] Dosya transferi başlatıldı: %s (%lu byte)",
                    safe_name, (unsigned long)state->tx_file.total_size);
    return;
  }

  ui_print_system(state, "komutlar: /addr  /connect <onion>  /add <onion> "
                         "<isim>  /msg <onion> <mesaj>  /file <dosya>  Ctrl+P");
}

static void process_stdin_events(struct app_state *state) {
  for (;;) {
    if (state->stdin_len + 512 >= state->stdin_cap) {
      size_t new_cap = state->stdin_cap == 0 ? 512 : state->stdin_cap * 2;
      char *new_buf = realloc(state->stdin_buf, new_cap);
      if (!new_buf) {
        NOX_ERROR(LOG_MOD_MAIN, "stdin buffer realloc failed");
        return;
      }
      state->stdin_buf = new_buf;
      state->stdin_cap = new_cap;
    }

    ssize_t r = read(STDIN_FILENO, state->stdin_buf + state->stdin_len,
                     state->stdin_cap - state->stdin_len - 1);
    if (r < 0) {
      if (errno == EINTR)
        continue;
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
#else
      if (errno == EAGAIN)
        break;
#endif
      NOX_ERROR(LOG_MOD_MAIN, "stdin read error: %s", strerror(errno));
      break;
    }
    if (r == 0) {
      if (state->stdin_len > 0) {
        process_line(state, state->stdin_buf);
        explicit_bzero(state->stdin_buf, state->stdin_cap);
        state->stdin_len = 0;
      }
      epoll_remove_fd(state->epoll_fd, STDIN_FILENO);
      break;
    }
    state->stdin_len += (size_t)r;
    state->stdin_buf[state->stdin_len] = '\0';
  }

  char *newline;
  while ((newline = memchr(state->stdin_buf, '\n', state->stdin_len)) != NULL) {
    size_t line_len = (size_t)(newline - state->stdin_buf);
    char *line = malloc(line_len + 1);
    if (!line) {
      NOX_ERROR(LOG_MOD_MAIN, "line allocation failed");
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

    // Clean trailing carriage return
    size_t trimmed_len = line_len;
    if (trimmed_len > 0 && line[trimmed_len - 1] == '\r') {
      line[trimmed_len - 1] = '\0';
      trimmed_len--;
    }

    // Clean trailing spaces/tabs
    while (trimmed_len > 0 &&
           (line[trimmed_len - 1] == ' ' || line[trimmed_len - 1] == '\t')) {
      line[trimmed_len - 1] = '\0';
      trimmed_len--;
    }

    if (trimmed_len == 0) {
      ui_print_prompt(state);
    } else {
      process_line(state, line);
    }

    explicit_bzero(line, line_len + 1);
    free(line);
  }
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
        epoll_add_fd(state->epoll_fd, peer_fd);

        state->session_arena_mark = arena_save(&state->arena);
        state->hs = arena_alloc(&state->arena, sizeof(struct noise_handshake));
        if (!state->hs) {
          close(peer_fd);
          state->peer_fd = -1;
          continue;
        }

        uint8_t cpriv[NOX_KEY_LEN], cpub[NOX_KEY_LEN];
        handshake_init(state->hs, false,
               state->my_static_priv,
               state->my_static_pub);    
        explicit_bzero(cpriv, sizeof(cpriv));

        NOX_INFO(LOG_MOD_MAIN, "gelen peer kabul edildi");
        ui_print_system(state, "[*] gelen bağlantı — handshake bekleniyor");

      } else if (fd == state->peer_fd) {
        /* ── Peer'a Veri Gönderimi (EPOLLOUT) ────── */
        if (events[i].events & EPOLLOUT) {
          if (state->tx_file.active) {
            /* Buffer'da kalan veri varsa önce onu gönder */
            if (state->tx_file.tx_len > 0) {
              ssize_t w =
                  write(fd, state->tx_file.tx_buf + state->tx_file.tx_offset,
                        state->tx_file.tx_len - state->tx_file.tx_offset);
              if (w > 0) {
                state->tx_file.tx_offset += (size_t)w;
                if (state->tx_file.tx_offset == state->tx_file.tx_len) {
                  state->tx_file.tx_len = 0;
                  state->tx_file.tx_offset = 0;
                  state->tx_file.sent_bytes +=
                      state->tx_file.current_chunk_size;
                  state->tx_file.current_chunk_size = 0;

                  if (state->tx_file.sent_bytes >= state->tx_file.total_size) {
                    ui_print_system(state,
                                    "[✓] Dosya gönderimi tamamlandı (%lu byte)",
                                    (unsigned long)state->tx_file.total_size);
                    close(state->tx_file.fd);
                    explicit_bzero(&state->tx_file, sizeof(state->tx_file));
                    epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
                  } else {
                    ui_print_progress(state, state->tx_file.filename,
                                      state->tx_file.sent_bytes,
                                      state->tx_file.total_size, true);
                  }
                }
              } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                         errno != EINTR) {
                ui_print_error(state, "Dosya gönderimi koptu (%s)",
                               strerror(errno));
                close(state->tx_file.fd);
                explicit_bzero(&state->tx_file, sizeof(state->tx_file));
                epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
              }
            } else {
              /* Yeni chunk oku ve şifrele */
              uint8_t plain[4096];
              ssize_t r = read(state->tx_file.fd, plain, sizeof(plain));
              if (r > 0) {
                state->tx_file.current_chunk_size = (size_t)r;
                ssize_t ct_len = noise_encrypt(state->session, plain, (size_t)r,
                                               state->tx_file.tx_buf +
                                                   FRAME_HEADER_WIRE_SIZE);
                explicit_bzero(plain, sizeof(plain));

                if (ct_len > 0) {
                  struct frame_header fh = {
                      .magic = NOX_FRAME_MAGIC,
                      .type = NOX_MSG_FILE,
                      .seq = state->tx_seq++,
                      .len = (uint32_t)ct_len,
                  };
                  frame_header_encode(&fh, state->tx_file.tx_buf);
                  state->tx_file.tx_len =
                      FRAME_HEADER_WIRE_SIZE + (size_t)ct_len;
                  state->tx_file.tx_offset = 0;
                } else {
                  ui_print_error(state, "Chunk şifreleme başarısız");
                  close(state->tx_file.fd);
                  explicit_bzero(&state->tx_file, sizeof(state->tx_file));
                  epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
                }
              } else if (r < 0 && errno != EINTR) {
                ui_print_error(state, "Yerel dosya okuma başarısız");
                close(state->tx_file.fd);
                explicit_bzero(&state->tx_file, sizeof(state->tx_file));
                epoll_modify_fd(state->epoll_fd, fd, EPOLLIN);
              }
            }
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
            if (state->tx_file.active) {
              close(state->tx_file.fd);
              explicit_bzero(&state->tx_file, sizeof(state->tx_file));
              ui_print_error(
                  state, "Bağlantı koptuğu için dosya gönderimi iptal edildi.");
            }
            if (state->rx_file.active) {
              char bad_path[NOX_PATH_MAX];
              snprintf(bad_path, sizeof(bad_path), "received_%s",
                       state->rx_file.filename);
              close(state->rx_file.fd);
              unlink(bad_path);
              explicit_bzero(&state->rx_file, sizeof(state->rx_file));
              ui_print_error(state, "Bağlantı koptuğu için dosya alımı iptal "
                                    "edildi ve yarım kalan dosya silindi.");
            }

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

          if (fh.len > 4096 + NOX_MAC_LEN)
            continue;

          /* Güvenli Heap Allocation — Stack/BSS yerine */
          uint8_t *payload = malloc(4096 + NOX_MAC_LEN);
          if (!payload)
            continue;

          /* Payload'u tam oku (partial read koruması) */
          if (read_full(fd, payload, fh.len) != NOX_OK) {
            NOX_ERROR(LOG_MOD_NET, "frame payload eksik okundu");
            free(payload);
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
              explicit_bzero(payload, 4096 + NOX_MAC_LEN);
              free(payload);
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
              write_full(fd, rwire, FRAME_HEADER_WIRE_SIZE);
              write_full(fd, hsbuf, hslen);
              NOX_INFO(LOG_MOD_NOISE, "handshake yanıt");
            }

            if (state->hs->msg_index >= 3) {
              char peer_onion[NOX_ONION_LEN + 1];
              explicit_bzero(peer_onion, sizeof(peer_onion));

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
                explicit_bzero(payload, 4096 + NOX_MAC_LEN);
                free(payload);
                continue;
              }

              char name[NOX_CONTACT_NAME_LEN + 1];
              uint8_t stored_key[NOX_KEY_LEN];
              explicit_bzero(name, sizeof(name));
              explicit_bzero(stored_key, sizeof(stored_key));

              nox_err_t db_err =
                  db_get_contact(peer_onion, name, sizeof(name), stored_key);
              uint8_t remote_pub[NOX_KEY_LEN];
              memcpy(remote_pub, state->hs->rs, NOX_KEY_LEN);

              char fp_str[NOX_KEY_LEN * 2 + 1];
              for (size_t k = 0; k < NOX_KEY_LEN; k++) {
                sprintf(&fp_str[k * 2], "%02x", remote_pub[k]);
              }

              bool zero_key = true;
              for (size_t k = 0; k < NOX_KEY_LEN; k++) {
                if (stored_key[k] != 0) {
                  zero_key = false;
                  break;
                }
              }

              if (db_err == NOX_OK && !zero_key) {
                if (memcmp(stored_key, remote_pub, NOX_KEY_LEN) == 0) {
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

                    db_process_queue(state->active_peer_onion,
                                     send_queued_callback, state);
                  } else {
                    ui_print_error(state, "Arena bellek hatası");
                    close(fd);
                    state->peer_fd = -1;
                    state->active_peer_onion[0] = '\0';
                    arena_restore(&state->arena, state->session_arena_mark);
                  }
                  state->hs = NULL;
                } else {
                  ui_save_input(state);
                  fprintf(stderr, "\n\033[31m  [!] UYARI: AKRANIN ANAHTARI "
                                  "DEĞİŞMİŞ! (MITM RİSKİ)\033[0m\n");
                  fprintf(stderr, "      Adres: %s\n", peer_onion);
                  fprintf(stderr, "      Kayıtlı İsim: %s\n", name);
                  fprintf(stderr, "      Yeni Fingerprint: %s\n", fp_str);
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
                fprintf(stderr, "      Fingerprint: %s\n", fp_str);
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
              explicit_bzero(payload, 4096 + NOX_MAC_LEN);
              free(payload);
              continue;
            }
            state->rx_seq++;

            if (fh.type == NOX_MSG_TEXT) {
              uint8_t *pt = malloc(4096 + 1);
              if (pt) {
                ssize_t pt_len =
                    noise_decrypt(state->session, payload, fh.len, pt);
                if (pt_len > 0) {
                  pt[pt_len] = '\0';
                  ui_print_incoming(state, (const char *)pt);
                }
                explicit_bzero(pt, 4096 + 1);
                free(pt);
              }
            } else if (fh.type == NOX_MSG_FILE) {
              uint8_t *pt = malloc(4096);
              if (pt) {
                ssize_t pt_len =
                    noise_decrypt(state->session, payload, fh.len, pt);
                if (pt_len > 0) {
                  if (!state->rx_file.active && pt_len == 305 &&
                      memcmp(pt, "METADATA", 9) == 0) {
                    /* Yeni dosya transferi (Metadata) */
                    char safe_name[256];
                    memcpy(safe_name, pt + 9, 256);
                    safe_name[255] = '\0';
                    sanitize_filename(safe_name, sizeof(safe_name));

                    uint64_t net_size;
                    net_size =
                        ((uint64_t)pt[265] << 56) | ((uint64_t)pt[266] << 48) |
                        ((uint64_t)pt[267] << 40) | ((uint64_t)pt[268] << 32) |
                        ((uint64_t)pt[269] << 24) | ((uint64_t)pt[270] << 16) |
                        ((uint64_t)pt[271] << 8) | ((uint64_t)pt[272]);

/* Dosya boyut sınırı kontrolü (O1) - Maksimum 100 GB */
#define NOX_MAX_FILE_SIZE (100ULL * 1024 * 1024 * 1024)
                    if (net_size == 0 || net_size > NOX_MAX_FILE_SIZE) {
                      ui_print_error(state,
                                     "Gelen dosya reddedildi: Geçersiz veya "
                                     "çok büyük dosya boyutu (%lu byte)",
                                     (unsigned long)net_size);
                    } else {
                      uint8_t file_hash[32];
                      memcpy(file_hash, pt + 273, 32);

                      /* Dosyayı diske aç (received_ öneki ile) */
                      char recv_path[NOX_PATH_MAX];
                      snprintf(recv_path, sizeof(recv_path), "received_%s",
                               safe_name);

                      int file_fd =
                          open(recv_path,
                               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                      if (file_fd >= 0) {
                        explicit_bzero(&state->rx_file, sizeof(state->rx_file));
                        state->rx_file.active = true;
                        state->rx_file.fd = file_fd;
                        state->rx_file.expected_size = net_size;
                        state->rx_file.received_bytes = 0;
                        memcpy(state->rx_file.expected_hash, file_hash, 32);
                        strncpy(state->rx_file.filename, safe_name, 255);
                        state->rx_file.filename[255] = '\0';

                        crypto_generichash_init(&state->rx_file.hash_state,
                                                NULL, 0, 32);

                        ui_print_system(state, "[⬇] Gelen dosya: %s (%lu byte)",
                                        safe_name, (unsigned long)net_size);
                      } else {
                        ui_print_error(state, "Gelen dosya (%s) oluşturulamadı",
                                       safe_name);
                      }
                    }
                  } else if (state->rx_file.active) {
                    /* Dosya verisi chunk'ı — beklenen boyuttan fazla veri
                     * yazılmasını önle (O3) */
                    size_t remaining = state->rx_file.expected_size -
                                       state->rx_file.received_bytes;
                    if ((size_t)pt_len > remaining) {
                      pt_len = (ssize_t)remaining;
                    }

                    ssize_t w = write(state->rx_file.fd, pt, (size_t)pt_len);
                    if (w == pt_len) {
                      crypto_generichash_update(&state->rx_file.hash_state, pt,
                                                (size_t)pt_len);
                      state->rx_file.received_bytes += (size_t)pt_len;

                      if (state->rx_file.received_bytes >=
                          state->rx_file.expected_size) {
                        uint8_t final_hash[32];
                        crypto_generichash_final(&state->rx_file.hash_state,
                                                 final_hash, 32);

                        close(state->rx_file.fd);

                        if (memcmp(final_hash, state->rx_file.expected_hash,
                                   32) == 0) {
                          ui_print_system(state,
                                          "[✓] Dosya başarıyla alındı: %s",
                                          state->rx_file.filename);
                        } else {
                          char bad_path[NOX_PATH_MAX];
                          snprintf(bad_path, sizeof(bad_path), "received_%s",
                                   state->rx_file.filename);
                          unlink(bad_path);
                          ui_print_error(
                              state,
                              "HATA: Alınan dosyanın (%s) hash'i uyuşmuyor! "
                              "Dosya silindi (bütünlük doğrulaması başarısız).",
                              state->rx_file.filename);
                        }

                        explicit_bzero(&state->rx_file, sizeof(state->rx_file));
                      } else {
                        ui_print_progress(state, state->rx_file.filename,
                                          state->rx_file.received_bytes,
                                          state->rx_file.expected_size, false);
                      }
                    } else {
                      char bad_path[NOX_PATH_MAX];
                      snprintf(bad_path, sizeof(bad_path), "received_%s",
                               state->rx_file.filename);
                      close(state->rx_file.fd);
                      unlink(bad_path);
                      ui_print_error(state,
                                     "Dosyaya yazılamadı, transfer iptal "
                                     "edildi ve yarım kalan dosya silindi.");
                      explicit_bzero(&state->rx_file, sizeof(state->rx_file));
                    }
                  }
                }
                explicit_bzero(pt, 4096);
                free(pt);
              }
            }

            /* Cleanup */
            explicit_bzero(payload, 4096 + NOX_MAC_LEN);
            free(payload);
          }
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
    };

    nox_err_t err;

    /* ── 0. Komut satırı argümanları ───────────────────── */
    if (argc == 2 && strcmp(argv[1], "--full_cleankeys") == 0) {
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
      explicit_bzero(pin_buf, sizeof(pin_buf));
      return 1;
    }

    /* ── 7. Secure arena init ──────────────────────────── */
    err = arena_init(&state.arena, NOX_ARENA_DEFAULT_SIZE);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "arena başlatılamadı: %s", nox_strerror(err));
      explicit_bzero(pin_buf, sizeof(pin_buf));
      return 1;
    }

    /* ── 8. Salt yükle veya oluştur ───────────────────── */
    uint8_t salt[NOX_SALT_LEN];
    err = crypto_load_or_create_salt(salt, state.config_dir);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "salt hatası: %s", nox_strerror(err));
      explicit_bzero(pin_buf, sizeof(pin_buf));
      arena_destroy(&state.arena);
      return 1;
    }

    /* ── 9. Key derivation: PIN → master_key ──────────── */
    state.master_key = arena_alloc(&state.arena, NOX_KEY_LEN);
    if (!state.master_key) {
      NOX_FATAL(LOG_MOD_MAIN, "arena alloc başarısız (master_key)");
      explicit_bzero(pin_buf, sizeof(pin_buf));
      arena_destroy(&state.arena);
      return 1;
    }

    err = crypto_derive_master_key(state.master_key, pin_buf, strlen(pin_buf),
                                   salt);

    /* PIN artık gerekli değil — hemen sil */
    explicit_bzero(pin_buf, sizeof(pin_buf));
    explicit_bzero(salt, sizeof(salt));
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
    uint8_t ed_pub[32];
    uint8_t ed_sk[64];
    explicit_bzero(ed_pub, sizeof(ed_pub));
    explicit_bzero(ed_sk, sizeof(ed_sk));

    if (state.first_run) {
      /* İlk çalıştırma: yeni key pair üret ve kaydet */
      err = crypto_generate_identity(state.identity_path, identity_unlock,
                                     ed_pub);
      if (err != NOX_OK) {
        NOX_FATAL(LOG_MOD_MAIN, "identity key üretimi başarısız: %s",
                  nox_strerror(err));
        arena_destroy(&state.arena);
        return 1;
      }
      NOX_INFO(LOG_MOD_MAIN, "yeni identity key oluşturuldu");
    }

    /* Diskten şifreli anahtarı yükle */
    err = crypto_load_identity(state.identity_path, identity_unlock, ed_sk,
                               ed_pub);
    if (err == NOX_ERR_AUTH) {
      NOX_FATAL(LOG_MOD_MAIN, "yanlış PIN — identity key çözülemedi");
      arena_destroy(&state.arena);
      return 1;
    }
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "identity key yükleme hatası: %s",
                nox_strerror(err));
      arena_destroy(&state.arena);
      return 1;
    }
    NOX_INFO(LOG_MOD_MAIN, "identity key yüklendi");

    /* Ed25519 anahtar çiftini Curve25519 (X25519) formatına dönüştür */
    err = crypto_ed25519_to_curve25519(state.my_static_pub,
                                       state.my_static_priv, ed_pub, ed_sk);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "anahtar dönüştürme başarısız");
      arena_destroy(&state.arena);
      return 1;
    }

    /* Hassas geçici Ed25519 verileri sıfırla */
    explicit_bzero(ed_pub, sizeof(ed_pub));
    explicit_bzero(ed_sk, sizeof(ed_sk));
    memory_barrier();

    /*
     * identity_unlock artık gerekli değil — hemen sil.
     * Bu en hassas subkey: identity.key'i açan anahtar.
     */
    explicit_bzero(identity_unlock, NOX_KEY_LEN);
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
    err = db_init(state.config_dir, state.db_key);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "veritabanı başlatılamadı: %s",
                nox_strerror(err));
      arena_destroy(&state.arena);
      return 1;
    }

    NOX_INFO(LOG_MOD_MAIN, "public key hazır");
    NOX_DEBUG(
        LOG_MOD_MAIN, "arena: %zu byte / %zu KB kullanımda",
        arena_bytes_used(&state.arena),
        (arena_bytes_used(&state.arena) + arena_bytes_free(&state.arena)) /
            1024);

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
      explicit_bzero(&sa, sizeof(sa));
      explicit_bzero(&sb, sizeof(sb));
      explicit_bzero(alice_priv, sizeof(alice_priv));
      explicit_bzero(bob_priv, sizeof(bob_priv));
    }
    NOX_INFO(LOG_MOD_MAIN, "=== Noise demo tamamlandı ===");

    /* ── 13. Tor spawn → bootstrap → HS ─────────────── */
    err = tor_spawn(&state);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "Tor başlatılamadı: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    err = tor_authenticate(state.tor_ctrl_fd, state.tor_data_dir);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "Tor auth başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    err = tor_wait_bootstrap(state.tor_ctrl_fd, 120);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "Tor bootstrap başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    /* SOCKS port'unu öğren (auto port) */
    err = tor_get_socks_port(state.tor_ctrl_fd, &state.socks_port);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "SOCKS port öğrenilemedi: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    /* ── 14. TCP listener + Hidden Service ─────────── */
    err = listener_create(&state.listen_port, &state.listen_fd);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "listener başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    err = tor_create_hidden_service(state.tor_ctrl_fd, state.listen_port,
                                    state.onion_addr, sizeof(state.onion_addr));
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "Hidden Service başarısız: %s",
                nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    NOX_INFO(LOG_MOD_MAIN, "adresiniz: %s", state.onion_addr);

    /* ── 15. epoll event loop ─────────────────────────── */
    err = epoll_setup(&state, state.listen_fd);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "epoll setup başarısız: %s", nox_strerror(err));
      cleanup(&state);
      return 1;
    }

    NOX_INFO(LOG_MOD_MAIN, "init tamamlandı — event loop başlıyor");
    NOX_INFO(LOG_MOD_MAIN, "arena: %zu byte / %zu KB kullanımda",
             arena_bytes_used(&state.arena),
             (arena_bytes_used(&state.arena) + arena_bytes_free(&state.arena)) /
                 1024);

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

    event_loop(&state);

    NOX_INFO(LOG_MOD_MAIN, "shutdown sinyali alındı");

    /* ── Cleanup ───────────────────────────────────────── */
    cleanup(&state);

    NOX_INFO(LOG_MOD_MAIN, "%s kapatıldı", PARANOID_APP_NAME);
    return 0;
  }
