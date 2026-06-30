/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT: Bu yazılım GPLv3 ile korunmaktadır ve hukuken herkesin kullanımına açıktır.
 * Ancak yazarın kişisel ricasıdır bu yazılımın ve türevlerinin aşağıda belirtilen kişi, kurum veya 
 * oluşumlar tarafından KULLANILMASI, BARINDIRILMASI veya GELİŞTİRİLMESİ yazar tarafından etik nedenlerden dolayı hoş karşılanmaz:
 *
 * 1.HALK İRADESİNİ GASPEDENLER: Seçme ve seçilme hakkını yok sayarak,
 *   halkın oylarıyla seçilmiş yerel veya ulusal yönetimlerin veya partilerin üzerine çöken, 
 *   hukuksuz bir şekilde atanan tüm kayyumlar, kayyum yönetimleri ve onların 
 *   alt kadroları.
 *
 * 2.DİKTATÖRLER VE OTORİTER REJİMLER: Gücü tek elde toplayarak yargıyı, basını 
 *   ve ifade özgürlüğünü baskılayan, demokratik süreçleri işletmeyen diktatörler, 
 *   otokratlar ve onların rejim aygıtları.
 *
 * 3.SANSÜR VE GÖZETİM MEKANİZMALARI: İnterneti kısıtlayan, insanları fikirlerinden 
 *   dolayı hapseden, kitlesel takip ve fişleme teknolojileri geliştiren tüm 
 *   devlet kurumları veya bunlara destek veren şirketler.
 *
 *
 *
 *
 *
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
#ifndef NO_SECCOMP
#include "seccomp_policy.h"
#endif
#include "state_machine.h"
#include "event_loop.h"

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
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <linux/capability.h>

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

static void sigchld_handler(int sig) {
  (void)sig;
  g_tor_died = 1;
}

/* ================================================================
 * SECCOMP STAGE 1 CONSTRUCTOR — main'den önce yüklenir
 *
 * glibc CRT → constructor → main sırasıyla çalışılır.
 * Bu noktada log sistemi, arena, sodium henüz başlatılmamış —
 * ama stage 1'in engellediği hiçbir syscall'a ihtiyaç yok.
 * ================================================================ */
#ifndef NO_SECCOMP
__attribute__((constructor))
static void seccomp_stage1_early(void) {
#ifdef PR_SET_NO_NEW_PRIVS
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif
  if (seccomp_policy_load(1) != NOX_OK) {
    const char msg[] = "FATAL: seccomp stage 1 yüklenemedi\n";
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
  }
}
#endif

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

  /* SIGCHLD → Tor crash tespiti (defense-in-depth) */
  struct sigaction sa_chld = {
      .sa_handler = sigchld_handler,
      .sa_flags = SA_RESTART | SA_NOCLDSTOP,
  };
  sigemptyset(&sa_chld.sa_mask);
  sigaction(SIGCHLD, &sa_chld, NULL);
}

/* Ctrl+P (0x10) → SIGQUIT eşlemesi */
static void setup_terminal(void) {
  if (!isatty(STDIN_FILENO))
    return;

  if (tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
    g_termios_saved = true;

    struct termios raw = g_orig_termios;
    raw.c_lflag &= ~((tcflag_t)ICANON);  /* Canonical mode kapat — anlık okuma */
    raw.c_lflag &= ~((tcflag_t)ECHO);    /* Echo kapat — program kendi yazacak */
    raw.c_cc[VMIN]  = 1;  /* En az 1 byte oku */
    raw.c_cc[VTIME] = 0;  /* Zaman aşımı yok */
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
  if (strncmp(state->downloads_dir, state->config_dir, strlen(state->config_dir)) != 0) {
    NOX_ERROR(LOG_MOD_MAIN, "downloads_dir config_dir altında değil — yapılandırma hatası");
    return NOX_ERR_CONFIG;
  }
  state->downloads_dir_fd = open(state->downloads_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
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
#ifndef DEBUG
  /* Release: Terminal scrollback'i hemen sil — session/chat
   * mesajları scrollback buffer'da kalmasın (OPSAFE). */
  fprintf(stderr, "\033[2J\033[3J\033[H");
  fflush(stderr);
#endif

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

  /* Tüm peer session'ları temizle */
  for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
    struct peer_session *ps = &state->peers[i];
    if (ps->fd >= 0 || ps->session || ps->hs) {
      sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
    }
    /* Manuel temizlik — sm_dispatch başarısız olursa bile fd kapat */
    if (ps->fd >= 0) {
      epoll_remove_fd(state->epoll_fd, ps->fd);
      close(ps->fd);
    }
    sodium_memzero(ps, sizeof(*ps));
    ps->fd = -1;
  }

  /* Secure arena — explicit_bzero + munmap */
  arena_destroy(&state->arena);

  /* Dosya transferi temizliği — FD'leri kapat, yarım dosyaları sil */
  file_transfer_cleanup(state);

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

  /* File descriptor'ları kapat — tor_shutdown SONRASINDA
   * (Tor process'i zaten sonlandırıldı, socket artık kullanılmıyor) */
  if (state->listen_fd >= 0) {
    close(state->listen_fd);
    state->listen_fd = -1;
  }
  /* UNIX socket dosyalarını temizle (tor_data_dir zaten silindi,
   * ama double-check: unlink başarısızlığı ENOENT ise zararsız) */
  if (state->listen_path[0] != '\0') {
    unlink(state->listen_path);
    state->listen_path[0] = '\0';
  }
  if (state->socks_path[0] != '\0') {
    unlink(state->socks_path);
    state->socks_path[0] = '\0';
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

  /* Honeypot scattered allocation: 0-3 rastgele sahte key yerleştirir.
   * Arena layout'u her çalıştırmada farklı olur → saldırgan tahmin edemez. */
  static void scatter_honeypots(struct secure_arena *a, size_t min, size_t max) {
    size_t count = min + randombytes_uniform((unsigned int)(max - min + 1));
    for (size_t i = 0; i < count; i++)
      arena_alloc_canary(a, NOX_KEY_LEN);
  }

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /* Struct'ı sıfırla — static: stack overflow riskini ortadan kaldırır
     * {0} → .bss (binary'de yer kaplamaz, runtime'da otomatik sıfırlanır) */
    static struct app_state state = {0};

    /* Default değerler — runtime'da ayarlanır */
    state.tor_ctrl_fd = -1;
    state.epoll_fd = -1;
    state.listen_fd = -1;
    state.peer_fd = -1;
    state.running = true;
    state.peer_state = ST_IDLE;
    state.active_peer_idx = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        state.peers[i].fd = -1;
        state.peers[i].tofu_peer_fd = -1;
    }

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

      /* Onion key dosyası yolu */
      char onion_key_path[NOX_PATH_MAX];
      size_t okp_len = strlen(state.config_dir);
      if (okp_len + 10 < NOX_PATH_MAX) {
        memcpy(onion_key_path, state.config_dir, okp_len);
        memcpy(onion_key_path + okp_len, "/onion.key", 10);
      } else {
        onion_key_path[0] = '\0';
      }

      /* contacts.db */
      char db_path[NOX_PATH_MAX];
      memcpy(db_path, state.config_dir, dir_len);
      memcpy(db_path + dir_len, "/contacts.db", 13); /* 12 + NUL */

      const char *all_files[] = {state.identity_path, salt_path, db_path,
                                 state.contacts_path, onion_key_path, NULL};

      int wiped = 0;
      for (int i = 0; all_files[i] != NULL; i++) {
        /* CodeQL #11 cpp/path-injection: tüm dosya yolları config_dir'den türetilmiştir */
        assert(strncmp(all_files[i], state.config_dir, dir_len) == 0);
        if (strncmp(all_files[i], state.config_dir, dir_len) != 0) {
          NOX_WARN(LOG_MOD_MAIN, "dosya yolu config_dir altında değil — silme atlanıyor");
          continue;
        }
        struct stat st;
        if (stat(all_files[i], &st) != 0)
          continue; /* dosya yok — sorun değil */

        /* Dosyayı sıfırlarla üzerine yaz */
        int fd = open(all_files[i], O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
          uint8_t zeros[256];
          explicit_bzero(zeros, sizeof(zeros));
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

    /* ── 7. RLIMIT_MEMLOCK kontrolü ──────────────────────
     * Arena + sodium_malloc tahmini toplamı mevcut kilitten
     * fazlaysa NOX_ERR_LOCKED ile başlattırmıyoruz. */
#define NOX_SODIUM_LOCKED_BUDGET  (64U * 1024U) /* tahmini sodium heap */
    {
      struct rlimit rl;
      if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        size_t needed = NOX_ARENA_DEFAULT_SIZE + NOX_SODIUM_LOCKED_BUDGET;
        if (rl.rlim_cur < needed) {
          NOX_FATAL(LOG_MOD_MAIN,
                    "RLIMIT_MEMLOCK yetersiz: %lu < %zu byte "
                    "(arena + sodium_heap)",
                    (unsigned long)rl.rlim_cur, needed);
          sodium_memzero(pin_buf, sizeof(pin_buf));
          return NOX_ERR_LOCKED;
        }
        NOX_INFO(LOG_MOD_MAIN, "RLIMIT_MEMLOCK: %lu byte (gerekli: %zu)",
                 (unsigned long)rl.rlim_cur, needed);
      }
    }

    /* ── 8. Secure arena init ──────────────────────────── */
    err = arena_init(&state.arena, NOX_ARENA_DEFAULT_SIZE);
    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "arena başlatılamadı: %s", nox_strerror(err));
      sodium_memzero(pin_buf, sizeof(pin_buf));
      return 1;
    }

    /* ── 8b. PR_SET_DUMPABLE=0 —mümkün olduğunca erken ──────
     * Arena mmap'landı, key'ler oluşmaya başlayacak.
     * /proc/PID/mem ve ptrace ile okuma engellenir.
     * Terminal I/O dumpable gerektirmez.
     * Core dump üretilmez (PR_SET_DUMPABLE=0 kernel-level engel). */
#ifdef PR_SET_DUMPABLE
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

    /* ── 8c. CAP_NET_RAW ──────────────────────────────────────
     * PR_CAPBSET_DROP normal kullanıcıda çalışmaz (CAP_SETPCAP gerekir).
     * Raw socket engelleme seccomp stage 2'de yapılıyor (AF_PACKET,
     * SOCK_RAW KILL kuralı). Bu blok sadece root/sudo için korunuyor. */
#ifdef PR_CAPBSET_QUERY
    if (prctl(PR_CAPBSET_QUERY, CAP_NET_RAW, 0, 0, 0) == 0) {
      /* CAP_NET_RAW zaten bounding set dışında — bir şey yapma */
    } else if (prctl(PR_CAPBSET_DROP, CAP_NET_RAW, 0, 0, 0) == 0) {
      NOX_INFO(LOG_MOD_HARD, "CAP_NET_RAW düşürüldü");
    }
    /* Normal kullanıcı: EPERM beklenir, sessizce atla */
#else
    prctl(PR_CAPBSET_DROP, CAP_NET_RAW, 0, 0, 0);
#endif

    /* ── 9. Salt yükle veya oluştur ───────────────────── */
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
    scatter_honeypots(&state.arena, 0, 3);
    state.master_key = arena_alloc(&state.arena, NOX_KEY_LEN);
    scatter_honeypots(&state.arena, 0, 3);
    if (!state.master_key) {
      NOX_FATAL(LOG_MOD_MAIN, "arena alloc başarısız (master_key)");
      sodium_memzero(pin_buf, sizeof(pin_buf));
      arena_destroy(&state.arena);
      return 1;
    }

    err = crypto_derive_master_key(state.master_key, pin_buf, strlen(pin_buf),
                                   salt);

    /* Kontrat: crypto_derive_master_key pin_buf'ı kendi siler (P9).
     * Main'de tekrar silmeye gerek yok — idempotent ama gereksiz. */
    sodium_memzero(salt, sizeof(salt));
    memory_barrier();
    NOX_INFO(LOG_MOD_MAIN, "Salt bellekten silindi");

    if (err != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "key derivation başarısız: %s",
                nox_strerror(err));
      arena_destroy(&state.arena);
      return 1;
    }

    /* ── 10. Subkey türetimi ─────────────────────────── */
    scatter_honeypots(&state.arena, 0, 3);
    state.db_key = arena_alloc(&state.arena, NOX_KEY_LEN);
    scatter_honeypots(&state.arena, 0, 3);
    uint8_t *identity_unlock = arena_alloc(&state.arena, NOX_KEY_LEN);
    scatter_honeypots(&state.arena, 0, 3);
    state.session_key = arena_alloc(&state.arena, NOX_KEY_LEN);
    scatter_honeypots(&state.arena, 0, 3);

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
    scatter_honeypots(&state.arena, 0, 3);
    state.my_static_priv = arena_alloc(&state.arena, NOX_KEY_LEN);
    scatter_honeypots(&state.arena, 0, 3);
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
    if (strncmp(state.identity_path, state.config_dir, strlen(state.config_dir)) != 0) {
      NOX_ERROR(LOG_MOD_MAIN, "identity_path config_dir altında değil — yapılandırma hatası");
      return NOX_ERR_CONFIG;
    }
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

    /* ── 10b. Seccomp Stage 1 ──────────────────────────────────
     * Artık __attribute__((constructor)) ile main'den önce yükleniyor.
     * Bak: seccomp_stage1_early() fonksiyonu. */

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
      handshake_read(&hs_b, msg_buf, msg_len, pl_buf, sizeof(pl_buf), &pl_len);
      NOX_INFO(LOG_MOD_NOISE, "msg0 alındı");

      /* msg1: Bob → Alice */
      msg_len = sizeof(msg_buf);
      handshake_write(&hs_b, NULL, 0, msg_buf, &msg_len);
      NOX_INFO(LOG_MOD_NOISE, "msg1 gönderildi (%zu byte)", msg_len);

      pl_len = sizeof(pl_buf);
      handshake_read(&hs_a, msg_buf, msg_len, pl_buf, sizeof(pl_buf), &pl_len);
      NOX_INFO(LOG_MOD_NOISE, "msg1 alındı");

      /* msg2: Alice → Bob */
      msg_len = sizeof(msg_buf);
      handshake_write(&hs_a, NULL, 0, msg_buf, &msg_len);
      NOX_INFO(LOG_MOD_NOISE, "msg2 gönderildi (%zu byte)", msg_len);

      pl_len = sizeof(pl_buf);
      handshake_read(&hs_b, msg_buf, msg_len, pl_buf, sizeof(pl_buf), &pl_len);
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

    /* ── 14. Tek Global Listener + Hidden Service ─────────── */
    /* Tek onion modeli: tek listener, tek HS, tüm peer'lar buraya bağlanır. */
    {
      err = listener_create(state.tor_data_dir, state.listen_path,
                            &state.listen_fd);
      if (err != NOX_OK) {
        if (g_shutdown) goto shutdown_clean;
        NOX_FATAL(LOG_MOD_MAIN, "listener başarısız: %s", nox_strerror(err));
        cleanup(&state);
        return 1;
      }

      /* HS — onion.key dosyasından veya yeni üret */
      {
        char onion_key_path[NOX_PATH_MAX];
        {
          size_t okp_len = strlen(state.config_dir);
          if (okp_len + 10 < NOX_PATH_MAX) {
            memcpy(onion_key_path, state.config_dir, okp_len);
            memcpy(onion_key_path + okp_len, "/onion.key", 10);
          } else {
            onion_key_path[0] = '\0';
          }
        }

        char saved_key[NOX_ONION_KEY_B64_LEN + 1];
        saved_key[0] = '\0';

        int key_fd = open(onion_key_path, O_RDONLY);
        if (key_fd >= 0) {
          ssize_t n = read(key_fd, saved_key, NOX_ONION_KEY_B64_LEN);
          close(key_fd);
          if (n == (ssize_t)NOX_ONION_KEY_B64_LEN) {
            saved_key[NOX_ONION_KEY_B64_LEN] = '\0';
          } else {
            saved_key[0] = '\0';
          }
        }

        if (saved_key[0] != '\0') {
          err = tor_create_persistent_hs(state.tor_ctrl_fd, state.listen_path,
                                          saved_key,
                                          state.onion_addr,
                                          sizeof(state.onion_addr));
          explicit_bzero(saved_key, sizeof(saved_key));
          if (err != NOX_OK) {
            if (g_shutdown) goto shutdown_clean;
            NOX_FATAL(LOG_MOD_MAIN, "Persistent HS başarısız: %s",
                      nox_strerror(err));
            cleanup(&state);
            return 1;
          }
          NOX_INFO(LOG_MOD_MAIN, "adresiniz (kalıcı): %s", state.onion_addr);
        } else {
          err = tor_create_new_hs(state.tor_ctrl_fd, state.listen_path,
                                   state.onion_addr, sizeof(state.onion_addr),
                                   saved_key, sizeof(saved_key));
          if (err != NOX_OK) {
            explicit_bzero(saved_key, sizeof(saved_key));
            if (g_shutdown) goto shutdown_clean;
            NOX_FATAL(LOG_MOD_MAIN, "Yeni HS başarısız: %s",
                      nox_strerror(err));
            cleanup(&state);
            return 1;
          }

          key_fd = open(onion_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
          if (key_fd >= 0) {
            nox_err_t werr = write_full(key_fd, saved_key, NOX_ONION_KEY_B64_LEN);
            close(key_fd);
            if (werr != NOX_OK) {
              NOX_WARN(LOG_MOD_MAIN, "onion key yazılamadı: %s",
                       nox_strerror(werr));
            } else {
              NOX_INFO(LOG_MOD_MAIN, "onion key kaydedildi: %s",
                       onion_key_path);
            }
          } else {
            NOX_WARN(LOG_MOD_MAIN, "onion key dosyaya yazılamadı: %s",
                     strerror(errno));
          }

          explicit_bzero(saved_key, sizeof(saved_key));
          NOX_INFO(LOG_MOD_MAIN, "adresiniz: %s", state.onion_addr);
        }
      }
    }

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
    tui_refresh_all(&state);

#ifndef NO_SECCOMP
    /* ── 15b. Seccomp Stage 2 — Tam blacklist ────────────────
     * Tor/HS hazır, TUI init bitti. Fork/execve artık gerekmez.
     * TUI init'i stage 1'de bırakıyoruz: ncurses/terminfo bazı sistemlerde
     * fork/clone kullanabiliyor; event loop stage 2 ile korunuyor. */
    if (seccomp_policy_load(2) != NOX_OK) {
      NOX_FATAL(LOG_MOD_MAIN, "seccomp stage 2 yüklenemedi — abort");
      cleanup(&state);
      return 1;
    }
#endif

    if (g_shutdown) goto shutdown_clean;

    event_loop(&state);

    NOX_INFO(LOG_MOD_MAIN, "shutdown sinyali alındı");

shutdown_clean:
    /* ── Cleanup ───────────────────────────────────────── */
    cleanup(&state);

    NOX_INFO(LOG_MOD_MAIN, "%s kapatıldı", PARANOID_APP_NAME);
    _exit(0); /* atexit handler'larını atla — clone() SIGSYS'e yol açar */
  }
