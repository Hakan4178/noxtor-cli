/* SPDX-License-Identifier: GPL-3.0-or-later
 * network.c — Tor entegrasyonu ve ağ katmanı
 */

#include "network.h"
#include "common.h"
#include "types.h"
#include "seccomp_policy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include <poll.h>

/* ── Timeout sabitleri ────────────────────────── */
#define NOX_READ_TIMEOUT_MS       10000
#define NOX_CTRL_TIMEOUT_MS       5000
#define NOX_BOOTSTRAP_TIMEOUT_MAX 3600
#define NOX_CTRL_SOCK_WAIT_SEC    30
#define NOX_CTRL_CONNECT_RETRIES  10

/* ── EINTR-safe nanosleep ─────────────────────── */
static void safe_nanosleep(const struct timespec *req) {
  struct timespec ts = *req;
  struct timespec rem;
  while (nanosleep(&ts, &rem) == -1 && errno == EINTR) {
    ts = rem;
  }
}

/* ================================================================
 * ONION ADDRESS VALIDATION
 *
 * A-2 FIX: Onion v3 adres format doğrulaması
 * Format: 56 karakter base32 + ".onion" = 62 karakter
 * Public: tor_create_hidden_service (S3 — kendi HS adresimiz) ve
 *         socks5_connect (peer adresi) tarafından çağrılır.
 *
 * S3 notu: v3 checksum (SHA3-256 truncated) doğrulaması YAPILMAZ.
 *   libsodium SHA3-256 sunmaz, ek kütüphane ekleme maliyeti
 *   defense-in-depth'e değmez. Tor ADD_ONION yanıtı zaten
 *   geçerli v3 adres üretir (deterministik ED25519-V3).
 * ================================================================ */
bool validate_onion_address(const char *addr) {
  if (!addr)
    return false;
  
  size_t len = strlen(addr);
  if (len != NOX_ONION_LEN)
    return false;
  
  /* ".onion" suffix kontrolü */
  if (strcmp(addr + 56, ".onion") != 0)
    return false;
  
  /* İlk 56 karakter base32 olmalı: a-z, 2-7 */
  for (size_t i = 0; i < 56; i++) {
    char c = addr[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
      return false;
  }
  
  return true;
}

/* ================================================================
 * I/O HELPERS — EINTR + EAGAIN/EWOULDBLOCK koruması
 * ================================================================ */
/* write_full — generic write helper.
 * CodeQL #6-#7: "Exposure of system data to an unauthorized control sphere"
 * Bu fonksiyon sadece bizim process'larımız tarafından çağrılır:
 * - Tor control socket (bizim child process)
 * - torrc dosyası (kendi config dosyamız)
 * - SOCKS5 greeting (sabit byte'lar)
 * Hassas veri 3. partiye gitmez — FP. */
nox_err_t write_full(int fd, const void *buf, size_t len) {
  /* CodeQL #6-#7 cpp/system-data-exposure: getenv("HOME") → config_dir → torrc zincirini
   * takip ediyor. Bu fonksiyon sadece bizim process'larımız tarafından çağrılır
   * (Tor control socket, torrc dosyası, SOCKS5). Hassas veri 3. partiye gitmez. */
  assert(buf != NULL || len == 0);
  const uint8_t *p = (const uint8_t *)buf;
  size_t written = 0;
  while (written < len) {
    /* CodeQL #6-#7 cpp/system-data-exposure: write() çağrısı Tor control socket'e
     * yapılıyor — bizim child process'ımız. Hassas veri 3. partiye gitmez. */
    assert(fd >= 0);
    ssize_t w = write(fd, p + written, len - written);
    if (w < 0) {
      if (errno == EINTR)
        continue;
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
#else
      if (errno == EAGAIN) {
#endif
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pret = poll(&pfd, 1, 3000);
        if (pret < 0 && errno != EINTR)
          return NOX_ERR_IO;
        continue;
      }
      return NOX_ERR_IO;
    }
    if (w == 0)
      return NOX_ERR_IO;
    written += (size_t)w;
  }
  return NOX_OK;
}

nox_err_t read_full(int fd, void *buf, size_t len) {
  uint8_t *p = (uint8_t *)buf;
  size_t received = 0;
  while (received < len) {
    ssize_t r = read(fd, p + received, len - received);
    if (r < 0) {
      if (errno == EINTR)
        continue;
#if defined(EAGAIN) && defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
#else
      if (errno == EAGAIN) {
#endif
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int poller = poll(&pfd, 1, NOX_READ_TIMEOUT_MS);
        if (poller <= 0) {
          return NOX_ERR_IO; /* Timeout veya hata */
        }
        continue;
      }
      return NOX_ERR_IO;
    }
    if (r == 0)
      return NOX_ERR_IO; /* EOF */
    received += (size_t)r;
  }
  return NOX_OK;
}

/* ================================================================
 * CONTROL PROTOCOL YARDIMCILARI
 * ================================================================ */
nox_err_t ctrl_send_command(int fd, const char *cmd) {
  return write_full(fd, cmd, strlen(cmd));
}

nox_err_t ctrl_read_line(int fd, char *buf, size_t buf_size, int timeout_ms) {
  if (buf_size < 2) {
    NOX_ERROR(LOG_MOD_NET, "ctrl_read_line buffer çok küçük");
    return NOX_ERR_CONFIG;
  }

  /* A-1: Deadline tabanlı timeout — her byte'da timeout resetlenmez.
   * Slow loris saldırısını engeller: tüm satır tek timeout_ms içinde
   * tamamlanmalı, aksi takdirde NOX_ERR_TOR döner. */
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += timeout_ms / 1000;
  deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
  if (deadline.tv_nsec >= 1000000000L) {
    deadline.tv_sec++;
    deadline.tv_nsec -= 1000000000L;
  }

  size_t pos = 0;

  while (pos < buf_size - 1) {
    if (g_shutdown)
      return NOX_ERR_TOR;

    /* Kalan süre hesapla */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long remaining_ms = (long)(deadline.tv_sec - now.tv_sec) * 1000 +
                        (long)(deadline.tv_nsec - now.tv_nsec) / 1000000L;
    if (remaining_ms <= 0) {
      NOX_ERROR(LOG_MOD_NET, "ctrl okuma timeout");
      return NOX_ERR_TOR;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int poll_timeout = (remaining_ms > INT_MAX) ? INT_MAX : (int)remaining_ms;
    int ret = poll(&pfd, 1, poll_timeout);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      NOX_ERROR(LOG_MOD_NET, "poll: %s", strerror(errno));
      return NOX_ERR_IO;
    }
    if (ret == 0) {
      NOX_ERROR(LOG_MOD_NET, "ctrl okuma timeout");
      return NOX_ERR_TOR;
    }

    char c;
    ssize_t r;
    do {
      r = read(fd, &c, 1);
    } while (r < 0 && errno == EINTR);

    if (r <= 0) {
      NOX_ERROR(LOG_MOD_NET, "Tor ctrl bağlantısı kapandı");
      return NOX_ERR_TOR;
    }

    buf[pos++] = c;
    if (c == '\n')
      break;
  }

  buf[pos] = '\0';
  return NOX_OK;
}

static nox_err_t ctrl_read_response(int fd, char *buf, size_t buf_size,
                                    int timeout_ms) {
  size_t total = 0;

  for (;;) {
    char line[256];
    nox_err_t err = ctrl_read_line(fd, line, sizeof(line), timeout_ms);
    if (err != NOX_OK)
      return err;

    size_t llen = strlen(line);

    /* Buffer taşma koruması */
    if (total + llen + 1 >= buf_size) {
      NOX_ERROR(LOG_MOD_NET, "ctrl yanıt buffer'ı taştı");
      return NOX_ERR_OVERFLOW;
    }
    memcpy(buf + total, line, llen);
    total += llen;

    /* "250 " = son satır, "250-" = devam */
    if (llen >= 4 && line[0] == '2' && line[1] == '5' && line[2] == '0' &&
        line[3] == ' ')
      break;

     if (llen >= 3 && (line[0] == '4' || line[0] == '5')) {
       buf[total] = '\0';
       NOX_ERROR(LOG_MOD_NET, "Tor hatası: %s", line);
       return NOX_ERR_TOR;
    }
  }

  buf[total] = '\0';
  return NOX_OK;
}

/* d_name güvenlik kontrolü — path traversal koruması */
static bool is_safe_filename(const char *name) {
  if (name[0] == '\0') return false;
  if (strchr(name, '/') != NULL) return false;
  if (strcmp(name, ".") == 0) return false;
  if (strcmp(name, "..") == 0) return false;
  return true;
}

/* Symlink-safe recursive delete.
 * lstat() + O_NOFOLLOW + fstatat(AT_SYMLINK_NOFOLLOW) + unlinkat()
 * ile symlink saldırılarını engeller.
 *
 * TOCTOU koruması: lstat()+unlink() yerine fstatat()+unlinkat()
 * kullanılır — check-use penceresi kaldırılmış olur.
 * [CodeQL #2-#5 — TOCTOU race condition]
 */
static void rm_rf(const char *path) {
  /* Dizin olarak aç (O_NOFOLLOW — symlink takibi yok) */
  int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dirfd < 0) {
    /* Dizin değilse dosya/symlink olarak sil */
    unlink(path);
    return;
  }

  /* İçeriği temizle */
  DIR *d = fdopendir(dirfd);
  if (!d) {
    close(dirfd);
    return;
  }

  struct dirent *p;
  while ((p = readdir(d))) {
    if (!is_safe_filename(p->d_name))
      continue;

    struct stat statbuf;
    if (fstatat(dirfd, p->d_name, &statbuf, AT_SYMLINK_NOFOLLOW) != 0)
      continue;

    if (S_ISDIR(statbuf.st_mode)) {
      /* Alt dizin — gerçekten recursive temizleme.
       * unlinkat(AT_REMOVEDIR) sadece boş dizinleri siler,
       * dolu dizinler ENOTEMPTY ile başarısız olur → anahtarlar sızar. */
      char subpath[NOX_PATH_MAX];
      int n = snprintf(subpath, sizeof(subpath), "%s/%s", path, p->d_name);
      if (n > 0 && (size_t)n < sizeof(subpath)) {
        rm_rf(subpath);
      }
    } else {
      unlinkat(dirfd, p->d_name, 0);
    }
  }
  closedir(d); /* fdopendir'den sonra closedir dirfd'yi de kapatır */

  /* Dizini sil — artık içi boş */
  rmdir(path);
}

/* Stale PID'yi güvenli parse et (atoi yerine strtol + hata kontrolü) */
static long safe_parse_pid(const char *str) {
  char *endptr;
  errno = 0;
  long pid = strtol(str, &endptr, 10);
  if (errno != 0 || *endptr != '\0' || pid <= 0 || pid > INT_MAX)
    return -1;
  return pid;
}

/* Stale Tor dizininin bizim UID'mize ait olduğunu ve
 * ilişkili PID'nin artık çalışmadığını (veya Tor olmadığını) doğrula */
static bool is_our_stale_entry(const char *full_path, long pid) {
  struct stat st;
  if (lstat(full_path, &st) != 0)
    return false;

  /* Sadece bizim UID'mize ait dosyaları temizle */
  if (st.st_uid != getuid())
    return false;

  /* PID hâlâ çalışıyor mu kontrol et */
  if (kill((pid_t)pid, 0) == 0 || errno != ESRCH) {
    /* Process var — Tor mu kontrol et (/proc/<pid>/comm) */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%ld/comm", pid);
    FILE *f = fopen(proc_path, "r");
    if (f) {
      char comm[32] = {0};
      if (fgets(comm, sizeof(comm), f)) {
        /* Trailing newline kaldır */
        comm[strcspn(comm, "\n")] = '\0';
        fclose(f);
        if (strcmp(comm, "tor") == 0)
          return false; /* Canlı Tor — silme */
      } else {
        fclose(f);
      }
    }
    /* /proc okunamazsa da silme (process hâlâ canlı olabilir) */
    if (kill((pid_t)pid, 0) == 0)
      return false;
  }

  return true;
}

static void cleanup_stale_tor_dirs(const char *config_dir) {
  DIR *d = opendir(config_dir);
  if (!d)
    return;

  struct dirent *p;
  while ((p = readdir(d))) {
    if (!is_safe_filename(p->d_name))
      continue;

    long pid = -1;
    bool is_data_dir = false;

    if (strncmp(p->d_name, "tor_data_", 9) == 0) {
      pid = safe_parse_pid(p->d_name + 9);
      is_data_dir = true;
    } else if (strncmp(p->d_name, "torrc_", 6) == 0) {
      pid = safe_parse_pid(p->d_name + 6);
    } else {
      continue;
    }

    if (pid <= 0)
      continue;

    char path[NOX_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", config_dir, p->d_name);
    if (n <= 0 || (size_t)n >= sizeof(path))
      continue;

    /* CodeQL cpp/path-injection: path'in config_dir altında olduğunu garanti et
     * (is_safe_filename + snprintf zaten bunu sağlıyor, ama CodeQL data flow'u takip edemiyor)
     * M-25 FIX: prefix-only değil, sonrasındaki karakteri de kontrol et */
    size_t cfg_len = strlen(config_dir);
    if (strncmp(path, config_dir, cfg_len) != 0)
      continue;
    if (path[cfg_len] != '\0' && path[cfg_len] != '/')
      continue;

    if (!is_our_stale_entry(path, pid))
      continue;

    if (is_data_dir) {
      rm_rf(path);
    } else {
      unlink(path);
    }
  }
  closedir(d);
}

/* ================================================================
 * TORRC ÜRETİMİ
 * ================================================================ */
static nox_err_t generate_torrc(struct app_state *state) {
  /* Temizlik: Stale (artık) Tor dizinlerini temizle */
  cleanup_stale_tor_dirs(state->config_dir);

  /* tor_data_<PID> — her instance kendi dizinini alır */
  int n = snprintf(state->tor_data_dir, NOX_PATH_MAX, "%s/tor_data_%d",
                   state->config_dir, (int)getpid());
  if (n <= 0 || (size_t)n >= NOX_PATH_MAX) {
    NOX_ERROR(LOG_MOD_NET, "config_dir yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  n = snprintf(state->torrc_path, NOX_PATH_MAX, "%s/torrc_%d",
               state->config_dir, (int)getpid());
  if (n <= 0 || (size_t)n >= NOX_PATH_MAX) {
    NOX_ERROR(LOG_MOD_NET, "config_dir yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  /* tor_data dizinini oluştur */
  if (mkdir(state->tor_data_dir, 0700) != 0 && errno != EEXIST) {
    NOX_ERROR(LOG_MOD_NET, "tor_data_dir oluşturulamadı: %s", strerror(errno));
    return NOX_ERR_TOR;
  }
  
  int dd = open(state->tor_data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dd >= 0) {
    fchmod(dd, 0700);
    close(dd);
  }

  /* torrc yaz — V6 FIX: O_NOFOLLOW symlink Engellemesi */
  int fd =
      open(state->torrc_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    if (errno == ELOOP) {
      NOX_ERROR(LOG_MOD_NET, "torrc yolu symlink — saldırı tespit edildi, siliniyor");
      unlink(state->torrc_path);
      fd = open(state->torrc_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    }
    if (fd < 0) {
      NOX_ERROR(LOG_MOD_NET, "torrc oluşturulamadı: %s", strerror(errno));
      return NOX_ERR_TOR;
    }
  }

  /* fstat ile dosya tipini doğrula — regular file değilse kapat */
  struct stat st;
  if (fstat(fd, &st) == 0 && !S_ISREG(st.st_mode)) {
    NOX_ERROR(LOG_MOD_NET, "torrc regular file değil — saldırı tespit edildi");
    close(fd);
    unlink(state->torrc_path);
    return NOX_ERR_TOR;
  }

  /* Buffer boyutunu yeterli yap: 4 * NOX_PATH_MAX + 1024 */
  char content[NOX_PATH_MAX * 4 + 1024];
  int clen = 0;

  if (state->transport_type == TRANSPORT_SNOWFLAKE) {
    const char *snowflake_path = "/usr/bin/snowflake-client";
    if (access("/usr/local/bin/snowflake-client", X_OK) == 0) {
      snowflake_path = "/usr/local/bin/snowflake-client";
    }
    clen = snprintf(
        content, sizeof(content),
        "SocksPort unix:%s/socks.sock\n"
        "ControlSocket %s/control.sock\n"
        "CookieAuthentication 1\n"
        "DataDirectory %s\n"
        "Log notice file %s/tor.log\n"
        "UseBridges 1\n"
        "UpdateBridgesFromAuthority 1\n"
        "ClientTransportPlugin snowflake exec %s\n"
        "Bridge snowflake 192.0.2.3:80 "
        "2B280B2313E81E262C97C20B2F2B4B2F5714EAB1 "
        "fingerprint=2B280B2313E81E262C97C20B2F2B4B2F5714EAB1 "
        "url=https://snowflake-broker.torproject.net/ front=cdn.sstatic.net "
        "ice=stun:stun.l.google.com:19302 utls-imitation=hellorandomizedalpn\n",
        state->tor_data_dir, state->tor_data_dir, state->tor_data_dir,
        state->tor_data_dir, snowflake_path);
  } else if (state->transport_type == TRANSPORT_OBFS4) {
    const char *obfs4_path = "/usr/bin/obfs4proxy";
    if (access("/usr/local/bin/obfs4proxy", X_OK) == 0) {
      obfs4_path = "/usr/local/bin/obfs4proxy";
    }
    if (strlen(state->obfs4_bridge_line) > 0) {
      /* C-1: Bridge line'daki \n karakterleri torrc'ye satır enjeksiyonu
       * yapabilir. Tor config dosyasında her satır tek bir direktördür.
       * Yeni satır karakteri varsa bridge line reddedilir. */
      if (strchr(state->obfs4_bridge_line, '\n') != NULL ||
          strchr(state->obfs4_bridge_line, '\r') != NULL) {
        NOX_ERROR(LOG_MOD_NET, "obfs4 bridge line newline/carriage return karakteri içeriyor");
        close(fd);
        return NOX_ERR_CONFIG;
      }
      clen =
          snprintf(content, sizeof(content),
                   "SocksPort unix:%s/socks.sock\n"
                   "ControlSocket %s/control.sock\n"
                   "CookieAuthentication 1\n"
                   "DataDirectory %s\n"
                   "Log notice file %s/tor.log\n"
                   "UseBridges 1\n"
                   "Bridge %s\n"
                   "ClientTransportPlugin obfs4 exec %s\n",
                   state->tor_data_dir, state->tor_data_dir,
                   state->tor_data_dir, state->tor_data_dir,
                   state->obfs4_bridge_line, obfs4_path);
    } else {
      clen = snprintf(content, sizeof(content),
                      "SocksPort unix:%s/socks.sock\n"
                      "ControlSocket %s/control.sock\n"
                      "CookieAuthentication 1\n"
                      "DataDirectory %s\n"
                      "Log notice file %s/tor.log\n"
                      "UseBridges 1\n"
                      "UpdateBridgesFromAuthority 1\n"
                      "ClientTransportPlugin obfs4 exec %s\n",
                      state->tor_data_dir, state->tor_data_dir,
                      state->tor_data_dir, state->tor_data_dir, obfs4_path);
    }
  } else {
    clen =
        snprintf(content, sizeof(content),
                 "SocksPort unix:%s/socks.sock\n"
                 "ControlSocket %s/control.sock\n"
                 "CookieAuthentication 1\n"
                 "DataDirectory %s\n"
                 "Log notice file %s/tor.log\n",
                 state->tor_data_dir, state->tor_data_dir,
                 state->tor_data_dir, state->tor_data_dir);
  }

  if (clen <= 0 || (size_t)clen >= sizeof(content)) {
    NOX_ERROR(LOG_MOD_NET, "torrc içeriği çok büyük");
    close(fd);
    return NOX_ERR_CONFIG;
  }

  nox_err_t err = write_full(fd, content, (size_t)clen);
  close(fd);
  if (err != NOX_OK)
    return err;

  NOX_INFO(LOG_MOD_NET, "torrc üretildi: %s", state->torrc_path);
  return NOX_OK;
}

/* ================================================================
 * TOR SPAWN — fork + execv (tam yol, PATH araması yok)
 *
 * Auto portlar: ControlPort auto + SocksPort auto
 * Kontrol portu ControlPortWriteToFile'dan okunur.
 * ================================================================ */

/* control.sock dosyasının oluşmasını bekler, Tor sürecini takip eder */
static nox_err_t wait_for_control_socket(pid_t tor_pid, const char *socket_path,
                                         int timeout_sec) {
  const struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000}; /* 100 ms */
  int max_tries = timeout_sec * 10;

  for (int i = 0; i < max_tries; i++) {
    if (g_shutdown)
      return NOX_ERR_TOR;

    /* Tor child sürecini kontrol et (zombi veya çökmüş mü?) */
    int status;
    pid_t res = waitpid(tor_pid, &status, WNOHANG);
    if (res > 0) {
      int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      NOX_ERROR(LOG_MOD_NET, "Tor beklenmedik şekilde sonlandı (exit=%d)",
                exit_code);

      NOX_WARN(LOG_MOD_TOR,
               "Tor başlatılamadı. Eğer eski bir Tor sürümü kullanıyorsanız, "
               "yerleşik köprüler (--use-default-bridges) desteklenmiyor "
               "olabilir. Lütfen Tor sürümünü güncelleyin veya manuel özel "
               "köprü yapılandırın.");

      return NOX_ERR_TOR;
    }

    if (access(socket_path, F_OK) == 0) {
      return NOX_OK;
    }

    safe_nanosleep(&ts);
  }

  return NOX_ERR_TOR;
}

nox_err_t tor_spawn(struct app_state *state) {
  nox_err_t err = generate_torrc(state);
  if (err != NOX_OK)
    return err;

  /* UDS soket yolunu oluştur ve boyut sınırını denetle */
  char socket_path[NOX_PATH_MAX];
  int sn = snprintf(socket_path, sizeof(socket_path), "%s/control.sock",
                    state->tor_data_dir);
  if (sn <= 0 || (size_t)sn >= sizeof(socket_path)) {
    NOX_ERROR(LOG_MOD_NET, "control.sock yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  if ((size_t)sn >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
    NOX_ERROR(LOG_MOD_NET, "Unix soket yolu sınırı aşındı (maksimum %zu byte)",
              sizeof(((struct sockaddr_un *)0)->sun_path) - 1);
    return NOX_ERR_CONFIG;
  }

  /* SocksSocket yolunu ayarla */
  int ssn = snprintf(state->socks_path, NOX_PATH_MAX, "%s/socks.sock",
                     state->tor_data_dir);
  if (ssn <= 0 || (size_t)ssn >= NOX_PATH_MAX) {
    NOX_ERROR(LOG_MOD_NET, "socks.sock yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  /* Stale control.sock dosyasını sil */
  unlink(socket_path);

  pid_t pid = fork();
  if (pid < 0) {
    NOX_ERROR(LOG_MOD_NET, "fork başarısız: %s", strerror(errno));
    return NOX_ERR_TOR;
  }

  if (pid == 0) {
    /* Child — tor'u başlat */

    /* PR_SET_DUMPABLE=0 main'de seccomp ÖNCESİ ayarlandı,
     * fork() ile child'a miras kalır — core dump üretilmez. */

    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      dup2(devnull, STDOUT_FILENO);
      close(devnull);
    }

    /* ── stderr yönlendirmesi ─────────────────────────────────
     * DEBUG build: Tor'un stderr'ı doğrudan ekrana gider.
     * Tor çökünce hata mesajını anında görürsün.
     * Release'de /dev/null'a gider (sessiz kapanış). */
#ifndef DEBUG
    {
      int dn = open("/dev/null", O_RDWR);
      if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
    }
#endif

    /* B-1: Tor child'ı parent FD'lerini miras alır. Bu FD'ler
     * Tor sürecin açık kalmasına neden olur (epoll, peer, vb.)
     * veya beklenmedik davranışa yol açar. stdin/stdout/stderr
     * zaten /dev/null'a yönlendirildi, geri kalan her şeyi kapat. */
    long max_fds = sysconf(_SC_OPEN_MAX);
    if (max_fds < 0 || max_fds > 4096)
      max_fds = 4096;
    for (int fd_i = 3; fd_i < max_fds; fd_i++)
      close(fd_i);

    char arg0[] = "tor";
    char arg1[] = "-f";

    char *argv[4];
    argv[0] = arg0;
    argv[1] = arg1;
    argv[2] = state->torrc_path;
    argv[3] = NULL;

    execv("/usr/bin/tor", argv);
    execv("/usr/local/bin/tor", argv);
    _exit(127);
  }

  /* Parent — child'ın çökmediğini doğrula */
  state->tor_pid = pid;
  NOX_INFO(LOG_MOD_NET, "Tor başlatıldı (PID=%d)", pid);

  const struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};

  /* Control soket dosyasını bekle (Tor async oluşturur) */
  err = wait_for_control_socket(pid, socket_path, NOX_CTRL_SOCK_WAIT_SEC);
  if (err != NOX_OK) {
    NOX_ERROR(LOG_MOD_NET,
              "control.sock dosyası oluşturulamadı veya Tor çöktü");
    return NOX_ERR_TOR;
  }

  NOX_INFO(LOG_MOD_NET, "Tor control soketi hazır");

  /* Control port'a Unix domain socket ile bağlan */
  int ctrl_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (ctrl_fd < 0) {
    NOX_ERROR(LOG_MOD_NET, "ctrl socket oluşturulamadı");
    return NOX_ERR_NET;
  }

  struct sockaddr_un addr = {
      .sun_family = AF_UNIX,
  };
  /* socket_path NOX_PATH_MAX (511) kadar olabilir, sun_path 108 byte.
   * Kasıtlı truncation —Unix socket path uzunluğu sınırı. */
  size_t copy_len = strlen(socket_path);
  assert(copy_len < NOX_PATH_MAX);
  if (copy_len >= sizeof(addr.sun_path))
      copy_len = sizeof(addr.sun_path) - 1;
  memcpy(addr.sun_path, socket_path, copy_len);
  addr.sun_path[copy_len] = '\0';

  int connected = 0;
  for (int retry = 0; retry < NOX_CTRL_CONNECT_RETRIES; retry++) {
    if (g_shutdown) {
      close(ctrl_fd);
      return NOX_ERR_TOR;
    }
    if (connect(ctrl_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      connected = 1;
      break;
    }
    safe_nanosleep(&ts);
  }

  if (!connected) {
    NOX_ERROR(LOG_MOD_NET, "Tor control soketine bağlanılamadı");
    close(ctrl_fd);
    return NOX_ERR_TOR;
  }

  state->tor_ctrl_fd = ctrl_fd;
  NOX_INFO(LOG_MOD_NET, "Tor control soketine başarıyla bağlanıldı");
  return NOX_OK;
}

/* ================================================================
 * TOR AUTHENTICATE — Cookie
 * ================================================================ */
nox_err_t tor_authenticate(int ctrl_fd, const char *data_dir) {
  char cookie_path[NOX_PATH_MAX];
  int n = snprintf(cookie_path, sizeof(cookie_path), "%s/control_auth_cookie",
                   data_dir);
  if (n <= 0 || (size_t)n >= sizeof(cookie_path)) {
    NOX_ERROR(LOG_MOD_NET, "cookie path çok uzun");
    return NOX_ERR_CONFIG;
  }

  int fd = open(cookie_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    NOX_ERROR(LOG_MOD_NET, "cookie dosyası okunamadı: %s", strerror(errno));
    return NOX_ERR_TOR;
  }

  /* E-1: Cookie dosyası boyutunu fstat ile doğrula.
   * Tor cookie her zaman 32 byte'tır. Farklı boyut (0, 16, 64)
   * beklenmeyen durum: symlink manipülasyonu, kısmi yazma hatası,
   * veya yanlış dosya. read_full EOF'ta zaten başarısız olur ama
   * fstat ile açık hata mesajı vermek daha iyi. */
  struct stat st;
  if (fstat(fd, &st) != 0) {
    NOX_ERROR(LOG_MOD_NET, "cookie fstat hatası: %s", strerror(errno));
    close(fd);
    return NOX_ERR_TOR;
  }
  if (st.st_size != 32) {
    NOX_ERROR(LOG_MOD_NET, "cookie boyutu beklenmeyen: %ld (32 bekleniyor)",
              (long)st.st_size);
    close(fd);
    return NOX_ERR_TOR;
  }

  uint8_t cookie[32];
  nox_err_t err = read_full(fd, cookie, sizeof(cookie));
  close(fd);
  if (err != NOX_OK) {
    NOX_ERROR(LOG_MOD_NET, "cookie okuma hatası");
    explicit_bzero(cookie, sizeof(cookie));
    return NOX_ERR_TOR;
  }

  /* V1 FIX: Cookie'yi diskten sil — metadata theft engeli.
   * Tor authenticate sonrası cookie'yi buffer'dan temizler. */
  unlink(cookie_path);

  /* "AUTHENTICATE " (13) + 64 hex + "\r\n" (2) + NUL = 80 */
  char cmd[80];
  size_t pos = 0;
  memcpy(cmd, "AUTHENTICATE ", 13);
  pos = 13;

  static const char hex[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    cmd[pos++] = hex[cookie[i] >> 4];
    cmd[pos++] = hex[cookie[i] & 0x0F];
  }
  cmd[pos++] = '\r';
  cmd[pos++] = '\n';
  cmd[pos] = '\0';

  explicit_bzero(cookie, sizeof(cookie));

  err = ctrl_send_command(ctrl_fd, cmd);
  explicit_bzero(cmd, sizeof(cmd));
  if (err != NOX_OK)
    return err;

  char resp[256];
  err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), NOX_CTRL_TIMEOUT_MS);
  if (err != NOX_OK)
    return err;

  NOX_INFO(LOG_MOD_NET, "Tor authentication başarılı");
  return NOX_OK;
}

/* ================================================================
 * TOR BOOTSTRAP BEKLEMESİ
 * ================================================================ */
nox_err_t tor_wait_bootstrap(int ctrl_fd, int timeout_sec) {
  if (timeout_sec <= 0 || timeout_sec > NOX_BOOTSTRAP_TIMEOUT_MAX) {
    NOX_ERROR(LOG_MOD_NET, "timeout_sec geçersiz: %d", timeout_sec);
    return NOX_ERR_TOR;
  }

  NOX_INFO(LOG_MOD_NET, "Tor bootstrap bekleniyor (timeout=%ds)...",
           timeout_sec);

  const struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};

  for (int elapsed = 0; elapsed < timeout_sec; elapsed += 2) {
    if (g_shutdown) {
      NOX_INFO(LOG_MOD_NET, "Tor bootstrap iptal edildi (kullanıcı isteği)");
      return NOX_ERR_TOR;
    }

    nox_err_t err =
        ctrl_send_command(ctrl_fd, "GETINFO status/bootstrap-phase\r\n");
    if (err != NOX_OK)
      return err;

    char resp[512];
    err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), NOX_CTRL_TIMEOUT_MS);
    if (err != NOX_OK)
      return err;

    if (strstr(resp, "PROGRESS=100") != NULL) {
      NOX_INFO(LOG_MOD_NET, "Tor bootstrap tamamlandı (%ds)", elapsed);
      return NOX_OK;
    }

    /* H-1 FIX: atoi() → strtol() ile güvenli parse + aralık kontrolü */
    char *prog = strstr(resp, "PROGRESS=");
    if (prog) {
      char *endptr = NULL;
      errno = 0;
      long pct = strtol(prog + 9, &endptr, 10);
      
      if (errno == 0 && endptr != prog + 9 && pct >= 0 && pct <= 100) {
        NOX_INFO(LOG_MOD_NET, "Tor bootstrap: %%%ld", pct);
      } else {
        NOX_WARN(LOG_MOD_NET, "Tor bootstrap PROGRESS parse hatası");
      }
    }

    safe_nanosleep(&ts);
  }

  NOX_ERROR(LOG_MOD_NET, "Tor bootstrap timeout (%ds)", timeout_sec);
  return NOX_ERR_TOR;
}

/* ================================================================
 * HIDDEN SERVICE — ADD_ONION
 * ================================================================ */
nox_err_t tor_create_hidden_service(int ctrl_fd, const char *listen_path,
                                     char *onion_out, size_t onion_len) {
  char cmd[128];
  int n = snprintf(cmd, sizeof(cmd),
                   "ADD_ONION NEW:ED25519-V3 Port=%u,unix:%s\r\n",
                   NOX_VIRTUAL_PORT, listen_path);
  if (n <= 0 || (size_t)n >= sizeof(cmd))
    return NOX_ERR_OVERFLOW;

  nox_err_t err = ctrl_send_command(ctrl_fd, cmd);
  if (err != NOX_OK)
    return err;

  char resp[512];
  err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), NOX_READ_TIMEOUT_MS);
  if (err != NOX_OK)
    return err;

  char *sid = strstr(resp, "ServiceID=");
  if (!sid) {
    NOX_ERROR(LOG_MOD_NET, "ADD_ONION yanıtında ServiceID yok");
    return NOX_ERR_TOR;
  }

  sid += 10;

  /* resp sınırları içinde kaldığından emin ol */
  size_t remaining = strlen(sid);
  if (remaining < 56) {
    NOX_ERROR(LOG_MOD_NET, "ServiceID truncated (%zu byte)", remaining);
    return NOX_ERR_TOR;
  }

  /* 56 byte base32 onion address doğrula */
  size_t i = 0;
  while (i < 56 && sid[i] && sid[i] != '\r' && sid[i] != '\n')
    i++;

  if (i != 56) {
    NOX_ERROR(LOG_MOD_NET, "onion adresi uzunluğu hatalı: %zu", i);
    return NOX_ERR_TOR;
  }

  if (onion_len < 63)
    return NOX_ERR_OVERFLOW;

  /* S3 (threat-model): Tor'dan gelen ServiceID'yi validate et.
   * Yanlış formatlı yanıt (compromised tor binary, control socket
   * manipülasyonu, vb.) peer handshake payload'umuza kirli veri
   * sızdırmadan reddedilmeli. Peer tarafında da aynı kontrolden
   * geçen adres artık bizim HS adresimiz de aynı sıkılıkta
   * doğrulanıyor. */
  char candidate[63];
  memcpy(candidate, sid, 56);
  memcpy(candidate + 56, ".onion", 7);
  candidate[62] = '\0';

  if (!validate_onion_address(candidate)) {
    NOX_ERROR(LOG_MOD_NET, "ADD_ONION yanıtı geçersiz format");
    sodium_memzero(candidate, sizeof(candidate));
    return NOX_ERR_TOR;
  }

  memcpy(onion_out, candidate, 63);
  sodium_memzero(candidate, sizeof(candidate));

  NOX_INFO(LOG_MOD_NET, "Hidden Service: %s", onion_out);
  return NOX_OK;
}

/* ================================================================
 * TOR SHUTDOWN
 * ================================================================ */
void tor_shutdown(struct app_state *state) {
  if (state->tor_ctrl_fd >= 0) {
    ctrl_send_command(state->tor_ctrl_fd, "SIGNAL SHUTDOWN\r\n");
    close(state->tor_ctrl_fd);
    state->tor_ctrl_fd = -1;
  }

  if (state->tor_pid > 0) {
    NOX_INFO(LOG_MOD_NET, "Tor sonlandırılıyor (PID=%d)", state->tor_pid);

    if (kill(state->tor_pid, SIGTERM) == 0) {
      int status;
      bool stopped = false;
      for (int i = 0; i < 50; i++) {
        pid_t r = waitpid(state->tor_pid, &status, WNOHANG);
        if (r > 0) {
          NOX_INFO(LOG_MOD_NET, "Tor temiz kapandı");
          stopped = true;
          break;
        }
        const struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000};
        safe_nanosleep(&ts);
      }
      if (!stopped) {
        kill(state->tor_pid, SIGKILL);
        waitpid(state->tor_pid, &status, 0);
        NOX_WARN(LOG_MOD_NET, "Tor SIGKILL ile sonlandırıldı");
      }
    } else {
      NOX_WARN(LOG_MOD_NET, "Tor SIGTERM başarısız: %s", strerror(errno));
    }
    state->tor_pid = 0;
  }

  /* torrc dosyasını sil */
  if (state->torrc_path[0] != '\0') {
    /* CodeQL #15 cpp/path-injection: torrc_path config_dir'den türetilmiştir */
    assert(strncmp(state->torrc_path, state->config_dir, strlen(state->config_dir)) == 0);
    size_t cfg_len2 = strlen(state->config_dir);
    if (strncmp(state->torrc_path, state->config_dir, cfg_len2) != 0 ||
        (state->torrc_path[cfg_len2] != '\0' && state->torrc_path[cfg_len2] != '/')) {
      NOX_ERROR(LOG_MOD_MAIN, "torrc_path config_dir altında değil — silme engellendi");
    } else {
      unlink(state->torrc_path);
    }
    state->torrc_path[0] = '\0';
  }
  /* tor_data dizinini temizle */
  if (state->tor_data_dir[0] != '\0') {
    /* CodeQL #15 cpp/path-injection: tor_data_dir config_dir'den türetilmiştir */
    assert(strncmp(state->tor_data_dir, state->config_dir, strlen(state->config_dir)) == 0);
    if (strncmp(state->tor_data_dir, state->config_dir, strlen(state->config_dir)) != 0) {
      NOX_ERROR(LOG_MOD_MAIN, "tor_data_dir config_dir altında değil — silme engellendi");
    } else {
      rm_rf(state->tor_data_dir);
    }
    state->tor_data_dir[0] = '\0';
  }
}

/* ================================================================
 * UNIX DOMAIN LISTENER — bind(listen.sock)
 *
 * Tor Hidden Service unix: prefix ile bağlanır.
 * Socket izinleri 0600 ile kısıtlanır (sadece owner erişimi).
 * ================================================================ */
nox_err_t listener_create(const char *tor_data_dir, char *listen_path_out,
                           int *listen_fd_out) {
  int n = snprintf(listen_path_out, NOX_PATH_MAX, "%s/listen.sock",
                   tor_data_dir);
  if (n <= 0 || (size_t)n >= NOX_PATH_MAX) {
    NOX_ERROR(LOG_MOD_NET, "listen.sock yolu çok uzun");
    return NOX_ERR_CONFIG;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    NOX_ERROR(LOG_MOD_NET, "listener socket: %s", strerror(errno));
    return NOX_ERR_NET;
  }

  /* Eski socket dosyasını temizle (double instance koruması) */
  unlink(listen_path_out);

  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  size_t copy_len = strlen(listen_path_out);
  if (copy_len >= sizeof(addr.sun_path)) {
    NOX_ERROR(LOG_MOD_NET, "listen socket yolu çok uzun (%zu byte, maks %zu)",
              copy_len, sizeof(addr.sun_path) - 1);
    close(fd);
    unlink(listen_path_out);
    return NOX_ERR_CONFIG;
  }
  memcpy(addr.sun_path, listen_path_out, copy_len);
  addr.sun_path[copy_len] = '\0';

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    NOX_ERROR(LOG_MOD_NET, "bind: %s", strerror(errno));
    close(fd);
    return NOX_ERR_NET;
  }

  /* Socket izinlerini kısıtla — sadece owner read/write */
  if (chmod(listen_path_out, 0600) != 0) {
    NOX_WARN(LOG_MOD_NET, "chmod listen.sock: %s", strerror(errno));
  }

  if (listen(fd, 1) != 0) {
    NOX_ERROR(LOG_MOD_NET, "listen: %s", strerror(errno));
    close(fd);
    unlink(listen_path_out);
    return NOX_ERR_NET;
  }

  *listen_fd_out = fd;

  NOX_INFO(LOG_MOD_NET, "listener: unix:%s", listen_path_out);
  return NOX_OK;
}

/* ================================================================
 * SOCKS5 CONNECT — Tor SocksSocket üzerinden .onion'a bağlan
 *
 * AF_UNIX SocksSocket ile bağlanır, SOCKS5 handshake aynı kalır.
 * Onion adresi domain name olarak gönderilir (tip 0x03).
 * ================================================================ */
nox_err_t socks5_connect(const char *onion_addr, uint16_t port,
                          const char *socks_path, int *fd_out) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return NOX_ERR_NET;

  struct sockaddr_un proxy = {0};
  proxy.sun_family = AF_UNIX;
  size_t path_len = strlen(socks_path);
  if (path_len >= sizeof(proxy.sun_path)) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS socket yolu çok uzun (%zu byte, maks %zu)",
              path_len, sizeof(proxy.sun_path) - 1);
    close(fd);
    return NOX_ERR_CONFIG;
  }
  memcpy(proxy.sun_path, socks_path, path_len);
  proxy.sun_path[path_len] = '\0';

  if (connect(fd, (struct sockaddr *)&proxy, sizeof(proxy)) != 0) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 UNIX socket bağlantısı başarısız");
    close(fd);
    return NOX_ERR_NET;
  }

  /* Greeting */
  uint8_t greet[] = {0x05, 0x01, 0x00};
  if (write_full(fd, greet, 3) != NOX_OK) {
    close(fd);
    return NOX_ERR_IO;
  }

  uint8_t gresp[2];
  if (read_full(fd, gresp, 2) != NOX_OK || gresp[0] != 0x05 ||
      gresp[1] != 0x00) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 greeting başarısız");
    close(fd);
    return NOX_ERR_NET;
  }

  /* A-2 FIX: Onion adres format doğrulaması */
  if (!validate_onion_address(onion_addr)) {
    NOX_ERROR(LOG_MOD_NET, "socks5_connect: geçersiz onion adresi");
    close(fd);
    return NOX_ERR_NET;
  }

  size_t addr_len = strlen(onion_addr);

  uint8_t req[4 + 1 + 256 + 2];
  size_t pos = 0;
  req[pos++] = 0x05;
  req[pos++] = 0x01;
  req[pos++] = 0x00;
  req[pos++] = 0x03;
  req[pos++] = (uint8_t)addr_len;
  memcpy(req + pos, onion_addr, addr_len);
  pos += addr_len;
  req[pos++] = (uint8_t)(port >> 8);
  req[pos++] = (uint8_t)(port & 0xFF);

  if (write_full(fd, req, pos) != NOX_OK) {
    close(fd);
    return NOX_ERR_IO;
  }

  /* SOCKS5 response: VER REP RSV ATYP [BND.ADDR] [BND.PORT] */
  uint8_t sresp[4] = {0};
  nox_err_t io_err = read_full(fd, sresp, sizeof(sresp));
  if (io_err != NOX_OK) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 response okunamadı");
    close(fd);
    return NOX_ERR_NET;
  }

  if (sresp[0] != 0x05 || sresp[1] != 0x00) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 CONNECT başarısız (rep=0x%02x)", sresp[1]);
    close(fd);
    return NOX_ERR_NET;
  }

  /* ATYP'e göre kalan veriyi oku ve at */
  uint8_t drain[256 + 2];
  size_t drain_len;
  switch (sresp[3]) {
  case 0x01:
    drain_len = 4 + 2;
    break; /* IPv4 + port */
  case 0x04:
    drain_len = 16 + 2;
    break; /* IPv6 + port */
  case 0x03: {
    uint8_t dlen;
    if (read_full(fd, &dlen, 1) != NOX_OK) {
      NOX_ERROR(LOG_MOD_NET, "SOCKS5 domain length okunamadı");
      close(fd);
      return NOX_ERR_NET;
    }
    drain_len = dlen + 2;
    break;
  }
  default:
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 bilinmeyen ATYP: 0x%02x", sresp[3]);
    close(fd);
    return NOX_ERR_NET;
  }

  if (read_full(fd, drain, drain_len) != NOX_OK) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 BND.ADDR/PORT okunamadı");
    close(fd);
    return NOX_ERR_NET;
  }

  /* Make socket non-blocking for asynchronous I/O */
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }

  *fd_out = fd;
  NOX_INFO(LOG_MOD_NET, "SOCKS5 bağlantı: %s:%u", onion_addr, port);

  return NOX_OK;
}

/* ================================================================
 * EPOLL YARDIMCILARI
 * ================================================================ */
nox_err_t epoll_add_fd(int epoll_fd, int fd) {
  struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
    NOX_ERROR(LOG_MOD_NET, "epoll_ctl ADD: %s", strerror(errno));
    return NOX_ERR_NET;
  }
  return NOX_OK;
}

nox_err_t epoll_remove_fd(int epoll_fd, int fd) {
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0) {
    NOX_ERROR(LOG_MOD_NET, "epoll_ctl DEL: %s", strerror(errno));
    return NOX_ERR_NET;
  }
  return NOX_OK;
}

nox_err_t epoll_modify_fd(int epoll_fd, int fd, uint32_t events) {
  struct epoll_event ev = {.events = events, .data.fd = fd};
  if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) {
    NOX_ERROR(LOG_MOD_NET, "epoll_ctl MOD: %s", strerror(errno));
    return NOX_ERR_NET;
  }
  return NOX_OK;
}

nox_err_t epoll_setup(struct app_state *state, int listen_fd) {
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) {
    NOX_ERROR(LOG_MOD_NET, "epoll_create1: %s", strerror(errno));
    return NOX_ERR_NET;
  }

  state->epoll_fd = efd;

  /* stdin non-blocking yap */
  int flags = fcntl(STDIN_FILENO, F_GETFL);
  if (flags >= 0) {
    if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) < 0) {
      NOX_WARN(LOG_MOD_NET, "stdin O_NONBLOCK ayarlanamadı: %s",
               strerror(errno));
    }
  }

  nox_err_t err = epoll_add_fd(efd, STDIN_FILENO);
  if (err != NOX_OK)
    return err;

  err = epoll_add_fd(efd, listen_fd);
  if (err != NOX_OK)
    return err;

  NOX_INFO(LOG_MOD_NET, "epoll hazır (stdin + listener)");
  return NOX_OK;
}

/* ================================================================
 * FRAME I/O — serialize / deserialize
 * ================================================================ */
void frame_header_encode(const struct frame_header *hdr, uint8_t *wire) {
  wire[0] = (uint8_t)(hdr->magic >> 24);
  wire[1] = (uint8_t)(hdr->magic >> 16);
  wire[2] = (uint8_t)(hdr->magic >> 8);
  wire[3] = (uint8_t)(hdr->magic);
  wire[4] = hdr->type;
  wire[5] = (uint8_t)(hdr->seq >> 24);
  wire[6] = (uint8_t)(hdr->seq >> 16);
  wire[7] = (uint8_t)(hdr->seq >> 8);
  wire[8] = (uint8_t)(hdr->seq);
  wire[9] = (uint8_t)(hdr->len >> 24);
  wire[10] = (uint8_t)(hdr->len >> 16);
  wire[11] = (uint8_t)(hdr->len >> 8);
  wire[12] = (uint8_t)(hdr->len);
}

nox_err_t frame_header_decode(const uint8_t *wire, struct frame_header *hdr) {
  hdr->magic = ((uint32_t)wire[0] << 24) | ((uint32_t)wire[1] << 16) |
               ((uint32_t)wire[2] << 8) | (uint32_t)wire[3];
  hdr->type = wire[4];
  hdr->seq = ((uint32_t)wire[5] << 24) | ((uint32_t)wire[6] << 16) |
             ((uint32_t)wire[7] << 8) | (uint32_t)wire[8];
  hdr->len = ((uint32_t)wire[9] << 24) | ((uint32_t)wire[10] << 16) |
             ((uint32_t)wire[11] << 8) | (uint32_t)wire[12];

  if (hdr->magic != NOX_FRAME_MAGIC) {
    NOX_ERROR(LOG_MOD_NET, "frame magic hatalı: 0x%08x", hdr->magic);
    return NOX_ERR_PROTO;
  }

  if (hdr->len > FRAME_MAX_PAYLOAD) {
    NOX_ERROR(LOG_MOD_NET, "frame payload çok büyük: %u", hdr->len);
    return NOX_ERR_PROTO;
  }

  return NOX_OK;
}
