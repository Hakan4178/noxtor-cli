/* SPDX-License-Identifier: GPL-3.0-or-later
 * network.c — Tor entegrasyonu ve ağ katmanı
 */

#include "network.h"
#include "common.h"
#include "types.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <poll.h>

/* ================================================================
 * I/O HELPERS — EINTR + EAGAIN/EWOULDBLOCK koruması
 * ================================================================ */
nox_err_t write_full(int fd, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  size_t written = 0;
  while (written < len) {
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
        poll(&pfd, 1, -1);
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

static nox_err_t read_full(int fd, void *buf, size_t len) {
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
        poll(&pfd, 1, -1);
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

  size_t pos = 0;

  while (pos < buf_size - 1) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ret = poll(&pfd, 1, timeout_ms);
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

    if (llen >= 3 && line[0] >= '4') {
      buf[total] = '\0';
      NOX_ERROR(LOG_MOD_NET, "Tor hatası: %s", line);
      return NOX_ERR_TOR;
    }
  }

  buf[total] = '\0';
  return NOX_OK;
}

/* ================================================================
 * TORRC ÜRETİMİ
 * ================================================================ */
static nox_err_t generate_torrc(struct app_state *state) {
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
  chmod(state->tor_data_dir, 0700);

  /* torrc yaz */
  int fd =
      open(state->torrc_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    NOX_ERROR(LOG_MOD_NET, "torrc oluşturulamadı: %s", strerror(errno));
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
    clen = snprintf(content, sizeof(content),
             "SocksPort auto\n"
             "ControlSocket %s/control.sock\n"
             "CookieAuthentication 1\n"
             "DataDirectory %s\n"
             "Log notice file %s/tor.log\n"
             "UseBridges 1\n"
             "ClientTransportPlugin snowflake exec %s\n",
             state->tor_data_dir, state->tor_data_dir, state->tor_data_dir, snowflake_path);
  } else if (state->transport_type == TRANSPORT_OBFS4) {
    const char *obfs4_path = "/usr/bin/obfs4proxy";
    if (access("/usr/local/bin/obfs4proxy", X_OK) == 0) {
      obfs4_path = "/usr/local/bin/obfs4proxy";
    }
    if (strlen(state->obfs4_bridge_line) > 0) {
      clen = snprintf(content, sizeof(content),
               "SocksPort auto\n"
               "ControlSocket %s/control.sock\n"
               "CookieAuthentication 1\n"
               "DataDirectory %s\n"
               "Log notice file %s/tor.log\n"
               "UseBridges 1\n"
               "Bridge %s\n"
               "ClientTransportPlugin obfs4 exec %s\n",
               state->tor_data_dir, state->tor_data_dir, state->tor_data_dir,
               state->obfs4_bridge_line, obfs4_path);
    } else {
      clen = snprintf(content, sizeof(content),
               "SocksPort auto\n"
               "ControlSocket %s/control.sock\n"
               "CookieAuthentication 1\n"
               "DataDirectory %s\n"
               "Log notice file %s/tor.log\n"
               "UseBridges 1\n"
               "ClientTransportPlugin obfs4 exec %s\n",
               state->tor_data_dir, state->tor_data_dir, state->tor_data_dir, obfs4_path);
    }
  } else {
    clen = snprintf(content, sizeof(content),
             "SocksPort auto\n"
             "ControlSocket %s/control.sock\n"
             "CookieAuthentication 1\n"
             "DataDirectory %s\n"
             "Log notice file %s/tor.log\n",
             state->tor_data_dir, state->tor_data_dir, state->tor_data_dir);
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
static nox_err_t wait_for_control_socket(pid_t tor_pid, const char *socket_path, int timeout_sec) {
  struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000}; /* 100 ms */
  int max_tries = timeout_sec * 10;

  for (int i = 0; i < max_tries; i++) {
    /* Tor child sürecini kontrol et (zombi veya çökmüş mü?) */
    int status;
    pid_t res = waitpid(tor_pid, &status, WNOHANG);
    if (res > 0) {
      int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      NOX_ERROR(LOG_MOD_NET, "Tor beklenmedik şekilde sonlandı (exit=%d)", exit_code);
      
      NOX_WARN(LOG_MOD_TOR, "Tor başlatılamadı. Eğer eski bir Tor sürümü kullanıyorsanız, yerleşik köprüler (--use-default-bridges) desteklenmiyor olabilir. Lütfen Tor sürümünü güncelleyin veya manuel özel köprü yapılandırın.");
      
      return NOX_ERR_TOR;
    }

    if (access(socket_path, F_OK) == 0) {
      return NOX_OK;
    }

    nanosleep(&ts, NULL);
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

  /* Stale control.sock dosyasını sil */
  unlink(socket_path);

  pid_t pid = fork();
  if (pid < 0) {
    NOX_ERROR(LOG_MOD_NET, "fork başarısız: %s", strerror(errno));
    return NOX_ERR_TOR;
  }

  if (pid == 0) {
    /* Child — tor'u başlat */
    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    
    char arg0[] = "tor";
    char arg1[] = "-f";
    char arg_bridge[] = "--use-default-bridges";
    
    char *argv[8];
    argv[0] = arg0;
    argv[1] = arg1;
    argv[2] = state->torrc_path;
    int idx = 3;

    bool use_default_bridges = false;
    if (state->transport_type == TRANSPORT_SNOWFLAKE) {
      use_default_bridges = true;
    } else if (state->transport_type == TRANSPORT_OBFS4 && strlen(state->obfs4_bridge_line) == 0) {
      use_default_bridges = true;
    }

    if (use_default_bridges) {
      argv[idx++] = arg_bridge;
    }
    argv[idx] = NULL;

    execv("/usr/bin/tor", argv);
    execv("/usr/local/bin/tor", argv);
    _exit(127);
  }

  /* Parent — child'ın çökmediğini doğrula */
  state->tor_pid = pid;
  NOX_INFO(LOG_MOD_NET, "Tor başlatıldı (PID=%d)", pid);

  struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};

  /* Control soket dosyasını bekle (Tor async oluşturur) */
  err = wait_for_control_socket(pid, socket_path, 30);
  if (err != NOX_OK) {
    NOX_ERROR(LOG_MOD_NET, "control.sock dosyası oluşturulamadı veya Tor çöktü");
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
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  int connected = 0;
  for (int retry = 0; retry < 10; retry++) {
    if (connect(ctrl_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      connected = 1;
      break;
    }
    nanosleep(&ts, NULL);
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

  uint8_t cookie[32];
  nox_err_t err = read_full(fd, cookie, sizeof(cookie));
  close(fd);
  if (err != NOX_OK) {
    NOX_ERROR(LOG_MOD_NET, "cookie okuma hatası");
    return NOX_ERR_TOR;
  }

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
  err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), 5000);
  if (err != NOX_OK)
    return err;

  NOX_INFO(LOG_MOD_NET, "Tor authentication başarılı");
  return NOX_OK;
}

/* ================================================================
 * TOR BOOTSTRAP BEKLEMESİ
 * ================================================================ */
nox_err_t tor_wait_bootstrap(int ctrl_fd, int timeout_sec) {
  if (timeout_sec <= 0 || timeout_sec > 3600) {
    NOX_ERROR(LOG_MOD_NET, "timeout_sec geçersiz: %d", timeout_sec);
    return NOX_ERR_TOR;
  }

  NOX_INFO(LOG_MOD_NET, "Tor bootstrap bekleniyor (timeout=%ds)...",
           timeout_sec);

  struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};

  for (int elapsed = 0; elapsed < timeout_sec; elapsed += 2) {
    nox_err_t err =
        ctrl_send_command(ctrl_fd, "GETINFO status/bootstrap-phase\r\n");
    if (err != NOX_OK)
      return err;

    char resp[512];
    err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), 5000);
    if (err != NOX_OK)
      return err;

    if (strstr(resp, "PROGRESS=100") != NULL) {
      NOX_INFO(LOG_MOD_NET, "Tor bootstrap tamamlandı (%ds)", elapsed);
      return NOX_OK;
    }

    char *prog = strstr(resp, "PROGRESS=");
    if (prog) {
      int pct = atoi(prog + 9);
      NOX_INFO(LOG_MOD_NET, "Tor bootstrap: %%%d", pct);
    }

    nanosleep(&ts, NULL);
  }

  NOX_ERROR(LOG_MOD_NET, "Tor bootstrap timeout (%ds)", timeout_sec);
  return NOX_ERR_TOR;
}

/* ================================================================
 * HIDDEN SERVICE — ADD_ONION
 * ================================================================ */
nox_err_t tor_create_hidden_service(int ctrl_fd, uint16_t local_port,
                                    char *onion_out, size_t onion_len) {
  char cmd[128];
  int n = snprintf(cmd, sizeof(cmd),
                   "ADD_ONION NEW:ED25519-V3 Port=%u,127.0.0.1:%u\r\n",
                   NOX_VIRTUAL_PORT, local_port);
  if (n <= 0 || (size_t)n >= sizeof(cmd))
    return NOX_ERR_OVERFLOW;

  nox_err_t err = ctrl_send_command(ctrl_fd, cmd);
  if (err != NOX_OK)
    return err;

  char resp[512];
  err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), 10000);
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

  memcpy(onion_out, sid, 56);
  memcpy(onion_out + 56, ".onion", 7);

  NOX_INFO(LOG_MOD_NET, "Hidden Service: %s", onion_out);
  return NOX_OK;
}

/* ================================================================
 * TOR SOCKS PORT — GETINFO ile otomatik portu öğren
 * ================================================================ */
nox_err_t tor_get_socks_port(int ctrl_fd, uint16_t *port_out) {
  nox_err_t err = ctrl_send_command(ctrl_fd, "GETINFO net/listeners/socks\r\n");
  if (err != NOX_OK)
    return err;

  char resp[512];
  err = ctrl_read_response(ctrl_fd, resp, sizeof(resp), 5000);
  if (err != NOX_OK)
    return err;

  /* Yanıt formatı: 250-net/listeners/socks="127.0.0.1:NNNNN"\r\n250 OK */
  const char *quote = strchr(resp, '"');
  if (!quote) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS listener parse hatası (quote yok)");
    return NOX_ERR_TOR;
  }

  const char *colon = strchr(quote, ':');
  if (!colon) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS port parse hatası (colon yok)");
    return NOX_ERR_TOR;
  }

  long port = strtol(colon + 1, NULL, 10);
  if (port <= 0 || port > 65535) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS port geçersiz: %ld", port);
    return NOX_ERR_TOR;
  }

  *port_out = (uint16_t)port;
  NOX_INFO(LOG_MOD_NET, "Tor SOCKS port: %u", *port_out);
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

  if (state->tor_pid <= 0)
    return;

  NOX_INFO(LOG_MOD_NET, "Tor sonlandırılıyor (PID=%d)", state->tor_pid);

  if (kill(state->tor_pid, SIGTERM) != 0) {
    NOX_WARN(LOG_MOD_NET, "Tor SIGTERM başarısız: %s", strerror(errno));
    state->tor_pid = 0;
    return;
  }

  int status;
  for (int i = 0; i < 50; i++) {
    pid_t r = waitpid(state->tor_pid, &status, WNOHANG);
    if (r > 0) {
      NOX_INFO(LOG_MOD_NET, "Tor temiz kapandı");
      state->tor_pid = 0;
      return;
    }
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000};
    nanosleep(&ts, NULL);
  }

  kill(state->tor_pid, SIGKILL);
  waitpid(state->tor_pid, &status, 0);
  NOX_WARN(LOG_MOD_NET, "Tor SIGKILL ile sonlandırıldı");
  state->tor_pid = 0;
}

/* ================================================================
 * TCP LISTENER — bind(0) ile rastgele port
 * ================================================================ */
nox_err_t listener_create(uint16_t *port_out, int *listen_fd_out) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    NOX_ERROR(LOG_MOD_NET, "listener socket: %s", strerror(errno));
    return NOX_ERR_NET;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = 0,
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
  };

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    NOX_ERROR(LOG_MOD_NET, "bind: %s", strerror(errno));
    close(fd);
    return NOX_ERR_NET;
  }

  if (listen(fd, 1) != 0) {
    NOX_ERROR(LOG_MOD_NET, "listen: %s", strerror(errno));
    close(fd);
    return NOX_ERR_NET;
  }

  socklen_t slen = sizeof(addr);
  getsockname(fd, (struct sockaddr *)&addr, &slen);
  *port_out = ntohs(addr.sin_port);
  *listen_fd_out = fd;

  NOX_INFO(LOG_MOD_NET, "listener: 127.0.0.1:%u", *port_out);
  return NOX_OK;
}

/* ================================================================
 * SOCKS5 CONNECT — Tor üzerinden .onion'a bağlan
 * ================================================================ */
nox_err_t socks5_connect(const char *onion_addr, uint16_t port,
                         uint16_t socks_port, int *fd_out) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return NOX_ERR_NET;

  struct sockaddr_in proxy = {
      .sin_family = AF_INET,
      .sin_port = htons(socks_port),
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
  };

  if (connect(fd, (struct sockaddr *)&proxy, sizeof(proxy)) != 0) {
    NOX_ERROR(LOG_MOD_NET, "SOCKS5 proxy bağlantısı başarısız");
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

  /* CONNECT — full hostname (.onion dahil, Tor bunu bekler) */
  size_t addr_len = strlen(onion_addr);
  if (addr_len > 255 || addr_len == 0) {
    close(fd);
    return NOX_ERR_NET;
  }

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
  memcpy(wire + 13, hdr->nonce, NOX_NONCE_LEN);
}

nox_err_t frame_header_decode(const uint8_t *wire, struct frame_header *hdr) {
  hdr->magic = ((uint32_t)wire[0] << 24) | ((uint32_t)wire[1] << 16) |
               ((uint32_t)wire[2] << 8) | (uint32_t)wire[3];
  hdr->type = wire[4];
  hdr->seq = ((uint32_t)wire[5] << 24) | ((uint32_t)wire[6] << 16) |
             ((uint32_t)wire[7] << 8) | (uint32_t)wire[8];
  hdr->len = ((uint32_t)wire[9] << 24) | ((uint32_t)wire[10] << 16) |
             ((uint32_t)wire[11] << 8) | (uint32_t)wire[12];
  memcpy(hdr->nonce, wire + 13, NOX_NONCE_LEN);

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
