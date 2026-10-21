/* ================================================================
 * test_socks_peer.c — socks5_connect SO_PEERCRED doğrulama testi
 *
 * Bulgu 2.1b: Tor AYAKTAYKEN <tor_data>/socks.sock yolu aynı-UID
 * saldırgan tarafından unlink/rebind edilebilir. Fix, connect sonrası
 * peer PID'ini spawn edilen tor_pid ile karşılaştırır; uyuşmazsa
 * SOCKS greeting'i BİLE gönderilmez (fail-closed).
 *
 * Senaryolar (gerçek AF_UNIX soketleri, ayrı child dinleyici):
 *   1) yanlış PID → NOX_ERR_TOR + dinleyicide 0 byte (sır sızmaz)
 *   2) expected_pid <= 0 → NOX_ERR_TOR, bağlantı hiç denenmez
 *   3) doğru PID → NOX_OK + SOCKS5 handshake tamamlanır
 *
 * Sertleştirme: dinleyici okuduğu baytları SAYAR ve sonucu yapı olarak
 * parent'a bildirir; hazır sinyali 'R' olarak doğrulanır; EINTR/kısa
 * okuma ve waitpid hataları sessizce yutulmaz. Beklenmeyen sonuçta
 * test 1 döner (CI sinyali).
 * ================================================================ */
#define _GNU_SOURCE
#include "common.h"
#include "network.h"

#include <sodium.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

enum server_mode {
  SRV_WATCH,     /* bağlantıyı kabul et; istemciden gelen baytları say */
  SRV_NO_CONNECT,/* hiç bağlantı bekleme; gelirse FAIL */
  SRV_HANDSHAKE  /* minimal SOCKS5 sunucusu; başarılıysa handshake_ok=1 */
};

struct srv_result {
  int accepted;     /* accept() çağrıldı mı */
  int handshake_ok; /* SRV_HANDSHAKE tamamlandı mı */
  size_t bytes;     /* istemciden okunan toplam bayt */
};

static int read_exact_fd(int fd, void *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r;
    do {
      r = read(fd, (char *)buf + off, n - off);
    } while (r < 0 && errno == EINTR);
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return 0;
}

static int write_all_fd(int fd, const void *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w;
    do {
      w = write(fd, (const char *)buf + off, n - off);
    } while (w < 0 && errno == EINTR);
    if (w <= 0)
      return -1;
    off += (size_t)w;
  }
  return 0;
}

static int exit_code_of(int st) {
  if (WIFEXITED(st))
    return WEXITSTATUS(st);
  if (WIFSIGNALED(st))
    return 128 + WTERMSIG(st);
  return -1;
}

/* Sonucu yaz ve çık — her çıkış yolu parent'a rapor bırakır. */
static void server_finish(int result_fd, const struct srv_result *r,
                          int code) {
  (void)write_all_fd(result_fd, r, sizeof(*r));
  _exit(code);
}

/* validate_onion_address'ten geçecek gerçek v3 onion üret. */
static void make_onion(char out[NOX_ONION_LEN + 1]) {
  uint8_t pub[32];
  uint8_t raw[35];
  uint8_t h[32];
  uint8_t msg[48];
  randombytes_buf(pub, sizeof(pub));
  memcpy(msg, ".onion checksum", 15);
  memcpy(msg + 15, pub, 32);
  msg[47] = 0x03;
  crypto_hash_sha3256(h, msg, sizeof(msg));
  memcpy(raw, pub, 32);
  raw[32] = h[0];
  raw[33] = h[1];
  raw[34] = 0x03;

  static const char b32[] = "abcdefghijklmnopqrstuvwxyz234567";
  char enc[57];
  int pos = 0;
  int bits = 0;
  uint32_t acc = 0;
  for (size_t i = 0; i < sizeof(raw); i++) {
    acc = (acc << 8) | raw[i];
    bits += 8;
    while (bits >= 5) {
      enc[pos] = b32[(acc >> (bits - 5)) & 31u];
      pos++;
      bits -= 5;
    }
  }
  enc[pos] = '\0';
  snprintf(out, NOX_ONION_LEN + 1, "%s.onion", enc);
}

/* Child: sahte SOCKS5 dinleyici. Exit 0 = dinleyici görevini yaptı;
 * güvenlik hükmü parent'ta (err + accepted/bytes/handshake) verilir. */
static void socks_server(const char *path, int ready_fd, int result_fd,
                         enum server_mode mode, const char *expected_onion) {
  struct srv_result sr;
  memset(&sr, 0, sizeof(sr));
  signal(SIGPIPE, SIG_IGN);

  int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  size_t plen = strlen(path);
  if (ls < 0 || plen >= sizeof(a.sun_path))
    server_finish(result_fd, &sr, 10);
  memcpy(a.sun_path, path, plen + 1);
  if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0)
    server_finish(result_fd, &sr, 11);
  if (listen(ls, 4) != 0)
    server_finish(result_fd, &sr, 12);

  char ready = 'R';
  if (write_all_fd(ready_fd, &ready, 1) != 0)
    server_finish(result_fd, &sr, 13);

  if (mode == SRV_NO_CONNECT) {
    struct pollfd p = {.fd = ls, .events = POLLIN};
    int pr;
    do {
      pr = poll(&p, 1, 1500);
    } while (pr < 0 && errno == EINTR);
    sr.accepted = (pr > 0) ? 1 : 0;
    server_finish(result_fd, &sr, 0);
  }

  int cfd = accept(ls, NULL, NULL);
  if (cfd < 0)
    server_finish(result_fd, &sr, 14);
  sr.accepted = 1;

  if (mode == SRV_WATCH) {
    /* İstemci hiçbir şey yazmadıysa EOF gelir ve bytes=0 kalır.
     * Kısmi/tam greeting gelirse bytes > 0 olur — parent FAIL sayar. */
    for (;;) {
      struct pollfd p = {.fd = cfd, .events = POLLIN};
      int pr;
      do {
        pr = poll(&p, 1, 500);
      } while (pr < 0 && errno == EINTR);
      if (pr <= 0)
        break;
      char buf[64];
      ssize_t rb;
      do {
        rb = read(cfd, buf, sizeof(buf));
      } while (rb < 0 && errno == EINTR);
      if (rb <= 0)
        break;
      sr.bytes += (size_t)rb;
      if (sr.bytes > 4096)
        break; /* testte bu kadar veri beklenmez */
    }
    server_finish(result_fd, &sr, 0);
  }

  /* SRV_HANDSHAKE: minimal SOCKS5 sunucusu */
  uint8_t greet[3];
  if (read_exact_fd(cfd, greet, sizeof(greet)) != 0 || greet[0] != 0x05)
    server_finish(result_fd, &sr, 20);
  sr.bytes += sizeof(greet);
  uint8_t gresp[2] = {0x05, 0x00};
  if (write_all_fd(cfd, gresp, sizeof(gresp)) != 0)
    server_finish(result_fd, &sr, 21);
  uint8_t hdr[4];
  if (read_exact_fd(cfd, hdr, sizeof(hdr)) != 0 || hdr[0] != 0x05 ||
      hdr[1] != 0x01 || hdr[3] != 0x03)
    server_finish(result_fd, &sr, 22);
  sr.bytes += sizeof(hdr);
  uint8_t dlen = 0;
  if (read_exact_fd(cfd, &dlen, 1) != 0)
    server_finish(result_fd, &sr, 23);
  sr.bytes += 1;
  char host[256] = {0};
  if (dlen == 0 || read_exact_fd(cfd, host, dlen) != 0)
    server_finish(result_fd, &sr, 24);
  sr.bytes += dlen;
  uint8_t portb[2];
  if (read_exact_fd(cfd, portb, sizeof(portb)) != 0)
    server_finish(result_fd, &sr, 25);
  sr.bytes += sizeof(portb);
  if (expected_onion != NULL && strcmp(host, expected_onion) != 0)
    server_finish(result_fd, &sr, 26);
  uint8_t ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
  if (write_all_fd(cfd, ok, sizeof(ok)) != 0)
    server_finish(result_fd, &sr, 27);
  sr.handshake_ok = 1;

  /* Parent fd'yi kapatana kadar bekle (EOF). */
  char sink[64];
  for (;;) {
    ssize_t rb;
    do {
      rb = read(cfd, sink, sizeof(sink));
    } while (rb < 0 && errno == EINTR);
    if (rb <= 0)
      break;
  }
  server_finish(result_fd, &sr, 0);
}

static int make_paths(char *dir, size_t dsz, char *path, size_t psz) {
  snprintf(dir, dsz, "/tmp/noxtor_socks_%d_XXXXXX", (int)getpid());
  if (mkdtemp(dir) == NULL)
    return -1;
  int n = snprintf(path, psz, "%s/socks.sock", dir);
  if (n <= 0 || (size_t)n >= psz) {
    rmdir(dir);
    return -1;
  }
  return 0;
}

static void cleanup_paths(const char *dir, const char *path) {
  unlink(path);
  rmdir(dir);
}

/* Ortak akış: dinleyici child kur → senaryoyu koştur → sonucu topla.
 * Hüküm: dönüş değeri 1 ise tüm beklentiler tuttu. */
static int run_case(const char *label, const char *onion, enum server_mode mode,
                    pid_t expected_pid, int expect_ok) {
  char dir[64];
  char path[128];
  if (make_paths(dir, sizeof(dir), path, sizeof(path)) != 0) {
    printf("[FAIL] %s: geçici dizin oluşturulamadı\n", label);
    return 0;
  }

  int rp[2];
  int res[2];
  if (pipe(rp) != 0) {
    printf("[FAIL] %s: ready pipe açılamadı: %s\n", label, strerror(errno));
    cleanup_paths(dir, path);
    return 0;
  }
  if (pipe(res) != 0) {
    printf("[FAIL] %s: result pipe açılamadı: %s\n", label, strerror(errno));
    close(rp[0]);
    close(rp[1]);
    cleanup_paths(dir, path);
    return 0;
  }

  pid_t srv = fork();
  if (srv < 0) {
    printf("[FAIL] %s: fork başarısız: %s\n", label, strerror(errno));
    close(rp[0]);
    close(rp[1]);
    close(res[0]);
    close(res[1]);
    cleanup_paths(dir, path);
    return 0;
  }
  if (srv == 0) {
    close(rp[0]);
    close(res[0]);
    socks_server(path, rp[1], res[1], mode, onion);
  }
  close(rp[1]);
  close(res[1]);

  int ok = 0;
  char ready = 0;
  ssize_t ready_rd;
  do {
    ready_rd = read(rp[0], &ready, 1);
  } while (ready_rd < 0 && errno == EINTR);
  close(rp[0]);

  if (ready_rd == 1 && ready == 'R') {
    pid_t target = (expected_pid == -1) ? srv : expected_pid;
    int fd = -1;
    nox_err_t err = socks5_connect(onion, 80, path, target, &fd);
    if (err == NOX_OK && fd >= 0)
      close(fd);

    int st = 0;
    pid_t wr;
    do {
      wr = waitpid(srv, &st, 0);
    } while (wr < 0 && errno == EINTR);
    int child_ok = (wr == srv) && WIFEXITED(st) && WEXITSTATUS(st) == 0;

    struct srv_result sr;
    memset(&sr, 0, sizeof(sr));
    int res_ok = (read_exact_fd(res[0], &sr, sizeof(sr)) == 0);

    int err_ok = expect_ok ? (err == NOX_OK) : (err == NOX_ERR_TOR);
    int mode_ok = 0;
    if (mode == SRV_WATCH) {
      mode_ok = (sr.accepted == 1 && sr.bytes == 0);
    } else if (mode == SRV_NO_CONNECT) {
      mode_ok = (sr.accepted == 0 && sr.bytes == 0);
    } else {
      mode_ok = (sr.accepted == 1 && sr.handshake_ok == 1 && sr.bytes > 0);
    }

    ok = err_ok && child_ok && res_ok && mode_ok;
    printf("[%s] %s: err=%d (beklenen %s), accepted=%d, bytes=%zu, "
           "handshake=%s\n",
           ok ? "OK" : "FAIL", label, (int)err,
           expect_ok ? "NOX_OK" : "NOX_ERR_TOR", sr.accepted, sr.bytes,
           sr.handshake_ok ? "OK" : "yok");
    if (!child_ok)
      printf("       dinleyici exit=%d (beklenen 0)\n", exit_code_of(st));
    if (!res_ok)
      printf("       dinleyici sonuç yapısı okunamadı (kısa/eksik yazım)\n");
  } else {
    int st = 0;
    kill(srv, SIGKILL);
    pid_t wr;
    do {
      wr = waitpid(srv, &st, 0);
    } while (wr < 0 && errno == EINTR);
    printf("[FAIL] %s: dinleyici hazır sinyali alınamadı (read=%zd, "
           "rc=0x%02x, exit=%d)\n",
           label, ready_rd, (unsigned char)ready,
           (wr == srv) ? exit_code_of(st) : -1);
  }
  close(res[0]);
  cleanup_paths(dir, path);
  return ok;
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  printf("=== SOCKS5 peer doğrulama testi (bulgu 2.1b) ===\n");
  printf("Gerçek AF_UNIX dinleyicilerle: yanlış PID / PID<=0 / doğru PID\n\n");

  char onion[NOX_ONION_LEN + 1];
  make_onion(onion);

  int passed = 0;
  const int total = 3;

  /* 1) Saldırgan dinleyici: peer pid != tor_pid → NOX_ERR_TOR + 0 byte. */
  passed += run_case("yanlış PID", onion, SRV_WATCH, getpid(), 0);

  /* 2) expected_pid <= 0 → NOX_ERR_TOR, bağlantı denemesi yok. */
  passed += run_case("PID<=0", onion, SRV_NO_CONNECT, 0, 0);

  /* 3) Doğru PID → NOX_OK + handshake tamam (pozitif kontrol). */
  passed += run_case("doğru PID", onion, SRV_HANDSHAKE, -1, 1);

  printf("\nSonuç: %d/%d test başarılı\n", passed, total);
  return passed == total ? 0 : 1;
}
