/* ================================================================
 * test_tor_peer.c — tor_verify_peer (SO_PEERCRED) regresyon testi
 *
 * Bulgu 2.1: "control soketine connect olmak, karşıdakinin Tor olduğunu
 * kanıtlamaz." Fix, connect sonrası SO_PEERCRED ile peer PID/UID
 * doğrulaması yapar. Bu test gerçek AF_UNIX soket çiftiyle senaryoları
 * kilitler:
 *   1) gerçek dinleyici child PID'i → kabul (NOX_OK)
 *   2) yanlış PID (parent) → ret (NOX_ERR_PEER) — sahte soket taklidi
 *   3) geçersiz fd (-1) → NOX_ERR_NET (getsockopt)
 *   4) socket olmayan fd (/dev/null) → NOX_ERR_NET
 *
 * Semantik doğrulama: /tmp/opencode/peercred_probe.c
 * (müşteri tarafında SO_PEERCRED = DİNLEYEN sürecin pid/uid'i).
 * ================================================================ */
#define _GNU_SOURCE
#include "common.h"
#include "network.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Dinleyici child: path'i bind+listen eder, hazır olunca ready_fd'e 1 byte
 * yazar, done_r'den 1 byte gelene kadar yaşar. Hata → _exit(1). */
static pid_t spawn_listener(const char *path, int ready_fd, int done_r) {
  pid_t child = fork();
  if (child < 0)
    return -1;
  if (child == 0) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    size_t len = strlen(path);
    if (s < 0 || len >= sizeof(a.sun_path))
      _exit(1);
    memcpy(a.sun_path, path, len + 1);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(s, 4) != 0)
      _exit(1);
    char c = 'R';
    if (write(ready_fd, &c, 1) != 1)
      _exit(1);
    char d;
    (void)read(done_r, &d, 1); /* parent bitene kadar yaşa */
    _exit(0);
  }
  return child;
}

/* path'e bağlan; hata → -1 */
static int connect_unix(const char *path) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  size_t len = strlen(path);
  if (len >= sizeof(a.sun_path)) {
    close(fd);
    return -1;
  }
  memcpy(a.sun_path, path, len + 1);
  if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int main(void) {
  printf("=== tor_verify_peer (SO_PEERCRED) testi — bulgu 2.1 ===\n");
  printf("Gerçek AF_UNIX dinleyici child ile peer kimlik doğrulaması\n\n");

  char dir[] = "/tmp/noxtor_peer_XXXXXX";
  if (mkdtemp(dir) == NULL) {
    printf("[FAIL] mkdtemp: %s\n", strerror(errno));
    return 1;
  }
  char sock_path[sizeof(dir) + 16];
  snprintf(sock_path, sizeof(sock_path), "%s/control.sock", dir);

  int ready_pipe[2];
  int done_pipe[2];
  if (pipe(ready_pipe) != 0 || pipe(done_pipe) != 0) {
    printf("[FAIL] pipe: %s\n", strerror(errno));
    rmdir(dir);
    return 1;
  }

  pid_t listener = spawn_listener(sock_path, ready_pipe[1], done_pipe[0]);
  close(ready_pipe[1]);
  close(done_pipe[0]);
  if (listener < 0) {
    printf("[FAIL] fork\n");
    rmdir(dir);
    return 1;
  }

  char r = 0;
  if (read(ready_pipe[0], &r, 1) != 1) {
    printf("[FAIL] dinleyici soketi bind edemedi\n");
    kill(listener, SIGKILL);
    waitpid(listener, NULL, 0);
    rmdir(dir);
    return 1;
  }

  int passed = 0;
  int total = 0;
  int cfd = connect_unix(sock_path);

  if (cfd >= 0) {
    /* 1) Gerçek dinleyici kabul edilir */
    total++;
    if (tor_verify_peer(cfd, listener) == NOX_OK) {
      printf("[OK] gerçek dinleyici doğrulandı (PID=%d)\n", (int)listener);
      passed++;
    } else {
      printf("[FAIL] gerçek dinleyici reddedildi!\n");
    }

    /* 2) Sahte soket taklidi: peer pid'i beklenenle uyuşmuyor */
    total++;
    nox_err_t peer_err = tor_verify_peer(cfd, getpid());
    if (peer_err == NOX_ERR_PEER) {
      printf("[OK] yanlış PID reddedildi (beklenen=%d, gerçek peer=%d)\n",
             (int)getpid(), (int)listener);
      passed++;
    } else {
      printf("[FAIL] yanlış PID reddedilmedi (err=%d, beklenen %d) — "
             "impersonation açık!\n",
             (int)peer_err, (int)NOX_ERR_PEER);
    }
    close(cfd);
  } else {
    total++;
    printf("[FAIL] test soketine connect edilemedi\n");
  }

  /* 3) Geçersiz fd — getsockopt hatası NOX_ERR_NET olmalı */
  total++;
  nox_err_t badfd_err = tor_verify_peer(-1, listener);
  if (badfd_err == NOX_ERR_NET) {
    printf("[OK] geçersiz fd reddedildi (NOX_ERR_NET)\n");
    passed++;
  } else {
    printf("[FAIL] geçersiz fd yanlış kodla döndü (err=%d, beklenen %d)\n",
           (int)badfd_err, (int)NOX_ERR_NET);
  }

  /* 4) Socket olmayan fd (getsockopt ENOTSOCK) — NOX_ERR_NET */
  total++;
  int nfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (nfd >= 0) {
    nox_err_t notsock_err = tor_verify_peer(nfd, listener);
    if (notsock_err == NOX_ERR_NET) {
      printf("[OK] socket olmayan fd reddedildi (NOX_ERR_NET)\n");
      passed++;
    } else {
      printf("[FAIL] socket olmayan fd yanlış kodla döndü "
             "(err=%d, beklenen %d)\n",
             (int)notsock_err, (int)NOX_ERR_NET);
    }
    close(nfd);
  } else {
    printf("[FAIL] /dev/null açılamadı: %s\n", strerror(errno));
  }

  /* Temizlik: dinleyiciyi serbest bırak + dizini kaldır */
  char d = 'D';
  (void)write(done_pipe[1], &d, 1);
  close(done_pipe[1]);
  close(ready_pipe[0]);
  waitpid(listener, NULL, 0);
  unlink(sock_path);
  rmdir(dir);

  printf("\nSonuç: %d/%d test başarılı\n", passed, total);
  return (passed == total) ? 0 : 1;
}
