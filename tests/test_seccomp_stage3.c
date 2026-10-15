/* ================================================================
 * test_seccomp_stage3.c — Stage 3 sıfır-ağ-sızıntısı testi
 *
 * src/seccomp.c'deki seccomp_policy_load(3) yüklenir; politika kopyası
 * DEĞİL. (Ders: kopya politika testi, kaynaktaki regresyonu gizler.)
 *
 * Her test ayrı child process'te çalışır:
 *   1. socket(AF_INET/AF_INET6) tüm tipler → SIGSYS beklenir
 *   2. clone() → SIGSYS; clone3 → ENOSYS (fallback yaşar)
 *   3. getaddrinfo/connect                → SIGSYS beklenir
 *   4. sendto/symlink/link/chmod/chown    → SIGSYS beklenir
 *   5. AF_UNIX/socketpair/mmap RW serbest → yaşaması beklenir
 *
 * Build:
 *   make test                    (src .test.o'ları ile link edilir)
 *
 * Run:
 *   ./tests/test_seccomp_stage3
 * ================================================================ */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <seccomp.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <linux/prctl.h>
#include <linux/netlink.h>

#include "common.h"
#include "seccomp_policy.h"

/* Stage 3 filtresini child process'e uygula — GERÇEK politika
 * (src/seccomp.c → seccomp_policy_load). Kopya filtre yerine kaynağın
 * kendisi yüklenir; kaynak↔test sapması artık gizlenemez. */
static int apply_stage3(void) {
  if (seccomp_policy_load(3) != NOX_OK) return -1;
  return 0;
}

/* Test sonuçları */
struct test_case {
  const char *name;
  const char *desc;
  void (*fn)(void);  /* bu fonksiyon asla dönüş yapmaz — SIGSYS ile öldürülür */
  int should_die;    /* 1 = SIGSYS beklenir, 0 = yaşamalı */
};

/* ── Test fonksiyonları ── */

static void test_tcp_v4(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Bu çağrı SIGSYS ile öldürmeli */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  /* Buraya ulaşırsak test başarısız */
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_tcp_v6(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_udp_v4(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_clone(void) {
  if (apply_stage3() < 0) _exit(2);
  /* glibc clone() wrapper'ı NULL fn ile EINVAL dönür — syscall'a ulaşmaz.
   * Doğrudan syscall() ile deniyoruz. */
  syscall(SYS_clone, 0, NULL, NULL, NULL, 0);
  /* Buraya ulaşırsak seccomp çalışmadı */
  _exit(1);
}

static void test_getaddrinfo(void) {
  if (apply_stage3() < 0) _exit(2);
  /* "8.8.8.8" IP literal — DNS çözümlemez.
   * "google.com" gerçek DNS çözümlemesi gerektirir.
   * glibc nsswitch.files → /etc/hosts'tan çözülebilir,
   * ama AF_NETLINK/AF_INET socket açmaya çalışır. */
  struct addrinfo hints = {0}, *result = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  getaddrinfo("google.com", "80", &hints, &result);
  if (result) freeaddrinfo(result);
  _exit(1);
}

/* AF_NETLINK doğrudan test */
static void test_netlink(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_connect_tcp_direct(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Doğrudan connect() denemesi — socket oluşturulamaz */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd >= 0) {
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(80),
    };
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
  }
  _exit(1);
}

static void test_af_unix_should_work(void) {
  if (apply_stage3() < 0) _exit(2);
  /* AF_UNIX serbest — bu yaşamalı */
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd >= 0) {
    close(fd);
    _exit(0);  /* BAŞARILI: AF_UNIX serbest */
  }
  _exit(1);
}

/* ── W^X: executable bellek yaratma engelleme testleri ── */

static void test_mprotect_exec(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Önce RW mapping al (serbest), sonra RX'e çevir → SIGSYS beklenir */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  mprotect(p, 4096, PROT_READ | PROT_EXEC);
  munmap(p, 4096);
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_mmap_exec(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Doğrudan executable mmap → SIGSYS beklenir */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  munmap(p, 4096);
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_mmap_rw_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* RW mapping serbest olmalı — normal bellek kullanımı bozulmamalı */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  munmap(p, 4096);
  _exit(0);  /* BAŞARILI: RW mmap serbest */
}

/* ── prctl option filtreleme testleri ── */

static void test_prctl_dumpable_kill(void) {
  if (apply_stage3() < 0) _exit(2);
  /* prctl(PR_SET_DUMPABLE, 1) → KILL (core dump engeli kaldırılamaz) */
  prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  _exit(1);
}

static void test_prctl_ptracer_kill(void) {
  if (apply_stage3() < 0) _exit(2);
  /* prctl(PR_SET_PTRACER, ANY) → KILL (ptrace attach) */
  prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
  _exit(1);
}

static void test_prctl_nonewprivs_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* prctl(PR_SET_NO_NEW_PRIVS, 1) → ALLOW (güvenlik özelliği) */
  int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  /* prctl başarılı olmalı (rc=0) */
  if (rc == 0)
    _exit(0);  /* BAŞARILI: PR_SET_NO_NEW_PRIVS serbest */
  _exit(1);
}

/* ── fs/kanal ek testleri ── */

static void test_symlink(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Hedef yok — politika bozuksa ENOENT döner, yan etki bırakmaz */
  symlink("/nonexistent-target", "/nonexistent-link");
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_link(void) {
  if (apply_stage3() < 0) _exit(2);
  link("/nonexistent-a", "/nonexistent-b");
  _exit(1);
}

static void test_chmod(void) {
  if (apply_stage3() < 0) _exit(2);
  chmod("/nonexistent", 0600);
  _exit(1);
}

static void test_chown(void) {
  if (apply_stage3() < 0) _exit(2);
  chown("/nonexistent", 0, 0);
  _exit(1);
}

static void test_sendto(void) {
  if (apply_stage3() < 0) _exit(2);
  /* AF_UNIX socketpair serbest, ama sendto() stage 3'te yasak */
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) _exit(2);
  sendto(sv[0], "x", 1, 0, NULL, 0);
  _exit(1);
}

static void test_socketpair_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* IPC aynı process içinde — serbest kalmalı */
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) _exit(1);
  close(sv[0]);
  close(sv[1]);
  _exit(0);
}

static void test_mprotect_rw_allow(void) {
  if (apply_stage3() < 0) _exit(2);
  /* PROT_EXEC içermeyen mprotect serbest (normal bellek yönetimi) */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  mprotect(p, 4096, PROT_READ | PROT_WRITE);
  munmap(p, 4096);
  _exit(0);
}

static void test_clone3_enosys(void) {
  if (apply_stage3() < 0) _exit(2);
  /* clone3 → ERRNO(ENOSYS): glibc pthread fallback'i sağlansın */
  struct {
    unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal;
    unsigned long long stack, stack_size, tls, set_tid, set_tid_size, cgroup;
  } args;
  memset(&args, 0, sizeof(args));
  args.flags = CLONE_THREAD;
  errno = 0;
  long r = syscall(SYS_clone3, &args, sizeof(args));
  if (r == -1 && errno == ENOSYS) _exit(0);  /* beklenen */
  _exit(1);
}

#ifdef AF_ALG
static void test_af_alg(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

#ifdef AF_VSOCK
static void test_af_vsock(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

#ifdef AF_XDP
static void test_af_xdp(void) {
  if (apply_stage3() < 0) _exit(2);
  int fd = socket(AF_XDP, SOCK_RAW, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

/* ── Stage 3 — gerçek event-loop syscall'ları (yaşaması beklenir) ──
 * NoxTor'un stage 3'te fiilen kullandığı syscall'lar:
 *   epoll_create1  → network.c:1810 (event loop kurulumu)
 *   epoll_ctl      → stdin_handler.c:566, event_loop.c (fd kaydı)
 *   epoll_wait     → event_loop.c (ana döngü)
 *   poll           → network.c read_full/write_full/ctrl_read_line
 *   fcntl(F_GETFL) → set_nonblocking deseni
 *   accept4        → event_loop.c:863 (AF_UNIX bağlantı kabulü)
 *   read/write     → network.c read_full/write_full
 *   clock_gettime  → zaman aşımı/aktivite takibi (CLOCK_MONOTONIC)
 *   nanosleep      → network.c safe_nanosleep (backoff)
 * Hiçbiri filtrede değil; stage 3'te event loop'u bloklamamalı. */

static void test_epoll_create1(void) {
  if (apply_stage3() < 0) _exit(2);
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) _exit(1);
  close(efd);
  _exit(0);
}

static void test_epoll_ctl(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) _exit(1);
  struct epoll_event ev = { .events = EPOLLIN, .data.fd = fds[0] };
  int rc = epoll_ctl(efd, EPOLL_CTL_ADD, fds[0], &ev);
  close(fds[0]);
  close(fds[1]);
  close(efd);
  _exit(rc == 0 ? 0 : 1);
}

static void test_epoll_wait(void) {
  if (apply_stage3() < 0) _exit(2);
  int efd = epoll_create1(EPOLL_CLOEXEC);
  if (efd < 0) _exit(1);
  struct epoll_event evs[1];
  /* Kayıtlı fd yok, timeout=0 → olaysız döner */
  int n = epoll_wait(efd, evs, 1, 0);
  close(efd);
  _exit(n == 0 ? 0 : 1);
}

static void test_poll_timeout(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
  /* Veri yok, timeout=0 → 0 döner (read_full/write_full deseni) */
  int r = poll(&pfd, 1, 0);
  close(fds[0]);
  close(fds[1]);
  _exit(r == 0 ? 0 : 1);
}

static void test_fcntl_getfl(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  int fl = fcntl(fds[0], F_GETFL, 0);
  close(fds[0]);
  close(fds[1]);
  _exit(fl >= 0 ? 0 : 1);
}

static void test_accept4(void) {
  if (apply_stage3() < 0) _exit(2);
  /* Abstract AF_UNIX — dosya sistemine dokunmaz (event_loop.c deseni).
   * SOCK_NONBLOCK accept4'ün kendisini bloklamaz → önce client bağlanır,
   * sonra kabul edilir (event_loop.c:863 ile aynı desen). */
  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) _exit(1);
  struct sockaddr_un sa;
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "nox_s3_accept4_%d", (int)getpid());
  if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) _exit(2);
  if (listen(sfd, 1) != 0) _exit(2);
  int cli = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (cli < 0) _exit(2);
  if (connect(cli, (struct sockaddr *)&sa, sizeof(sa)) != 0) _exit(2);
  int cfd = accept4(sfd, NULL, NULL, SOCK_NONBLOCK);
  int ok = (cfd >= 0);
  if (cfd >= 0) close(cfd);
  close(cli);
  close(sfd);
  _exit(ok ? 0 : 1);
}

static void test_read_pipe(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  ssize_t w = write(fds[1], "x", 1);
  char c = 0;
  ssize_t n = (w == 1) ? read(fds[0], &c, 1) : -1;
  close(fds[0]);
  close(fds[1]);
  _exit(n == 1 && c == 'x' ? 0 : 1);
}

static void test_write_pipe(void) {
  if (apply_stage3() < 0) _exit(2);
  int fds[2];
  if (pipe(fds) != 0) _exit(2);
  ssize_t w = write(fds[1], "x", 1);
  close(fds[0]);
  close(fds[1]);
  _exit(w == 1 ? 0 : 1);
}

static void test_clock_gettime(void) {
  if (apply_stage3() < 0) _exit(2);
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) _exit(1);
  _exit(0);
}

static void test_nanosleep_zero(void) {
  if (apply_stage3() < 0) _exit(2);
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
  if (nanosleep(&ts, NULL) != 0) _exit(1);
  _exit(0);
}

/* ── Ana test çalıştırıcı ── */

static int run_test(const char *name __attribute__((unused)), const char *desc, void (*fn)(void), int should_die) {
  printf("  %-38s ", desc);

  pid_t child = fork();
  if (child < 0) {
    printf("[SKIP] fork başarısız\n");
    return 0;
  }

  if (child == 0) {
    fn();  /* asla dönmez — SIGSYS veya _exit */
    _exit(0);
  }

  int status;
  waitpid(child, &status, 0);

  if (should_die) {
    /* SIGSYS ile ölüm bekleniyor */
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
      printf("[PASS] SIGSYS ✓\n");
      return 1;
    } else if (WIFEXITED(status)) {
      printf("[FAIL] exit=%d (SIGSYS bekleniyordu)\n", WEXITSTATUS(status));
      return 0;
    } else {
      printf("[FAIL] signal=%d (SIGSYS bekleniyordu)\n", WTERMSIG(status));
      return 0;
    }
  } else {
    /* Yaşaması bekleniyor */
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      printf("[PASS] yaşadı ✓\n");
      return 1;
    } else if (WIFSIGNALED(status)) {
      printf("[FAIL] signal=%d (yaşaması bekleniyordu)\n", WTERMSIG(status));
      return 0;
    } else {
      printf("[FAIL] exit=%d (yaşaması bekleniyordu)\n", WEXITSTATUS(status));
      return 0;
    }
  }
}

int main(void) {
  printf("=== Seccomp Stage 3 Testi (gerçek politika) ===\n");
  printf("TCP/UDP/clone/DNS/fs/W^X engelleme doğrulaması\n");
  printf("Her test ayrı child process'te çalışır\n\n");

  int passed = 0;
  int total = 0;

  /* Engellenmesi gerekenler (SIGSYS beklenir) */
  total++; passed += run_test("tcp_v4",  "socket(AF_INET, SOCK_STREAM)  ", test_tcp_v4, 1);
  total++; passed += run_test("tcp_v6",  "socket(AF_INET6, SOCK_STREAM) ", test_tcp_v6,  1);
  total++; passed += run_test("udp_v4",  "socket(AF_INET, SOCK_DGRAM)   ", test_udp_v4,  1);
  total++; passed += run_test("clone",   "clone()                        ", test_clone,   1);
  total++; passed += run_test("dns",     "getaddrinfo(google.com)         ", test_getaddrinfo, 1);
  total++; passed += run_test("connect", "connect(AF_INET, 8.8.8.8:80)  ", test_connect_tcp_direct, 1);
  total++; passed += run_test("netlink", "socket(AF_NETLINK, ROUTE)     ", test_netlink, 1);

  /* Serbest olması gerekenler */
  total++; passed += run_test("af_unix", "socket(AF_UNIX, SOCK_STREAM)   ", test_af_unix_should_work, 0);

  /* prctl option filtreleme */
  total++; passed += run_test("prctl_dump", "prctl(PR_SET_DUMPABLE)         ", test_prctl_dumpable_kill, 1);
  total++; passed += run_test("prctl_ptr",  "prctl(PR_SET_PTRACER)          ", test_prctl_ptracer_kill, 1);
  total++; passed += run_test("prctl_nnp",  "prctl(PR_SET_NO_NEW_PRIVS)     ", test_prctl_nonewprivs_allow, 0);

  /* W^X: executable bellek yaratma */
  total++; passed += run_test("mprotect_exec", "mprotect(PROT_READ|PROT_EXEC)   ", test_mprotect_exec, 1);
  total++; passed += run_test("mmap_exec",     "mmap(PROT_READ|WRITE|EXEC)      ", test_mmap_exec, 1);
  total++; passed += run_test("mmap_rw",       "mmap(PROT_READ|WRITE) serbest   ", test_mmap_rw_allow, 0);

  /* fs/kanal ek testleri */
  total++; passed += run_test("symlink",  "symlink()                      ", test_symlink, 1);
  total++; passed += run_test("link",     "link()                         ", test_link, 1);
  total++; passed += run_test("chmod",    "chmod()                        ", test_chmod, 1);
  total++; passed += run_test("chown",    "chown()                        ", test_chown, 1);
  total++; passed += run_test("sendto",   "sendto(AF_UNIX)                ", test_sendto, 1);
  total++; passed += run_test("spair",    "socketpair(AF_UNIX) serbest    ", test_socketpair_allow, 0);
  total++; passed += run_test("mprot_rw", "mprotect(READ|WRITE) serbest   ", test_mprotect_rw_allow, 0);
  total++; passed += run_test("clone3",   "clone3 → ENOSYS (fallback)     ", test_clone3_enosys, 0);
#ifdef AF_ALG
  total++; passed += run_test("af_alg",   "socket(AF_ALG)                 ", test_af_alg, 1);
#endif
#ifdef AF_VSOCK
  total++; passed += run_test("af_vsock", "socket(AF_VSOCK)               ", test_af_vsock, 1);
#endif
#ifdef AF_XDP
  total++; passed += run_test("af_xdp",   "socket(AF_XDP)                 ", test_af_xdp, 1);
#endif

  /* Stage 3 — gerçek event-loop syscall'ları (yaşaması beklenir) */
  total++; passed += run_test("ep1",     "epoll_create1() serbest        ", test_epoll_create1, 0);
  total++; passed += run_test("eptl",    "epoll_ctl(ADD) serbest         ", test_epoll_ctl, 0);
  total++; passed += run_test("epw",     "epoll_wait(timeout=0) serbest  ", test_epoll_wait, 0);
  total++; passed += run_test("poll",    "poll(timeout=0) serbest        ", test_poll_timeout, 0);
  total++; passed += run_test("fcntl",   "fcntl(F_GETFL) serbest         ", test_fcntl_getfl, 0);
  total++; passed += run_test("acc4",    "accept4(AF_UNIX, nonblock)     ", test_accept4, 0);
  total++; passed += run_test("read",    "read(pipe) serbest             ", test_read_pipe, 0);
  total++; passed += run_test("write",   "write(pipe) serbest            ", test_write_pipe, 0);
  total++; passed += run_test("clock",   "clock_gettime(MONOTONIC)       ", test_clock_gettime, 0);
  total++; passed += run_test("nsleep",  "nanosleep(0) serbest           ", test_nanosleep_zero, 0);

  printf("\nSonuç: %d/%d test başarılı\n", passed, total);
  return (passed == total) ? 0 : 1;
}
