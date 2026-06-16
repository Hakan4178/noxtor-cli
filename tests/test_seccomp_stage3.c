/* ================================================================
 * test_seccomp_stage3.c — Stage 3 TCP/UDP/clone engelleme testi
 *
 * Her test ayrı child process'te çalışır:
 *   1. socket(AF_INET, SOCK_STREAM)  → SIGSYS beklenir
 *   2. socket(AF_INET6, SOCK_STREAM) → SIGSYS beklenir
 *   3. socket(AF_INET, SOCK_DGRAM)   → SIGSYS beklenir
 *   4. clone()                        → SIGSYS beklenir
 *   5. getaddrinfo("8.8.8.8")        → SIGSYS beklenir
 *
 * Compile:
 *   cc -o tests/test_seccomp_stage3 tests/test_seccomp_stage3.c -lseccomp
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
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <seccomp.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <linux/netlink.h>

/* Stage 3 filtresini child process'e uygula */
static int apply_stage3(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx) return -1;

  /* Stage 1 */
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(io_uring_setup), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(io_uring_enter), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(io_uring_register), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(userfaultfd), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(perf_event_open), 0);

  /* Stage 2 — prctl: sadece tehlikeli option'ları engelle */
  {
    static const int dangerous[] = {
      PR_SET_DUMPABLE,              /* 4  — core dump engeli kaldırma */
      PR_SET_PTRACER,               /* 0x59616d61 — ptrace attach */
      PR_SET_TIMING,                /* 14 — profiling bypass */
      PR_SET_MM,                    /* 35 — memory mapping manipülasyon */
      PR_SET_TSC,                   /* 26 — timing attack */
      PR_SET_SECUREBITS,            /* 28 — privilege escalation */
      PR_SET_SYSCALL_USER_DISPATCH, /* 59 — syscall interception */
      PR_SET_VMA,                   /* 0x53564d41 — memory manipulation */
      PR_SET_MDWE,                  /* 65 — memory write execute */
    };
    for (size_t i = 0; i < sizeof(dangerous)/sizeof(dangerous[0]); i++)
      seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 1,
                       SCMP_A0(SCMP_CMP_EQ, (uint64_t)dangerous[i]));
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount2), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);

  /* Stage 3 — clone tamamen yasak */
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
  int rc3 = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone3), 0);
  if (rc3 != 0 && rc3 != -EDOM)
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone3), 0);

  /* Stage 3 — AF_INET/AF_INET6 tüm tipler */
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1,
                   SCMP_A0(SCMP_CMP_EQ, (uint64_t)AF_INET));
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1,
                   SCMP_A0(SCMP_CMP_EQ, (uint64_t)AF_INET6));

  /* Stage 3 — AF_NETLINK */
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1,
                   SCMP_A0(SCMP_CMP_EQ, (uint64_t)AF_NETLINK));

  /* Stage 3 — AF_PACKET */
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1,
                   SCMP_A0(SCMP_CMP_EQ, (uint64_t)AF_PACKET));

  /* Stage 3 — symlink, link, chmod, chown */
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(symlink), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(link), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chmod), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chown), 0);

  int rc = seccomp_load(ctx);
  seccomp_release(ctx);
  return rc;
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
  printf("=== Seccomp Stage 3 Testi ===\n");
  printf("TCP/UDP/clone/DNS engelleme doğrulaması\n");
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

  printf("\nSonuç: %d/%d test başarılı\n", passed, total);
  return (passed == total) ? 0 : 1;
}
