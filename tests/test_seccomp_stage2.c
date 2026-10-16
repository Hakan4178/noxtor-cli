/* ================================================================
 * test_seccomp_stage2.c — Stage 2 filtre testi (GERÇEK politika)
 *
 * src/seccomp.c'deki seccomp_policy_load(2) yüklenir; politika kopyası
 * DEĞİL. K-01 regresyon matrisi burada: clone yalnız CLONE_THREAD biti
 * set ise geçer; fork-benzeri (bit'siz) her clone SIGSYS alır.
 *
 * Stage 2 = tor_spawn sonrası: fork/execve penceresi kapandı.
 *   SIGSYS : fork/vfork/execve, fork-benzeri clone'lar, raw socket'lar
 *            (AF_INET/AF_INET6 SOCK_RAW, AF_PACKET), tehlikeli prctl
 *            option'ları, unshare/setns/mount/reboot/keyctl,
 *            K-02 FIX: AF_INET/AF_INET6 tüm tipler (TCP/UDP dahil),
 *            AF_NETLINK,
 *            W^X FIX: mprotect/mmap(PROT_EXEC), pkey_mprotect,
 *            shmat (SHM_EXEC dahil), uselib,
 *            32-bit ABI: i386 int 0x80 + x32 (mimari allowlist → badarch)
 *   Serbest: CLONE_THREAD'li clone (pthread_create), clone3 → ENOSYS
 *            fallback'i, AF_UNIX, prctl(PR_SET_NO_NEW_PRIVS),
 *            mprotect(EXEC'suz)
 *   Not    : K-02 + W^X FIX — ağ aileleri ve exec-gain stage-2'den
 *            itibaren kapalı (bootstrap penceresi).
 *
 * Her test ayrı child process'te çalışır.
 *
 * Build:
 *   make test                    (src .test.o'ları ile link edilir)
 *
 * Run:
 *   ./tests/test_seccomp_stage2
 * ================================================================ */
#include "common.h"
#include "seccomp_policy.h"

#include <errno.h>
#include <linux/prctl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* SHM_EXEC (man7 shmop(2)): System V segmentini yürütülebilir eşler.
 * Linux ≥2.6.9; glibc sabiti her sürümde olmayabilir → kernel uapi değeri. */
#ifndef SHM_EXEC
#define SHM_EXEC 0100000
#endif

/* Stage 2 filtresini child process'e uygula — gerçek politika */
static int apply_stage2(void) {
  if (seccomp_policy_load(2) != NOX_OK) return -1;
  return 0;
}

/* ── clone matrisi (K-01 regresyonu) ──
 * Kural: (flags & CLONE_THREAD) == 0 ise SIGSYS.
 * expect_alive=1 → clone dönmeli; expect_alive=0 → süreç ölmeli. */

/* Ham clone trampolini: çocuk/thread yeni yığında ASLA `ret` çalıştırmaz.
 * Neden gerekli: syscall(SYS_clone...) + "if (r==0) exit" deseni, çocuğun
 * glibc syscall() wrapper'ının `ret`'iyle YENİ yığından çöp adres çekmesine
 * yol açar → yarışlı SIGSEGV (ölçüm: 40 koşuda 28 çökme; CET-SS yokken).
 * Bu trampolin çocuk yolunu doğrudan yönetir: yalnız SYS_exit çağırır. */
#define STR_(x) #x
#define STR(x) STR_(x)

__attribute__((naked, noinline, used))
static long raw_clone_exit(unsigned long flags __attribute__((unused)),
                           void *stack __attribute__((unused)),
                           int *ptid __attribute__((unused))) {
  __asm__(
    "movq $" STR(__NR_clone) ", %rax\n\t"
    "syscall\n\t"
    "testq %rax, %rax\n\t"
    "jz 1f\n\t"
    "ret\n\t"
    /* Çocuk/thread — burada %rsp = stack; asla ret yok: */
    "1:\n\t"
    "xorl %edi, %edi\n\t"
    "movq $" STR(__NR_exit) ", %rax\n\t"
    "syscall\n\t"
    "ud2\n\t"
  );
}

static void clone_attempt(unsigned long flags, int expect_alive) {
  static char stk[1 << 20] __attribute__((aligned(64)));
  int ptid = 0;
  void *stack = (flags & CLONE_THREAD) ? (void *)(stk + sizeof(stk) - 64) : NULL;
  long r = raw_clone_exit(flags, stack, &ptid);
  if (r > 0) _exit(expect_alive ? 0 : 1);  /* parent */
  _exit(1);                                /* beklenmedik hata/ölmeliydi */
}

static void test_clone_thread(void) {
  if (apply_stage2() < 0) _exit(2);
  clone_attempt(CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, 1);
}

static void test_clone_glibc_like(void) {
  if (apply_stage2() < 0) _exit(2);
  clone_attempt(CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_PARENT_SETTID, 1);
}

static void test_clone_plain(void) {
  if (apply_stage2() < 0) _exit(2);
  clone_attempt(SIGCHLD, 0);
}

static void test_clone_incidental(void) {
  if (apply_stage2() < 0) _exit(2);
  /* SB-1: 0x00100000 (CLONE_PARENT_SETTID) taklidi fork-benzeri clone */
  clone_attempt(SIGCHLD | 0x00100000UL, 0);
}

static void test_clone_sharedvm_incidental(void) {
  if (apply_stage2() < 0) _exit(2);
  clone_attempt(CLONE_VM | CLONE_SIGHAND | 0x00100000UL, 0);
}

static void test_clone_userns_incidental(void) {
  if (apply_stage2() < 0) _exit(2);
  clone_attempt(SIGCHLD | 0x00100000UL | CLONE_NEWUSER, 0);
}

/* clone3 → ENOSYS (glibc pthread fallback'i sağlansın; süreç yaşar) */
static void test_clone3_enosys(void) {
  if (apply_stage2() < 0) _exit(2);
  struct {
    unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal;
    unsigned long long stack, stack_size, tls, set_tid, set_tid_size, cgroup;
  } args;
  memset(&args, 0, sizeof(args));
  args.flags = CLONE_THREAD;
  args.exit_signal = 0;
  errno = 0;
  long r = syscall(SYS_clone3, &args, sizeof(args));
  if (r == -1 && errno == ENOSYS) _exit(0);  /* beklenen: ERRNO(ENOSYS) */
  _exit(1);
}

static void *pth_fn(void *a) { (void)a; return NULL; }

static void test_pthread_create(void) {
  if (apply_stage2() < 0) _exit(2);
  /* Gerçek akış: glibc clone3 dener → ENOSYS → clone(CLONE_THREAD...) */
  pthread_t t;
  if (pthread_create(&t, NULL, pth_fn, NULL) != 0) _exit(1);
  pthread_join(t, NULL);
  _exit(0);
}

/* ── fork ailesi ── */

static void test_fork(void) {
  if (apply_stage2() < 0) _exit(2);
  pid_t p = fork();
  if (p == 0) _exit(0);
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_vfork(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(SYS_vfork);
  _exit(1);
}

static void test_execve(void) {
  if (apply_stage2() < 0) _exit(2);
  char path[] = "/bin/true";
  char *const argv[] = { path, NULL };
  char *const envp[] = { NULL };
  syscall(SYS_execve, path, argv, envp);
  _exit(1);
}

/* ── socket ailesi ── */

static void test_socket_inet_raw(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_INET, SOCK_RAW, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

#ifdef AF_INET6
static void test_socket_inet6_raw(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_INET6, SOCK_RAW, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

#ifdef AF_PACKET
static void test_socket_af_packet(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_PACKET, SOCK_RAW, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

/* K-02 FIX: TCP/UDP ve NETLINK artık stage 2'den itibaren SIGSYS.
 * (Eski test_socket_inet_dgram_allow "serbest" bekliyordu; denetim
 * bulgusu kapatıldı → ölüm yönüne çevrildi.) */
static void test_socket_inet_dgram(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

static void test_socket_inet_stream(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}

#ifdef AF_INET6
static void test_socket_inet6_stream(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

#ifdef AF_NETLINK
static void test_socket_netlink(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_NETLINK, SOCK_RAW, 0);
  if (fd >= 0) close(fd);
  _exit(1);
}
#endif

/* ── W^X FIX: exec'li bellek yaratma stage-2'den itibaren yasak ──
 * (Denetim: W^X iddiası yalnız stage-3'te geçerliydi; bootstrap
 * penceresinde mprotect/mmap/SHM_EXEC ile RX bölge yaratılabiliyordu.
 * Kural seti stage-2'ye taşındı; bu testler pencereyi kilitler.) */

static void test_mprotect_exec(void) {
  if (apply_stage2() < 0) _exit(2);
  /* Önce RW mapping (serbest), sonra PROT_EXEC ekle → SIGSYS beklenir */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  mprotect(p, 4096, PROT_READ | PROT_EXEC);
  munmap(p, 4096);
  _exit(1);
}

static void test_mmap_exec(void) {
  if (apply_stage2() < 0) _exit(2);
  /* Doğrudan W|X mapping → SIGSYS beklenir */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p != MAP_FAILED) munmap(p, 4096);
  _exit(1);
}

static void test_mprotect_noexec_allow(void) {
  if (apply_stage2() < 0) _exit(2);
  /* PROT_EXEC içermeyen mprotect serbest (normal bellek yönetimi) */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  if (mprotect(p, 4096, PROT_READ) != 0) _exit(1);
  munmap(p, 4096);
  _exit(0);
}

static void test_shmat_shm_exec(void) {
  if (apply_stage2() < 0) _exit(2);
  /* SHM_EXEC: System V segmentini YÜRÜTÜLEBİLİR eşler (man7 shmop(2)).
   * Geçersiz shmid önemsiz — seccomp syscall girişinde KILL eder. */
  void *p = shmat(0, NULL, SHM_EXEC);
  if (p != (void *)-1) (void)shmdt(p);
  _exit(1);
}

#ifdef SYS_pkey_mprotect
static void test_pkey_mprotect(void) {
  if (apply_stage2() < 0) _exit(2);
  /* pkey_mprotect W^X kuralının kardeşi — tümü yasak */
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  syscall(SYS_pkey_mprotect, p, 4096, PROT_READ, 0);
  munmap(p, 4096);
  _exit(1);
}
#endif

#ifdef SYS_uselib
static void test_uselib(void) {
  if (apply_stage2() < 0) _exit(2);
  /* Legacy exec-gain: kütüphane eşleyerek kod çalıştırma — yasak */
  syscall(SYS_uselib, "/nonexistent");
  _exit(1);
}
#endif

/* ── 32-bit ABI (i386 int 0x80 + x32) — mimari allowlist regresyonu ──
 * Filtre yalnız native x86_64 arch'ı ile kurulur; başka ABI'den gelen
 * syscall'lar libseccomp badarch aksiyonuyla ölür (seccomp.c'de açıkça
 * KILL_PROCESS). BPF, çekirdeğin ABI dispatcher'ından ÖNCE koşar →
 * kernel'de x32/ia32 desteği olsa da olmasa da beklenen sonuç SIGSYS.
 * Ampirik kanıt: /tmp/opencode/probe-32bit.log + probe_32bit.c. */

#define X32_BIT 0x40000000L

/* i386 syscall — int 0x80 (nr: eax, argümanlar: ebx/ecx/edx) */
static long int80(long nr, long a, long b, long c) {
  long ret;
  __asm__ volatile("int $0x80"
                   : "=a"(ret)
                   : "a"(nr), "b"(a), "c"(b), "d"(c)
                   : "memory");
  return ret;
}

static void test_i386_int80_getpid(void) {
  if (apply_stage2() < 0) _exit(2);
  int80(20, 0, 0, 0); /* i386 getpid (syscall_32.tbl) */
  _exit(1);
}

static void test_i386_int80_socket_inet(void) {
  if (apply_stage2() < 0) _exit(2);
  int80(359, AF_INET, SOCK_STREAM, 0); /* i386 socket (direct) */
  _exit(1);
}

static void test_i386_int80_execve(void) {
  if (apply_stage2() < 0) _exit(2);
  int80(11, 0, 0, 0); /* i386 execve — NULL yol, çalıştırmaz */
  _exit(1);
}

static void test_x32_getpid(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(X32_BIT | 39); /* x32 getpid (ortak numara + bit) */
  _exit(1);
}

static void test_x32_socket_inet(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(X32_BIT | 41, AF_INET, SOCK_STREAM, 0); /* x32 socket */
  _exit(1);
}

static void test_x32_execve(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(X32_BIT | 520, 0, 0, 0); /* x32 execve (x32'ye özel numara) */
  _exit(1);
}

static void test_socket_unix_allow(void) {
  if (apply_stage2() < 0) _exit(2);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) _exit(1);
  close(fd);
  _exit(0);
}

/* ── prctl option filtreleme ── */

static void test_prctl_dumpable(void) {
  if (apply_stage2() < 0) _exit(2);
  prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  _exit(1);
}

static void test_prctl_ptracer(void) {
  if (apply_stage2() < 0) _exit(2);
  prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
  _exit(1);
}

#ifdef PR_SET_MDWE
static void test_prctl_mdwe(void) {
  if (apply_stage2() < 0) _exit(2);
  prctl(PR_SET_MDWE, 0UL, 0, 0, 0);
  _exit(1);
}
#endif

static void test_prctl_nnp_allow(void) {
  if (apply_stage2() < 0) _exit(2);
  /* PR_SET_NO_NEW_PRIVS güvenlik özelliği — serbest kalmalı */
  int rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  _exit(rc == 0 ? 0 : 1);
}

/* ── namespace / sistem ── */

static void test_unshare_userns(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(SYS_unshare, CLONE_NEWUSER);
  _exit(1);
}

static void test_setns(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(SYS_setns, -1, 0);
  _exit(1);
}

static void test_mount(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(SYS_mount, "none", "/tmp", "tmpfs", 0UL, NULL);
  _exit(1);
}

static void test_reboot(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(SYS_reboot, 0xfee1deadUL, 672274793UL, 0x01234567UL, NULL);
  _exit(1);
}

static void test_keyctl(void) {
  if (apply_stage2() < 0) _exit(2);
  syscall(SYS_keyctl, 0UL, 0UL, 0UL, 0UL, 0UL);
  _exit(1);
}

static void test_io_setup(void) {
  if (apply_stage2() < 0) _exit(2);
  /* Legacy kernel AIO kapısı — context'siz ailenin tamamı ölü */
  syscall(SYS_io_setup, 128UL, NULL);
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
  printf("=== Seccomp Stage 2 Testi (gerçek politika) ===\n");
  printf("clone matrisi (K-01) + fork/raw-socket/prctl + ağ (K-02) + W^X + 32-bit ABI\n");
  printf("Her test ayrı child process'te çalışır\n\n");

  int passed = 0;
  int total = 0;

  /* Engellenmesi gerekenler (SIGSYS beklenir) */
  total++; passed += run_test("fork",        "fork                          ", test_fork,                    1);
  total++; passed += run_test("vfork",       "vfork                         ", test_vfork,                   1);
  total++; passed += run_test("execve",      "execve                        ", test_execve,                  1);
  total++; passed += run_test("clone_plain", "clone(SIGCHLD)                ", test_clone_plain,             1);
  total++; passed += run_test("clone_inc",   "clone(SIGCHLD|0x100000)       ", test_clone_incidental,        1);
  total++; passed += run_test("clone_svm",   "clone(VM|SIGHAND|0x100000)    ", test_clone_sharedvm_incidental, 1);
  total++; passed += run_test("clone_uns",   "clone(NEWUSER|0x100000)       ", test_clone_userns_incidental, 1);
  total++; passed += run_test("raw_v4",      "socket(AF_INET, SOCK_RAW)     ", test_socket_inet_raw,         1);
#ifdef AF_INET6
  total++; passed += run_test("raw_v6",      "socket(AF_INET6, SOCK_RAW)    ", test_socket_inet6_raw,        1);
#endif
#ifdef AF_PACKET
  total++; passed += run_test("af_packet",   "socket(AF_PACKET, SOCK_RAW)   ", test_socket_af_packet,        1);
#endif
  total++; passed += run_test("prctl_dump",  "prctl(PR_SET_DUMPABLE)        ", test_prctl_dumpable,          1);
  total++; passed += run_test("prctl_ptr",   "prctl(PR_SET_PTRACER)         ", test_prctl_ptracer,           1);
#ifdef PR_SET_MDWE
  total++; passed += run_test("prctl_mdwe",  "prctl(PR_SET_MDWE)            ", test_prctl_mdwe,              1);
#endif
  total++; passed += run_test("unshare",     "unshare(CLONE_NEWUSER)        ", test_unshare_userns,          1);
  total++; passed += run_test("setns",       "setns()                       ", test_setns,                   1);
  total++; passed += run_test("mount",       "mount()                       ", test_mount,                   1);
  total++; passed += run_test("reboot",      "reboot()                      ", test_reboot,                  1);
  total++; passed += run_test("keyctl",      "keyctl()                      ", test_keyctl,                  1);
  total++; passed += run_test("aio_setup",   "io_setup() (legacy AIO kapısı) ", test_io_setup,                1);
  /* K-02 FIX: ana akım ağ aileleri — stage 2'den itibaren KILL beklenir */
  total++; passed += run_test("tcp_v4",      "socket(AF_INET, SOCK_STREAM)  ", test_socket_inet_stream,      1);
  total++; passed += run_test("udp_v4",      "socket(AF_INET, SOCK_DGRAM)   ", test_socket_inet_dgram,       1);
#ifdef AF_INET6
  total++; passed += run_test("tcp_v6",      "socket(AF_INET6, SOCK_STREAM) ", test_socket_inet6_stream,     1);
#endif
#ifdef AF_NETLINK
  total++; passed += run_test("netlink",     "socket(AF_NETLINK, SOCK_RAW)  ", test_socket_netlink,          1);
#endif
  /* W^X FIX: exec'li bellek ailesi — stage 2'den itibaren KILL beklenir */
  total++; passed += run_test("mprot_exec",  "mprotect(PROT_EXEC)           ", test_mprotect_exec,           1);
  total++; passed += run_test("mmap_exec",   "mmap(PROT_EXEC)               ", test_mmap_exec,               1);
  total++; passed += run_test("shmat_exec",  "shmat(SHM_EXEC)               ", test_shmat_shm_exec,          1);
#ifdef SYS_pkey_mprotect
  total++; passed += run_test("pkey_mprot",  "pkey_mprotect()               ", test_pkey_mprotect,           1);
#endif
#ifdef SYS_uselib
  total++; passed += run_test("uselib",      "uselib()                      ", test_uselib,                  1);
#endif
  /* 32-bit ABI (mimari allowlist): i386 int 0x80 + x32 → SIGSYS beklenir */
  total++; passed += run_test("int80_gp",    "i386 int80 getpid             ", test_i386_int80_getpid,       1);
  total++; passed += run_test("int80_sock",  "i386 int80 socket(AF_INET)    ", test_i386_int80_socket_inet,  1);
  total++; passed += run_test("int80_exec",  "i386 int80 execve             ", test_i386_int80_execve,       1);
  total++; passed += run_test("x32_gp",      "x32 getpid (0x40000027)       ", test_x32_getpid,              1);
  total++; passed += run_test("x32_sock",    "x32 socket(AF_INET)           ", test_x32_socket_inet,         1);
  total++; passed += run_test("x32_exec",    "x32 execve (0x40000208)       ", test_x32_execve,              1);

  /* Serbest olması gerekenler */
  total++; passed += run_test("clone_thr",  "clone(CLONE_THREAD)           ", test_clone_thread,            0);
  total++; passed += run_test("clone_glibc","clone(glibc pthread-benzeri)  ", test_clone_glibc_like,        0);
  total++; passed += run_test("clone3",     "clone3 → ENOSYS (fallback)    ", test_clone3_enosys,           0);
  total++; passed += run_test("pthread",    "pthread_create                ", test_pthread_create,          0);
  total++; passed += run_test("af_unix",    "socket(AF_UNIX, SOCK_STREAM)  ", test_socket_unix_allow,       0);
  total++; passed += run_test("prctl_nnp",  "prctl(PR_SET_NO_NEW_PRIVS)    ", test_prctl_nnp_allow,         0);
  total++; passed += run_test("mprot_rw",   "mprotect(EXEC'suz)            ", test_mprotect_noexec_allow,   0);

  printf("\nSonuç: %d/%d test başarılı\n", passed, total);
  return (passed == total) ? 0 : 1;
}
