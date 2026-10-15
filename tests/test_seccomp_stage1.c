/* ================================================================
 * test_seccomp_stage1.c — Stage 1 filtre testi (GERÇEK politika)
 *
 * src/seccomp.c'deki seccomp_policy_load(1) yüklenir; politika kopyası
 * DEĞİL. (Ders: kopya politika testi, kaynaktaki regresyonu gizler —
 * K-01 tam bu yüzden stage testleri yeşilken canlı kalmıştı.)
 *
 * Stage 1 = key_derive sonrası 120 sn Tor bootstrap penceresi:
 *   Engellenenler : process_vm_readv/writev, io_uring*, userfaultfd,
 *                   perf_event_open, bpf, kexec_file_load, finit_module,
 *                   personality → SIGSYS
 *   Serbest       : normal syscall'lar (getpid/write/mmap RW),
 *                   socket(AF_UNIX), fork (tor_spawn penceresi)
 *   ptrace        : yalnız release (NDEBUG) build'de engelli
 *
 * Her test ayrı child process'te çalışır.
 *
 * Build:
 *   make test                    (src .test.o'ları ile link edilir)
 *
 * Run:
 *   ./tests/test_seccomp_stage1
 * ================================================================ */
#include "common.h"
#include "seccomp_policy.h"

#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Stage 1 filtresini child process'e uygula — gerçek politika */
static int apply_stage1(void) {
  if (seccomp_policy_load(1) != NOX_OK) return -1;
  return 0;
}

/* ── Test fonksiyonları ── */

static void test_process_vm_readv(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_process_vm_readv, getpid(), NULL, 0UL, NULL, 0UL, 0UL);
  _exit(1);  /* buraya ulaşılırsa filtre çalışmadı */
}

static void test_process_vm_writev(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_process_vm_writev, getpid(), NULL, 0UL, NULL, 0UL, 0UL);
  _exit(1);
}

static void test_io_uring_setup(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_io_uring_setup, 0U, NULL);
  _exit(1);
}

static void test_io_uring_enter(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_io_uring_enter, 0, 0, 0, 0, 0, NULL);
  _exit(1);
}

static void test_io_uring_register(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_io_uring_register, 0U, 0U, NULL, 0U);
  _exit(1);
}

static void test_userfaultfd(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_userfaultfd, 0);
  _exit(1);
}

static void test_perf_event_open(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_perf_event_open, NULL, 0, -1, -1, 0UL);
  _exit(1);
}

static void test_bpf(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_bpf, 0, NULL, 0U);
  _exit(1);
}

static void test_kexec_file_load(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_kexec_file_load, -1, -1, 0UL, NULL, 0UL);
  _exit(1);
}

static void test_finit_module(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_finit_module, -1, NULL, 0U);
  _exit(1);
}

static void test_personality(void) {
  if (apply_stage1() < 0) _exit(2);
  syscall(SYS_personality, 0xffffffffUL);
  _exit(1);
}

#ifdef NDEBUG
static void test_ptrace(void) {
  if (apply_stage1() < 0) _exit(2);
  /* ptrace yalnız release build'de blacklist'e girer */
  syscall(SYS_ptrace, 0L, 0L, 0UL, 0UL);
  _exit(1);
}
#endif

/* ── Serbest kalması gerekenler ── */

static void test_safe_syscalls(void) {
  if (apply_stage1() < 0) _exit(2);
  /* getpid + write zarar görmemeli (TUI/init akışı) */
  if (getpid() <= 0) _exit(1);
  if (write(STDOUT_FILENO, "", 0) < 0) _exit(1);
  _exit(0);
}

static void test_mmap_rw_allow(void) {
  if (apply_stage1() < 0) _exit(2);
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) _exit(1);
  munmap(p, 4096);
  _exit(0);
}

static void test_af_unix_allow(void) {
  if (apply_stage1() < 0) _exit(2);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) _exit(1);
  close(fd);
  _exit(0);
}

static void test_fork_allow(void) {
  if (apply_stage1() < 0) _exit(2);
  /* Stage 1'de fork serbest — tor_spawn() penceresi */
  pid_t p = fork();
  if (p == 0) _exit(0);
  if (p > 0) {
    int st = 0;
    waitpid(p, &st, 0);
    _exit(0);
  }
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
  printf("=== Seccomp Stage 1 Testi (gerçek politika) ===\n");
  printf("Bootstrap penceresi: memory/ring/perf/kernel syscall engeli\n");
  printf("Her test ayrı child process'te çalışır\n\n");

  int passed = 0;
  int total = 0;

  /* Engellenmesi gerekenler (SIGSYS beklenir) */
  total++; passed += run_test("pvm_readv",   "process_vm_readv              ", test_process_vm_readv,   1);
  total++; passed += run_test("pvm_writev",  "process_vm_writev             ", test_process_vm_writev,  1);
  total++; passed += run_test("iou_setup",   "io_uring_setup                ", test_io_uring_setup,     1);
  total++; passed += run_test("iou_enter",   "io_uring_enter                ", test_io_uring_enter,     1);
  total++; passed += run_test("iou_reg",     "io_uring_register             ", test_io_uring_register,  1);
  total++; passed += run_test("uffd",        "userfaultfd                   ", test_userfaultfd,        1);
  total++; passed += run_test("perf",        "perf_event_open               ", test_perf_event_open,    1);
  total++; passed += run_test("bpf",         "bpf                           ", test_bpf,                1);
  total++; passed += run_test("kexec_file",  "kexec_file_load               ", test_kexec_file_load,    1);
  total++; passed += run_test("finit_mod",   "finit_module                  ", test_finit_module,       1);
  total++; passed += run_test("personality", "personality                   ", test_personality,        1);
#ifdef NDEBUG
  total++; passed += run_test("ptrace",      "ptrace (release)              ", test_ptrace,             1);
#endif

  /* Serbest olması gerekenler */
  total++; passed += run_test("safe",      "getpid/write                  ", test_safe_syscalls,    0);
  total++; passed += run_test("mmap_rw",   "mmap(PROT_READ|WRITE)         ", test_mmap_rw_allow,    0);
  total++; passed += run_test("af_unix",   "socket(AF_UNIX)               ", test_af_unix_allow,    0);
  total++; passed += run_test("fork",      "fork (tor_spawn penceresi)    ", test_fork_allow,       0);

  printf("\nSonuç: %d/%d test başarılı\n", passed, total);
  return (passed == total) ? 0 : 1;
}
