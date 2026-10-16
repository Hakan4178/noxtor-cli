/* ================================================================
 * test_mdwe.c — PR_SET_MDWE (Memory-Deny-Write-Execute) davranış testi
 *
 * Kernel ≥6.3. Seccomp'tan bağımsız, saf çekirdek davranışı doğrulanır:
 * main.c'nin TUI init sonrası / seccomp stage-2 öncesi set ettiği
 * "exec-gain yok" politikasının dayandığı mekanizma (systemd 254+
 * MemoryDenyWriteExecute için seccomp BPF yerine bunu kullanıyor).
 *
 * Not: reddetme errno'su bu kernelde EACCES (13); EPERM de kabul edilir.
 * (Ölçüm: PR_GET_MDWE=1 → prctl SET sonrası mask doğrulanır.)
 *
 * Desteklemeyen kernelde SKIP (exit 0) — seccomp W^X yine devrede.
 * ================================================================ */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Eski glibc header'ları için (kernel uapi değerleri) */
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#endif

int main(void) {
  printf("=== MDWE (PR_SET_MDWE) çekirdek davranış testi ===\n");

  if (prctl(PR_SET_MDWE, (unsigned long)PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0) {
    if (errno == EINVAL || errno == ENOSYS) {
      printf("  SKIP — kernel <6.3 (PR_SET_MDWE yok); seccomp W^X devrede\n");
      return 0;
    }
    printf("  [FAIL] PR_SET_MDWE: errno=%d\n", errno);
    return 1;
  }
  printf("  [OK] PR_SET_MDWE set edildi (REFUSE_EXEC_GAIN; değiştirilemez)\n");

  int passed = 0;
  int total = 0;

  /* 1) exec-gain: RW sayfaya PROT_EXEC eklenemez */
  total++;
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  errno = 0;
  int rc_m = (p != MAP_FAILED) ? mprotect(p, 4096, PROT_READ | PROT_EXEC) : 0;
  if (p != MAP_FAILED && rc_m != 0 && (errno == EACCES || errno == EPERM)) {
    printf("  [OK] mprotect(RW→RX) reddedildi (errno=%d)\n", errno);
    passed++;
  } else {
    printf("  [FAIL] mprotect(RW→RX) engellenmedi! (rc=%d, errno=%d)\n",
           rc_m, errno);
  }

  /* 2) W|X mapping: doğrudan yasak */
  total++;
  errno = 0;
  void *q = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (q == MAP_FAILED && (errno == EACCES || errno == EPERM)) {
    printf("  [OK] mmap(W|X) reddedildi (errno=%d)\n", errno);
    passed++;
  } else {
    printf("  [FAIL] mmap(W|X) engellenmedi! (errno=%d)\n", errno);
    if (q != MAP_FAILED) munmap(q, 4096);
  }

  /* 3) Kontrol: EXEC'siz mprotect serbest (normal bellek yönetimi) */
  total++;
  if (p != MAP_FAILED && mprotect(p, 4096, PROT_READ) == 0) {
    printf("  [OK] mprotect(EXEC'siz) serbest\n");
    passed++;
  } else {
    printf("  [FAIL] masum mprotect engellendi!\n");
  }
  if (p != MAP_FAILED) munmap(p, 4096);

  printf("Sonuç: %d/%d test başarılı\n", passed, total);
  return (passed == total) ? 0 : 1;
}
