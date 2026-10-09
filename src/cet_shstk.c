/* SPDX-License-Identifier: GPL-3.0-or-later
 * cet_shstk.c — CET-SS kilidi + fork-CP self-test (init 4b)
 *
 * Referans:
 *   kernel Documentation/arch/x86/shstk.rst:
 *     "On exec, shadow stack features are disabled by the kernel. At
 *      which point, userspace can choose to re-enable, or lock them."
 *      — shstk'yi loader (glibc ld.so) açar; ELF notu (-Wl,-z,shstk)
 *      tek başına yetmez. glibc 2.44 default: kapalı (dl-cet.c USABLE
 *      kapısı); hwcaps tunable ile açılır.
 *   arch_prctl(ARCH_SHSTK_LOCK, mask):
 *     "Lock in features at their current enabled or disabled status...
 *      The mask is ORed with the existing value." — LOCK mevcut DURUMU
 *     dondurur: shstk kapalıyken atılırsa korumayı OFF'a kilitler ve
 *     geri alınamaz. Bu yüzden LOCK yalnızca STATUS=aktifken atılır.
 *     Empirik (lock_states, glibc 2.44 / kernel 7.2.9): pasif, aktif-
 *     kilitsiz, aktif-kilitli — üç durumda da LOCK rc=0 (idempotent).
 *   /proc/self/status (shstk.rst "Proc Status"):
 *     x86_Thread_features:        → gerçekten ENABLE edilenler = AKTİFLİK
 *     x86_Thread_features_locked: → durumu DONDURAN kilit mask'ı
 *     locked satırındaki shstk, özelliğin AÇIK olduğu anlamına GELMEZ;
 *     eski 8c bu iki satırı karıştırdığı için shstk kapalıyken bile
 *     "AKTİF ve KİLİTLİ" raporluyordu (yanlış-PASS).
 *   SEGV_CPERR (asm-generic/siginfo.h, = 10): sayfa-dışı olmayan #CP'nin
 *     si_code'u; si_addr=NULL. "Plain SIGSEGV ≠ PASS" ayrımı bununla
 *     yapılır.
 *
 * ASSUMPTION:
 *   - shstk ancak process başından itibaren aktifse anlamlıdır.
 *     Runtime'da ARCH_SHSTK_ENABLE ile açmak mevcut çağrı zincirini
 *     bozar: ilk ret, shadow stack altında SEGV_ACCERR ile ölür
 *     (gözlemlendi: syscall+37, shstk VMA tabanı). Bu yüzden enable
 *     edilmez, sadece STATUS ile okunur.
 *   - Pasif durumda LOCK asla çağrılmaz (yukarıdaki OFF kilidi tuzağı).
 *
 * INVARIANT:
 *   - Self-test, main init sırasının 4b adımıdır: PIN'den ÖNCE fork()
 *     edilir; child key materyali göremez.
 *   - Test penceresinde SIGCHLD blokludur: adım 2'deki sigchld_handler
 *     waitpid(-1, WNOHANG) ile child'ı ezip ECHILD yarışı yaratmasın.
 *   - Child yalnız async-signal-safe çağrı kullanır (_exit); atexit
 *     handler'ları (terminal restore vb.) çağırmaz.
 *
 * Child exit protokolü (parent WIFEXITED üzerinden okur):
 *   100 = enforcement yok — trigger temiz döndü (CET-OFF yolu)
 *   101 = #CP → SIGSEGV, si_code == SEGV_CPERR  → PASS
 *   102 = SIGSEGV ama si_code != SEGV_CPERR     → başka fault (bozuk)
 *   104 = sigaction kurulamadı
 *   WIFSIGNALED = handler'ı görmeden öldü → BROKEN
 */

#include "cet_shstk.h"

#include "common.h" /* _GNU_SOURCE — signal.h/sigaction için */

#include "asm_utils.h"

#include <asm/prctl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SEGV_CPERR
#define SEGV_CPERR 10 /* asm-generic/siginfo.h — kernel 6.6+ */
#endif

/* ------------------------------------------------------------------
 * nox_cet_trigger — dönüş adresi uydurması (rdx varyantı)
 *
 * Normal stack'teki RA, kendisiyle değiştirilir; shadow stack'teki RA
 * olduğu gibi kalır:
 *   CET ON  : ret → .Lfake ≠ shstk RA → #CP → SIGSEGV(SEGV_CPERR)
 *   CET OFF : ret → .Lfake → xorl/pushq/ret → caller'a temiz dönüş
 * naked: compiler prologue yok; basic asm (operandsuz) → tek %.
 * ------------------------------------------------------------------ */
__attribute__((naked, noinline, noipa))
static void nox_cet_trigger(void)
{
  __asm__ volatile(
      "endbr64\n\t"
      "movq (%rsp), %rdx\n\t"
      "leaq .Lfake(%rip), %rcx\n\t"
      "movq %rcx, (%rsp)\n\t"
      "ret\n\t"
      ".Lfake:\n\t"
      "xorl %eax, %eax\n\t"
      "pushq %rdx\n\t"
      "ret\n\t");
}

/* Child handler — async-signal-safe: yalnız _exit, ucontext'e dokunulmaz. */
static void cet_segv_handler(int sig, siginfo_t *si, void *uctx)
{
  (void)sig;
  (void)uctx;
  _exit(si->si_code == SEGV_CPERR ? 101 : 102);
}

/* /proc/self/status — AKTİFLİK ve KİLİT satırlarını ayrı ayrı okur.
 * Eski 8c tek noktada ("locked") shstk arayıp "AKTİF" diyordu. */
static int proc_ss_lines(int *active_seen, int *locked_seen)
{
  FILE *fp;
  char line[256];

  *active_seen = 0;
  *locked_seen = 0;

  fp = fopen("/proc/self/status", "r");
  if (fp == NULL)
    return -1;

  while (fgets(line, (int)sizeof(line), fp) != NULL) {
    if (strncmp(line, "x86_Thread_features:", 20) == 0) {
      if (strstr(line, "shstk") != NULL)
        *active_seen = 1;
    } else if (strncmp(line, "x86_Thread_features_locked:", 27) == 0) {
      if (strstr(line, "shstk") != NULL)
        *locked_seen = 1;
    }
  }
  fclose(fp);
  return 0;
}

cet_ss_state cet_ss_lock_and_verify(void)
{
  unsigned long st = 0;
  int active = 0;
  sigset_t block_set, saved_set;
  pid_t pid, r;
  int status;
  cet_ss_state live;

  /* 1) CPU yeteneği — yoksa kernel de boşa denemesin (capability-gated). */
  if (!cpu_has_shstk())
    return CET_SS_UNSUPPORTED;

  /* 2) Aktiflik = tek girdi (ARCH_SHSTK_STATUS). API yoksa (ENOTSUPP /
   *    EINVAL / ENOSYS) destek yok sayılır → WARN + devam. */
  if (syscall(SYS_arch_prctl, ARCH_SHSTK_STATUS, &st) != 0)
    return CET_SS_UNSUPPORTED;
  active = (st & ARCH_SHSTK_SHSTK) != 0;

  /* 3) Aktifse KİLİTLE + /proc'dan iki satırı birlikte doğrula.
   *    Pasifken LOCK çağrılmaz (kapalıyı kilitleme tuzağı — eski 8c). */
  if (active) {
    int active_seen, locked_seen;
    long rc_lock = syscall(SYS_arch_prctl, ARCH_SHSTK_LOCK,
                           ARCH_SHSTK_SHSTK | ARCH_SHSTK_WRSS);
    int lock_err = (rc_lock == 0) ? 0 : errno;

    /* rc=0: kilitlendi. EPERM: doc'a göre zaten kilitli — nihai kanıt
     * locked satırıdır. Diğer hatalar tutarsızlık: STATUS ve LOCK aynı
     * API ailesi (6.6 ile geldi), biri varsa öbürü de vardır. */
    if (lock_err != 0 && lock_err != EPERM)
      return CET_SS_BROKEN;

    if (proc_ss_lines(&active_seen, &locked_seen) != 0)
      return CET_SS_BROKEN;
    if (!active_seen || !locked_seen)
      return CET_SS_BROKEN; /* "aktif" iddiası ya da kilidi tutmadı */
  }

  /* 4) fork-CP self-test — SIGCHLD bloklu (INVARIANT). */
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &block_set, &saved_set) != 0)
    return CET_SS_BROKEN;

  pid = fork();
  if (pid < 0) {
    sigprocmask(SIG_SETMASK, &saved_set, NULL);
    return CET_SS_BROKEN;
  }

  if (pid == 0) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = cet_segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0)
      _exit(104);

    nox_cet_trigger(); /* CET-OFF: temiz dönüş — CET-ON: asla dönmez */
    _exit(100); /* buraya kadar geldiyse enforcement yok */
  }

  do {
    r = waitpid(pid, &status, 0);
  } while (r < 0 && errno == EINTR);

  if (sigprocmask(SIG_SETMASK, &saved_set, NULL) != 0)
    return CET_SS_BROKEN; /* maske geri gelmedi — SIGCHLD sekmelenmiş */

  if (r != pid || !WIFEXITED(status))
    return CET_SS_BROKEN; /* ya reapedemedik ya handler görmeden öldü */

  switch (WEXITSTATUS(status)) {
  case 101:
    live = CET_SS_ENFORCED;
    break;
  case 100:
    live = CET_SS_NOT_ENFORCED;
    break;
  default: /* 102 = CPERR olmayan SIGSEGV, 104 = sigaction */
    return CET_SS_BROKEN;
  }

  /* 5) Kesişim — her dönüş, o yolun KANITLARIYLA tutarlı olmalı:
   *    aktif + temiz dönüş → BROKEN (koruma iddiası tutmadı → sahte PASS)
   *    pasif  + #CP        → BROKEN (STATUS canlı kanıtla çelişiyor;
   *                           kilitleme bloğuna hiç girilmedi — "aktif+
   *                           kilitli" iddiası kurulamaz) */
  if (active && live == CET_SS_NOT_ENFORCED)
    return CET_SS_BROKEN;
  if (!active && live == CET_SS_ENFORCED)
    return CET_SS_BROKEN;

  return live;
}

const char *cet_ss_state_str(cet_ss_state st)
{
  switch (st) {
  case CET_SS_UNSUPPORTED:
    return "desteklenmiyor";
  case CET_SS_ENFORCED:
    return "aktif+kilitli+engellendi";
  case CET_SS_NOT_ENFORCED:
    return "pasif";
  case CET_SS_BROKEN:
    return "dogrulanamadi";
  default:
    return "?";
  }
}
