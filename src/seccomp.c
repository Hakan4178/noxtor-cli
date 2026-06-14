/* ================================================================
 * seccomp.c — Seccomp Blacklist Policy (İki Aşamalı)
 *
 * noxtor-cli'nin kullanmadığı tehlikeli syscall'ları engeller.
 *
 * Aşama 1 (key_derive sonrası): 120s Tor bootstrap penceresini korur.
 *   process_vm_readv, ptrace, io_uring, userfaultfd, perf_event_open
 *   Bu kurallar kalıcıdır — stage 2 ile kaldırılamaz (seccomp-bpf additive).
 *
 * Aşama 2 (Tor HS sonrası): Tam blacklist.
 *   fork, execve, mount, reboot vs. — Tor artık fork/execve kullanmaz.
 *
 * Mod: SCMP_ACT_KILL — engellenen syscall çağrılırsa process SIGSYS ile öldürülür.
 *
 * Yeni syscall eklemek için:
 *   1. strace -c ./noxtor-cli 2>&1 | sort -rnk1
 *   2. Tehlikeli olanı blacklist[]'e ekle (stage belirle)
 * ================================================================ */
#include "common.h"
#include "seccomp_policy.h"

#include <errno.h>
#include <seccomp.h>

/* ── Blacklist tablosu ── */
#define KILL(ctx, name) \
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(name), 0)

static const struct {
  int num;
  const char *name;
  int stage;   /* 1 = hemen (key_derive sonrası), 2 = tor_spawn sonrası */
} blacklist[] = {
  /* ═══ Stage 1 — 120s Tor bootstrap pencere koruması ═══ */

  /* Process memory access — saldırgan /proc/self/mem veya process_vm_readv ile
   * arena anahtarlarını okuyamaz */
  { .num = SCMP_SYS(process_vm_readv),  .name = "process_vm_readv",  .stage = 1 },
  { .num = SCMP_SYS(process_vm_writev), .name = "process_vm_writev", .stage = 1 },

  /* ptrace — production'da LSan ile uyumsuz, saldırgan attach edemez */
#ifdef NDEBUG
  { .num = SCMP_SYS(ptrace),            .name = "ptrace",            .stage = 1 },
#endif

  /* io_uring — çok sayıda kernel CVE, program kullanmıyor */
  { .num = SCMP_SYS(io_uring_setup),    .name = "io_uring_setup",    .stage = 1 },
  { .num = SCMP_SYS(io_uring_enter),    .name = "io_uring_enter",    .stage = 1 },
  { .num = SCMP_SYS(io_uring_register), .name = "io_uring_register", .stage = 1 },

  /* Memory management bypass */
  { .num = SCMP_SYS(userfaultfd),       .name = "userfaultfd",       .stage = 1 },

  /* Profiling / Timing attack koruması */
  { .num = SCMP_SYS(perf_event_open),   .name = "perf_event_open",   .stage = 1 },

  /* ═══ Stage 2 — Tor spawn sonrası (fork/execve artık gerekmez) ═══ */

  /* Security bypass — PR_SET_DUMPABLE=0 arena_init'de ayarlandı,
   * Tor bootstrap sırasında prctl gerekebilir (PR_SET_NAME vb.).
   * Stage 2'de engellenir. */
  { .num = SCMP_SYS(prctl),             .name = "prctl",             .stage = 2 },

  /* Process manipulation */
  { .num = SCMP_SYS(execve),            .name = "execve",            .stage = 2 },
  { .num = SCMP_SYS(execveat),          .name = "execveat",          .stage = 2 },
  { .num = SCMP_SYS(fork),              .name = "fork",              .stage = 2 },
  { .num = SCMP_SYS(vfork),             .name = "vfork",             .stage = 2 },
  { .num = SCMP_SYS(pidfd_open),        .name = "pidfd_open",        .stage = 2 },
  { .num = SCMP_SYS(process_madvise),   .name = "process_madvise",   .stage = 2 },
  { .num = SCMP_SYS(kcmp),             .name = "kcmp",              .stage = 2 },

  /* Filesystem */
  { .num = SCMP_SYS(mount),             .name = "mount",             .stage = 2 },
  { .num = SCMP_SYS(umount2),           .name = "umount2",           .stage = 2 },
  { .num = SCMP_SYS(pivot_root),        .name = "pivot_root",        .stage = 2 },
  { .num = SCMP_SYS(open_by_handle_at), .name = "open_by_handle_at", .stage = 2 },
  { .num = SCMP_SYS(openat2),           .name = "openat2",           .stage = 2 },

  /* System */
  { .num = SCMP_SYS(reboot),            .name = "reboot",            .stage = 2 },
  { .num = SCMP_SYS(sethostname),       .name = "sethostname",       .stage = 2 },
  { .num = SCMP_SYS(setdomainname),     .name = "setdomainname",     .stage = 2 },
  { .num = SCMP_SYS(kexec_load),        .name = "kexec_load",        .stage = 2 },

  /* Kernel module */
  { .num = SCMP_SYS(init_module),       .name = "init_module",       .stage = 2 },
  { .num = SCMP_SYS(delete_module),     .name = "delete_module",     .stage = 2 },

  /* Namespace */
  { .num = SCMP_SYS(unshare),           .name = "unshare",           .stage = 2 },
  { .num = SCMP_SYS(setns),             .name = "setns",             .stage = 2 },

  /* Swap */
  { .num = SCMP_SYS(swapon),            .name = "swapon",            .stage = 2 },
  { .num = SCMP_SYS(swapoff),           .name = "swapoff",           .stage = 2 },

  /* Kernel key management */
  { .num = SCMP_SYS(request_key),       .name = "request_key",       .stage = 2 },
  { .num = SCMP_SYS(add_key),           .name = "add_key",           .stage = 2 },
  { .num = SCMP_SYS(keyctl),            .name = "keyctl",            .stage = 2 },

  /* Other */
  { .num = SCMP_SYS(nfsservctl),        .name = "nfsservctl",        .stage = 2 },
  { .num = SCMP_SYS(quotactl),          .name = "quotactl",          .stage = 2 },
};

/* ================================================================
 * seccomp_policy_load
 * Blacklist filter'ı oluştur, yükle ve userspace context'i serbest bırak.
 *
 * @stage: 1 = sadece stage 1 kuralları (120s pencere koruması)
 *         2 = tüm kurallar (stage 1 + stage 2)
 *
 * Seccomp-bpf additive'tir: stage 1 kuralları kalıcıdır,
 * stage 2 sadece yeni ekler. Hiçbir kural kaldırılamaz.
 *
 * Return: NOX_OK veya NOX_ERR_CRYPTO (filter yükleme hatası).
 * ================================================================ */
nox_err_t seccomp_policy_load(int stage) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx)
    return NOX_ERR_CRYPTO;

  size_t n_blocked = 0;
  for (size_t i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
    if (blacklist[i].stage > stage)
      continue;  /* bu stage henüz aktif değil */
    int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, blacklist[i].num, 0);
    if (rc == 0) {
      n_blocked++;
    } else if (rc != -EDOM) {
      /* EDOM: syscall bu arch'ta yok — kabul edilebilir.
       * Diğer hatalar: kural eklenemedi — güvenlik açığı. */
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi (rc=%d)",
                blacklist[i].name, rc);
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
  }

  /* ── clone/clone3 Argument Filtering (sadece stage 2) ────────────
   * pthread_create clone(flags=CLONE_VM|CLONE_THREAD|...) çağırır.
   * CLONE_THREAD bit'i set ise → izin ver (pthread_create çalışsın).
   * CLONE_THREAD bit'i set değilse → KILL (fork, vfork engellenir).
   * clone3 tamamen yasak — glibc hâlâ clone kullanıyor.
   *
   * Stage 1'de clone'a dokunmuyoruz — tor_spawn() fork()+execv() kullanıyor.
   * ─────────────────────────────────────────────────────────────── */
  if (stage >= 2) {
    #define CLONE_THREAD 0x00100000

    /* H-2 FIX: Tek kural — clone sadece CLONE_THREAD ile izin ver. */
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 1,
          SCMP_A2(SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0)) != 0) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: clone kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }

    /* clone3: flags 1. argümanın (clone_args*) offset 16'sında.
     * Seccomp argument komutları pointer arithmetic desteklemez →
     * clone3 tamamen yasak. */
    int rc_clone3 = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone3), 0);
    if (rc_clone3 != 0 && rc_clone3 != -EDOM) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: clone3 kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
  }

  int rc = seccomp_load(ctx);
  seccomp_release(ctx);

  if (rc < 0) {
    NOX_ERROR(LOG_MOD_MAIN, "seccomp: filter yüklenemedi (rc=%d)", rc);
    return NOX_ERR_CRYPTO;
  }

  NOX_INFO(LOG_MOD_MAIN, "seccomp: stage %d yüklendi (%zu syscall → SIGSYS)",
           stage, n_blocked);
  return NOX_OK;
}
