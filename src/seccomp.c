/* ================================================================
 * seccomp.c — Seccomp Blacklist Policy
 *
 * noxtor-cli'nin kullanmadığı tehlikeli syscall'ları engeller.
 * Tor bağlantısı + Hidden Service kurulduktan sonra bir kez çağrılır.
 *
 * Mod: SCMP_ACT_KILL — engellenen syscall çağrılırsa process SIGSYS ile öldürülür.
 * Neden blacklist? Gerekli syscall'lar strace ile tespit edildi.
 * Neden Tor sonrası? fork+execve Tor başlatmak için gerekli, sonrası ASLA gerekmez.
 *
 * Yeni syscall eklemek için:
 *   1. strace -c ./noxtor-cli 2>&1 | sort -rnk1
 *   2. Tehlikeli olanı blacklist_tablosu[]'na ekle
 * ================================================================ */
#include "common.h"
#include "seccomp_policy.h"

#include <seccomp.h>

/* ── Blacklist tablosu ── */
typedef struct {
  int (*filter)(scmp_filter_ctx ctx, unsigned int arch, int syscall);
  const char *name;
} seccomp_entry;

#define KILL(ctx, name) \
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(name), 0)

static const struct {
  int num;
  const char *name;
} blacklist[] = {
  /* Process manipulation — traced edilemez, clone/clone3 ile process oluşturma */
  { .num = SCMP_SYS(ptrace),            .name = "ptrace" },
  { .num = SCMP_SYS(execve),            .name = "execve" },
  { .num = SCMP_SYS(execveat),          .name = "execveat" },
  { .num = SCMP_SYS(fork),              .name = "fork" },
  { .num = SCMP_SYS(vfork),             .name = "vfork" },
  { .num = SCMP_SYS(clone3),            .name = "clone3" },
  { .num = SCMP_SYS(pidfd_open),        .name = "pidfd_open" },
  { .num = SCMP_SYS(process_madvise),   .name = "process_madvise" },
  { .num = SCMP_SYS(process_vm_readv),  .name = "process_vm_readv" },
  { .num = SCMP_SYS(process_vm_writev), .name = "process_vm_writev" },
  { .num = SCMP_SYS(kcmp),             .name = "kcmp" },

  /* Filesystem */
  { .num = SCMP_SYS(mount),             .name = "mount" },
  { .num = SCMP_SYS(umount2),           .name = "umount2" },
  { .num = SCMP_SYS(pivot_root),        .name = "pivot_root" },
  { .num = SCMP_SYS(open_by_handle_at), .name = "open_by_handle_at" },
  { .num = SCMP_SYS(openat2),           .name = "openat2" },

  /* System */
  { .num = SCMP_SYS(reboot),            .name = "reboot" },
  { .num = SCMP_SYS(sethostname),       .name = "sethostname" },
  { .num = SCMP_SYS(setdomainname),     .name = "setdomainname" },
  { .num = SCMP_SYS(kexec_load),        .name = "kexec_load" },

  /* Kernel module */
  { .num = SCMP_SYS(init_module),       .name = "init_module" },
  { .num = SCMP_SYS(delete_module),     .name = "delete_module" },

  /* Namespace */
  { .num = SCMP_SYS(unshare),           .name = "unshare" },
  { .num = SCMP_SYS(setns),             .name = "setns" },

  /* Swap */
  { .num = SCMP_SYS(swapon),            .name = "swapon" },
  { .num = SCMP_SYS(swapoff),           .name = "swapoff" },

  /* Memory management bypass */
  { .num = SCMP_SYS(userfaultfd),       .name = "userfaultfd" },

  /* Kernel key management */
  { .num = SCMP_SYS(request_key),       .name = "request_key" },
  { .num = SCMP_SYS(add_key),           .name = "add_key" },
  { .num = SCMP_SYS(keyctl),            .name = "keyctl" },

  /* Other */
  { .num = SCMP_SYS(nfsservctl),        .name = "nfsservctl" },
  { .num = SCMP_SYS(quotactl),          .name = "quotactl" },
};

/* ================================================================
 * seccomp_policy_load
 * Blacklist filter'ı oluştur, yükle ve userspace context'i serbest bırak.
 * Return: NOX_OK veya NOX_ERR_CRYPTO (filter yükleme hatası).
 * ================================================================ */
nox_err_t seccomp_policy_load(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx)
    return NOX_ERR_CRYPTO;

  size_t n_blocked = 0;
  for (size_t i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, blacklist[i].num, 0) == 0)
      n_blocked++;
  }

  int rc = seccomp_load(ctx);
  seccomp_release(ctx);

  if (rc < 0) {
    NOX_ERROR(LOG_MOD_MAIN, "seccomp: filter yüklenemedi (rc=%d)", rc);
    return NOX_ERR_CRYPTO;
  }

  NOX_INFO(LOG_MOD_MAIN, "seccomp: blacklist yüklendi (%zu syscall → SIGSYS)", n_blocked);
  return NOX_OK;
}
