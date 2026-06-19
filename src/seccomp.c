/* ================================================================
 * seccomp.c — Seccomp Blacklist Policy (Üç Aşamalı)
 *
 * noxtor-cli'nin kullanmadığı tehlikeli syscall'ları engeller.
 *
 * Aşama 1 (key_derive sonrası): 120s Tor bootstrap penceresini korur.
 *   process_vm_readv, ptrace, io_uring, userfaultfd, perf_event_open
 *   Bu kurallar kalıcıdır — stage 2 ile kaldırılamaz (seccomp-bpf additive).
 *
 * Aşama 2 (Tor HS sonrası): Tam blacklist + raw socket engelleme.
 *   fork, execve, mount, reboot vs. — Tor artık fork/execve kullanmaz.
 *   AF_PACKET/SOCK_RAW raw socket'lar engellenir.
 *
 * Aşama 3 (Event loop başı): Sıfır ağ sızıntısı garantisi.
 *   clone tamamen yasak (tek thread), AF_INET/AF_INET6 tüm tipler,
 *   AF_NETLINK, symlink, link, chmod, chown.
 *   Tüm iletişim AF_UNIX üzerinden (Tor control, SOCKS, peer).
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
#include <stdint.h>
#include <sys/socket.h>
#include <sys/prctl.h>

/* ── Blacklist tablosu ── */
#define KILL(ctx, name) \
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(name), 0)

static int add_socket_domain_rule(scmp_filter_ctx ctx, uint64_t domain, const char *name) {
  int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1,
                            SCMP_A0(SCMP_CMP_EQ, domain));
  if (rc == 0 || rc == -EDOM)
    return rc == 0 ? 0 : 1;

  NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi (rc=%d)", name, rc);
  return -1;
}

static int add_socket_raw_rule(scmp_filter_ctx ctx, uint64_t domain, const char *name) {
  int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 2,
                            SCMP_A0(SCMP_CMP_EQ, domain),
                            SCMP_A1(SCMP_CMP_MASKED_EQ,
                                    (uint64_t)SOCK_RAW, (uint64_t)SOCK_RAW));
  if (rc == 0 || rc == -EDOM)
    return rc == 0 ? 0 : 1;

  NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi (rc=%d)", name, rc);
  return -1;
}

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

  /* ═══ Stage 3 — Event loop başı: Sıfır ağ sızıntısı garantisi ═══ */

  /* Filesystem manipulation — init'ten sonra değişiklik gerekmez */
  { .num = SCMP_SYS(symlink),           .name = "symlink",           .stage = 3 },
  { .num = SCMP_SYS(symlinkat),         .name = "symlinkat",         .stage = 3 },
  { .num = SCMP_SYS(link),              .name = "link",              .stage = 3 },
  { .num = SCMP_SYS(linkat),            .name = "linkat",            .stage = 3 },
  { .num = SCMP_SYS(chmod),             .name = "chmod",             .stage = 3 },
  { .num = SCMP_SYS(fchmod),            .name = "fchmod",            .stage = 3 },
  { .num = SCMP_SYS(fchmodat),          .name = "fchmodat",          .stage = 3 },
  { .num = SCMP_SYS(chown),             .name = "chown",             .stage = 3 },
  { .num = SCMP_SYS(fchown),            .name = "fchown",            .stage = 3 },
  { .num = SCMP_SYS(fchownat),          .name = "fchownat",          .stage = 3 },

  /* open/openat/creat — Landlock ile path-based filtering desteklenmiyorsa
   * fallback olarak tamamen yasaklanır.
   * Landlock aktifse bu kurallar ATLANIR (Landlock zaten kısıtlıyor). */
  { .num = SCMP_SYS(open),              .name = "open",              .stage = 3 },
  { .num = SCMP_SYS(openat),            .name = "openat",            .stage = 3 },
  { .num = SCMP_SYS(creat),             .name = "creat",             .stage = 3 },
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

  /* ── 32-bit compat modunu tamamen devre dışı bırak ────────────────
   * x86_64 process'lerde i386 compat modu farklı syscall numaraları
   * kullanır (execve: 59→11, clone: 56→120, socket: 41→102).
   * Filtre sadece x86_64 numaralarını engeller → 32-bit bypass mümkün.
   * Bu uygulama 64-bit → i386 support gereksiz.
   *
   * Yöntem: Filtreyi TÜM mimarilere senkronize et (TSYNC).
   * Bu sayede i386/x32 compat modu da aynı filtreye tabi olur.
   * Tek alternatif: seccomp_arch_remove + her mimari için tek tek KILL. */
  {
    int rc_tsync = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
    if (rc_tsync < 0) {
      /* TSYNC desteklenmiyorsa (eski kernel) → fallback: i386'u tamamen kaldır */
      NOX_WARN(LOG_MOD_MAIN, "seccomp: TSYNC desteklenmiyor (rc=%d), "
               "32-bit fallback deneniyor", rc_tsync);
      int rc_rem = seccomp_arch_remove(ctx, SCMP_ARCH_X86);
      if (rc_rem < 0 && rc_rem != -EEXIST) {
        NOX_ERROR(LOG_MOD_MAIN, "seccomp: 32-bit arch kaldırılamadı (rc=%d)",
                  rc_rem);
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
    }
  }

  size_t n_blocked = 0;
  size_t n_custom_blocked = 0;
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

    /* H-2 FIX: Tek kural — clone sadece CLONE_THREAD ile izin ver.
     * x86_64 clone(flags, newsp, ptid, ctid, tls):
     *   SCMP_A0 = flags (CLONE_THREAD burada)
     *   SCMP_A2 = ptid (eski hata: wrong argument index)
     * CLONE_THREAD bit'i set ise → izin ver (pthread_create çalışsın).
     * CLONE_THREAD bit'i set değilse → KILL (fork/vfork engellenir). */
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 1,
          SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0)) != 0) {
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
    if (rc_clone3 == 0)
      n_custom_blocked++;

    /* ── prctl: option'a göre filtreleme ─────────────────────────
     * prctl() tamamen yasaklanmaz — seccomp_load() prctl(PR_SET_SECCOMP)
     * kullanarak stage 3 yükler. Tehlikeli option'lar engellenir.
     *
     * prctl(option, arg2, arg3, arg4, arg5):
     *   SCMP_A0 = option (ilk argüman)
     *
     * KILL: Tehlikeli option'lar (security bypass)
     * ALLOW: PR_SET_SECCOMP (seccomp_load), PR_SET_NO_NEW_PRIVS,
     *        PR_SET_NAME, PR_SET_TIMERSLACK (zararsız) */
    {
      static const struct { int op; const char *name; } blocked[] = {
        { PR_SET_DUMPABLE,              "prctl(PR_SET_DUMPABLE)" },
        { PR_SET_PTRACER,               "prctl(PR_SET_PTRACER)" },
        { PR_SET_TIMING,                "prctl(PR_SET_TIMING)" },
        { PR_SET_MM,                    "prctl(PR_SET_MM)" },
        { PR_SET_TSC,                   "prctl(PR_SET_TSC)" },
        { PR_SET_SECUREBITS,            "prctl(PR_SET_SECUREBITS)" },
        { PR_SET_SYSCALL_USER_DISPATCH, "prctl(PR_SET_SYSCALL_USER_DISPATCH)" },
        { PR_SET_VMA,                   "prctl(PR_SET_VMA)" },
        { PR_SET_MDWE,                  "prctl(PR_SET_MDWE)" },
      };
      for (size_t i = 0; i < sizeof(blocked)/sizeof(blocked[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 1,
                                  SCMP_A0(SCMP_CMP_EQ, (uint64_t)blocked[i].op));
        if (rc != 0 && rc != -EDOM) {
          NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi", blocked[i].name);
          seccomp_release(ctx);
          return NOX_ERR_CRYPTO;
        }
        if (rc == 0)
          n_custom_blocked++;
      }
    }

    /* Raw socket blocking — CAP_NET_RAW drop'a ek savunma katmanı.
     * AF_PACKET (Layer 2) ve AF_INET/AF_INET6 SOCK_RAW (IP raw)
     * stage 2'den sonra asla kullanılmaz. AF_UNIX ve AF_INET SOCK_STREAM
     * (Tor control/SOCKS/listener) serbest kalır. */
#ifdef AF_PACKET
    {
      int rc = add_socket_domain_rule(ctx, AF_PACKET, "socket(AF_PACKET)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif

#ifdef AF_INET
    {
      int rc = add_socket_raw_rule(ctx, AF_INET, "socket(AF_INET, SOCK_RAW)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif

#ifdef AF_INET6
    {
      int rc = add_socket_raw_rule(ctx, AF_INET6, "socket(AF_INET6, SOCK_RAW)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif
  }

  /* ── Stage 3: Event loop başı — Sıfır ağ sızıntısı garantisi ──────
   * Tüm mevcut bağlantılar AF_UNIX (Tor control, SOCKS, peer).
   * Event loop tek thread — clone tamamen yasak.
   * TCP/UDP/NETLINK socket oluşturulamaz.
   * ─────────────────────────────────────────────────────────────── */
  if (stage >= 3) {
    /* clone tamamen yasak — event loop tek thread, thread gerekmez */
    int rc_clone = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
    if (rc_clone != 0 && rc_clone != -EDOM) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: stage 3 clone kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
    if (rc_clone == 0)
      n_custom_blocked++;

    /* socket(AF_INET/AF_INET6) tüm tipler — TCP ve UDP tamamen yasak */
    {
      static const struct { int domain; const char *name; } blocked[] = {
#ifdef AF_INET
        { AF_INET,  "socket(AF_INET)" },
#endif
#ifdef AF_INET6
        { AF_INET6, "socket(AF_INET6)" },
#endif
      };
      for (size_t i = 0; i < sizeof(blocked)/sizeof(blocked[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 1,
                                  SCMP_A0(SCMP_CMP_EQ, (uint64_t)blocked[i].domain));
        if (rc != 0 && rc != -EDOM) {
          NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi", blocked[i].name);
          seccomp_release(ctx);
          return NOX_ERR_CRYPTO;
        }
        if (rc == 0)
          n_custom_blocked++;
      }
    }

    /* socket(AF_NETLINK) — kernel network config iletişim */
#ifdef AF_NETLINK
    {
      int rc = add_socket_domain_rule(ctx, AF_NETLINK, "socket(AF_NETLINK)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif
  }

  int rc = seccomp_load(ctx);
  seccomp_release(ctx);

  if (rc < 0) {
    NOX_ERROR(LOG_MOD_MAIN, "seccomp: filter yüklenemedi (rc=%d)", rc);
    return NOX_ERR_CRYPTO;
  }

  NOX_INFO(LOG_MOD_MAIN, "seccomp: stage %d yüklendi (%zu syscall → SIGSYS)",
           stage, n_blocked + n_custom_blocked);
  return NOX_OK;
}
