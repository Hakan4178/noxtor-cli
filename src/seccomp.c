/* SPDX-License-Identifier: GPL-3.0-or-later
 * seccomp.c — Seccomp Blacklist Policy (Üç Aşamalı)
 *
 * noxtor-cli'nin kullanmadığı tehlikeli syscall'ları engeller.
 *
 * Aşama 1 (constructor, main öncesi — main.c seccomp_stage1_early):
 *   init + tor_spawn penceresini korur.
 *   process_vm_readv, ptrace, io_uring, userfaultfd, perf_event_open
 *   Bu kurallar kalıcıdır — stage 2 ile kaldırılamaz (seccomp-bpf additive).
 *
 * Aşama 2 (tor_spawn + TUI init sonrası; auth/bootstrap/listener/HS öncesi):
 *   fork, execve, mount, reboot vs. — tor_spawn() son fork/exec.
 *   Auth, bootstrap, listener ve HS bu koruma altında koşar.
 *   Yeni AF_PACKET/SOCK_RAW, AF_INET, AF_INET6 ve AF_NETLINK socket'leri
 *   stage-2'den itibaren kapalı — parent Tor ile yalnız AF_UNIX konuşur.
 *   (Tor çocuğu stage-1 filtresini miras alır, bu bloklardan etkilenmez.)
 *   W^X FIX: exec'li bellek ailesi de stage-2'den kapalı — mprotect/mmap
 *   PROT_EXEC maskeli, pkey_*, shm* (shmat SHM_EXEC dahil), uselib;
 *   çekirdek tamamlayıcısı PR_SET_MDWE main.c'de set edilir.
 *
 * Aşama 3 (event loop başı): socket yaratma yasağı genişler.
 *   clone tamamen yasak (tek thread), kalan egzotik aileler (XDP/ALG/VSOCK,
 *   BLUETOOTH/SMC/RDS/QIPCRTR), symlink, link, chmod, chown.
 *   Tüm iletişim AF_UNIX üzerinden (Tor control, SOCKS, peer).
 *
 * Kapsam notu: kurallar socket() YARATMAYI engeller; önceden açılmış
 * fd'lerin kullanımı (read/write/connect) ayrıca kısıtlanmaz. Tam liste
 * için blacklist[] + stage bloklarına bak. NO_SECCOMP=1 politikayı
 * derlemeden çıkarır (koruma yok).
 *
 * Mod: SCMP_ACT_KILL_PROCESS — engellenen syscall çağrılırsa TÜM process
 * SIGSYS ile öldürülür (KILL yalnızca ihlal eden thread'i öldürürdü).
 *
 * Yeni syscall eklemek için:
 *   1. strace -c ./noxtor-cli 2>&1 | sort -rnk1
 *   2. Tehlikeli olanı blacklist[]'e ekle (stage belirle)
 * ================================================================ */
#include "common.h"
#include "seccomp_policy.h"

#include <asm/prctl.h> /* ARCH_SHSTK_DISABLE/UNLOCK (CET-SS) */
#include <errno.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

/* K-03: glibc bazı AF sabitlerini taşımayabilir — kernel uapi değerleri */
#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#ifndef AF_RDS
#define AF_RDS 21
#endif
#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif
#ifndef AF_SMC
#define AF_SMC 43
#endif

/* ── Blacklist tablosu ── */
#define KILL(ctx, name) \
  seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(name), 0)

static int add_socket_domain_rule(scmp_filter_ctx ctx, uint64_t domain, const char *name) {
  int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socket), 1,
                            SCMP_A0(SCMP_CMP_EQ, domain));
  if (rc == 0 || rc == -EDOM)
    return rc == 0 ? 0 : 1;

  NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi (rc=%d)", name, rc);
  return -1;
}

static const struct {
  int num;
  const char *name;
  int stage;   /* 1 = constructor (main öncesi), 2 = tor_spawn sonrası,
                * 3 = event loop başı */
} blacklist[] = {
  /* ═══ Stage 1 — init + tor_spawn penceresi ═══ */

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

  /* Kernel/code injection — uygulama hiçbirini kullanmaz */
  { .num = SCMP_SYS(bpf),               .name = "bpf",               .stage = 1 },
  { .num = SCMP_SYS(kexec_file_load),   .name = "kexec_file_load",   .stage = 1 },
  { .num = SCMP_SYS(finit_module),      .name = "finit_module",      .stage = 1 },

  /* personality — exec domaini / ASLR kişiliğini değiştirme yüzeyi.
   * Doğrudan filtre bypass'ı değildir (i386/x32 syscall'ları badarch
   * ile zaten ölür) ama gereksizdir — defense-in-depth kapalı. */
  { .num = SCMP_SYS(personality),       .name = "personality",       .stage = 1 },

  /* ═══ Stage 2 — Tor spawn sonrası (fork/execve artık gerekmez) ═══ */

  /* Process manipulation */
  { .num = SCMP_SYS(execve),            .name = "execve",            .stage = 2 },
  { .num = SCMP_SYS(execveat),          .name = "execveat",          .stage = 2 },
  /* W^X: legacy exec-gain yolu (uselib kütüphane eşler) — kod kullanmıyor */
  { .num = SCMP_SYS(uselib),            .name = "uselib",            .stage = 2 },
  { .num = SCMP_SYS(fork),              .name = "fork",              .stage = 2 },
  { .num = SCMP_SYS(vfork),             .name = "vfork",             .stage = 2 },
  /* acct: process accounting — kodda hiç kullanılmıyor, telemetri
   * vektörünü kapatmak için engelli. */
  { .num = SCMP_SYS(acct),              .name = "acct",              .stage = 2 },
  { .num = SCMP_SYS(pidfd_open),        .name = "pidfd_open",        .stage = 2 },
  { .num = SCMP_SYS(process_madvise),   .name = "process_madvise",   .stage = 2 },
  { .num = SCMP_SYS(kcmp),             .name = "kcmp",              .stage = 2 },

  /* Legacy kernel AIO ailesi — io_uring gibi kullanılmıyor, ailece kapalı.
   * io_setup kapı (context'siz diğerleri işe yaramaz), diğerleri tamamlar. */
  { .num = SCMP_SYS(io_setup),          .name = "io_setup",          .stage = 2 },
  { .num = SCMP_SYS(io_destroy),        .name = "io_destroy",        .stage = 2 },
  { .num = SCMP_SYS(io_submit),         .name = "io_submit",         .stage = 2 },
  { .num = SCMP_SYS(io_cancel),         .name = "io_cancel",         .stage = 2 },
  { .num = SCMP_SYS(io_getevents),      .name = "io_getevents",      .stage = 2 },
  { .num = SCMP_SYS(io_pgetevents),     .name = "io_pgetevents",     .stage = 2 },

  /* Filesystem */
  { .num = SCMP_SYS(mount),             .name = "mount",             .stage = 2 },
  { .num = SCMP_SYS(umount2),           .name = "umount2",           .stage = 2 },
  { .num = SCMP_SYS(fsopen),            .name = "fsopen",            .stage = 2 },
  { .num = SCMP_SYS(fsconfig),          .name = "fsconfig",          .stage = 2 },
  { .num = SCMP_SYS(fsmount),           .name = "fsmount",           .stage = 2 },
  { .num = SCMP_SYS(fspick),            .name = "fspick",            .stage = 2 },
  { .num = SCMP_SYS(move_mount),        .name = "move_mount",        .stage = 2 },
  { .num = SCMP_SYS(open_tree),         .name = "open_tree",         .stage = 2 },
  { .num = SCMP_SYS(umount),            .name = "umount",            .stage = 2 },
  { .num = SCMP_SYS(pivot_root),        .name = "pivot_root",        .stage = 2 },
  { .num = SCMP_SYS(open_by_handle_at), .name = "open_by_handle_at", .stage = 2 },

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

  /* Stage 3 — event loop bunları kullanmıyor: exfil/privilege
   * syscall'ları. Stage 3 ana process'e özel — Tor çocuğu etkilenmez. */
  { .num = SCMP_SYS(sendto),            .name = "sendto",            .stage = 3 },
  { .num = SCMP_SYS(mknod),             .name = "mknod",             .stage = 3 },
  { .num = SCMP_SYS(mknodat),           .name = "mknodat",           .stage = 3 },
  { .num = SCMP_SYS(modify_ldt),        .name = "modify_ldt",        .stage = 3 },
  { .num = SCMP_SYS(iopl),              .name = "iopl",              .stage = 3 },
  { .num = SCMP_SYS(ioperm),            .name = "ioperm",            .stage = 3 },
  { .num = SCMP_SYS(syslog),            .name = "syslog",            .stage = 3 },

  /* Mevcut kuralların bypass'ları + exfil vektörleri.
   * pkey_mprotect W^X kuralını (mprotect gibi çalışır) — W^X ailesi,
   * stage 2'den itibaren kapalı (mprotect/mmap kurallarıyla aynı anda;
   * bootstrap penceresi dahil). fchmodat2 fchmodat kuralını deler —
   * event loop bunları kullanmıyor; Tor çocuğu etkilenmez. */
  { .num = SCMP_SYS(pkey_mprotect),     .name = "pkey_mprotect",     .stage = 2 },
  { .num = SCMP_SYS(pkey_alloc),        .name = "pkey_alloc",        .stage = 2 },
  { .num = SCMP_SYS(pkey_free),         .name = "pkey_free",         .stage = 2 },
  { .num = SCMP_SYS(fchmodat2),         .name = "fchmodat2",         .stage = 3 },
  { .num = SCMP_SYS(name_to_handle_at), .name = "name_to_handle_at", .stage = 3 },
  { .num = SCMP_SYS(pidfd_getfd),       .name = "pidfd_getfd",       .stage = 3 },
  { .num = SCMP_SYS(memfd_secret),      .name = "memfd_secret",      .stage = 3 },
  { .num = SCMP_SYS(vmsplice),          .name = "vmsplice",          .stage = 3 },

  
  { .num = SCMP_SYS(mount_setattr),     .name = "mount_setattr",     .stage = 3 },
  /* Yeni nesil syscall'lar farklı sürümlerde farklı bağımlılıklara sahip:
   *  - open_tree_attr/file_setattr (Linux 6.13+) yalnız __NR_ sabidi olarak
   *  - statmount/listmount (Linux 6.8+, libseccomp 2.6+) kernel header'da var
   * Eski bağımlılık (örn. Ubuntu 24.04) kuralları üretmez — syscall kernel'de
   * yoksa çağrılamaz, engellenmesi gerekmez (runtime -EDOM tolerant). */
#if defined(__NR_open_tree_attr)
  { .num = __NR_open_tree_attr,         .name = "open_tree_attr",    .stage = 3 },
#endif
#if defined(__NR_file_setattr)
  { .num = __NR_file_setattr,           .name = "file_setattr",      .stage = 3 },
#endif
  { .num = SCMP_SYS(splice),            .name = "splice",            .stage = 3 },
  /* W^X ailesi: System V shm — shmat(SHM_EXEC) YÜRÜTÜLEBİLİR eşleme
   * yaratır (man7 shmop(2): "Allow the contents of the segment to be
   * executed"; Linux ≥2.6.9). Kullanım yok (grep) → tüm aile stage 2'den
   * kapalı; böylece W^X iddiası bootstrap penceresini de kapsar.
   * (shmdt engellenmedi — yalnız ayırır, exec-gain değildir.) */
  { .num = SCMP_SYS(shmget),            .name = "shmget",            .stage = 2 },
  { .num = SCMP_SYS(shmat),             .name = "shmat",             .stage = 2 },
  { .num = SCMP_SYS(shmctl),            .name = "shmctl",            .stage = 2 },
  { .num = SCMP_SYS(msgget),            .name = "msgget",            .stage = 3 },
  { .num = SCMP_SYS(msgsnd),            .name = "msgsnd",            .stage = 3 },
  { .num = SCMP_SYS(msgrcv),            .name = "msgrcv",            .stage = 3 },
   { .num = SCMP_SYS(sendmsg),           .name = "sendmsg",           .stage = 3 },
   { .num = SCMP_SYS(recvmsg),           .name = "recvmsg",           .stage = 3 },
   { .num = SCMP_SYS(sendmmsg),          .name = "sendmmsg",          .stage = 3 },
   { .num = SCMP_SYS(recvmmsg),          .name = "recvmmsg",          .stage = 3 },
   { .num = SCMP_SYS(msgctl),            .name = "msgctl",            .stage = 3 },
  { .num = SCMP_SYS(memfd_create),      .name = "memfd_create",      .stage = 3 },
#if defined(__NR_statmount)
  { .num = __NR_statmount,              .name = "statmount",         .stage = 3 },
#endif
#if defined(__NR_listmount)
  { .num = __NR_listmount,              .name = "listmount",         .stage = 3 },
#endif
};

/* ================================================================
 * seccomp_policy_load
 * Blacklist filter'ı oluştur, yükle ve userspace context'i serbest bırak.
 *
 * @stage: 1 = stage 1 kuralları (init + tor_spawn penceresi)
 *         2 = stage 1 + 2 (tor_spawn sonrası: fork/exec + W^X kısıtı)
 *         3 = stage 1 + 2 + 3 (event loop: clone yasak, kalan aileler)
 *
 * Seccomp-bpf additive'tir: stage 1 kuralları kalıcıdır,
 * stage 2/3 sadece yeni ekler. Hiçbir kural kaldırılamaz.
 *
 * Return: NOX_OK veya NOX_ERR_CRYPTO (filter yükleme hatası).
 * ================================================================ */
nox_err_t seccomp_policy_load(int stage) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx)
    return NOX_ERR_CRYPTO;


  /* ── Mimari allowlist'i + thread senkronizasyonu (ayrı eksenler) ──
   * Mimari allowlist: filtre YALNIZ native x86_64 arch'ı ile kurulur
   * (seccomp_init yalnız native ekler). Başka ABI'den gelen her syscall
   * — i386 int 0x80 (AUDIT_ARCH_I386) veya x32 (nr ≥ 0x40000000) —
   * libseccomp'ın "badarch" aksiyonuna düşer. Varsayılana (SCMP_ACT_KILL)
   * güvenmek yerine AÇIKÇA KILL_PROCESS set edilir: niyet belgesi +
   * libseccomp sürüm değişimine karşı fail-closed.
   * (Kanıt: probe_32bit.c — i386/x32 tüm numaralar her stage'de SIGSYS.)
   *
   * Thread senkronizasyonu: TSYNC = filtrenin süreçteki TÜM thread'lere
   * senkron yüklenmesi (SECCOMP_FILTER_FLAG_TSYNC); mimari engellemeyle
   * ilgisi yoktur. Desteklenmiyorsa (kernel <3.17) diğer thread'ler
   * filtresiz kalabilir → sessiz devam değil, yükleme başarısız olur.
   *
   * Not: eski fallback'teki seccomp_arch_remove(SCMP_ARCH_X86) ölü koddu:
   * X86 zaten filtrede değil → -EEXIST döner; kod bunu "başarı" sayıyordu. */
  {
    int rc_arch = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH,
                                   SCMP_ACT_KILL_PROCESS);
    if (rc_arch < 0) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: badarch aksiyonu ayarlanamadı (rc=%d)",
                rc_arch);
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
    int rc_tsync = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
    if (rc_tsync < 0) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: TSYNC yok (rc=%d) — thread'ler "
                "filtresiz kalabilir; politika yüklenmedi", rc_tsync);
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
  }

  size_t n_blocked = 0;
  size_t n_custom_blocked = 0;
  for (size_t i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
    if (blacklist[i].stage > stage)
      continue;  /* bu stage henüz aktif değil */
    int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, blacklist[i].num, 0);
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
    #define CLONE_THREAD 0x00010000  

    /* Tek kural — clone sadece CLONE_THREAD ile izinli.
     * x86_64 clone(flags, newsp, ptid, ctid, tls): SCMP_A0 = flags.
     * CLONE_THREAD biti setliyse izin ver (pthread_create çalışır),
     * değilse KILL (fork/vfork engellenir). */
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(clone), 1,
          SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0)) != 0) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: clone kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }

    /* clone3: ENOSYS döndür — KILL_PROCESS olsa modern glibc (2.34+)
     * pthread_create clone3'ü dener ve seccomp sinyali fallback'e izin
     * vermez, process ölürdü. ENOSYS ile glibc güvenle clone'a düşer
     * (CLONE_THREAD izni yukarıdaki clone kuralında). Fork/vfork yine
     * imkânsız — clone kuralı CLONE_THREAD'siz çağrıyı KILL eder. */
    int rc_clone3 = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
    if (rc_clone3 != 0 && rc_clone3 != -EDOM) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: clone3 kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
    if (rc_clone3 == 0)
      n_custom_blocked++;

    /* ── arch_prctl: CET-SS yönetimini engelle (sadece stage 2) ──
     * Kilit main'de seccomp stage 2 ÖNCESİ atılır (main.c adım 4b).
     * Burada yalnızca kilidi atlatma yolları kapatılır:
     * DISABLE (0x5002) shadow stack'i kapatır; UNLOCK (0x5004) kilitli
     * bitleri açar. Meşru glibc TLS çağrısı ARCH_SET_FS (0x1002)
     * serbest kalır — arch_prctl tamamen engellenemez. */
#ifdef ARCH_SHSTK_DISABLE
    int rc_prctl_ss = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS,
                                       SCMP_SYS(arch_prctl), 1,
                                       SCMP_A0(SCMP_CMP_EQ,
                                               (uint64_t)ARCH_SHSTK_DISABLE));
    if (rc_prctl_ss != 0 && rc_prctl_ss != -EDOM) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: arch_prctl(DISABLE) kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
    if (rc_prctl_ss == 0)
      n_custom_blocked++;
#endif
#ifdef ARCH_SHSTK_UNLOCK
    int rc_prctl_ul = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS,
                                       SCMP_SYS(arch_prctl), 1,
                                       SCMP_A0(SCMP_CMP_EQ,
                                               (uint64_t)ARCH_SHSTK_UNLOCK));
    if (rc_prctl_ul != 0 && rc_prctl_ul != -EDOM) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: arch_prctl(UNLOCK) kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
    if (rc_prctl_ul == 0)
      n_custom_blocked++;
#endif

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
        { PR_SET_MDWE,                  "prctl(PR_SET_MDWE)" },
      };
      for (size_t i = 0; i < sizeof(blocked)/sizeof(blocked[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(prctl), 1,
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

    /* Socket aile engelleri — CAP_NET_RAW drop'a ek savunma katmanı.
     * Uygulama stage 2'den sonra yalnız AF_UNIX kullanır (Tor control,
     * SOCKS, listener, peer); AF_PACKET/raw socket'lar asla. */
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

    /* Ana akım ağ aileleri stage-2'de kapalı: auth/bootstrap/listener/HS
     * öncesi parent artık yeni AF_INET/AF_INET6/AF_NETLINK socket'i
     * açamaz. Parent Tor ile yalnız AF_UNIX konuşur; Tor ayrı süreç —
     * yalnız stage-1 filtresini miras alır, bu bloklardan etkilenmez. */
#ifdef AF_INET
    {
      int rc = add_socket_domain_rule(ctx, AF_INET, "socket(AF_INET)");
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
      int rc = add_socket_domain_rule(ctx, AF_INET6, "socket(AF_INET6)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif

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

    /* Exfil alternatifleri — tor_spawn sonrası ana process
     * hiçbirini kullanmıyor (yalnızca AF_UNIX socket açar). */
#ifdef AF_CAN
    {
      int rc = add_socket_domain_rule(ctx, AF_CAN, "socket(AF_CAN)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif
#ifdef AF_KEY
    {
      int rc = add_socket_domain_rule(ctx, AF_KEY, "socket(AF_KEY)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif
#ifdef AF_NFC
    {
      int rc = add_socket_domain_rule(ctx, AF_NFC, "socket(AF_NFC)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif
#ifdef AF_APPLETALK
    {
      int rc = add_socket_domain_rule(ctx, AF_APPLETALK, "socket(AF_APPLETALK)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif
#ifdef AF_IPX
    {
      int rc = add_socket_domain_rule(ctx, AF_IPX, "socket(AF_IPX)");
      if (rc < 0) {
        seccomp_release(ctx);
        return NOX_ERR_CRYPTO;
      }
      if (rc == 0)
        n_custom_blocked++;
    }
#endif

    /* ── W^X: çalışma zamanında yeni executable bellek yasağı ─────────
     * JIT yok, lazy binding yok (BIND_NOW) — PROT_EXEC içeren hiçbir
     * meşru çağrı yok; maskeli karşılaştırma yalnızca EXEC bitini test
     * eder (READ/WRITE serbest).
     * İddia ("runtime'da yeni executable bellek yaratılamaz") bu kurallar
     * bütününden çıkar — tek blok değil, TAM aile:
     *   - mprotect/mmap: PROT_EXEC maskeli KILL (bu blok)
     *   - pkey_mprotect/pkey_alloc/pkey_free: blacklist (stage 2)
     *   - shmget/shmat/shmctl: blacklist (stage 2) — shmat SHM_EXEC dahil;
     *     man7 shmop(2): "Allow the contents of the segment to be executed"
     *   - execve/execveat/uselib: blacklist (stage 2) — yeni kod yürütme
     *   - PR_SET_MDWE: main.c TUI-init sonrası (kernel ≥6.3, REFUSE_EXEC_GAIN)
     * Kapsam: stage-2'den itibaren; stage-1 penceresi (constructor →
     * tor_spawn) kapsam dışıdır. Shellcode için RX bölge yaratma girişimi
     * process'i öldürür. */
    {
      static const struct { int sys; const char *name; } exec_blocked[] = {
        { SCMP_SYS(mprotect), "mprotect(PROT_EXEC)" },
        { SCMP_SYS(mmap),     "mmap(PROT_EXEC)"     },
      };
      for (size_t i = 0; i < sizeof(exec_blocked)/sizeof(exec_blocked[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS,
                                  exec_blocked[i].sys, 1,
                                  SCMP_A2(SCMP_CMP_MASKED_EQ,
                                          (uint64_t)PROT_EXEC, (uint64_t)PROT_EXEC));
        if (rc != 0 && rc != -EDOM) {
          NOX_ERROR(LOG_MOD_MAIN, "seccomp: %s kuralı eklenemedi",
                    exec_blocked[i].name);
          seccomp_release(ctx);
          return NOX_ERR_CRYPTO;
        }
        if (rc == 0)
          n_custom_blocked++;
      }
    }
  }

  /* ── Stage 3: event loop başı ─────────────────────────────
   * Tüm mevcut bağlantılar AF_UNIX (Tor control, SOCKS, peer).
   * Event loop tek thread — clone tamamen yasak.
   * AF_INET/AF_INET6/AF_NETLINK zaten stage-2'den beri kapalı.
   * ─────────────────────────────────────────────────────────────── */
  if (stage >= 3) {
    /* clone tamamen yasak — event loop tek thread, thread gerekmez */
    int rc_clone = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(clone), 0);
    if (rc_clone != 0 && rc_clone != -EDOM) {
      NOX_ERROR(LOG_MOD_MAIN, "seccomp: stage 3 clone kuralı eklenemedi");
      seccomp_release(ctx);
      return NOX_ERR_CRYPTO;
    }
    if (rc_clone == 0)
      n_custom_blocked++;

    /* Kalan egzotik aileler — hepsi AF_UNIX dışı. */
    {
      static const struct { int domain; const char *name; } blocked[] = {
        /* Alternatif sızıntı yolları — hepsi AF_UNIX dışı:
         * AF_XDP:  raw paket I/O (driver bypass)
         * AF_ALG:  kernel crypto API erişimi
         * AF_VSOCK: VM/host iletişimi */
#ifdef AF_XDP
        { AF_XDP,   "socket(AF_XDP)" },
#endif
#ifdef AF_ALG
        { AF_ALG,   "socket(AF_ALG)" },
#endif
#ifdef AF_VSOCK
        { AF_VSOCK, "socket(AF_VSOCK)" },
#endif
        /* Kalan socket aileleri: BLUETOOTH/SMC STREAM, RDS SEQPACKET,
         * QIPCRTR DGRAM — hepsi AF_UNIX dışı, kapalı. */
        { AF_BLUETOOTH, "socket(AF_BLUETOOTH)" },
        { AF_SMC,       "socket(AF_SMC)" },
        { AF_RDS,       "socket(AF_RDS)" },
        { AF_QIPCRTR,   "socket(AF_QIPCRTR)" },
      };
      for (size_t i = 0; i < sizeof(blocked)/sizeof(blocked[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socket), 1,
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
