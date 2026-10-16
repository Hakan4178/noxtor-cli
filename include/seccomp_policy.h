/* ================================================================
 * seccomp_policy.h — Seccomp Blacklist Policy (Üç Aşamalı)
 *
 * noxtor-cli syscall kısıtlama politikası.
 *
 * Aşama 1 (constructor, main öncesi): init + tor_spawn penceresini korur.
 *   process_vm_readv, ptrace, io_uring, userfaultfd, perf_event_open
 *
 * Aşama 2 (tor_spawn + TUI sonrası; auth/bootstrap/listener/HS öncesi):
 *   fork, execve, mount, reboot vs. + yeni AF_INET/AF_INET6/AF_NETLINK
 *   socket'leri + W^X ailesi (mprotect/mmap PROT_EXEC maskeli, pkey_*,
 *   shm* SHM_EXEC dahil, uselib; PR_SET_MDWE main.c'de) kapalı/aktif.
 *
 * Aşama 3 (event loop başı): clone tamamen yasak, kalan egzotik aileler
 *   (XDP/ALG/VSOCK/BT/SMC/RDS/QIPCRTR), symlink/link/chmod/chown.
 *
 * Kapsam notu: kurallar socket() YARATMAYI engeller; önceden açılmış
 * fd'lerin kullanımı ayrıca kısıtlanmaz. NO_SECCOMP=1 politikayı
 * derlemeden çıkarır.
 *
 * Mimari allowlist: filtre yalnız native x86_64 içindir; i386 (int 0x80)
 * ve x32 (X32_SYSCALL_BIT'li nr) syscall'ları badarch=KILL_PROCESS ile
 * ölür. TSYNC (thread senkronizasyonu) ayrı bir eksendir.
 *
 * Dosya erişimi (open/openat/creat):
 *   Seccomp tarafından engellenMEZ — Landlock tarafından kısıtlanır.
 *   Landlock event loop başında yüklenir (seccomp stage 1+2'den sonra).
 *   Landlock yoksa: open/openat/creat serbesttir (bilinen limitasyon).
 * ================================================================ */
#ifndef NOX_SECCOMP_POLICY_H
#define NOX_SECCOMP_POLICY_H

#include "types.h"

/* seccomp_policy_load — Seccomp blacklist filter'ını yükle
 *
 * @stage: 1 = stage 1 kuralları (constructor, main öncesi)
 *         2 = stage 1 + stage 2 (tor_spawn sonrası)
 *         3 = stage 1 + 2 + 3 (event loop başı)
 *
 * Seccomp-bpf additive'tir: her stage bir öncekini korur.
 * Hiçbir kural kaldırılamaz.
 *
 * Kullanım (gerçek sıra — main.c / event_loop.c):
 *   1. constructor (main öncesi): seccomp_policy_load(1)
 *   2. tor_spawn() çalışsın (fork/execve henüz engellenmez) + TUI init
 *   3. tor_spawn sonrası:         seccomp_policy_load(2)
 *   4. auth → bootstrap → listener → HS (stage 2 koruması altında)
 *   5. Event loop başında:        seccomp_policy_load(3) + Landlock
 *
 * Return: NOX_OK başarı, NOX_ERR_CRYPTO hata
 */
nox_err_t seccomp_policy_load(int stage);

#endif /* NOX_SECCOMP_POLICY_H */
