/* ================================================================
 * seccomp_policy.h — Seccomp Blacklist Policy (Üç Aşamalı)
 *
 * noxtor-cli syscall kısıtlama politikası.
 *
 * Aşama 1 (key_derive sonrası): 120s Tor bootstrap penceresini korur.
 *   process_vm_readv, ptrace, io_uring, userfaultfd, perf_event_open
 *
 * Aşama 2 (Tor HS sonrası): Tam blacklist + raw socket engelleme.
 *   fork, execve, mount, reboot vs.
 *
 * Aşama 3 (Event loop başı): Sıfır ağ sızıntısı garantisi.
 *   clone tamamen yasak, AF_INET/AF_INET6 tüm tipler, AF_NETLINK,
 *   symlink, link, chmod, chown — tüm iletişim AF_UNIX.
 * ================================================================ */
#ifndef NOX_SECCOMP_POLICY_H
#define NOX_SECCOMP_POLICY_H

#include "types.h"

/* seccomp_policy_load — Seccomp blacklist filter'ını yükle
 *
 * @stage: 1 = stage 1 kuralları (120s pencere koruması)
 *         2 = stage 1 + stage 2 (Tor sonrası)
 *         3 = stage 1 + 2 + 3 (event loop — sıfır ağ sızıntısı)
 *
 * Seccomp-bpf additive'tir: her stage bir öncekini korur.
 * Hiçbir kural kaldırılamaz.
 *
 * Kullanım:
 *   1. key_derive sonrası:       seccomp_policy_load(1)
 *   2. tor_spawn() çalışsın (fork/execve engellenmez)
 *   3. Tor HS sonrası:           seccomp_policy_load(2)
 *   4. Event loop başında:       seccomp_policy_load(3)
 *   5. Bundan sonra clone, TCP, UDP, NETLINK çalışmaz
 *
 * Return: NOX_OK başarı, NOX_ERR_CRYPTO hata
 */
nox_err_t seccomp_policy_load(int stage);

#endif /* NOX_SECCOMP_POLICY_H */
