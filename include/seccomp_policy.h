/* ================================================================
 * seccomp_policy.h — Seccomp Blacklist Policy (İki Aşamalı)
 *
 * noxtor-cli syscall kısıtlama politikası.
 *
 * Aşama 1 (key_derive sonrası): 120s Tor bootstrap penceresini korur.
 *   process_vm_readv, ptrace, io_uring, userfaultfd, perf_event_open, prctl
 *
 * Aşama 2 (Tor HS sonrası): Tam blacklist + raw socket engelleme.
 *   fork, execve, mount, reboot vs.
 * ================================================================ */
#ifndef NOX_SECCOMP_POLICY_H
#define NOX_SECCOMP_POLICY_H

#include "types.h"

/* seccomp_policy_load — Seccomp blacklist filter'ını yükle
 *
 * @stage: 1 = stage 1 kuralları (120s pencere koruması)
 *         2 = tüm kurallar (stage 1 + stage 2, Tor sonrası)
 *
 * Seccomp-bpf additive'tir: stage 1 kuralları kalıcıdır,
 * stage 2 sadece yeni ekler. Hiçbir kural kaldırılamaz.
 *
 * Kullanım:
 *   1. key_derive sonrası: seccomp_policy_load(1)
 *   2. tor_spawn() çalışsın (fork/execve engellenmez)
 *   3. Tor HS sonrası: seccomp_policy_load(2)
 *   4. Bundan sonra fork, execve, mount, reboot çalışmaz
 *
 * Return: NOX_OK başarı, NOX_ERR_CRYPTO hata
 */
nox_err_t seccomp_policy_load(int stage);

#endif /* NOX_SECCOMP_POLICY_H */
