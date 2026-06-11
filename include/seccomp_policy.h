/* ================================================================
 * seccomp_policy.h — Seccomp Blacklist Policy
 *
 * noxtor-cli syscall kısıtlama politikası.
 * Tor bağlantısı kurulduktan sonra aktif edilir.
 * ================================================================ */
#ifndef NOX_SECCOMP_POLICY_H
#define NOX_SECCOMP_POLICY_H

#include "types.h"

/* seccomp_policy_load — Seccomp blacklist filter'ını yükle
 *
 * Bu fonksiyon SADECE Tor bağlantısı kurulduktan sonra çağrılmalı.
 * Çağrıldıktan sonra tehlikeli syscall'lar EPERM ile başarısız olur.
 *
 * Kullanım:
 *   1. socks5_connect() başarılı döner
 *   2. seccomp_policy_load() çağrılır
 *   3. Bundan sonra ptrace, mount, reboot vs. çalışmaz
 *
 * Return: NOX_OK başarı, NOX_ERR_CRYPTO hata
 */
nox_err_t seccomp_policy_load(void);

#endif /* NOX_SECCOMP_POLICY_H */
