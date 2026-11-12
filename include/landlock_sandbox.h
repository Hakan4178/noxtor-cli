/* SPDX-License-Identifier: GPL-3.0-or-later
 * landlock_sandbox.h — Landlock LSM dosya erişim kısıtlaması
 *
 * open/openat/creat'i sadece downloads dizinine kısıtlar; ABI >= 9'da
 * pathname Unix soketlerine connect'i de kısıtlar ve yalnız Tor'un
 * socks.sock inode'una dosya düzeyinde istisna tanır.
 * Config kökü salt-okunur; silme hakkı yalnız tor_data_<pid> dizinine
 * verilir (F3) — identity.key/salt/contacts.db config kökünden silinemez.
 * Kernel 5.13+ gerektirir. Desteklemiyorsa fail-closed
 * (landlock_sandbox_init NOX_ERR_* döner, sessiz devam yok).
 */

#ifndef PARANOID_LANDLOCK_SANDBOX_H
#define PARANOID_LANDLOCK_SANDBOX_H

#include "common.h"

#include <linux/landlock.h>

/* Eski kernel header'larıyla derlenen binary yeni kernelde sessizce
 * korumasız kalmasın: sabit yoksa ABI 9 değerini tanımla. Runtime'da
 * yalnız abi >= 9 ise handled'a eklenir. */
#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif

/* ABI 1 temel haklar — REFER/TRUNCATE/IOCTL_DEV/RESOLVE_UNIX hariç
 * (ABI'ye göre koşullu eklenir). Tek kaynak: landlock_sandbox.c hem
 * handled hem testler buradan türetir. */
#define NOX_LL_BASE_RIGHTS \
    (LANDLOCK_ACCESS_FS_EXECUTE      | \
     LANDLOCK_ACCESS_FS_WRITE_FILE   | \
     LANDLOCK_ACCESS_FS_READ_FILE    | \
     LANDLOCK_ACCESS_FS_READ_DIR     | \
     LANDLOCK_ACCESS_FS_REMOVE_DIR   | \
     LANDLOCK_ACCESS_FS_REMOVE_FILE  | \
     LANDLOCK_ACCESS_FS_MAKE_CHAR    | \
     LANDLOCK_ACCESS_FS_MAKE_DIR     | \
     LANDLOCK_ACCESS_FS_MAKE_REG     | \
     LANDLOCK_ACCESS_FS_MAKE_SOCK    | \
     LANDLOCK_ACCESS_FS_MAKE_FIFO    | \
     LANDLOCK_ACCESS_FS_MAKE_BLOCK   | \
     LANDLOCK_ACCESS_FS_MAKE_SYM)

/**
 * nox_ll_compute_rule_rights — C-1/C-2 test edilebilirliği için saf fonksiyon.
 *
 * Path-beneath kuralının allowed_access'ı, wanted hakların handled setiyle
 * kesişimidir. Kernel, allowed_access'ın handled_access_fs'in alt kümesi
 * olmasını zorunlu tutar (ihlalde EINVAL — eski C-2 bug'ı).
 *
 * - C-1: MAKE_REG wanted'ta olmalı (yoksa downloads'da O_CREAT → EACCES)
 * - C-2: wanted'taki ABI üstü haklar (TRUNCATE vb.) otomatik elenir
 *
 * @wanted:  uygulamanın ihtiyaç duyduğu haklar (ABI farkı gözetmeksizin)
 * @handled: ruleset'in handled_access_fs'i (ABI'ye göre hazırlanmış)
 * Return:   allowed_access — her zaman handled'ın alt kümesi
 */
__u64 nox_ll_compute_rule_rights(__u64 wanted, __u64 handled);

/**
 * landlock_abi_version — Kernel Landlock ABI sürümü.
 *
 * Return: ABI (>=1) veya hata durumunda -1 (errno set).
 */
int landlock_abi_version(void);

/**
 * landlock_open_unix_socket_fd — Bir pathname Unix soketini O_PATH ile aç.
 *
 * @path: Soket yolu (ör. Tor socks.sock).
 *
 * O_PATH | O_NOFOLLOW | O_CLOEXEC ile açar; fstat ile S_ISSOCK ve
 * st_uid == geteuid() doğrular. Başarıda fd, hatada -1 (errno set).
 * Dönen fd yalnız Landlock kuralı için kullanılmalı, okuma/yazma için değil.
 */
int landlock_open_unix_socket_fd(const char *path);

/**
 * landlock_sandbox_init — Landlock sandbox'ı başlat.
 *
 * @config_dir_fd:    config dizinin fd'si (O_DIRECTORY|O_NOFOLLOW, main:ensure_config_dir)
 *                    — salt-okunur (READ_FILE|READ_DIR). <0 ise fail-closed.
 * @downloads_dir_fd: downloads dizinin fd'si (O_DIRECTORY|O_NOFOLLOW)
 * @tor_data_fd:      tor_data_<pid> dizinin fd'si (O_DIRECTORY|O_NOFOLLOW,
 *                    generate_torrc). Silme kuralının tek anchor'ı:
 *                    READ_DIR|REMOVE_FILE|REMOVE_DIR. <0 ise fail-closed.
 * @socks_fd:         Tor socks.sock için O_PATH fd'si
 *                    (landlock_open_unix_socket_fd). ABI >= 9'da zorunlu;
 *                    ABI < 9'da yok sayılır (-1 geçilebilir).
 *
 * fd = anchor, path'e asla geri dönülmez (TOCTOU kapalı).
 * Sadece downloads (RW) + config (RO) + tor_data (silme) altında erişim
 * verilir; ABI >= 9'da ayrıca yalnız socks_fd inode'una RESOLVE_UNIX
 * istisnası tanınır.
 *
 * Return: NOX_OK veya NOX_ERR_CONFIG / NOX_ERR_LANDLOCK_UNSUPPORTED
 */
nox_err_t landlock_sandbox_init(int config_dir_fd, int downloads_dir_fd,
                                int tor_data_fd, int socks_fd);

/**
 * landlock_is_available — Landlock ABI detectable mi? (hardened)
 *
 * Kernel Landlock `LANDLOCK_CREATE_RULESET_VERSION` sorgusuna
 * `abi>=1` ile cevap veriyorsa true döner.
 *
 * NOT: true olması "usable right now" demek değildir.
 * `landlock_sandbox_init()` sonrası `ruleset creation`, `add_rule`,
 * `no_new_privs`, `restrict_self` adımlarında hata çıkabilir.
 * Gerçek aktiflik için `landlock_is_active()` veya
 * `landlock_sandbox_init()` dönüşü (`NOX_OK`) kontrol edilmeli.
 *
 * Return: hardened true (ABI detectable) veya false
 */
nox_hardbool_t landlock_is_available(void);

/**
 * landlock_is_active — Landlock gerçekten uygulandı mı? (hardened)
 *
 * landlock_sandbox_init() başarılı olduysa true döner.
 *
 * Return: hardened true/false
 */
nox_hardbool_t landlock_is_active(void);

#endif /* PARANOID_LANDLOCK_SANDBOX_H */
