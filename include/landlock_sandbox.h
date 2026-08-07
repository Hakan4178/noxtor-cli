/* SPDX-License-Identifier: GPL-3.0-or-later
 * landlock_sandbox.h — Landlock LSM dosya erişim kısıtlaması
 *
 * open/openat/creat'i sadece downloads dizinine kısıtlar.
 * Kernel 5.13+ gerektirir. Desteklemiyorsa sessizce fallback.
 */

#ifndef PARANOID_LANDLOCK_SANDBOX_H
#define PARANOID_LANDLOCK_SANDBOX_H

#include "common.h"

#include <linux/landlock.h>

/* ABI 1 temel haklar — REFER/TRUNCATE/IOCTL_DEV hariç (daha sonra eklenir).
 * Tek kaynak: landlock_sandbox.c hem handled hem testler buradan türetir. */
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
 * landlock_sandbox_init — Landlock sandbox'ı başlat.
 *
 * @downloads_dir_fd: downloads dizinin fd'si (O_PATH ile açılmış)
 *
 * Sadece downloads dizinine okuma/yazma izni verir.
 * Diğer tüm dosya erişimleri engellenir (default deny).
 *
 * Return: NOX_OK veya NOX_ERR_CONFIG / NOX_ERR_LANDLOCK_UNSUPPORTED
 */
nox_err_t landlock_sandbox_init(int downloads_dir_fd);

/**
 * landlock_is_available — Landlock mevcut mu?
 *
 * Return: true (ABI v1+) veya false
 */
bool landlock_is_available(void);

/**
 * landlock_is_active — Landlock gerçekten uygulandı mı?
 *
 * landlock_sandbox_init() başarılı olduysa true döner.
 * landlock_is_available() sadece ABI versiyonuna bakar,
 * landlock_is_active() gerçekten uygulandığından emin olur.
 *
 * Return: true/false
 */
bool landlock_is_active(void);

#endif /* PARANOID_LANDLOCK_SANDBOX_H */
