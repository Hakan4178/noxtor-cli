/* SPDX-License-Identifier: GPL-3.0-or-later
 * landlock_sandbox.h — Landlock LSM dosya erişim kısıtlaması
 *
 * open/openat/creat'i sadece downloads dizinine kısıtlar.
 * Kernel 5.13+ gerektirir. Desteklemiyorsa sessizce fallback.
 */

#ifndef PARANOID_LANDLOCK_SANDBOX_H
#define PARANOID_LANDLOCK_SANDBOX_H

#include "common.h"

/**
 * landlock_sandbox_init — Landlock sandbox'ı başlat.
 *
 * @downloads_dir_fd: downloads dizinin fd'si (O_PATH ile açılmış)
 *
 * Sadece downloads dizinine okuma/yazma izni verir.
 * Diğer tüm dosya erişimleri engellenir (default deny).
 *
 * Return: NOX_OK veya NOX_ERR_CONFIG
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
