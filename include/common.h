/* SPDX-License-Identifier: GPL-3.0-or-later
 * common.h — noxtor-cli temel tanımlar, hata kodları, yardımcı makrolar
 *
 * Bu dosya projenin tüm .c dosyaları tarafından include edilir.
 * Hiçbir implementasyon içermez — yalnızca tanımlar.
 */

#ifndef PARANOID_COMMON_H
#define PARANOID_COMMON_H

/* Feature macros — diğer include'lardan önce */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* ================================================================
 * STANDART INCLUDE'LAR
 * ================================================================ */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>       /* pid_t, sysconf */
#include <linux/limits.h> /* PATH_MAX */

/* ================================================================
 * PROJE SABİTLERİ
 * ================================================================ */
#define PARANOID_VERSION       "0.1.0"
#define PARANOID_APP_NAME      "paranoidcli"
#define PARANOID_CONFIG_DIR    ".config/paranoidcli"

/* Kriptografi sabitleri */
#define NOX_KEY_LEN            32U       /* tüm key'ler 32 byte */
#define NOX_NONCE_LEN          24U       /* XChaCha20-Poly1305 nonce */
#define NOX_MAC_LEN            16U       /* Poly1305 MAC */
#define NOX_SALT_LEN           16U       /* Argon2id salt */
#define NOX_CANARY_LEN         16U       /* arena canary */

/* Mesajlaşma sabitleri */
#define NOX_MAX_MSG_LEN        65536U    /* 64 KB — tek mesaj üst sınır */
#define NOX_CHUNK_SIZE         65536U    /* 64 KB — dosya transfer chunk */
#define NOX_FRAME_MAGIC        0xDEADC0DEU

/* PIN politikası */
#define NOX_PIN_MIN_LEN        8U
#define NOX_PIN_MAX_LEN        128U

/* Onion adresi */
#define NOX_ONION_LEN          62U       /* 56 + ".onion" */
#define NOX_VIRTUAL_PORT       9876U     /* HS virtual port (sabit) */
#define NOX_ONION_KEY_B64_LEN  88U       /* ED25519-V3 private key base64 */

/* Contact */
#define NOX_CONTACT_NAME_LEN   64U

/* Config yol limiti — PATH_MAX (4096) stack'te çok yer kaplar */
#define NOX_PATH_MAX           512U

/* ================================================================
 * HATA KODLARI — nox_err_t
 *
 * Negatif errno tarzı. NOX_ERR_AUTH ayrı çünkü Noise MAC hatası
 * ile I/O hatasını karıştırmak tehlikeli.
 * ================================================================ */
typedef enum {
    NOX_OK              =  0,
    NOX_ERR_ALLOC       = -1,   /* bellek ayırma hatası              */
    NOX_ERR_CRYPTO      = -2,   /* genel kriptografi hatası          */
    NOX_ERR_IO          = -3,   /* dosya / socket I/O hatası         */
    NOX_ERR_PROTO       = -4,   /* Noise protokol hatası             */
    NOX_ERR_AUTH        = -5,   /* MAC doğrulama başarısız           */
    NOX_ERR_LOCKED      = -6,   /* mlock / MAP_LOCKED başarısız      */
    NOX_ERR_PIN         = -7,   /* PIN geçersiz / çok kısa           */
    NOX_ERR_CONFIG      = -8,   /* config dizin / dosya hatası       */
    NOX_ERR_TOR         = -9,   /* Tor spawn / kontrol hatası        */
    NOX_ERR_NET         = -10,  /* ağ bağlantı hatası                */
    NOX_ERR_DB          = -11,  /* SQLite hatası                     */
    NOX_ERR_OVERFLOW    = -12,  /* arena / buffer taşması            */
    NOX_ERR_STATE       = -13,  /* geçersiz state geçişi             */
} nox_err_t;

/* Hata kodu → okunabilir string */
const char *nox_strerror(nox_err_t err);

/* PIN doğrulama — terminal'den bağımsız, test edilebilir */
nox_err_t validate_pin(const char *pin, size_t raw_len);

/* ================================================================
 * LOG SİSTEMİ — prototip ve makrolar
 *
 * Release build'de LOG_LEVEL_DEBUG tamamen derlenmeden çıkar.
 * ================================================================ */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4,
} log_level_t;

/* Modül tanımlayıcıları — renk kodlaması log.c'de */
typedef enum {
    LOG_MOD_MAIN  = 0,
    LOG_MOD_NOISE,
    LOG_MOD_CRYPTO,
    LOG_MOD_TOR,
    LOG_MOD_NET,
    LOG_MOD_DB,
    LOG_MOD_HARD,
    LOG_MOD_UI,
    LOG_MOD_FRAME,
    LOG_MOD_ARENA,
    LOG_MOD_COUNT,    /* sentinel — toplam modül sayısı */
} log_module_t;

/* Asıl log fonksiyonu — log.c'de implemente edilir */
void nox_log_impl(log_level_t level, log_module_t mod,
                  const char *file, int line,
                  const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

/* Hex dump — key debug için kritik */
void nox_hexdump(log_module_t mod, const char *label,
                 const void *data, size_t len);

/*
 * Log makroları — kaynak dosya ve satır otomatik eklenir.
 * DEBUG seviyesi release'de derlenmeden çıkar.
 */
#ifdef DEBUG
  #define NOX_DEBUG(mod, fmt, ...) \
      nox_log_impl(LOG_LEVEL_DEBUG, (mod), __FILE__, __LINE__, \
                   fmt __VA_OPT__(,) __VA_ARGS__)
#else
  #define NOX_DEBUG(mod, fmt, ...)  /* sıfır overhead */
#endif

#define NOX_INFO(mod, fmt, ...) \
    nox_log_impl(LOG_LEVEL_INFO, (mod), __FILE__, __LINE__, \
                 fmt __VA_OPT__(,) __VA_ARGS__)

#define NOX_WARN(mod, fmt, ...) \
    nox_log_impl(LOG_LEVEL_WARN, (mod), __FILE__, __LINE__, \
                 fmt __VA_OPT__(,) __VA_ARGS__)

#define NOX_ERROR(mod, fmt, ...) \
    nox_log_impl(LOG_LEVEL_ERROR, (mod), __FILE__, __LINE__, \
                 fmt __VA_OPT__(,) __VA_ARGS__)

#define NOX_FATAL(mod, fmt, ...) \
    nox_log_impl(LOG_LEVEL_FATAL, (mod), __FILE__, __LINE__, \
                 fmt __VA_OPT__(,) __VA_ARGS__)

/* ================================================================
 * UTILITY MAKROLARI
 * ================================================================ */

/* Dizi eleman sayısı — pointer'da derleme hatası verir */
#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))

/* Kullanılmayan parametre uyarısını bastır */
#define UNUSED(x)        ((void)(x))

/* Compile-time assert (C23 static_assert zaten var ama alias) */
#define NOX_STATIC_ASSERT(cond, msg)  static_assert((cond), msg)

/* Güvenli minimum/maksimum — çift değerlendirme yok (C23 typeof) */
#define NOX_MIN(a, b)  ({ typeof(a) _a = (a); typeof(b) _b = (b); \
                          _a < _b ? _a : _b; })
#define NOX_MAX(a, b)  ({ typeof(a) _a = (a); typeof(b) _b = (b); \
                          _a > _b ? _a : _b; })

#endif /* PARANOID_COMMON_H */
