/* SPDX-License-Identifier: GPL-3.0-or-later
 * log.c — noxtor-cli renkli log altyapısı
 *
 * Tüm çıktı stderr'e gider. stdout mesajlaşma için temiz kalır.
 * Release build'de LOG_LEVEL_DEBUG çağrıları derlenmeden çıkar
 * (common.h'deki makro ile).
 *
 * Renk kodlaması:
 *   [MAIN ] → beyaz        [NOISE] → cyan
 *   [TOR  ] → sarı         [NET  ] → mavi
 *   [DB   ] → magenta      [HARD ] → kırmızı
 *   [UI   ] → yeşil        [FRAME] → beyaz dim
 *   [ARENA] → cyan dim
 */

#include "common.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* ================================================================
 * ANSI RENK KODLARI
 * ================================================================ */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_RED     "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_BLUE    "\033[34m"
#define CLR_MAGENTA "\033[35m"
#define CLR_CYAN    "\033[36m"
#define CLR_WHITE   "\033[37m"

/* ================================================================
 * MODÜL İSİMLERİ VE RENKLERİ
 * ================================================================ */
struct mod_info {
    const char *name;   /* 5 karakter, sabit genişlik */
    const char *color;
};

static const struct mod_info modules[LOG_MOD_COUNT] = {
    [LOG_MOD_MAIN]   = { "MAIN ", CLR_WHITE   },
    [LOG_MOD_NOISE]  = { "NOISE", CLR_CYAN    },
    [LOG_MOD_CRYPTO] = { "CRYPT", CLR_CYAN CLR_BOLD },
    [LOG_MOD_TOR]    = { "TOR  ", CLR_YELLOW  },
    [LOG_MOD_NET]    = { "NET  ", CLR_BLUE    },
    [LOG_MOD_DB]     = { "DB   ", CLR_MAGENTA },
    [LOG_MOD_HARD]   = { "HARD ", CLR_RED     },
    [LOG_MOD_UI]     = { "UI   ", CLR_GREEN   },
    [LOG_MOD_FRAME]  = { "FRAME", CLR_DIM CLR_WHITE },
    [LOG_MOD_ARENA]  = { "ARENA", CLR_DIM CLR_CYAN  },
};

/* ================================================================
 * LOG SEVİYE İSİMLERİ VE RENKLERİ
 * ================================================================ */
struct level_info {
    const char *tag;
    const char *color;
};

static const struct level_info levels[] = {
    [LOG_LEVEL_DEBUG] = { "DBG", CLR_DIM     },
    [LOG_LEVEL_INFO]  = { "INF", CLR_WHITE   },
    [LOG_LEVEL_WARN]  = { "WRN", CLR_YELLOW  },
    [LOG_LEVEL_ERROR] = { "ERR", CLR_RED     },
    [LOG_LEVEL_FATAL] = { "FTL", CLR_BOLD CLR_RED },
};

/* ================================================================
 * ZAMAN DAMGASI — monotonic olmayan ama okunabilir
 * ================================================================ */
static void print_timestamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_buf;
    localtime_r(&ts.tv_sec, &tm_buf);

    fprintf(stderr, "%s%02d:%02d:%02d.%03ld%s",
            CLR_DIM,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
            ts.tv_nsec / 1000000L,
            CLR_RESET);
}

/* ================================================================
 * ANA LOG FONKSİYONU
 *
 * Format: [HH:MM:SS.mmm] [SEV] [MODÜL] mesaj    (dosya:satır)
 * ================================================================ */
void nox_log_impl(log_level_t level, log_module_t mod,
                  const char *file, int line,
                  const char *fmt, ...)
{
    if ((unsigned)mod >= LOG_MOD_COUNT)
        mod = LOG_MOD_MAIN;

    if ((unsigned)level > LOG_LEVEL_FATAL)
        level = LOG_LEVEL_INFO;

    /* Zaman damgası */
    fprintf(stderr, "[");
    print_timestamp();
    fprintf(stderr, "] ");

    /* Seviye */
    fprintf(stderr, "[%s%s%s] ",
            levels[level].color,
            levels[level].tag,
            CLR_RESET);

    /* Modül */
    fprintf(stderr, "[%s%s%s] ",
            modules[mod].color,
            modules[mod].name,
            CLR_RESET);

    /* Mesaj */
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    /* Kaynak dosya — yalnızca debug build */
#ifdef DEBUG
    /* Dosya yolundan sadece basename al */
    const char *base = file;
    for (const char *p = file; *p; p++) {
        if (*p == '/')
            base = p + 1;
    }
    fprintf(stderr, "  %s(%s:%d)%s", CLR_DIM, base, line, CLR_RESET);
#else
    (void)file;
    (void)line;
#endif

    fprintf(stderr, "\n");
    fflush(stderr);
}

/* ================================================================
 * HEX DUMP — binary data görselleştirme
 *
 * Key debug için kritik. Her satırda 16 byte, ASCII karşılığı ile.
 * Yalnızca DEBUG build'de çalışır (çağıran makro kontrol eder).
 * ================================================================ */
void nox_hexdump(log_module_t mod, const char *label,
                 const void *data, size_t len)
{
#ifdef DEBUG
    const uint8_t *p = (const uint8_t *)data;

    NOX_DEBUG(mod, "hexdump: %s (%zu bytes)", label, len);

    for (size_t off = 0; off < len; off += 16) {
        /* Offset */
        fprintf(stderr, "  %04zx: ", off);

        /* Hex */
        for (size_t i = 0; i < 16; i++) {
            if (off + i < len)
                fprintf(stderr, "%02x ", p[off + i]);
            else
                fprintf(stderr, "   ");
            if (i == 7)
                fprintf(stderr, " ");
        }

        fprintf(stderr, " |");

        /* ASCII */
        for (size_t i = 0; i < 16 && off + i < len; i++) {
            uint8_t c = p[off + i];
            fprintf(stderr, "%c", (c >= 0x20 && c < 0x7f) ? (char)c : '.');
        }

        fprintf(stderr, "|\n");
    }
    fflush(stderr);
#else
    (void)mod; (void)label; (void)data; (void)len;
#endif
}

/* ================================================================
 * HATA KODU → STRING
 * ================================================================ */
const char *nox_strerror(nox_err_t err)
{
    switch (err) {
    case NOX_OK:           return "başarılı";
    case NOX_ERR_ALLOC:    return "bellek ayırma hatası";
    case NOX_ERR_CRYPTO:   return "kriptografi hatası";
    case NOX_ERR_IO:       return "I/O hatası";
    case NOX_ERR_PROTO:    return "protokol hatası";
    case NOX_ERR_AUTH:     return "MAC doğrulama başarısız";
    case NOX_ERR_LOCKED:   return "bellek kilitleme başarısız";
    case NOX_ERR_PIN:      return "geçersiz PIN";
    case NOX_ERR_CONFIG:   return "yapılandırma hatası";
    case NOX_ERR_TOR:      return "Tor hatası";
    case NOX_ERR_NET:      return "ağ hatası";
    case NOX_ERR_DB:       return "veritabanı hatası";
    case NOX_ERR_OVERFLOW: return "taşma hatası";
    case NOX_ERR_STATE:    return "geçersiz durum geçişi";
    }
    return "bilinmeyen hata";
}

/* ================================================================
 * PIN DOĞRULAMA — test edilebilir saf fonksiyon
 *
 * Kurallar:
 *   1. Minimum NOX_PIN_MIN_LEN (8) byte
 *   2. Maksimum NOX_PIN_MAX_LEN (128) byte
 *   3. Embedded null byte yasak (binary injection)
 *   4. Sadece printable ASCII + UTF-8 continuation bytes
 *
 * Terminal'e bağımlı DEĞİL — unit test edilebilir.
 * ================================================================ */
nox_err_t validate_pin(const char *pin, size_t raw_len)
{
    if (!pin)
        return NOX_ERR_PIN;

    /* Uzunluk kontrolleri */
    if (raw_len < NOX_PIN_MIN_LEN) {
        NOX_ERROR(LOG_MOD_MAIN,
                  "PIN çok kısa: %zu byte (minimum %u)",
                  raw_len, NOX_PIN_MIN_LEN);
        return NOX_ERR_PIN;
    }

    if (raw_len > NOX_PIN_MAX_LEN) {
        NOX_ERROR(LOG_MOD_MAIN,
                  "PIN çok uzun: %zu byte (maksimum %u)",
                  raw_len, NOX_PIN_MAX_LEN);
        return NOX_ERR_PIN;
    }

    /*
     * Karakter kontrolü — embedded null ve kontrol karakterleri yasak.
     * Tab hariç tüm kontrol karakterleri reddedilir.
     * UTF-8 multi-byte devamları (0x80-0xFF) kabul edilir.
     */
    for (size_t i = 0; i < raw_len; i++) {
        unsigned char c = (unsigned char)pin[i];
        if (c == 0x00) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "PIN'de null byte tespit edildi (offset %zu)", i);
            return NOX_ERR_PIN;
        }
        if (c < 0x20 && c != '\t') {
            NOX_ERROR(LOG_MOD_MAIN,
                      "PIN'de geçersiz kontrol karakteri: 0x%02x", c);
            return NOX_ERR_PIN;
        }
        if (c == 0x7F) {
            NOX_ERROR(LOG_MOD_MAIN, "PIN'de DEL karakteri");
            return NOX_ERR_PIN;
        }
    }

    return NOX_OK;
}
