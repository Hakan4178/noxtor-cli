/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_common.h — Ortak test framework makroları (sıfır bağımlılık)
 *
 * Bu header'ı SADECE test dosyaları include eder (test binary'leri).
 * src/ nesneleri dahil edilmez — production koduna sızma yok.
 *
 * Kullanım:
 *   #include "test_common.h"   (aynı dizin olduğundan -I gerekmez)
 *
 * TEST_ASSERT   — başarısızlıkta satır numarasıyla FAIL basar ve 1 döner
 *                 (test fonksiyonu int dönmeli; return 1 = başarısız).
 * TEST_ASSERT_MEM_ZERO — bellek bloğunun tamamının sıfır olduğunu doğrular.
 * RUN_TEST      — testi çalıştırır, OK/FAIL renkli basar, sayacı ilerletir.
 *
 * Çıkış kodu sözleşmesi (main):
 *   return (tests_passed == tests_run) ? 0 : 1;
 */

#ifndef NOX_TEST_COMMON_H
#define NOX_TEST_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond) do {                                      \
    if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL %s:%d: %s\n",                        \
                __FILE__, __LINE__, #cond);                         \
        return 1;                                                   \
    }                                                               \
} while (0)

#define TEST_ASSERT_MEM_ZERO(ptr, len) do {                         \
    const uint8_t *_p = (const uint8_t *)(ptr);                     \
    for (size_t _i = 0; _i < (len); _i++) {                         \
        if (_p[_i] != 0) {                                          \
            fprintf(stderr, "FAIL: bellek sıfır değil"              \
                    " offset=%zu val=0x%02x\n", _i, _p[_i]);       \
            return 1;                                               \
        }                                                           \
    }                                                               \
} while (0)

#define RUN_TEST(test_fn) do {                                      \
    tests_run++;                                                    \
    fprintf(stderr, "  [%d] %-45s ", tests_run, #test_fn);          \
    if (test_fn() == 0) {                                           \
        tests_passed++;                                             \
        fprintf(stderr, "\033[32mOK\033[0m\n");                     \
    } else {                                                        \
        fprintf(stderr, "\033[31mFAIL\033[0m\n");                   \
    }                                                               \
} while (0)

/* ================================================================
 * Ortak yardımcılar
 * ================================================================ */

/*
 * nox_test_base32_encode — RFC4648 base32 (lowercase, padding yok).
 * v3 onion body (pub(32) || checksum(2) || 0x03 = 35 byte) → 56 char.
 * out kapasitesi: ceil(inlen * 8 / 5) + 1 byte (NUL) olmalı.
 * (test_onion_bind + test_onion_derive aynı kodlayıcıyı paylaşır.)
 */
static inline void nox_test_base32_encode(const uint8_t *in, size_t inlen,
                                          char *out)
{
    static const char ALPHA[] = "abcdefghijklmnopqrstuvwxyz234567";
    size_t bitbuf = 0;
    int    bits   = 0;
    size_t o      = 0;

    for (size_t i = 0; i < inlen; i++) {
        bitbuf = (bitbuf << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            out[o++] = ALPHA[(bitbuf >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if (bits > 0)
        out[o++] = ALPHA[(bitbuf << (5 - bits)) & 0x1F];
    out[o] = '\0';
}

#endif /* NOX_TEST_COMMON_H */
