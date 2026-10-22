/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_log.c — nox_strerror exhaustive sözleşmesi
 *
 * Amaç: nox_err_t'ye yeni bir değer eklendiğinde nox_strerror()
 * switch'inin ve kullanıcıya gösterilen metnin sessizce eksik
 * kalmamasını normal test paketinde de zorunlu kılmak.
 *
 * Bu test, tests/cbmc_log.c'deki formal harness'in hızlı ve
 * ASan/UBSan altında çalışan ikizidir.
 */

#include "common.h"
#include "test_common.h"

#include <string.h>

struct err_case {
    nox_err_t code;
    const char *msg;
};

static int test_strerror_exhaustive(void)
{
    static const struct err_case cases[] = {
        { NOX_OK,           "başarılı" },
        { NOX_ERR_ALLOC,    "bellek ayırma hatası" },
        { NOX_ERR_CRYPTO,   "kriptografi hatası" },
        { NOX_ERR_IO,       "I/O hatası" },
        { NOX_ERR_PROTO,    "protokol hatası" },
        { NOX_ERR_AUTH,     "MAC doğrulama başarısız" },
        { NOX_ERR_LOCKED,   "bellek kilitleme başarısız" },
        { NOX_ERR_PIN,      "geçersiz PIN" },
        { NOX_ERR_CONFIG,   "yapılandırma hatası" },
        { NOX_ERR_TOR,      "Tor hatası" },
        { NOX_ERR_NET,      "ağ hatası" },
        { NOX_ERR_DB,       "veritabanı hatası" },
        { NOX_ERR_OVERFLOW, "taşma hatası" },
        { NOX_ERR_STATE,    "geçersiz durum geçişi" },
        { NOX_ERR_NOT_FOUND,"öğe bulunamadı" },
        { NOX_ERR_LANDLOCK_UNSUPPORTED,
          "Landlock desteklenmiyor (kernel 5.13+ gerekli)" },
        { NOX_ERR_TIMEOUT,  "zaman aşımı" },
        { NOX_ERR_PEER,     "peer kimliği doğrulanamadı" },
        { NOX_ERR_ONION,    "onion kimlik doğrulama hatası" },
        { NOX_ERR_QUOTA,    "dosya boyutu/kota sınırı aşıldı" },
    };

    const size_t n = sizeof(cases) / sizeof(cases[0]);
    TEST_ASSERT(n == 20);

    for (size_t i = 0; i < n; i++) {
        const char *s = nox_strerror(cases[i].code);
        TEST_ASSERT(s != NULL);
        TEST_ASSERT(strlen(s) > 0);
        TEST_ASSERT(strcmp(s, cases[i].msg) == 0);
    }

    return 0;
}

int main(void)
{
    fprintf(stderr, "=== nox_strerror exhaustive testi ===\n");

    RUN_TEST(test_strerror_exhaustive);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
