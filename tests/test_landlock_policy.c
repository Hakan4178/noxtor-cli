/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_landlock_policy.c — F5 fail-closed karar matrisi testleri
 *
 * Landlock dosya sistemi politikasının saf karar fonksiyonunu
 * (landlock_fs_policy_decide) doğrular. Kernel/Landlock gerektirmez;
 * her CI'da ve Android/arm64 build'inde de derlenebilir.
 *
 * Matris:
 *   - Eksik config/downloads fd              → ABORT (bayrak bypass etmez)
 *   - init OK + aktif                        → RUN
 *   - init OK + aktif değil (invariant)      → ABORT
 *   - UNSUPPORTED + onay yok                 → ABORT (varsayılan fail-closed)
 *   - UNSUPPORTED + onay var + aktif değil   → RUN_UNSANDBOXED
 *   - UNSUPPORTED + onay var + aktif         → ABORT (tutarsız durum)
 *   - CONFIG / IO / diğer hatalar + onay var → ABORT (bayrak yalnız
 *                                              UNSUPPORTED için geçerli)
 *
 * Compile:  (make test tarafından otomatik — TEST_SRC_OBJS'a linklenir)
 * Run:      ./tests/test_landlock_policy
 * ================================================================ */
#include <stdio.h>
#include <string.h>

#include "landlock_sandbox.h"

static int g_passed = 0;
static int g_total = 0;

#define CHECK(cond, name) do {                                      \
    g_total++;                                                      \
    if (cond) {                                                     \
        g_passed++;                                                 \
        printf("  [%2d] %-58s OK\n", g_total, name);                \
    } else {                                                        \
        printf("  [%2d] %-58s FAIL\n", g_total, name);              \
    }                                                               \
} while (0)

typedef struct {
    const char *name;
    bool fds_ok;
    nox_err_t init_rc;
    bool active;
    bool allow_unsandboxed;
    nox_ll_fs_policy_t expected;
} policy_case_t;

static void test_policy_matrix(void) {
    static const policy_case_t cases[] = {
        /* Eksik fd: her durumda abort — allow bayrağı kurtarmaz. */
        { "eksik fd + unsupported + onay", false,
          NOX_ERR_LANDLOCK_UNSUPPORTED, false, true, NOX_LL_FS_ABORT },
        { "eksik fd + init OK + aktif", false,
          NOX_OK, true, false, NOX_LL_FS_ABORT },
        { "eksik fd + init OK + onay", false,
          NOX_OK, false, true, NOX_LL_FS_ABORT },

        /* Sağlıklı sandbox. */
        { "init OK + aktif", true,
          NOX_OK, true, false, NOX_LL_FS_RUN },
        { "init OK + aktif + onay (bayrak etkisiz)", true,
          NOX_OK, true, true, NOX_LL_FS_RUN },

        /* init OK dedi ama aktiflik yok: invariant ihlali, fail-closed. */
        { "init OK + aktif değil", true,
          NOX_OK, false, false, NOX_LL_FS_ABORT },
        { "init OK + aktif değil + onay", true,
          NOX_OK, false, true, NOX_LL_FS_ABORT },

        /* Desteklenmiyor: varsayılan abort, yalnız açık onayla devam. */
        { "unsupported + onay yok", true,
          NOX_ERR_LANDLOCK_UNSUPPORTED, false, false, NOX_LL_FS_ABORT },
        { "unsupported + onay var", true,
          NOX_ERR_LANDLOCK_UNSUPPORTED, false, true,
          NOX_LL_FS_RUN_UNSANDBOXED },

        /* Desteklenmiyor ama aktiflik true: çelişkili durum, abort. */
        { "unsupported + aktif + onay", true,
          NOX_ERR_LANDLOCK_UNSUPPORTED, true, true, NOX_LL_FS_ABORT },

        /* Yapılandırma/diğer hatalar: bayrak bypass etmez. */
        { "config hatası + onay var", true,
          NOX_ERR_CONFIG, false, true, NOX_LL_FS_ABORT },
        { "config hatası + onay yok", true,
          NOX_ERR_CONFIG, false, false, NOX_LL_FS_ABORT },
        { "IO hatası + onay var", true,
          NOX_ERR_IO, false, true, NOX_LL_FS_ABORT },
        { "beklenmeyen hata + onay var", true,
          NOX_ERR_STATE, false, true, NOX_LL_FS_ABORT },
    };

    printf("\n== F5 karar matrisi (kernel gerektirmez) ==\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const policy_case_t *c = &cases[i];
        nox_ll_fs_policy_t got =
            landlock_fs_policy_decide(c->fds_ok, c->init_rc,
                                      c->active, c->allow_unsandboxed);
        CHECK(got == c->expected, c->name);
    }
}

int main(void) {
    printf("=== Landlock F5 Politika Testi ===\n");

    test_policy_matrix();

    printf("\nSonuç: %d/%d\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
