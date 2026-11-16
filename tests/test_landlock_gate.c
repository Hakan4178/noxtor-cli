/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_landlock_gate.c — ABI probe sınıflandırması + event loop
 * Landlock kapısı fault-injection testleri.
 *
 * İki şeyi doğrular:
 *   1. landlock_syscall_status(): ENOSYS/EOPNOTSUPP → unsupported,
 *      EINVAL/diğer → config hatası.
 *   2. event_loop_landlock_gate(): gerçek abort/return davranışı —
 *      state->running=false, init çağrı sırası, socks fd kapatma.
 *
 * Kernel/Landlock gerektirmez; fake ops enjekte edilir.
 *
 * Compile:  (make test tarafından otomatik — TEST_SRCS wildcard)
 * Run:      ./tests/test_landlock_gate
 * ================================================================ */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "event_loop.h"
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

/* ── Fake Landlock ops ─────────────────────────────────────────── */

struct fake_ops_state {
    int abi_ret;
    int abi_errno;
    int socks_ret;
    int socks_errno;
    nox_err_t init_ret;
    bool active;

    int abi_calls;
    int open_calls;
    int init_calls;
    int close_calls;

    int last_config_fd;
    int last_downloads_fd;
    int last_tor_data_fd;
    int last_socks_fd;
    int last_closed_fd;
};

static struct fake_ops_state g_fake;
static struct app_state g_state;

static int fake_abi_version(void) {
    g_fake.abi_calls++;
    errno = g_fake.abi_errno;
    return g_fake.abi_ret;
}

static int fake_open_socks(const char *path) {
    (void)path;
    g_fake.open_calls++;
    errno = g_fake.socks_errno;
    return g_fake.socks_ret;
}

static nox_err_t fake_sandbox_init(int config_fd, int downloads_fd,
                                   int tor_data_fd, int socks_fd) {
    g_fake.init_calls++;
    g_fake.last_config_fd = config_fd;
    g_fake.last_downloads_fd = downloads_fd;
    g_fake.last_tor_data_fd = tor_data_fd;
    g_fake.last_socks_fd = socks_fd;
    return g_fake.init_ret;
}

static nox_hardbool_t fake_is_active(void) {
    return g_fake.active ? true : false;
}

static int fake_close_fd(int fd) {
    g_fake.close_calls++;
    g_fake.last_closed_fd = fd;
    return 0;
}

static const struct nox_ll_gate_ops g_fake_ops = {
    .abi_version = fake_abi_version,
    .open_socks = fake_open_socks,
    .sandbox_init = fake_sandbox_init,
    .is_active = fake_is_active,
    .close_fd = fake_close_fd,
};

static void fake_reset(void) {
    memset(&g_fake, 0, sizeof(g_fake));
    g_fake.abi_ret = 8;
    g_fake.socks_ret = -1;
    g_fake.init_ret = NOX_OK;
    g_fake.active = true;
}

static void state_reset(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.running = true;
    g_state.config_dir_fd = 10;
    g_state.downloads_dir_fd = 11;
    g_state.tor_data_fd = 12;
    g_state.allow_unsandboxed_fs = false;
    g_state.require_landlock_resolve_unix = false;
    snprintf(g_state.socks_path, sizeof(g_state.socks_path), "%s",
             "/tmp/noxtor-test.sock");
}

/* ── 1. Saf ABI errno sınıflandırması ─────────────────────────── */

static void test_abi_status_matrix(void) {
    static const struct {
        const char *name;
        int ret;
        int err;
        nox_ll_syscall_status_t expected;
    } cases[] = {
        { "ABI 9 başarı", 9, 0, NOX_LL_SYSCALL_OK },
        { "ABI 1 başarı", 1, 0, NOX_LL_SYSCALL_OK },
        { "ABI 0 (çağıran unsupported sayar)", 0, 0,
          NOX_LL_SYSCALL_OK },
        { "ENOSYS → unsupported", -1, ENOSYS,
          NOX_LL_SYSCALL_UNSUPPORTED },
        { "EOPNOTSUPP → unsupported", -1, EOPNOTSUPP,
          NOX_LL_SYSCALL_UNSUPPORTED },
        { "EINVAL → config", -1, EINVAL,
          NOX_LL_SYSCALL_CONFIG_ERROR },
        { "EACCES → config", -1, EACCES,
          NOX_LL_SYSCALL_CONFIG_ERROR },
        { "ENOMEM → config", -1, ENOMEM,
          NOX_LL_SYSCALL_CONFIG_ERROR },
        { "errno 0 → config (defansif)", -1, 0,
          NOX_LL_SYSCALL_CONFIG_ERROR },
    };

    printf("\n== ABI probe errno sınıflandırması ==\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        nox_ll_syscall_status_t got =
            landlock_syscall_status(cases[i].ret, cases[i].err);
        CHECK(got == cases[i].expected, cases[i].name);
    }
}

/* ── 2. Event loop Landlock kapısı ────────────────────────────── */

typedef struct {
    const char *name;
    int abi_ret;
    int abi_errno;
    int socks_ret;
    int socks_errno;
    nox_err_t init_ret;
    bool active;
    bool strict;
    bool allow;
    int config_fd;
    int downloads_fd;
    int tor_data_fd;
    bool expected_ret;
    bool expected_running;
    int expected_abi_calls;
    int expected_open_calls;
    int expected_init_calls;
    int expected_close_calls;
} gate_case_t;

static void run_gate_case(const gate_case_t *c) {
    fake_reset();
    state_reset();

    g_fake.abi_ret = c->abi_ret;
    g_fake.abi_errno = c->abi_errno;
    g_fake.socks_ret = c->socks_ret;
    g_fake.socks_errno = c->socks_errno;
    g_fake.init_ret = c->init_ret;
    g_fake.active = c->active;

    g_state.require_landlock_resolve_unix = c->strict;
    g_state.allow_unsandboxed_fs = c->allow;
    g_state.config_dir_fd = c->config_fd;
    g_state.downloads_dir_fd = c->downloads_fd;
    g_state.tor_data_fd = c->tor_data_fd;

    bool got = event_loop_landlock_gate(&g_state, &g_fake_ops);
    char label[256];

    snprintf(label, sizeof(label), "%s: dönüş", c->name);
    CHECK(got == c->expected_ret, label);

    snprintf(label, sizeof(label), "%s: running", c->name);
    CHECK(g_state.running == c->expected_running, label);

    snprintf(label, sizeof(label), "%s: abi çağrısı", c->name);
    CHECK(g_fake.abi_calls == c->expected_abi_calls, label);

    snprintf(label, sizeof(label), "%s: socks açma", c->name);
    CHECK(g_fake.open_calls == c->expected_open_calls, label);

    snprintf(label, sizeof(label), "%s: init çağrısı", c->name);
    CHECK(g_fake.init_calls == c->expected_init_calls, label);

    snprintf(label, sizeof(label), "%s: close çağrısı", c->name);
    CHECK(g_fake.close_calls == c->expected_close_calls, label);
}

static void test_gate_matrix(void) {
    static const gate_case_t cases[] = {
        /* fd / tor_data ön-kontrolleri: init'e hiç gidilmez. */
        { .name = "tor_data fd yok",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_OK, .active = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = -1,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 0, .expected_open_calls = 0,
          .expected_init_calls = 0, .expected_close_calls = 0 },

        { .name = "config fd yok",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_OK, .active = true,
          .config_fd = -1, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 0, .expected_open_calls = 0,
          .expected_init_calls = 0, .expected_close_calls = 0 },

        { .name = "downloads fd yok",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_OK, .active = true,
          .config_fd = 10, .downloads_fd = -1, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 0, .expected_open_calls = 0,
          .expected_init_calls = 0, .expected_close_calls = 0 },

        /* Strict F1: ABI < 9'da init'e gitmeden abort. */
        { .name = "strict ABI 8",
          .abi_ret = 8, .init_ret = NOX_OK, .active = true, .strict = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 0, .expected_close_calls = 0 },

        /* ABI 9: socks fd zorunlu. */
        { .name = "ABI 9 socks yok",
          .abi_ret = 9, .socks_ret = -1, .socks_errno = EACCES,
          .init_ret = NOX_OK, .active = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 1,
          .expected_init_calls = 0, .expected_close_calls = 0 },

        /* Sağlıklı ABI 9: init fd'leri alır, socks fd kapatılır. */
        { .name = "ABI 9 başarılı",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_OK, .active = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = true, .expected_running = true,
          .expected_abi_calls = 1, .expected_open_calls = 1,
          .expected_init_calls = 1, .expected_close_calls = 1 },

        /* F5 invariant: init OK ama aktif değil → abort. */
        { .name = "init OK + aktif değil",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_OK, .active = false,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 1,
          .expected_init_calls = 1, .expected_close_calls = 1 },

        /* Config hatası: onay bayrağı bypass etmez. */
        { .name = "init config + onay",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_ERR_CONFIG,
          .active = false, .allow = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 1,
          .expected_init_calls = 1, .expected_close_calls = 1 },

        /* Unsupported: varsayılan abort. */
        { .name = "unsupported + onay yok",
          .abi_ret = -1, .abi_errno = ENOSYS,
          .init_ret = NOX_ERR_LANDLOCK_UNSUPPORTED, .active = false,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 1, .expected_close_calls = 0 },

        /* Unsupported + açık onay → uyarıyla devam. */
        { .name = "unsupported + onay",
          .abi_ret = -1, .abi_errno = EOPNOTSUPP,
          .init_ret = NOX_ERR_LANDLOCK_UNSUPPORTED, .active = false,
          .allow = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = true, .expected_running = true,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 1, .expected_close_calls = 0 },

        /* Çelişkili durum: unsupported ama aktif → abort. */
        { .name = "unsupported + aktif + onay",
          .abi_ret = -1, .abi_errno = ENOSYS,
          .init_ret = NOX_ERR_LANDLOCK_UNSUPPORTED, .active = true,
          .allow = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 1, .expected_close_calls = 0 },

        /* ABI 1-8: görünür uyarı, normal devam (socks yok). */
        { .name = "ABI 8 normal",
          .abi_ret = 8, .init_ret = NOX_OK, .active = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = true, .expected_running = true,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 1, .expected_close_calls = 0 },

        { .name = "ABI 1 normal",
          .abi_ret = 1, .init_ret = NOX_OK, .active = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = true, .expected_running = true,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 1, .expected_close_calls = 0 },

        /* Bayrak, aktif sandbox'ta etkisiz. */
        { .name = "ABI 9 + onay (bayrak etkisiz)",
          .abi_ret = 9, .socks_ret = 42, .init_ret = NOX_OK, .active = true,
          .allow = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = true, .expected_running = true,
          .expected_abi_calls = 1, .expected_open_calls = 1,
          .expected_init_calls = 1, .expected_close_calls = 1 },

        /* IO hatası + onay: yine abort. */
        { .name = "ABI 1 init IO + onay",
          .abi_ret = 1, .init_ret = NOX_ERR_IO, .active = false,
          .allow = true,
          .config_fd = 10, .downloads_fd = 11, .tor_data_fd = 12,
          .expected_ret = false, .expected_running = false,
          .expected_abi_calls = 1, .expected_open_calls = 0,
          .expected_init_calls = 1, .expected_close_calls = 0 },
    };

    printf("\n== Event loop Landlock kapısı (fault injection) ==\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        run_gate_case(&cases[i]);
    }
}

/* Başarılı init'e giden fd'ler ve socks fd kapatma davranışı. */
static void test_gate_fd_passing(void) {
    fake_reset();
    state_reset();

    g_fake.abi_ret = 9;
    g_fake.socks_ret = 42;
    g_fake.init_ret = NOX_OK;
    g_fake.active = true;

    bool got = event_loop_landlock_gate(&g_state, &g_fake_ops);

    CHECK(got == true, "fd aktarımı: dönüş");
    CHECK(g_fake.last_config_fd == 10, "fd aktarımı: config");
    CHECK(g_fake.last_downloads_fd == 11, "fd aktarımı: downloads");
    CHECK(g_fake.last_tor_data_fd == 12, "fd aktarımı: tor_data");
    CHECK(g_fake.last_socks_fd == 42, "fd aktarımı: socks");
    CHECK(g_fake.last_closed_fd == 42, "fd aktarımı: socks kapatıldı");
}

int main(void) {
    printf("=== Landlock ABI + event loop kapı testi ===\n");

    test_abi_status_matrix();
    test_gate_matrix();
    test_gate_fd_passing();

    printf("\nSonuç: %d/%d\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
