/* ================================================================
 * test_landlock_rights.c — Landlock hak maskeleme testleri
 *
 * C-1 + C-2 regresyon testleri. İki katman:
 *
 * 1) Saf fonksiyon testleri (GERÇEK KERNEL GEREKMEZ — her CI'da çalışır):
 *    nox_ll_compute_rule_rights(wanted, handled) maskesi üzerinden:
 *      - C-2: ABI 1-2'de TRUNCATE otomatik elenir (allowed ⊄ handled → EINVAL
 *             kernel hatası asla oluşamaz — subset invariant test edilir)
 *      - C-1: MAKE_REG her ABI'da allowed'da kalır (downloads'da O_CREAT çalışır)
 *
 * 2) Entegrasyon testi (gerçek kernel, Landlock ABI >= 1):
 *      - downloads içinde openat(O_CREAT) → BAŞARI beklenir
 *      - downloads dışında openat(O_CREAT) → EACCES beklenir
 *        (sandbox'ın hem izin verdiğini hem GERÇEKTEN kısıtladığını doğrular —
 *        C-1'in "sandbox kuruldu ama hiçbir şey çalışmıyor" tuzağını yakalar)
 *
 * 3) F1 testleri (ABI >= 9):
 *      - yalnız socks.sock inode'una RESOLVE_UNIX istisnası verilir
 *      - izinli socks connect BAŞARILI, control.sock connect EACCES
 *      - socks_fd = -1 / dizin / normal dosya → init fail-closed
 *
 * 4) F3 testleri (her ABI):
 *      - config kökünde identity.key/salt/contacts.db/WAL/SHM unlink → EACCES
 *      - tor_data içinde torrc/listen.sock/alt dizin silme → OK
 *      - tor_data_fd = -1 / normal dosya → init fail-closed
 *      - tor_data dizininin kendisi config'ten silinemez (EACCES);
 *        boş dizin sonraki açılışta cleanup_stale_tor_dirs'e kalır
 *      - tor_data içinde yeni dosya oluşturma → EACCES (MAKE_REG yok)
 *
 * Kernel'de Landlock yoksa entegrasyon testi SKIP edilir (fail değil).
 * ABI < 9'da F1 kısmı SKIP edilir; C-1/C-2/F3 entegrasyonu yine koşar.
 *
 * Compile:  (make test tarafından otomatik — TEST_SRC_OBJS'a linklenir)
 * Run:      ./tests/test_landlock_rights
 * ================================================================ */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "landlock_sandbox.h"

static int g_passed = 0;
static int g_total = 0;

#define CHECK(cond, name) do {                                      \
    g_total++;                                                      \
    if (cond) {                                                     \
        g_passed++;                                                 \
        printf("  [%2d] %-46s OK\n", g_total, name);                \
    } else {                                                        \
        printf("  [%2d] %-46s FAIL (errno=%d %s)\n",                \
               g_total, name, errno, strerror(errno));              \
    }                                                               \
} while (0)

/* ── 1. Saf fonksiyon testleri — kernel gerekmez ──────────────────── */

static void test_abi1_truncate_excluded(void) {
    printf("\n== Saf fonksiyon (kernel gerektirmez) ==\n");
    __u64 handled_abi1 = NOX_LL_BASE_RIGHTS;              /* ABI 1: REFER/TRUNCATE yok */
    __u64 wanted = NOX_LL_BASE_RIGHTS | LANDLOCK_ACCESS_FS_TRUNCATE;
    __u64 allowed = nox_ll_compute_rule_rights(wanted, handled_abi1);

    /* C-2 regresyonu: ABI < 3'te TRUNCATE allowed'a giremez */
    CHECK((allowed & LANDLOCK_ACCESS_FS_TRUNCATE) == 0,
          "abi1: TRUNCATE elenir (C-2)");
    /* subset invariant: allowed her zaman handled'ın alt kümesi */
    CHECK((allowed | handled_abi1) == handled_abi1,
          "abi1: subset invariant (allowed|handled)==handled");
    CHECK((allowed & ~handled_abi1) == 0,
          "abi1: allowed'da handled dışı hak yok");
}

static void test_make_reg_always_present(void) {
    __u64 handled_abi1 = NOX_LL_BASE_RIGHTS;
    __u64 wanted = NOX_LL_BASE_RIGHTS | LANDLOCK_ACCESS_FS_TRUNCATE;
    __u64 allowed = nox_ll_compute_rule_rights(wanted, handled_abi1);

    /* C-1 regresyonu: MAKE_REG wanted'ta → allowed'da kalmalı */
    CHECK((allowed & LANDLOCK_ACCESS_FS_MAKE_REG) != 0,
          "abi1: MAKE_REG korunur (C-1)");

    /* Least-privilege: wanted'ta olmayan hak eklenemez */
    __u64 wanted_lean = LANDLOCK_ACCESS_FS_READ_FILE |
                        LANDLOCK_ACCESS_FS_WRITE_FILE |
                        LANDLOCK_ACCESS_FS_READ_DIR  |
                        LANDLOCK_ACCESS_FS_REMOVE_FILE |
                        LANDLOCK_ACCESS_FS_MAKE_REG;
    __u64 allowed_lean = nox_ll_compute_rule_rights(wanted_lean, handled_abi1);
    CHECK((allowed_lean & LANDLOCK_ACCESS_FS_MAKE_DIR) == 0,
          "abi1: wanted'ta olmayan MAKE_DIR eklenmez");
}

static void test_abi_conditional_rights(void) {
    /* ABI 2: REFER eklenmeli, TRUNCATE hâlâ elenmeli */
    __u64 handled_abi2 = NOX_LL_BASE_RIGHTS | LANDLOCK_ACCESS_FS_REFER;
    __u64 wanted = NOX_LL_BASE_RIGHTS | LANDLOCK_ACCESS_FS_REFER
                 | LANDLOCK_ACCESS_FS_TRUNCATE;
    __u64 allowed = nox_ll_compute_rule_rights(wanted, handled_abi2);

    CHECK((allowed & LANDLOCK_ACCESS_FS_REFER) != 0,
          "abi2: REFER korunur");
    CHECK((allowed & LANDLOCK_ACCESS_FS_TRUNCATE) == 0,
          "abi2: TRUNCATE elenir");
    CHECK((allowed | handled_abi2) == handled_abi2,
          "abi2: subset invariant");

    /* ABI 3: TRUNCATE de eklenmeli */
    __u64 handled_abi3 = handled_abi2 | LANDLOCK_ACCESS_FS_TRUNCATE;
    allowed = nox_ll_compute_rule_rights(wanted, handled_abi3);
    CHECK((allowed & LANDLOCK_ACCESS_FS_TRUNCATE) != 0,
          "abi3: TRUNCATE korunur");
    CHECK((allowed | handled_abi3) == handled_abi3,
          "abi3: subset invariant");

    /* ABI 5 (IOCTL_DEV): handled'da olsa bile wanted'ta yoksa eklenmez */
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    __u64 handled_abi5 = handled_abi3 | LANDLOCK_ACCESS_FS_IOCTL_DEV;
    allowed = nox_ll_compute_rule_rights(wanted, handled_abi5);
    CHECK((allowed & LANDLOCK_ACCESS_FS_IOCTL_DEV) == 0,
          "abi5: IOCTL_DEV wanted'ta yok → eklenmez");
    CHECK((allowed | handled_abi5) == handled_abi5,
          "abi5: subset invariant");
#endif
}

static void test_resolve_unix_masking(void) {
    printf("\n== F1: RESOLVE_UNIX maskeleme ==\n");

    /* ABI 8: RESOLVE_UNIX henüz yok → wanted olsa bile allowed = 0 */
    __u64 handled_abi8 = NOX_LL_BASE_RIGHTS |
                         LANDLOCK_ACCESS_FS_REFER |
                         LANDLOCK_ACCESS_FS_TRUNCATE;
    __u64 allowed = nox_ll_compute_rule_rights(
        LANDLOCK_ACCESS_FS_RESOLVE_UNIX, handled_abi8);
    CHECK(allowed == 0, "abi8: RESOLVE_UNIX elenir (F1-U1)");
    CHECK((allowed | handled_abi8) == handled_abi8,
          "abi8: subset invariant (F1-U3)");

    /* Base rights'a sızmamalı — yoksa ABI < 9'da EINVAL olur */
    CHECK((NOX_LL_BASE_RIGHTS & LANDLOCK_ACCESS_FS_RESOLVE_UNIX) == 0,
          "base rights'ta RESOLVE_UNIX yok (F1-U4)");

    /* ABI 9: bit handled'a girince wanted korunur */
    __u64 handled_abi9 = handled_abi8 | LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    allowed = nox_ll_compute_rule_rights(
        LANDLOCK_ACCESS_FS_RESOLVE_UNIX, handled_abi9);
    CHECK(allowed == LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
          "abi9: RESOLVE_UNIX korunur (F1-U2)");
    CHECK((allowed | handled_abi9) == handled_abi9,
          "abi9: subset invariant (F1-U3)");
}

/* ── F1 yardımcıları ─────────────────────────────────────────────── */

static int make_unix_listener(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    size_t len = strlen(path);
    if (len >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(addr.sun_path, path, len);
    addr.sun_path[len] = '\0';

    (void)unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (listen(fd, 4) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int connect_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    size_t len = strlen(path);
    if (len >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(addr.sun_path, path, len);
    addr.sun_path[len] = '\0';

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}

/* Geçersiz fd ile init'in fail-closed döndüğünü ayrı child'da doğrula
 * (başarısız init ana test sürecini kilitlemesin). */
static int run_init_expect_config_fail(int cfg_fd, int dl_fd, int td_fd,
                                       int socks_fd) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        nox_err_t err = landlock_sandbox_init(cfg_fd, dl_fd, td_fd, socks_fd);
        _exit(err == NOX_ERR_CONFIG ? 0 : 1);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0)
        return 1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
}

/* Dizin içinde normal dosya oluştur (fork öncesi hazırlık). */
static int make_file_at(int dir_fd, const char *name, const char *content) {
    int fd = openat(dir_fd, name,
                    O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    close(fd);
    return (w == (ssize_t)len) ? 0 : -1;
}

/* ── 2. Entegrasyon testi — gerçek kernel, Landlock ABI >= 1 ───────
 * Sandbox ayrı child process'te uygulanır:
 *  - child: landlock_sandbox_init + openat kontrolleri, _exit ile çıkar
 *    (LSAN'ı atlar — sandbox sonrası /proc okunamaz)
 *  - parent: sandbox'sızdır → /proc erişimi ve dizin temizliği sorunsuz
 * Return: 0 = GEÇTİ, 1 = BAŞARISIZ, 2 = SKIP (kernel Landlock'suz)  */

static int run_integration(void) {
    char dl_tpl[] = "/tmp/ll_dl_XXXXXX";
    char out_tpl[] = "/tmp/ll_out_XXXXXX";
    char cfg_tpl[] = "/tmp/ll_cfg_XXXXXX";
    char *dl_dir = mkdtemp(dl_tpl);
    char *out_dir = mkdtemp(out_tpl);
    char *cfg_dir = mkdtemp(cfg_tpl);
    char td_name[64] = {0};
    char socks_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char control_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    char regular_path[NOX_PATH_MAX] = {0};
    int dl_fd = -1, out_fd = -1, cfg_fd = -1, td_fd = -1;
    int socks_fd = -1, socks_listener = -1, control_listener = -1;
    int regular_fd = -1, td_file_fd = -1;
    int rc = 1;
    int abi = -1;
    int tn = -1;
    pid_t pid = -1;
    int status = 0;

    if (!dl_dir || !out_dir || !cfg_dir) {
        printf("  [FAIL] mkdtemp başarısız (errno=%d)\n", errno);
        goto cleanup;
    }

    /* fd'ler sandbox'tan ÖNCE açılmalı — sonrasında dış erişim yok */
    dl_fd = open(dl_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    out_fd = open(out_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    cfg_fd = open(cfg_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dl_fd < 0 || out_fd < 0 || cfg_fd < 0) {
        printf("  [FAIL] dizin açılamadı (errno=%d)\n", errno);
        goto cleanup;
    }

    /* F3: tor_data_<pid> config kökünün altında — gerçek yerleşim. */
    tn = snprintf(td_name, sizeof(td_name), "tor_data_%d", (int)getpid());
    if (tn <= 0 || (size_t)tn >= sizeof(td_name) ||
        mkdirat(cfg_fd, td_name, 0700) != 0) {
        printf("  [FAIL] tor_data dizini oluşturulamadı (errno=%d %s)\n",
               errno, strerror(errno));
        goto cleanup;
    }
    td_fd = openat(cfg_fd, td_name,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (td_fd < 0) {
        printf("  [FAIL] tor_data fd açılamadı (errno=%d %s)\n",
               errno, strerror(errno));
        goto cleanup;
    }

    /* Fork öncesi fixture'lar: config'te korunması gerekenler,
     * tor_data'da silinmesi gerekenler. */
    if (make_file_at(cfg_fd, "identity.key", "encrypted-identity") != 0 ||
        make_file_at(cfg_fd, "salt", "salt-bytes") != 0 ||
        make_file_at(cfg_fd, "contacts.db", "sqlite-db") != 0 ||
        make_file_at(cfg_fd, "contacts.db-wal", "wal") != 0 ||
        make_file_at(cfg_fd, "contacts.db-shm", "shm") != 0 ||
        make_file_at(td_fd, "torrc", "SocksPort unix:socks.sock\n") != 0 ||
        make_file_at(td_fd, "listen.sock", "socket-placeholder") != 0 ||
        mkdirat(td_fd, "Cached", 0700) != 0 ||
        make_file_at(td_fd, "Cached/inner", "x") != 0) {
        printf("  [FAIL] test fixture oluşturulamadı (errno=%d %s)\n",
               errno, strerror(errno));
        goto cleanup;
    }

    /* tor_data_fd doğrulaması için normal dosya fd'si (F3-N2) */
    td_file_fd = openat(out_fd, "td_notdir",
                        O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (td_file_fd < 0) {
        printf("  [FAIL] td_notdir oluşturulamadı (errno=%d %s)\n",
               errno, strerror(errno));
        goto cleanup;
    }

    abi = landlock_abi_version();
    if (abi >= 9) {
        int n1 = snprintf(socks_path, sizeof(socks_path),
                          "%s/socks.sock", out_dir);
        int n2 = snprintf(control_path, sizeof(control_path),
                          "%s/control.sock", out_dir);
        int n3 = snprintf(regular_path, sizeof(regular_path),
                          "%s/notasock", out_dir);
        if (n1 <= 0 || (size_t)n1 >= sizeof(socks_path) ||
            n2 <= 0 || (size_t)n2 >= sizeof(control_path) ||
            n3 <= 0 || (size_t)n3 >= sizeof(regular_path)) {
            printf("  [FAIL] test soket yolu çok uzun\n");
            goto cleanup;
        }

        socks_listener = make_unix_listener(socks_path);
        control_listener = make_unix_listener(control_path);
        if (socks_listener < 0 || control_listener < 0) {
            printf("  [FAIL] Unix listener oluşturulamadı (errno=%d %s)\n",
                   errno, strerror(errno));
            goto cleanup;
        }

        socks_fd = landlock_open_unix_socket_fd(socks_path);
        if (socks_fd < 0) {
            printf("  [FAIL] socks O_PATH fd açılamadı (errno=%d %s)\n",
                   errno, strerror(errno));
            goto cleanup;
        }

        /* F1-N2/N3: yardımcı, dizin ve normal dosyayı reddetmeli */
        errno = 0;
        int dir_probe = landlock_open_unix_socket_fd(out_dir);
        CHECK(dir_probe < 0 && errno == ENOTSOCK,
              "dizin fd'si reddedilir (F1-N2)");
        if (dir_probe >= 0)
            close(dir_probe);

        regular_fd = open(regular_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (regular_fd < 0) {
            printf("  [FAIL] normal dosya oluşturulamadı (errno=%d %s)\n",
                   errno, strerror(errno));
            goto cleanup;
        }
        errno = 0;
        int file_probe = landlock_open_unix_socket_fd(regular_path);
        CHECK(file_probe < 0 && errno == ENOTSOCK,
              "normal dosya reddedilir (F1-N3)");
        if (file_probe >= 0)
            close(file_probe);

        /* F1-N1/N2/N3: init, geçersiz socks_fd ile fail-closed */
        CHECK(run_init_expect_config_fail(cfg_fd, dl_fd, td_fd, -1) == 0,
              "socks_fd=-1 → init fail-closed (F1-N1)");
        CHECK(run_init_expect_config_fail(cfg_fd, dl_fd, td_fd, out_fd) == 0,
              "dizin fd → init fail-closed (F1-N2)");
        CHECK(run_init_expect_config_fail(cfg_fd, dl_fd, td_fd, regular_fd) == 0,
              "normal dosya fd → init fail-closed (F1-N3)");
    }

    /* F3-N1/N2: tor_data fd yok/yanlış tipte → init fail-closed.
     * ABI'den bağımsız: kural her ABI'da zorunlu. */
    CHECK(run_init_expect_config_fail(cfg_fd, dl_fd, -1, socks_fd) == 0,
          "tor_data_fd=-1 → init fail-closed (F3-N1)");
    CHECK(run_init_expect_config_fail(cfg_fd, dl_fd, td_file_fd, socks_fd) == 0,
          "normal dosya td fd → init fail-closed (F3-N2)");

    /* fork'tan önce stdout'u boşalt — child'ın fflush'i buffer'ı
     * iki kez basmasın (fork buffer'ı kopyalar) */
    fflush(stdout);

    pid = fork();
    if (pid < 0) {
        printf("  [FAIL] fork başarısız (errno=%d)\n", errno);
        goto cleanup;
    }

    if (pid == 0) {
        /* ── child: sandbox'ı uygula ve doğrula ── */
        int failed = 0;

        if (!landlock_is_available()) {
            printf("  [SKIP] Landlock bu kernel'de yok (abi<1)\n");
            fflush(stdout);
            _exit(2);
        }

        nox_err_t err = landlock_sandbox_init(cfg_fd, dl_fd, td_fd, socks_fd);
        if (err == NOX_ERR_LANDLOCK_UNSUPPORTED) {
            printf("  [SKIP] Landlock LSM bu kernel'de devre dışı (boot parametresi)\n");
            fflush(stdout);
            _exit(2);
        }
        if (err != NOX_OK) {
            printf("  [FAIL] landlock_sandbox_init err=%d (%s)\n",
                   err, nox_strerror(err));
            fflush(stdout);
            _exit(1);
        }

        /* C-1: downloads içinde dosya oluşturulabilmeli (MAKE_REG) */
        int fd = openat(dl_fd, "probe.bin", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) {
            printf("  [FAIL] downloads/ içinde O_CREAT reddedildi (errno=%d %s) — C-1\n",
                   errno, strerror(errno));
            failed = 1;
        } else {
            printf("  [ OK ] downloads/ içinde openat(O_CREAT) başarılı (C-1)\n");
            ssize_t w = write(fd, "x", 1);
            if (w != 1) {
                printf("  [FAIL] write başarısız (errno=%d)\n", errno);
                failed = 1;
            }
            close(fd);
        }

        /* REMOVE_FILE: oluşturulan dosya silinebilmeli */
        if (unlinkat(dl_fd, "probe.bin", 0) != 0) {
            printf("  [FAIL] unlinkat başarısız (errno=%d %s)\n",
                   errno, strerror(errno));
            failed = 1;
        } else {
            printf("  [ OK ] downloads/ içinde unlinkat çalışır (REMOVE_FILE)\n");
        }

        /* Sandbox GERÇEKTEN kısıtlamalı: downloads dışı O_CREAT → EACCES */
        errno = 0;
        int out = openat(out_fd, "probe.bin", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (out >= 0) close(out);
        if (out < 0 && errno == EACCES) {
            printf("  [ OK ] downloads/ dışında O_CREAT → EACCES\n");
        } else {
            printf("  [FAIL] dış O_CREAT engellenmedi (fd=%d errno=%d %s)\n",
                   out, errno, strerror(errno));
            failed = 1;
        }

        /* ── F3: config kökü salt-okunur, tor_data dar silme ── */
        {
            const char *protected[] = {
                "identity.key", "salt", "contacts.db",
                "contacts.db-wal", "contacts.db-shm"
            };
            for (size_t i = 0;
                 i < sizeof(protected) / sizeof(protected[0]); i++) {
                errno = 0;
                int u = unlinkat(cfg_fd, protected[i], 0);
                if (u < 0 && errno == EACCES) {
                    printf("  [ OK ] config/%s unlink → EACCES (F3-I1)\n",
                           protected[i]);
                } else {
                    printf("  [FAIL] config/%s unlink engellenmedi "
                           "(rc=%d errno=%d %s) — F3-I1\n",
                           protected[i], u, errno, strerror(errno));
                    failed = 1;
                }
            }

            int ro = openat(cfg_fd, "identity.key", O_RDONLY | O_CLOEXEC);
            if (ro >= 0) {
                printf("  [ OK ] config/identity.key okuma serbest (F3-I2)\n");
                close(ro);
            } else {
                printf("  [FAIL] config/identity.key okunamadı "
                       "(errno=%d %s) — F3-I2\n", errno, strerror(errno));
                failed = 1;
            }
        }

        errno = 0;
        int u1 = unlinkat(td_fd, "torrc", 0);
        if (u1 == 0) {
            printf("  [ OK ] tor_data/torrc unlink başarılı (F3-I3)\n");
        } else {
            printf("  [FAIL] tor_data/torrc unlink (errno=%d %s) — F3-I3\n",
                   errno, strerror(errno));
            failed = 1;
        }

        errno = 0;
        int u2 = unlinkat(td_fd, "listen.sock", 0);
        if (u2 == 0) {
            printf("  [ OK ] tor_data/listen.sock unlink başarılı (F3-I3)\n");
        } else {
            printf("  [FAIL] tor_data/listen.sock unlink (errno=%d %s) — F3-I3\n",
                   errno, strerror(errno));
            failed = 1;
        }

        int cached_fd = openat(td_fd, "Cached",
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (cached_fd < 0) {
            printf("  [FAIL] tor_data/Cached açılamadı (errno=%d %s) — F3-I4\n",
                   errno, strerror(errno));
            failed = 1;
        } else {
            errno = 0;
            int u3 = unlinkat(cached_fd, "inner", 0);
            int u3_errno = errno;
            close(cached_fd);
            errno = 0;
            int u4 = unlinkat(td_fd, "Cached", AT_REMOVEDIR);
            if (u3 == 0 && u4 == 0) {
                printf("  [ OK ] tor_data alt dizini silindi (F3-I4)\n");
            } else {
                printf("  [FAIL] tor_data alt dizin silme "
                       "(inner=%d errno=%d, dir=%d errno=%d %s) — F3-I4\n",
                       u3, u3_errno, u4, errno, strerror(errno));
                failed = 1;
            }
        }

        errno = 0;
        int nf = openat(td_fd, "newfile",
                        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (nf >= 0)
            close(nf);
        if (nf < 0 && errno == EACCES) {
            printf("  [ OK ] tor_data içinde O_CREAT → EACCES (F3-I5)\n");
        } else {
            printf("  [FAIL] tor_data içinde O_CREAT engellenmedi "
                   "(fd=%d errno=%d %s) — F3-I5\n",
                   nf, errno, strerror(errno));
            failed = 1;
        }

        errno = 0;
        int rd = unlinkat(cfg_fd, td_name, AT_REMOVEDIR);
        if (rd < 0 && errno == EACCES) {
            printf("  [ OK ] tor_data dizini config'ten silinemez (F3-I6)\n");
        } else {
            printf("  [FAIL] tor_data dizini silindi/engellenmedi "
                   "(rc=%d errno=%d %s) — F3-I6\n",
                   rd, errno, strerror(errno));
            failed = 1;
        }

        /* F1: yalnız socks.sock'a connect serbest, control.sock EACCES */
        if (abi >= 9) {
            errno = 0;
            int socks_rc = connect_unix(socks_path);
            if (socks_rc == 0) {
                printf("  [ OK ] socks.sock connect başarılı (F1-I1)\n");
            } else {
                printf("  [FAIL] socks.sock connect reddedildi (errno=%d %s) — F1-I1\n",
                       errno, strerror(errno));
                failed = 1;
            }

            errno = 0;
            int ctrl_rc = connect_unix(control_path);
            if (ctrl_rc < 0 && errno == EACCES) {
                printf("  [ OK ] control.sock connect → EACCES (F1-I2/I3)\n");
            } else {
                printf("  [FAIL] control.sock connect engellenmedi "
                       "(rc=%d errno=%d %s) — F1-I2/I3\n",
                       ctrl_rc, errno, strerror(errno));
                failed = 1;
            }
        } else {
            printf("  [SKIP] ABI < 9 — F1 connect testleri atlandı (F1-A1)\n");
        }

        /* Sandbox GERÇEKTEN aktif olduğunu teyit (ölü state değil) */
        if (!landlock_is_active()) {
            printf("  [FAIL] landlock_is_active() false\n");
            failed = 1;
        } else {
            printf("  [ OK ] landlock_is_active() == true\n");
        }

        fflush(stdout);
        _exit(failed ? 1 : 0);
    }

    /* ── parent: sandbox yok → temizlik sorunsuz ── */
    if (waitpid(pid, &status, 0) < 0) {
        printf("  [FAIL] waitpid başarısız (errno=%d)\n", errno);
        goto cleanup;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 2)
        rc = 2;
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        rc = 0;
    else
        printf("  [FAIL] entegrasyon child'ı hatalı çıktı (status=%d)\n", status);

cleanup:
    /* child'ın çıkarmadığı olası kalıntı dosyayı temizle */
    if (socks_fd >= 0) close(socks_fd);
    if (socks_listener >= 0) close(socks_listener);
    if (control_listener >= 0) close(control_listener);
    if (regular_fd >= 0) close(regular_fd);
    if (td_file_fd >= 0) close(td_file_fd);
    if (socks_path[0] != '\0') (void)unlink(socks_path);
    if (control_path[0] != '\0') (void)unlink(control_path);
    if (regular_path[0] != '\0') (void)unlink(regular_path);
    if (out_fd >= 0) (void)unlinkat(out_fd, "td_notdir", 0);
    if (dl_fd >= 0) (void)unlinkat(dl_fd, "probe.bin", 0);

    /* F3 fixture temizliği — parent sandbox'sız, path serbest */
    if (td_fd >= 0) {
        (void)unlinkat(td_fd, "torrc", 0);
        (void)unlinkat(td_fd, "listen.sock", 0);
        (void)unlinkat(td_fd, "Cached/inner", 0);
        (void)unlinkat(td_fd, "Cached", AT_REMOVEDIR);
        (void)unlinkat(td_fd, "newfile", 0);
        close(td_fd);
    }
    if (cfg_fd >= 0) {
        (void)unlinkat(cfg_fd, "identity.key", 0);
        (void)unlinkat(cfg_fd, "salt", 0);
        (void)unlinkat(cfg_fd, "contacts.db", 0);
        (void)unlinkat(cfg_fd, "contacts.db-wal", 0);
        (void)unlinkat(cfg_fd, "contacts.db-shm", 0);
        if (td_name[0] != '\0')
            (void)unlinkat(cfg_fd, td_name, AT_REMOVEDIR);
    }

    if (dl_fd >= 0) close(dl_fd);
    if (out_fd >= 0) close(out_fd);
    if (cfg_fd >= 0) close(cfg_fd);
    if (dl_dir) (void)rmdir(dl_dir);
    if (out_dir) (void)rmdir(out_dir);
    if (cfg_dir) (void)rmdir(cfg_dir);
    return rc;
}

int main(void) {
    printf("=== Landlock Hak Maskeleme Testi ===\n");

    test_abi1_truncate_excluded();
    test_make_reg_always_present();
    test_abi_conditional_rights();
    test_resolve_unix_masking();

    int rc = run_integration();

    const char *verdict =
        rc == 0 ? "GEÇTİ" : (rc == 2 ? "SKIP (kernel Landlock'suz)" : "BAŞARISIZ");
    printf("\nSonuç: birim %d/%d — entegrasyon %s\n", g_passed, g_total, verdict);
    return (g_passed == g_total && rc != 1) ? 0 : 1;
}
