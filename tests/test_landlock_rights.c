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
 * Kernel'de Landlock yoksa entegrasyon testi SKIP edilir (fail değil).
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
#include <sys/stat.h>
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
    if (!dl_dir || !out_dir || !cfg_dir) {
        printf("  [FAIL] mkdtemp başarısız (errno=%d)\n", errno);
        return 1;
    }

    /* fd'ler sandbox'tan ÖNCE açılmalı — sonrasında dış erişim yok */
    int dl_fd = open(dl_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int out_fd = open(out_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int cfg_fd = open(cfg_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dl_fd < 0 || out_fd < 0 || cfg_fd < 0) {
        printf("  [FAIL] dizin açılamadı (errno=%d)\n", errno);
        return 1;
    }

    /* fork'tan önce stdout'u boşalt — child'ın fflush'i buffer'ı
     * iki kez basmasın (fork buffer'ı kopyalar) */
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        printf("  [FAIL] fork başarısız (errno=%d)\n", errno);
        return 1;
    }

    if (pid == 0) {
        /* ── child: sandbox'ı uygula ve doğrula ── */
        int failed = 0;

        if (!landlock_is_available()) {
            printf("  [SKIP] Landlock bu kernel'de yok (abi<1)\n");
            fflush(stdout);
            _exit(2);
        }

        nox_err_t err = landlock_sandbox_init(cfg_fd, dl_fd);
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
    int status;
    waitpid(pid, &status, 0);

    /* child'ın çıkarmadığı olası kalıntı dosyayı temizle */
    (void)unlinkat(dl_fd, "probe.bin", 0);
    close(dl_fd); close(out_fd); close(cfg_fd);
    (void)rmdir(dl_dir); (void)rmdir(out_dir); (void)rmdir(cfg_dir);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 2) return 2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    printf("  [FAIL] entegrasyon child'ı hatalı çıktı (status=%d)\n", status);
    return 1;
}

int main(void) {
    printf("=== Landlock Hak Maskeleme Testi ===\n");

    test_abi1_truncate_excluded();
    test_make_reg_always_present();
    test_abi_conditional_rights();

    int rc = run_integration();

    const char *verdict =
        rc == 0 ? "GEÇTİ" : (rc == 2 ? "SKIP (kernel Landlock'suz)" : "BAŞARISIZ");
    printf("\nSonuç: birim %d/%d — entegrasyon %s\n", g_passed, g_total, verdict);
    return (g_passed == g_total && rc != 1) ? 0 : 1;
}
