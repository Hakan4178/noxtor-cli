/* ================================================================
 * landlock_sandbox.c — Landlock LSM dosya erişim kısıtlaması
 *
 * open/openat/creat'i sadece downloads dizinine kısıtlar.
 * seccomp'un yapamadığı path-based filtering'i yapar.
 *
 * Kernel 5.13+ gerektirir (Landlock ABI v1+).
 * Kernel desteklemiyorsa sessizce fallback.
 *
 * Kullanım:
 *   landlock_sandbox_init(downloads_dir_fd);
 *   // Bu noktadan sonra sadece downloads_dir içinde dosya okunabilir/yazılabilir
 * ================================================================ */
#include "common.h"
#include "landlock_sandbox.h"
#include <assert.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ── Landlock syscall wrapper'ları ── */
static inline int sys_landlock_create_ruleset(
    const struct landlock_ruleset_attr *attr, size_t size, __u32 flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int sys_landlock_add_rule(
    int ruleset_fd, enum landlock_rule_type rule_type,
    const void *rule_attr, __u32 flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
                        rule_attr, flags);
}

static inline int sys_landlock_restrict_self(int ruleset_fd, __u32 flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* ── Landlock ABI versiyonunu kontrol et ── */
static int landlock_abi_version(void) {
    int version = sys_landlock_create_ruleset(NULL, 0,
                    LANDLOCK_CREATE_RULESET_VERSION);
    return version;
}

/* ================================================================
 * landlock_sandbox_init
 *
 * @downloads_dir_fd: downloads dizinin fd'si (O_PATH ile açılmış)
 *
 * Sadece downloads dizinine okuma/yazma izni verir.
 * Diğer tüm dosya erişimleri engellenir (default deny).
 *
 * Returns: NOX_OK veya NOX_ERR_CONFIG
 * ================================================================ */
static bool s_landlock_active = false;

nox_err_t landlock_sandbox_init(int downloads_dir_fd) {
    if (downloads_dir_fd < 0) {
        NOX_ERROR(LOG_MOD_MAIN, "landlock: geçersiz downloads dir fd");
        return NOX_ERR_CONFIG;
    }

    /* ABI versiyonunu kontrol et */
    int abi = landlock_abi_version();
    if (abi < 0) {
        NOX_WARN(LOG_MOD_MAIN, "landlock: desteklenmiyor (abi=%d), "
                 "dosya erişimi KISITLI DEĞİL — seccomp alone yetersiz", abi);
        return NOX_ERR_CONFIG;
    }

    if (abi < 1) {
        NOX_WARN(LOG_MOD_MAIN, "landlock: ABI v1 gerekli (abi=%d), "
                 "dosya erişimi KISITLI DEĞİL — seccomp alone yetersiz", abi);
        return NOX_ERR_CONFIG;
    }

    NOX_INFO(LOG_MOD_MAIN, "landlock: ABI v%d tespit edildi", abi);

    /* ── Ruleset oluştur ── */
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE      |
            LANDLOCK_ACCESS_FS_WRITE_FILE   |
            LANDLOCK_ACCESS_FS_READ_FILE    |
            LANDLOCK_ACCESS_FS_READ_DIR     |
            LANDLOCK_ACCESS_FS_REMOVE_DIR   |
            LANDLOCK_ACCESS_FS_REMOVE_FILE  |
            LANDLOCK_ACCESS_FS_MAKE_CHAR    |
            LANDLOCK_ACCESS_FS_MAKE_DIR     |
            LANDLOCK_ACCESS_FS_MAKE_REG     |
            LANDLOCK_ACCESS_FS_MAKE_SOCK    |
            LANDLOCK_ACCESS_FS_MAKE_FIFO    |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK   |
            LANDLOCK_ACCESS_FS_MAKE_SYM     |
            LANDLOCK_ACCESS_FS_REFER        |
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
            LANDLOCK_ACCESS_FS_TRUNCATE     |
            LANDLOCK_ACCESS_FS_IOCTL_DEV,
#else
            LANDLOCK_ACCESS_FS_TRUNCATE,
#endif
    };

    int ruleset_fd = sys_landlock_create_ruleset(&ruleset_attr,
                                                  sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        if (errno == EOPNOTSUPP) {
            NOX_WARN(LOG_MOD_MAIN, "landlock: desteklenmiyor, atlanıyor");
            return NOX_OK;
        }
        NOX_ERROR(LOG_MOD_MAIN, "landlock: ruleset oluşturulamadı (%s)",
                  strerror(errno));
        return NOX_ERR_CONFIG;
    }

    /* ── Downloads dizini için kural ekle ──
     * Sadece okuma, yazma, dizin listeleme ve dosya silme izni.
     * Execute, symlink oluşturma, hardlink vs. yasak. */
    struct landlock_path_beneath_attr downloads_rule = {
        .allowed_access =
            LANDLOCK_ACCESS_FS_READ_FILE    |
            LANDLOCK_ACCESS_FS_WRITE_FILE   |
            LANDLOCK_ACCESS_FS_READ_DIR     |
            LANDLOCK_ACCESS_FS_REMOVE_FILE  |
            LANDLOCK_ACCESS_FS_TRUNCATE,
        .parent_fd = downloads_dir_fd,
    };

    int rc = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &downloads_rule, 0);
    if (rc < 0) {
        NOX_ERROR(LOG_MOD_MAIN, "landlock: downloads kuralı eklenemedi (%s)",
                  strerror(errno));
        close(ruleset_fd);
        return NOX_ERR_CONFIG;
    }

    /* ── noxtor-cli config dizini için kural ekle ──
     * Sadece okuma izni — config dosyaları okunabilir, yazılamaz. */
    char config_dir[NOX_PATH_MAX];
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    /* CodeQL: cpp/path-injection — HOME mutlak path olmalı */
    assert(home != NULL && "HOME must be set");
    if (home[0] == '/') {
        snprintf(config_dir, sizeof(config_dir), "%s/.config/paranoidcli", home);

        int config_fd = open(config_dir, O_PATH | O_DIRECTORY);
        if (config_fd >= 0) {
            struct landlock_path_beneath_attr config_rule = {
                .allowed_access =
                    LANDLOCK_ACCESS_FS_READ_FILE |
                    LANDLOCK_ACCESS_FS_READ_DIR,
                .parent_fd = config_fd,
            };
            rc = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                      &config_rule, 0);
            if (rc < 0) {
                NOX_ERROR(LOG_MOD_MAIN, "landlock: config kuralı eklenemedi (%s)",
                          strerror(errno));
                close(config_fd);
                close(ruleset_fd);
                return NOX_ERR_CONFIG;
            }
            close(config_fd);
        }
    }

    /* ── no_new_privs ayarla ──
     * Landlock'un çalışması için gerekli. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        NOX_ERROR(LOG_MOD_MAIN, "landlock: no_new_privs ayarlanamadı (%s)",
                  strerror(errno));
        close(ruleset_fd);
        return NOX_ERR_CONFIG;
    }

    /* ── Ruleset'i uygula ── */
    rc = sys_landlock_restrict_self(ruleset_fd, 0);
    if (rc < 0) {
        NOX_ERROR(LOG_MOD_MAIN, "landlock: restrict_self başarısız (%s)",
                  strerror(errno));
        close(ruleset_fd);
        return NOX_ERR_CONFIG;
    }

    s_landlock_active = true;

    close(ruleset_fd);

    NOX_INFO(LOG_MOD_MAIN,
             "landlock: sandbox aktif — sadece downloads dir okunabilir/yazılabilir");
    return NOX_OK;
}

/* ================================================================
 * landlock_is_available
 *
 * Landlock mevcut mu kontrol et.
 * Returns: true/false
 * ================================================================ */

bool landlock_is_available(void) {
    int abi = landlock_abi_version();
    return abi >= 1;
}

bool landlock_is_active(void) {
    return s_landlock_active;
}
