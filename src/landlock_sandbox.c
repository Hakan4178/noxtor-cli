/* SPDX-License-Identifier: GPL-3.0-or-later
 * landlock_sandbox.c — Landlock LSM dosya erişim kısıtlaması
 *
 * open/openat/creat'i sadece downloads dizinine kısıtlar.
 * seccomp'un yapamadığı path-based filtering'i yapar.
 *
 * Kernel 5.13+ gerektirir (Landlock ABI v1+).
 * Kernel desteklemiyorsa sessizce fallback.
 *
 * Kullanım:
 *   landlock_sandbox_init(config_dir_fd, downloads_dir_fd);
 *   // Bu noktadan sonra sadece downloads_dir (RW) + config_dir (RO) altında erişim
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
 * @config_dir_fd:    config dizinin fd'si (O_DIRECTORY|O_NOFOLLOW) — RO
 * @downloads_dir_fd: downloads dizinin fd'si (O_DIRECTORY|O_NOFOLLOW) — RW
 *
 * fd = anchor, path'e asla geri dönülmez (TOCTOU kapalı).
 * Sadece downloads (RW) + config (RO) altında erişim verilir.
 *
 * Returns: NOX_OK veya NOX_ERR_CONFIG
 * ================================================================ */
static bool s_landlock_active = false;

nox_err_t landlock_sandbox_init(int config_dir_fd, int downloads_dir_fd) {
    if (config_dir_fd < 0 || downloads_dir_fd < 0) {
        NOX_ERROR(LOG_MOD_MAIN, "landlock: geçersiz dir fd (config=%d, downloads=%d)",
                  config_dir_fd, downloads_dir_fd);
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
    /* ABI versiyonuna göre desteklenen flag'lericonditional ekle */
    __u32 handled = NOX_LL_BASE_RIGHTS;
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = handled,
    };

    int ruleset_fd = sys_landlock_create_ruleset(&ruleset_attr,
                                                  sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        if (errno == EOPNOTSUPP) {
            /* C-2 EK FIX: artık NOX_OK DEĞİL — sandbox kurulamadıysa
             * bunu çağırana "başarı" diye yalan söylemiyoruz. */
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: kernel'de devre dışı (lsm= boot parametresi?) "
                      "— dosya sistemi sandbox'ı KURULAMADI");
            return NOX_ERR_LANDLOCK_UNSUPPORTED;
        }
        NOX_ERROR(LOG_MOD_MAIN, "landlock: ruleset oluşturulamadı (%s)",
                  strerror(errno));
        return NOX_ERR_CONFIG;
    }

    /* ── Downloads dizini kuralı — C-1 + C-2 BİRLEŞİK FIX ──
     *
     * "wanted" = uygulamanın downloads/ dizininde GERÇEKTEN ihtiyaç duyduğu
     * haklar, ABI farkı gözetmeden tam liste olarak yazılır.
     * Gerçek allowed_access, bunun `handled` ile kesişimidir.
     *
     * Bu tek satır (`wanted & handled`) hem C-1'i hem C-2'yi yapısal
     * olarak imkansız hale getirir:
     *   - C-1: MAKE_REG artık wanted'da → allowed'da da var → EACCES yok.
     *   - C-2: TRUNCATE, handled'da yoksa (ABI<3) maskeden otomatik düşer →
     *          allowed ⊄ handled durumu asla oluşamaz → EINVAL yok.
     */
    __u64 wanted =
        LANDLOCK_ACCESS_FS_READ_FILE    |
        LANDLOCK_ACCESS_FS_WRITE_FILE   |
        LANDLOCK_ACCESS_FS_READ_DIR     |
        LANDLOCK_ACCESS_FS_REMOVE_FILE  |
        LANDLOCK_ACCESS_FS_MAKE_REG     |   /* C-1 FIX: yeni dosya oluşturmak için zorunlu */
        LANDLOCK_ACCESS_FS_TRUNCATE;
        /* MAKE_DIR / REFER bilerek eklenmedi — least-privilege:
         * downloads/ içinde alt dizin veya cross-dir rename kullanılmıyor */

    struct landlock_path_beneath_attr downloads_rule = {
        .allowed_access = nox_ll_compute_rule_rights(wanted, handled),
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

    /* ── config dizini için kural ekle — fd anchor, HOME parse yok (Q1 Şık A) ──
     * Sadece okuma izni — TOCTOU kapalı, path'e asla geri dönülmez. */
    {
        struct landlock_path_beneath_attr config_rule = {
            .allowed_access =
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_READ_DIR |
                LANDLOCK_ACCESS_FS_REMOVE_FILE, /* L-21 FIX: shutdown'da
                listen.sock unlink'i EPERM almadan çalışsın — yoksa bayat
                socket dosyası bir sonraki bind()'i engeller */
            .parent_fd = config_dir_fd,
        };
        rc = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                  &config_rule, 0);
        if (rc < 0) {
            NOX_ERROR(LOG_MOD_MAIN, "landlock: config kuralı eklenemedi (%s)",
                      strerror(errno));
            close(ruleset_fd);
            return NOX_ERR_CONFIG;
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

/* ================================================================
 * nox_ll_compute_rule_rights — C-1/C-2 için SAF maskeleme fonksiyonu
 *
 * Kernel syscall'ı içermez → herhangi bir CI runner'da test edilebilir
 * (tests/test_landlock_rights.c). Gerçek kernel gerekmez.
 *
 * Invariant: dönen değer her zaman @handled'ın alt kümesidir:
 *     (allowed | handled) == handled
 * Bu sayede kernel'in landlock_add_rule'da uyguladığı EINVAL
 * (allowed ⊄ handled) koşulu yapısal olarak asla oluşamaz.
 * ================================================================ */
__u64 nox_ll_compute_rule_rights(__u64 wanted, __u64 handled) {
    return wanted & handled;
}
