/* SPDX-License-Identifier: GPL-3.0-or-later
 * landlock_sandbox.c — Landlock LSM dosya erişim kısıtlaması
 *
 * open/openat/creat'i sadece downloads dizinine kısıtlar.
 * seccomp'un yapamadığı path-based filtering'i yapar.
 *
 * Kernel 5.13+ gerektirir (Landlock ABI v1+; yeni haklar ABI'ye göre
 * koşullu eklenir, tablo için landlock_sandbox_init'e bak).
 * ABI 9+ ile pathname Unix soketlerine connect de kısıtlanır; yalnız
 * Tor'un socks.sock inode'una dosya düzeyinde istisna tanınır.
 * Kernel desteklemiyorsa fail-closed: NOX_ERR_* döner, çağıran
 * (--allow-unsandboxed-fs yoksa) çıkmak zorundadır.
 *
 * Kullanım:
 *   int socks_fd = landlock_open_unix_socket_fd(socks_path);
 *   landlock_sandbox_init(config_dir_fd, downloads_dir_fd, tor_data_fd, socks_fd);
 *   close(socks_fd);
 *   // Bu noktadan sonra sadece downloads_dir (RW) + config_dir (RO)
 *   // + tor_data_dir (silme) altında erişim
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
#include <sys/stat.h>
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
int landlock_abi_version(void) {
    int version = sys_landlock_create_ruleset(NULL, 0,
                    LANDLOCK_CREATE_RULESET_VERSION);
    return version;
}

/* ── Pathname Unix soketini O_PATH ile aç ve kimliğini doğrula ──
 * Dizin veya normal dosya kabul edilmez: yanlış fd, Landlock kuralıyla
 * tüm alt ağaca/soks olmayan inode'a hak vermemeli. */
int landlock_open_unix_socket_fd(const char *path) {
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        close(fd);
        errno = ENOTSOCK;
        return -1;
    }
    if (st.st_uid != geteuid()) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    return fd;
}

/* ================================================================
 * landlock_sandbox_init
 *
 * @config_dir_fd:    config dizinin fd'si (O_DIRECTORY|O_NOFOLLOW) — RO
 * @downloads_dir_fd: downloads dizinin fd'si (O_DIRECTORY|O_NOFOLLOW) — RW
 * @tor_data_fd:      tor_data_<pid> dizinin fd'si — dar silme kuralı
 * @socks_fd:         socks.sock için O_PATH fd (ABI >= 9'da zorunlu)
 *
 * fd = anchor, path'e asla geri dönülmez (TOCTOU kapalı).
 * Sadece downloads (RW) + config (RO) + tor_data (silme) altında erişim
 * verilir; ABI >= 9'da yalnız socks_fd inode'una RESOLVE_UNIX istisnası
 * tanınır.
 *
 * Returns: NOX_OK veya NOX_ERR_CONFIG
 * ================================================================ */
static nox_hardbool_t s_landlock_active = 0;

nox_err_t landlock_sandbox_init(int config_dir_fd, int downloads_dir_fd,
                                int tor_data_fd, int socks_fd) {
    if (config_dir_fd < 0 || downloads_dir_fd < 0 || tor_data_fd < 0) {
        NOX_ERROR(LOG_MOD_MAIN,
                  "landlock: geçersiz dir fd (config=%d, downloads=%d, tor_data=%d)",
                  config_dir_fd, downloads_dir_fd, tor_data_fd);
        return NOX_ERR_CONFIG;
    }

    /* ── tor_data fd doğrulaması — her ABI'da zorunlu ──
     * Silme kuralı yalnız bu inode'a bağlanır. Yanlış fd (dosya, başka
     * kullanıcı) tüm config ağacına silme hakkı vermemeli. */
    {
        struct stat td_st;
        if (fstat(tor_data_fd, &td_st) != 0) {
            NOX_ERROR(LOG_MOD_MAIN, "landlock: tor_data fd doğrulanamadı (%s)",
                      strerror(errno));
            return NOX_ERR_CONFIG;
        }
        if (!S_ISDIR(td_st.st_mode)) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: tor_data fd bir dizin değil (mode=0%o)",
                      td_st.st_mode);
            return NOX_ERR_CONFIG;
        }
        if (td_st.st_uid != geteuid()) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: tor_data dizini başka UID'ye ait (uid=%u, euid=%u)",
                      (unsigned)td_st.st_uid, (unsigned)geteuid());
            return NOX_ERR_CONFIG;
        }
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

    /* ── socks.sock fd doğrulaması (yalnız ABI >= 9) ──
     * ABI < 9'da RESOLVE_UNIX yok; fd gerekmez ve yok sayılır.
     * ABI >= 9'da eksik/yanlış fd fail-closed: aksi halde ya tüm
     * pathname connect'ler EACCES olur ya da kural yanlış inode'a gider. */
    if (abi >= 9) {
        if (socks_fd < 0) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: ABI v%d için socks.sock fd gerekli (fd=%d)",
                      abi, socks_fd);
            return NOX_ERR_CONFIG;
        }
        struct stat socks_st;
        if (fstat(socks_fd, &socks_st) != 0) {
            NOX_ERROR(LOG_MOD_MAIN, "landlock: socks fd doğrulanamadı (%s)",
                      strerror(errno));
            return NOX_ERR_CONFIG;
        }
        if (!S_ISSOCK(socks_st.st_mode)) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: socks fd bir Unix soketi değil (mode=0%o)",
                      socks_st.st_mode);
            return NOX_ERR_CONFIG;
        }
        if (socks_st.st_uid != geteuid()) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: socks soketi başka UID'ye ait (uid=%u, euid=%u)",
                      (unsigned)socks_st.st_uid, (unsigned)geteuid());
            return NOX_ERR_CONFIG;
        }
    }

    /* ── Ruleset oluştur ── */
    /* ABI versiyonuna göre desteklenen hakları koşullu ekle */
    __u64 handled = NOX_LL_BASE_RIGHTS;
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
    if (abi >= 9) handled |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = handled,
    };

    /* ABI v6+: domain-dışı abstract unix soketlere connect'i kapat.
     * Tüm soketlerimiz path-based (sun_path[0]=='/' */
#ifdef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
    if (abi >= 6)
        ruleset_attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
#endif

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
     * F3: yalnız okuma — REMOVE_FILE kaldırıldı. identity.key, salt ve
     * contacts.db (WAL/SHM dahil) config kökünden silinemez. Silme
     * ihtiyacı olan tek şey tor_data_<pid> içeriğidir; o ayrı kuralla
     * verilir. NOT: identity.key/salt event loop'ta RO okunabilir
     * (şeffaf, bilerek): dosyalar XSalsa20-Poly1305 şifreli, HS sonrası
     * RAM'de arena+mlock'ta, retry yok. */
    {
        struct landlock_path_beneath_attr config_rule = {
            .allowed_access =
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_READ_DIR,
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

    /* ── tor_data_<pid> için dar silme kuralı — F3 ──
     * Yalnız bu alt ağaçta dosya/dizin silme serbest:
     *   - torrc, listen.sock, Tor'un DataDirectory içeriği
     * READ_FILE/MAKE_* verilmez: uygulama burada yeni dosya üretmez
     * (torrc Landlock'tan önce yazıldı), yalnız temizler.
     * REMOVE_DIR bu dizinin ALTINDAKİ dizinler içindir; tor_data_dir'ın
     * kendisini silmek config kökünde REMOVE_DIR gerektirir ve bilerek
     * verilmez — boş dizin sonraki açılışta Landlock öncesi
     * cleanup_stale_tor_dirs ile temizlenir. */
    {
        __u64 td_wanted =
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_DIR;
        struct landlock_path_beneath_attr tor_data_rule = {
            .allowed_access = nox_ll_compute_rule_rights(td_wanted, handled),
            .parent_fd = tor_data_fd,
        };
        rc = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                   &tor_data_rule, 0);
        if (rc < 0) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: tor_data kuralı eklenemedi (%s)",
                      strerror(errno));
            close(ruleset_fd);
            return NOX_ERR_CONFIG;
        }
    }

    /* ── socks.sock istisnası — yalnız ABI >= 9 ──
     * RESOLVE_UNIX handled edilince domain dışındaki tüm pathname Unix
     * soketlerine connect EACCES olur. Tor Landlock'tan önce spawn
     * edildiği için socks.sock domain dışındadır; yalnız o inode'a
     * dosya düzeyinde istisna tanınır. control.sock/listen.sock için
     * kural YOK — onlar kapalı kalmalı. */
    if (abi >= 9) {
        __u64 socks_allowed =
            nox_ll_compute_rule_rights(LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
                                       handled);
        if (socks_allowed == 0) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: socks RESOLVE_UNIX maskesi boş — fail-closed");
            close(ruleset_fd);
            return NOX_ERR_CONFIG;
        }
        struct landlock_path_beneath_attr socks_rule = {
            .allowed_access = socks_allowed,
            .parent_fd = socks_fd,
        };
        rc = sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                   &socks_rule, 0);
        if (rc < 0) {
            NOX_ERROR(LOG_MOD_MAIN,
                      "landlock: socks.sock RESOLVE_UNIX kuralı eklenemedi (%s)",
                      strerror(errno));
            close(ruleset_fd);
            return NOX_ERR_CONFIG;
        }
        NOX_INFO(LOG_MOD_MAIN,
                 "landlock: socks.sock RESOLVE_UNIX istisnası eklendi");
    } else {
        NOX_WARN(LOG_MOD_MAIN,
                 "landlock: ABI v%d < 9 — pathname Unix connect kısıtlanmıyor "
                 "(F1 açık)", abi);
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
             "landlock: sandbox aktif — downloads RW + config RO + "
             "tor_data silme, dışı yasak");
    return NOX_OK;
}

/* ================================================================
 * landlock_is_available
 *
 * Landlock ABI detectable mi? Kernel VERSION sorgusu abi>=1 ise true.
 * NOT: true "usable right now" demek değil — ruleset/add_rule/
 * no_new_privs/restrict_self sonrası hata çıkabilir. Gerçek aktiflik
 * için landlock_is_active() veya landlock_sandbox_init()==NOX_OK bak.
 * Returns: true/false
 * ================================================================ */

nox_hardbool_t landlock_is_available(void) {
    int abi = landlock_abi_version();
    return abi >= 1;
}

nox_hardbool_t landlock_is_active(void) {
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
