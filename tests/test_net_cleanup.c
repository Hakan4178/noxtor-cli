/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_net_cleanup.c — stale Tor kalıntı süpürme sözleşmesi (network.c)
 *
 * EN KÖTÜ ŞİDDET SINIFI testleri: sweep yanlış olursa (a) Tor anahtarları
 * diskte sızar, (b) symlink takip edilirse config dışı victim dizin
 * silinir, (c) aşırı agresif silme canlı Tor'un verisini uçurur.
 *
 * Sözleşme (cleanup_stale_tor_dirs + is_our_stale_entry + safe_parse_pid):
 *   - tor_data_<pid> (dizin): ölü pid + bizim UID → rm_rf (içi dolu dahil)
 *   - torrc_<pid> (dosya): ölü pid → unlink
 *   - canlı pid (tor olmasa bile) → DOKUNULMAZ
 *   - symlink: takip EDİLMEZ — link gider, hedef KALIR
 *   - eşleşmeyen adlar → dokunulmaz
 *   - pid parse: strtol + ERANGE + endptr; <=0 / >INT_MAX → red
 *
 * Bad patch avı: rm_rf→rmdir (anahtar sızması), lstat→stat (symlink
 * takibi), kill mantığında ters karar (canlıyı silme).
 */

#include "common.h"
#include "network.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Format-truncation uyarıları: test fixture'leri sabit TEST_DIR
 * (≤ 256 byte) kullanır — derleyici bunu statik olarak bilmez. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond) do {                                      \
    if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL %s:%d: %s\n",                        \
                __FILE__, __LINE__, #cond);                         \
        return 1;                                                   \
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

#define FIX_DIR  "tests/.tmp_net_clean"
#define VIC_DIR  "tests/.tmp_net_clean_victim"

/* ================================================================
 * YARDIMCILAR
 * ================================================================ */

/* Ölü pid üret: fork + hemen çık + reap — sweep "kesin ölü" görmeli */
static pid_t spawn_dead_pid(void)
{
    pid_t p = fork();
    if (p == 0)
        _exit(0);
    int status;
    waitpid(p, &status, 0);
    return p;
}

static int path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int mkdir_p(const char *path)
{
    return mkdir(path, 0700);
}

static int write_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return n == (ssize_t)strlen(content) ? 0 : -1;
}

static int read_file_ok(const char *path, const char *want)
{
    char buf[64] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return n == (ssize_t)strlen(want) && strcmp(buf, want) == 0;
}

static void rm_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) {
        unlink(path);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[512];
        snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
        struct stat st;
        if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode))
            rm_tree(sub);
        else
            unlink(sub);
    }
    closedir(d);
    rmdir(path);
}

static void fixture_reset(void)
{
    rm_tree(FIX_DIR);
    rm_tree(VIC_DIR);
    mkdir_p(FIX_DIR);
}

/* ================================================================
 * SWEEP TESTLERİ
 * ================================================================ */

/* 1) Ölü pid'li tor_data dizini İÇERİĞİYLE silinir — rm_rf→rmdir
 *    "basitleştirmesi" (anahtar sızması) bu testte kırmızı verir */
static int test_sweep_dead_data_dir_recursive(void)
{
    fixture_reset();
    pid_t dead = spawn_dead_pid();
    TEST_ASSERT(dead > 0);

    char dir[256], sub[256], file[256];
    snprintf(dir, sizeof(dir), "%s/tor_data_%d", FIX_DIR, (int)dead);
    snprintf(sub, sizeof(sub), "%s/sub", dir);
    snprintf(file, sizeof(file), "%s/sub/hs_keys.bin", dir);
    TEST_ASSERT(mkdir_p(dir) == 0);
    TEST_ASSERT(mkdir_p(sub) == 0);
    TEST_ASSERT(write_file(file, "SECRET-KEY-MATERIAL") == 0);

    cleanup_stale_tor_dirs(FIX_DIR);

    TEST_ASSERT(!path_exists(dir));      /* dizin komple gitti */
    TEST_ASSERT(!path_exists(sub));
    TEST_ASSERT(!path_exists(file));
    return 0;
}

/* 2) Ölü pid'li torrc dosyası unlink edilir */
static int test_sweep_dead_torrc_file(void)
{
    fixture_reset();
    pid_t dead = spawn_dead_pid();

    char f[256];
    snprintf(f, sizeof(f), "%s/torrc_%d", FIX_DIR, (int)dead);
    TEST_ASSERT(write_file(f, "SocksPort auto\n") == 0);

    cleanup_stale_tor_dirs(FIX_DIR);
    TEST_ASSERT(!path_exists(f));
    return 0;
}

/* 3) tor_data_<pid> DOSYA olarak plant edilmişse de silinir
 *    (rm_rf fallback: dizin açılamaz → unlink) */
static int test_sweep_data_prefixed_plain_file(void)
{
    fixture_reset();
    pid_t dead = spawn_dead_pid();

    char f[256];
    snprintf(f, sizeof(f), "%s/tor_data_%d", FIX_DIR, (int)dead);
    TEST_ASSERT(write_file(f, "not-a-dir") == 0);

    cleanup_stale_tor_dirs(FIX_DIR);
    TEST_ASSERT(!path_exists(f));
    return 0;
}

/* 4) CANLI pid (bu test süreci; tor olmasa bile) → dokunulmaz.
 *    Aşırı agresif silme (ters kill mantığı) burada kırmızı verir. */
static int test_sweep_live_pid_preserved(void)
{
    fixture_reset();
    pid_t self = getpid();

    char dir[256], inner[256], torrc[256];
    snprintf(dir, sizeof(dir), "%s/tor_data_%d", FIX_DIR, (int)self);
    snprintf(inner, sizeof(inner), "%s/canary.bin", dir);
    snprintf(torrc, sizeof(torrc), "%s/torrc_%d", FIX_DIR, (int)self);
    TEST_ASSERT(mkdir_p(dir) == 0);
    TEST_ASSERT(write_file(inner, "LIVE-DATA") == 0);
    TEST_ASSERT(write_file(torrc, "live config") == 0);

    cleanup_stale_tor_dirs(FIX_DIR);

    TEST_ASSERT(path_exists(dir));                     /* canlı → kaldı */
    TEST_ASSERT(read_file_ok(inner, "LIVE-DATA"));     /* içerik bozulmadı */
    TEST_ASSERT(path_exists(torrc));
    return 0;
}

/* 5) SYMLINK SALDIRISI: tor_data_<ölü-pid> → victim dizin.
 *    Link takip edilirse victim SİLİNİR; doğru davranış: yalnız link
 *    gider, hedef dokunulmaz (lstat + O_NOFOLLOW + fstatat NOFOLLOW). */
static int test_sweep_symlink_not_followed(void)
{
    fixture_reset();
    pid_t dead = spawn_dead_pid();

    TEST_ASSERT(mkdir_p(VIC_DIR) == 0);
    char secret[256];
    snprintf(secret, sizeof(secret), "%s/secret.bin", VIC_DIR);
    TEST_ASSERT(write_file(secret, "VICTIM-DATA") == 0);

    char link[256];
    snprintf(link, sizeof(link), "%s/tor_data_%d", FIX_DIR, (int)dead);
    TEST_ASSERT(symlink(VIC_DIR, link) == 0);

    cleanup_stale_tor_dirs(FIX_DIR);

    TEST_ASSERT(!path_exists(link));                   /* symlink gitti */
    TEST_ASSERT(path_exists(VIC_DIR));                 /* victim KALDI */
    TEST_ASSERT(read_file_ok(secret, "VICTIM-DATA"));  /* içerik sağlam */
    return 0;
}

/* 6) Eşleşmeyen adlar korunur — aşırı geniş prefix bölmesi reddi */
static int test_sweep_ignores_non_matching(void)
{
    fixture_reset();
    static const char *names[] = {
        "notes.txt", "tor_data_abc", "tor_data_", "tor_data_-5",
        "torrc_xyz", "torrc_", "identity.key.tmp.1234.aabbccdd",
        "tor_data_12x", "x_tor_data_5",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char p[256];
        snprintf(p, sizeof(p), "%s/%s", FIX_DIR, names[i]);
        TEST_ASSERT(write_file(p, "keep") == 0);
    }

    cleanup_stale_tor_dirs(FIX_DIR);

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char p[256];
        snprintf(p, sizeof(p), "%s/%s", FIX_DIR, names[i]);
        TEST_ASSERT(path_exists(p));                   /* hepsi yerinde */
    }
    return 0;
}

/* 7) Olmayan dizin → sessiz no-op, çökme yok */
static int test_sweep_nonexistent_dir_no_crash(void)
{
    cleanup_stale_tor_dirs("/nonexistent/noxtor/cleanup/path");
    return 0;
}

/* 8) Trailing slash'li config_dir → çift slash path'te prefix kontrolü
 *    yine geçer, sweep çalışır (normalize edilmiş HOME'a regresyon kilidi) */
static int test_sweep_trailing_slash_dir(void)
{
    fixture_reset();
    pid_t dead = spawn_dead_pid();

    char dir[256], with_slash[256];
    snprintf(dir, sizeof(dir), "%s/tor_data_%d", FIX_DIR, (int)dead);
    TEST_ASSERT(mkdir_p(dir) == 0);

    snprintf(with_slash, sizeof(with_slash), "%s/", FIX_DIR);
    cleanup_stale_tor_dirs(with_slash);

    TEST_ASSERT(!path_exists(dir));
    return 0;
}

/* 9) safe_parse_pid kenar matrisi — yanlış parse yanlış silme demektir */
static int test_parse_pid_edges(void)
{
    /* Geçerli */
    TEST_ASSERT(safe_parse_pid("1") == 1);
    TEST_ASSERT(safe_parse_pid("12345") == 12345);
    TEST_ASSERT(safe_parse_pid("2147483647") == 2147483647); /* INT_MAX */
    /* Geçersiz → -1 */
    TEST_ASSERT(safe_parse_pid("") == -1);
    TEST_ASSERT(safe_parse_pid("abc") == -1);
    TEST_ASSERT(safe_parse_pid("-3") == -1);
    TEST_ASSERT(safe_parse_pid("0") == -1);
    TEST_ASSERT(safe_parse_pid("5x") == -1);
    TEST_ASSERT(safe_parse_pid("12_extra") == -1);
    TEST_ASSERT(safe_parse_pid("2147483648") == -1);         /* INT_MAX+1 */
    TEST_ASSERT(safe_parse_pid("99999999999999999999") == -1); /* ERANGE */
    /* strtol toleransı — mevcut davranış kilidi (zararsız: UID kapısı) */
    TEST_ASSERT(safe_parse_pid("+15") == 15);
    TEST_ASSERT(safe_parse_pid(" 5") == 5);
    return 0;
}

int main(void)
{
    fprintf(stderr, "=== stale Tor süpürme sözleşmesi ===\n");

    RUN_TEST(test_sweep_dead_data_dir_recursive);
    RUN_TEST(test_sweep_dead_torrc_file);
    RUN_TEST(test_sweep_data_prefixed_plain_file);
    RUN_TEST(test_sweep_live_pid_preserved);
    RUN_TEST(test_sweep_symlink_not_followed);
    RUN_TEST(test_sweep_ignores_non_matching);
    RUN_TEST(test_sweep_nonexistent_dir_no_crash);
    RUN_TEST(test_sweep_trailing_slash_dir);
    RUN_TEST(test_parse_pid_edges);

    /* Fixture temizliği */
    rm_tree(FIX_DIR);
    rm_tree(VIC_DIR);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}

#pragma GCC diagnostic pop
