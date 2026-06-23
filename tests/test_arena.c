/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_arena.c — Secure arena birim testleri
 *
 * ASan + UBSan altında çalıştırılır (make test).
 * Sıfır bağımlılık test framework'ü.
 */

#include "common.h"
#include "types.h"
#include "arena.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>


/* ================================================================
 * TEST MAKROLARI
 * ================================================================ */
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
    fprintf(stderr, "  [%d] %-40s ", tests_run, #test_fn);          \
    if (test_fn() == 0) {                                           \
        tests_passed++;                                             \
        fprintf(stderr, "\033[32mOK\033[0m\n");                     \
    } else {                                                        \
        fprintf(stderr, "\033[31mFAIL\033[0m\n");                   \
    }                                                               \
} while (0)

/* ================================================================
 * TEST: arena_init — başarılı oluşturma
 * ================================================================ */
static int test_arena_init_success(void)
{
    struct secure_arena a = {0};

    nox_err_t err = arena_init(&a, 4096);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(a.base != NULL);
    TEST_ASSERT(a.usable_size >= 4096);
    TEST_ASSERT(a.offset == 0);
    TEST_ASSERT(a.total_size > a.usable_size);  /* guard page'ler */

    arena_destroy(&a);

    /* Destroy sonrası struct sıfırlanmış olmalı */
    TEST_ASSERT(a.base == NULL);
    TEST_ASSERT(a.total_size == 0);

    return 0;
}

/* ================================================================
 * TEST: arena_init — NULL pointer ile çağrılırsa hata
 * ================================================================ */
static int test_arena_init_null(void)
{
    nox_err_t err = arena_init(NULL, 4096);
    TEST_ASSERT(err == NOX_ERR_ALLOC);

    struct secure_arena a = {0};
    err = arena_init(&a, 0);
    TEST_ASSERT(err == NOX_ERR_ALLOC);

    return 0;
}

/* ================================================================
 * TEST: arena_alloc — 16-byte alignment
 * ================================================================ */
static int test_arena_alloc_alignment(void)
{
    struct secure_arena a = {0};
    nox_err_t err = arena_init(&a, 4096);
    TEST_ASSERT(err == NOX_OK);

    /* Farklı boyutlarda alloc — hepsi 16-byte aligned olmalı */
    void *p1 = arena_alloc(&a, 1);
    TEST_ASSERT(p1 != NULL);
    TEST_ASSERT(((uintptr_t)p1 & 0xF) == 0);

    void *p2 = arena_alloc(&a, 7);
    TEST_ASSERT(p2 != NULL);
    TEST_ASSERT(((uintptr_t)p2 & 0xF) == 0);

    void *p3 = arena_alloc(&a, 32);
    TEST_ASSERT(p3 != NULL);
    TEST_ASSERT(((uintptr_t)p3 & 0xF) == 0);

    void *p4 = arena_alloc(&a, 33);
    TEST_ASSERT(p4 != NULL);
    TEST_ASSERT(((uintptr_t)p4 & 0xF) == 0);

    /* Pointer'lar birbirini overlap etmemeli */
    TEST_ASSERT(p1 != p2);
    TEST_ASSERT(p2 != p3);
    TEST_ASSERT(p3 != p4);

    arena_destroy(&a);
    return 0;
}

/* ================================================================
 * TEST: arena_alloc — taşma durumunda NULL dönüş
 * ================================================================ */
static int test_arena_alloc_overflow(void)
{
    struct secure_arena a = {0};
    nox_err_t err = arena_init(&a, 4096);
    TEST_ASSERT(err == NOX_OK);

    /*
     * page_align(4096 + 16 canary) → usable alanı sayfa hizasına
     * yuvarlanır. Gerçek usable boyutu a.usable_size'dan öğren.
     */
    size_t usable = a.usable_size;

    /* Usable alanın çoğunu doldur — 32 byte bırak */
    void *p = arena_alloc(&a, usable - 32);
    TEST_ASSERT(p != NULL);

    /* Kalan alandan fazlasını iste — NULL dönmeli */
    void *over = arena_alloc(&a, 64);
    TEST_ASSERT(over == NULL);

    /* Kalan 32 byte'a sığan alloc çalışmalı (16-byte aligned → 32) */
    void *small = arena_alloc(&a, 16);
    TEST_ASSERT(small != NULL);

    arena_destroy(&a);
    return 0;
}

/* ================================================================
 * TEST: arena_bytes_used / arena_bytes_free
 * ================================================================ */
static int test_arena_usage_tracking(void)
{
    struct secure_arena a = {0};
    nox_err_t err = arena_init(&a, 4096);
    TEST_ASSERT(err == NOX_OK);

    size_t initial_free = arena_bytes_free(&a);
    TEST_ASSERT(initial_free > 0);
    TEST_ASSERT(arena_bytes_used(&a) == 0);

    /* 32 byte alloc (16-byte aligned → 32 byte) */
    arena_alloc(&a, 32);
    TEST_ASSERT(arena_bytes_used(&a) == 32);
    TEST_ASSERT(arena_bytes_free(&a) == initial_free - 32);

    /* 7 byte alloc → 16 byte aligned */
    arena_alloc(&a, 7);
    TEST_ASSERT(arena_bytes_used(&a) == 32 + 16);  /* 7 → 16 */

    arena_destroy(&a);
    return 0;
}

/* ================================================================
 * TEST: arena_alloc — NULL arena ile çağrılırsa
 * ================================================================ */
static int test_arena_alloc_null(void)
{
    void *p = arena_alloc(NULL, 32);
    TEST_ASSERT(p == NULL);

    struct secure_arena a = {0};
    p = arena_alloc(&a, 32);
    TEST_ASSERT(p == NULL);  /* base == NULL */

    return 0;
}

/* ================================================================
 * TEST: arena — varsayılan 64KB boyut
 * ================================================================ */
static int test_arena_default_size(void)
{
    struct secure_arena a = {0};
    nox_err_t err = arena_init(&a, NOX_ARENA_DEFAULT_SIZE);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(a.usable_size >= NOX_ARENA_DEFAULT_SIZE);

    /* Spesifikasyondaki bütçeyi simüle et */
    void *keys = arena_alloc(&a, 4 * NOX_KEY_LEN);    /* 128 byte  */
    TEST_ASSERT(keys != NULL);

    void *noise = arena_alloc(&a, 1024);               /* ~1 KB     */
    TEST_ASSERT(noise != NULL);

    void *tor_buf = arena_alloc(&a, 1024);              /* 1 KB      */
    TEST_ASSERT(tor_buf != NULL);

    void *io_buf = arena_alloc(&a, 32768);              /* 32 KB     */
    TEST_ASSERT(io_buf != NULL);

    void *scratch = arena_alloc(&a, 16384);             /* 16 KB     */
    TEST_ASSERT(scratch != NULL);

    /* Toplam ~49 KB — hala margin olmalı */
    TEST_ASSERT(arena_bytes_free(&a) > 0);

    NOX_DEBUG(LOG_MOD_ARENA,
              "64KB test: used=%zu free=%zu",
              arena_bytes_used(&a), arena_bytes_free(&a));

    arena_destroy(&a);
    return 0;
}

/* ================================================================
 * TEST: arena_destroy — bellek sıfırlanıyor mu
 *
 * Not: Bu test arena_destroy sonrası belleğe erişir.
 * munmap sonrası erişim UB olduğu için, destroy öncesi kontrol.
 * ================================================================ */
static int test_arena_memory_zeroed(void)
{
    struct secure_arena a = {0};
    nox_err_t err = arena_init(&a, 4096);
    TEST_ASSERT(err == NOX_OK);

    /* Hassas veri yaz */
    uint8_t *secret = arena_alloc(&a, 32);
    TEST_ASSERT(secret != NULL);
    memset(secret, 0xAA, 32);

    /* Destroy öncesi verinin orada olduğunu doğrula */
    TEST_ASSERT(secret[0] == 0xAA);
    TEST_ASSERT(secret[31] == 0xAA);

    /*
     * arena_destroy çağrıldığında explicit_bzero + munmap yapılır.
     * munmap sonrası belleğe erişemeyiz.
     * Burada sadece destroy'un crash olmadan tamamlandığını doğruluyoruz.
     */
    arena_destroy(&a);

    /* Struct sıfırlanmış olmalı */
    TEST_ASSERT_MEM_ZERO(&a, sizeof(a));

    return 0;
}

/* ================================================================
 * arena_alloc_canary — honeypot allocation testleri
 * ================================================================ */
static int test_arena_alloc_canary_null(void)
{
    /* NULL guard */
    void *p = arena_alloc_canary(NULL, 32);
    TEST_ASSERT(p == NULL);

    return 0;
}

static int test_arena_alloc_canary_zero_size(void)
{
    struct secure_arena a;
    nox_err_t err = arena_init(&a, NOX_ARENA_DEFAULT_SIZE);
    TEST_ASSERT(err == NOX_OK);

    /* size=0 → NULL */
    void *p = arena_alloc_canary(&a, 0);
    TEST_ASSERT(p == NULL);

    arena_destroy(&a);
    return 0;
}

static int test_arena_alloc_canary_valid(void)
{
    struct secure_arena a;
    nox_err_t err = arena_init(&a, NOX_ARENA_DEFAULT_SIZE);
    TEST_ASSERT(err == NOX_OK);

    /* Canary allocation başarılı olmalı */
    void *p = arena_alloc_canary(&a, NOX_KEY_LEN);
    TEST_ASSERT(p != NULL);

    /* 16-byte hizalı olmalı */
    TEST_ASSERT(((uintptr_t)p) % 16 == 0);

    /* Offset artmış olmalı */
    TEST_ASSERT(a.offset == NOX_KEY_LEN);

    arena_destroy(&a);
    return 0;
}

static int test_arena_alloc_canary_random(void)
{
    struct secure_arena a;
    nox_err_t err = arena_init(&a, NOX_ARENA_DEFAULT_SIZE);
    TEST_ASSERT(err == NOX_OK);

    /* İki canary allocation'ı farklı içerik döndürmeli */
    uint8_t *c1 = arena_alloc_canary(&a, NOX_KEY_LEN);
    uint8_t *c2 = arena_alloc_canary(&a, NOX_KEY_LEN);
    TEST_ASSERT(c1 != NULL);
    TEST_ASSERT(c2 != NULL);

    /* Rastgele oldukları için farklı olmaları çok muhtemel */
    bool all_same = true;
    for (size_t i = 0; i < NOX_KEY_LEN; i++) {
        if (c1[i] != c2[i]) {
            all_same = false;
            break;
        }
    }
    /* Teknik olarak aynı olma ihtimali var (2^-256), ama pratikte imkansız */
    TEST_ASSERT(!all_same);

    arena_destroy(&a);
    return 0;
}

static int test_arena_alloc_canary_overflow(void)
{
    struct secure_arena a;
    nox_err_t err = arena_init(&a, NOX_ARENA_DEFAULT_SIZE);
    TEST_ASSERT(err == NOX_OK);

    /* Arena'yı doldur — canary allocation başarısız olmalı */
    size_t huge = a.usable_size + 1;
    void *p = arena_alloc_canary(&a, huge);
    TEST_ASSERT(p == NULL);

    arena_destroy(&a);
    return 0;
}

static int test_arena_alloc_canary_between_keys(void)
{
    struct secure_arena a;
    nox_err_t err = arena_init(&a, NOX_ARENA_DEFAULT_SIZE);
    TEST_ASSERT(err == NOX_OK);

    /* Gerçek key → canary → gerçek key simülasyonu */
    uint8_t *key1 = arena_alloc(&a, NOX_KEY_LEN);
    TEST_ASSERT(key1 != NULL);
    memset(key1, 0x11, NOX_KEY_LEN);

    void *canary = arena_alloc_canary(&a, NOX_KEY_LEN);
    TEST_ASSERT(canary != NULL);

    uint8_t *key2 = arena_alloc(&a, NOX_KEY_LEN);
    TEST_ASSERT(key2 != NULL);
    memset(key2, 0x22, NOX_KEY_LEN);

    /* Key'lerin içerikleri korunmalı */
    TEST_ASSERT(key1[0] == 0x11);
    TEST_ASSERT(key2[0] == 0x22);

    /* Canary rastgele (0x11 veya 0x22 olmamalı) */
    TEST_ASSERT(((uint8_t *)canary)[0] != 0x11);
    TEST_ASSERT(((uint8_t *)canary)[0] != 0x22);

    /* Offset: 3 × NOX_KEY_LEN (16-byte hizalı) */
    TEST_ASSERT(a.offset == NOX_KEY_LEN * 3);

    arena_destroy(&a);
    return 0;
}

/* ================================================================
 * MAIN — Tüm testleri çalıştır
 * ================================================================ */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== test_arena ===\n\n");

    RUN_TEST(test_arena_init_success);
    RUN_TEST(test_arena_init_null);
    RUN_TEST(test_arena_alloc_alignment);
    RUN_TEST(test_arena_alloc_overflow);
    RUN_TEST(test_arena_usage_tracking);
    RUN_TEST(test_arena_alloc_null);
    RUN_TEST(test_arena_default_size);
    RUN_TEST(test_arena_memory_zeroed);
    RUN_TEST(test_arena_alloc_canary_null);
    RUN_TEST(test_arena_alloc_canary_zero_size);
    RUN_TEST(test_arena_alloc_canary_valid);
    RUN_TEST(test_arena_alloc_canary_random);
    RUN_TEST(test_arena_alloc_canary_overflow);
    RUN_TEST(test_arena_alloc_canary_between_keys);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
