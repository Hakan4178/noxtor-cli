/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_wire_hardening.c — saldırgan kaynaklı iki yüzeyin sertleştirme kilidi
 *
 * İki bağımsız korpus, tek dosya:
 *
 * A) sanitize_filename (file_transfer.c:31) — PEERDAN GELEN dosya adı.
 *    Path traversal'ın ilk savunma hattı; daha önce HİÇ unit corpus'u yoktu.
 *    Sözleşme: basename / max_len sınırı / whitelist (a-z A-Z 0-9 . _ -) /
 *    ".."→"__" / baştaki '.'→'_' / boş→"file_%08x". Testler hem temiz
 *    isimleri (iyi) hem traversal denemelerini (kötü) sabitler.
 *
 * B) frame_header_decode (network.c:1865) — AĞDAN GELEN 13 byte.
 *    Sözleşme: magic/type/len doğrulanır, hata NOX_ERR_PROTO. L-7 (tip
 *    aralığı) ve uzunluk tavanı burada kilitlenir. NULL wire → fail-closed
 *    (çökme yok, PROTO).
 */

#include "common.h"
#include "types.h"
#include "file_transfer.h"
#include "network.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

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

/* sanitize sonucu yalnız whitelist karakterlerden mi oluşuyor? */
static int only_whitelist(const char *s)
{
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int expect_sanitized(const char *in, size_t max_len, const char *want)
{
    char buf[512];
    size_t n = strlen(in);
    if (n + 1 > sizeof(buf)) return -1;
    memcpy(buf, in, n + 1);
    sanitize_filename(buf, max_len);
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "\n  sanitize mismatch: in=[%s] max=%zu\n"
                        "    got =[%s]\n    want=[%s]\n",
                in, max_len, buf, want);
        return 1;
    }
    return 0;
}

/* ================================================================
 * A) sanitize_filename — iyi yol (temiz isimler bozulmaz)
 * ================================================================ */

static int test_sanitize_clean_names_unchanged(void)
{
    TEST_ASSERT(expect_sanitized("rapor.txt", 256, "rapor.txt") == 0);
    TEST_ASSERT(expect_sanitized("a_b-c.1", 256, "a_b-c.1") == 0);
    return 0;
}

/* ================================================================
 * A) sanitize_filename — kötü yol (traversal korpusu)
 * ================================================================ */

static int test_sanitize_traversal(void)
{
    /* Klasik traversal — basename'e indirgenir */
    TEST_ASSERT(expect_sanitized("../../etc/passwd", 256, "passwd") == 0);
    TEST_ASSERT(expect_sanitized("/etc/shadow", 256, "shadow") == 0);
    TEST_ASSERT(expect_sanitized("/abs/path/../../x", 256, "x") == 0);
    /* Sadece ".." / "." — nokta kuralları */
    TEST_ASSERT(expect_sanitized("..", 256, "__") == 0);
    TEST_ASSERT(expect_sanitized(".", 256, "_") == 0);
    TEST_ASSERT(expect_sanitized("a..b", 256, "a__b") == 0);
    TEST_ASSERT(expect_sanitized("....", 256, "____") == 0);
    /* Gizli dosya */
    TEST_ASSERT(expect_sanitized(".gizli", 256, "_gizli") == 0);
    return 0;
}

static int test_sanitize_weird_inputs(void)
{
    /* Boşluk ve yüzde-encoded separator */
    TEST_ASSERT(expect_sanitized("file with spaces.txt", 256,
                                 "file_with_spaces.txt") == 0);
    TEST_ASSERT(expect_sanitized("..%2f", 256, "___2f") == 0);
    /* Sondaki slash → basename boş → rastgele ad (prefix kontrol) */
    char buf[32];
    snprintf(buf, sizeof(buf), "dir/");
    sanitize_filename(buf, sizeof(buf));
    TEST_ASSERT(strncmp(buf, "file_", 5) == 0);
    TEST_ASSERT(strlen(buf) == 13);           /* file_ + 8 hex */
    /* UTF-8: her non-ASCII byte whitelist dışı → '_' (ad hâlâ güvenli) */
    char utf[64];
    snprintf(utf, sizeof(utf), "Şifre.txt");
    sanitize_filename(utf, sizeof(utf));
    TEST_ASSERT(only_whitelist(utf));
    TEST_ASSERT(strcmp(utf + strlen(utf) - 4, ".txt") == 0);
    /* Boş ad → rastgele */
    char empty[32] = "";
    sanitize_filename(empty, sizeof(empty));
    TEST_ASSERT(strncmp(empty, "file_", 5) == 0 && strlen(empty) == 13);
    return 0;
}

static int test_sanitize_bounds_and_null(void)
{
    /* 300 karakter → max_len 256'da 255'e kırpılır */
    char big[512];
    memset(big, 'a', 300);
    big[300] = '\0';
    sanitize_filename(big, 256);
    TEST_ASSERT(strlen(big) == 255);

    /* max_len = 1: sığmaz → NUL garantisi, çökme yok */
    char tiny[8] = "abc";
    sanitize_filename(tiny, 1);
    TEST_ASSERT(tiny[0] == '\0');

    /* NULL ve max_len=0 → no-op, çökme yok */
    sanitize_filename(NULL, 16);
    char keep[8] = "abc";
    sanitize_filename(keep, 0);
    TEST_ASSERT(strcmp(keep, "abc") == 0);

    /* Uzun traversal: kırpma sonrası yine güvenli */
    char long_atk[512];
    memset(long_atk, '.', 400);
    long_atk[400] = '\0';
    sanitize_filename(long_atk, 256);
    TEST_ASSERT(only_whitelist(long_atk));
    TEST_ASSERT(long_atk[0] != '.');
    return 0;
}

/* ================================================================
 * B) frame_header_decode — roundtrip (iyi yol)
 * ================================================================ */

static int test_frame_roundtrip_all_types(void)
{
    for (uint8_t t = NOX_MSG_TEXT; t <= NOX_MSG_CTRL; t++) {
        struct frame_header orig = {
            .magic = NOX_FRAME_MAGIC,
            .type  = t,
            .seq   = 0xA1B2C3D4u,
            .len   = 100,
        };
        uint8_t wire[FRAME_HEADER_WIRE_SIZE];
        frame_header_encode(&orig, wire);

        /* Wire: big-endian garantisi — ilk 4 byte magic'in BE hâli */
        TEST_ASSERT(wire[0] == 0xDE && wire[1] == 0xAD &&
                    wire[2] == 0xC0 && wire[3] == 0xDE);

        struct frame_header dec;
        memset(&dec, 0, sizeof(dec));
        TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_OK);
        TEST_ASSERT(dec.magic == orig.magic);
        TEST_ASSERT(dec.type  == orig.type);
        TEST_ASSERT(dec.seq   == orig.seq);
        TEST_ASSERT(dec.len   == orig.len);
    }
    return 0;
}

static int test_frame_boundary_len_and_seq(void)
{
    struct frame_header hdr = {
        .magic = NOX_FRAME_MAGIC, .type = NOX_MSG_TEXT,
        .seq = 0xFFFFFFFFu, .len = FRAME_MAX_PAYLOAD,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&hdr, wire);

    struct frame_header dec;
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_OK);
    TEST_ASSERT(dec.len == FRAME_MAX_PAYLOAD);
    TEST_ASSERT(dec.seq == 0xFFFFFFFFu);

    /* Tavan + 1 → PROTO */
    hdr.len = FRAME_MAX_PAYLOAD + 1;
    frame_header_encode(&hdr, wire);
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_ERR_PROTO);
    return 0;
}

/* ================================================================
 * B) frame_header_decode — kötü yol (hostile wire)
 * ================================================================ */

static int test_frame_bad_magic(void)
{
    struct frame_header hdr = {
        .magic = 0x12345678, .type = NOX_MSG_TEXT, .seq = 1, .len = 10,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&hdr, wire);

    struct frame_header dec;
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_ERR_PROTO);

    /* Tamamen sıfır wire */
    uint8_t zeros[FRAME_HEADER_WIRE_SIZE] = {0};
    TEST_ASSERT(frame_header_decode(zeros, &dec) == NOX_ERR_PROTO);

    /* Ayna senaryosu: 9d 9b 3e 9b (magic'in tersi — endian karışması) */
    uint8_t swapped[FRAME_HEADER_WIRE_SIZE] = {
        0xDE, 0xC0, 0xAD, 0xDE, NOX_MSG_TEXT, 0, 0, 0, 1, 0, 0, 0, 10
    };
    TEST_ASSERT(frame_header_decode(swapped, &dec) == NOX_ERR_PROTO);
    return 0;
}

static int test_frame_type_range(void)
{
    struct frame_header hdr = {
        .magic = NOX_FRAME_MAGIC, .type = 0, .seq = 0, .len = 0,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    struct frame_header dec;

    /* 0 → L-7 alt sınır dışı */
    frame_header_encode(&hdr, wire);
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_ERR_PROTO);

    /* CTRL + 1 → üst sınır dışı */
    hdr.type = NOX_MSG_CTRL + 1;
    frame_header_encode(&hdr, wire);
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_ERR_PROTO);

    /* 255 → üst sınır dışı */
    hdr.type = 255;
    frame_header_encode(&hdr, wire);
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_ERR_PROTO);

    /* len=0 geçerli (decode tavan kontrolü yapar, alt sınır koymaz) */
    hdr.type = NOX_MSG_TEXT;
    frame_header_encode(&hdr, wire);
    TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_OK);
    TEST_ASSERT(dec.len == 0);
    return 0;
}

/* NULL wire → fail-closed: çökme değil, PROTO (red beklentisi) */
static int test_frame_null_wire_fails_closed(void)
{
    struct frame_header dec;
    TEST_ASSERT(frame_header_decode(NULL, &dec) == NOX_ERR_PROTO);
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== wire/dosya-adı sertleştirme korpusu ===\n");

    RUN_TEST(test_sanitize_clean_names_unchanged);
    RUN_TEST(test_sanitize_traversal);
    RUN_TEST(test_sanitize_weird_inputs);
    RUN_TEST(test_sanitize_bounds_and_null);
    RUN_TEST(test_frame_roundtrip_all_types);
    RUN_TEST(test_frame_boundary_len_and_seq);
    RUN_TEST(test_frame_bad_magic);
    RUN_TEST(test_frame_type_range);
    RUN_TEST(test_frame_null_wire_fails_closed);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
