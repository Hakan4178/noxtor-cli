/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_network.c — Network modülü birim testleri
 *
 * Testler:
 *   1. Frame header encode/decode round-trip
 *   2. Frame header endianness doğrulama
 *   3. Frame magic hatalı → NOX_ERR_PROTO
 *   4. Frame payload overflow → NOX_ERR_PROTO
 *   5. SOCKS5 greeting bytes doğrulama
 *   6. Listener create + close
 */

#include "common.h"
#include "types.h"
#include "network.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* F-2 FIX: g_shutdown test dosyalarında da tanımlı olmalı */
volatile sig_atomic_t g_shutdown = 0;

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

/* ================================================================
 * TEST: Frame header round-trip
 * ================================================================ */
static int test_frame_roundtrip(void)
{
    struct frame_header orig = {
        .magic = NOX_FRAME_MAGIC,
        .type  = NOX_MSG_TEXT,
        .seq   = 42,
        .len   = 128,
    };

    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&orig, wire);

    struct frame_header decoded;
    nox_err_t err = frame_header_decode(wire, &decoded);
    TEST_ASSERT(err == NOX_OK);

    TEST_ASSERT(decoded.magic == orig.magic);
    TEST_ASSERT(decoded.type  == orig.type);
    TEST_ASSERT(decoded.seq   == orig.seq);
    TEST_ASSERT(decoded.len   == orig.len);

    return 0;
}

/* ================================================================
 * TEST: Endianness — wire'da big-endian olmalı
 * ================================================================ */
static int test_frame_endian(void)
{
    struct frame_header hdr = {
        .magic = 0xDEADC0DE,
        .type  = 1,
        .seq   = 0x01020304,
        .len   = 0x00FF0011,
    };

    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&hdr, wire);

    /* magic: DE AD C0 DE */
    TEST_ASSERT(wire[0] == 0xDE);
    TEST_ASSERT(wire[1] == 0xAD);
    TEST_ASSERT(wire[2] == 0xC0);
    TEST_ASSERT(wire[3] == 0xDE);

    /* type: 1 */
    TEST_ASSERT(wire[4] == 1);

    /* seq: 01 02 03 04 */
    TEST_ASSERT(wire[5] == 0x01);
    TEST_ASSERT(wire[6] == 0x02);
    TEST_ASSERT(wire[7] == 0x03);
    TEST_ASSERT(wire[8] == 0x04);

    /* len: 00 FF 00 11 */
    TEST_ASSERT(wire[9]  == 0x00);
    TEST_ASSERT(wire[10] == 0xFF);
    TEST_ASSERT(wire[11] == 0x00);
    TEST_ASSERT(wire[12] == 0x11);

    return 0;
}

/* ================================================================
 * TEST: Yanlış magic → NOX_ERR_PROTO
 * ================================================================ */
static int test_frame_bad_magic(void)
{
    uint8_t wire[FRAME_HEADER_WIRE_SIZE] = {0};
    /* magic = 0x00000000 (yanlış) */
    wire[0] = 0x00;

    struct frame_header hdr;
    nox_err_t err = frame_header_decode(wire, &hdr);
    TEST_ASSERT(err == NOX_ERR_PROTO);

    return 0;
}

/* ================================================================
 * TEST: Payload overflow → NOX_ERR_PROTO
 * ================================================================ */
static int test_frame_overflow(void)
{
    struct frame_header hdr = {
        .magic = NOX_FRAME_MAGIC,
        .type  = NOX_MSG_TEXT,
        .seq   = 0,
        .len   = FRAME_MAX_PAYLOAD + 1,  /* taşma */
    };

    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&hdr, wire);

    struct frame_header decoded;
    nox_err_t err = frame_header_decode(wire, &decoded);
    TEST_ASSERT(err == NOX_ERR_PROTO);

    return 0;
}

/* ================================================================
 * TEST: Tüm msg_type değerleri
 * ================================================================ */
static int test_frame_all_types(void)
{
    uint8_t types[] = { NOX_MSG_TEXT, NOX_MSG_FILE, NOX_MSG_ACK, NOX_MSG_CTRL };

    for (size_t i = 0; i < sizeof(types); i++) {
        struct frame_header hdr = {
            .magic = NOX_FRAME_MAGIC,
            .type  = types[i],
            .seq   = (uint32_t)i,
            .len   = 64,
        };

        uint8_t wire[FRAME_HEADER_WIRE_SIZE];
        frame_header_encode(&hdr, wire);

        struct frame_header dec;
        TEST_ASSERT(frame_header_decode(wire, &dec) == NOX_OK);
        TEST_ASSERT(dec.type == types[i]);
        TEST_ASSERT(dec.seq == (uint32_t)i);
    }

    return 0;
}

/* ================================================================
 * TEST: Listener create + port > 0 + close
 * ================================================================ */
static int test_listener_create(void)
{
    uint16_t port = 0;
    int fd = -1;

    nox_err_t err = listener_create(&port, &fd);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(fd >= 0);
    TEST_ASSERT(port > 0);

    close(fd);
    return 0;
}

/* UTF-8 multi-byte helper for testing chunk alignment */
static size_t get_next_chunk_size_test(const char *msg, size_t offset, size_t total_len, size_t chunk_limit) {
    if (total_len - offset <= chunk_limit) {
        return total_len - offset;
    }

    size_t size = chunk_limit;
    while (size > 0 && ((uint8_t)msg[offset + size] & 0xC0) == 0x80) {
        size--;
    }

    if (size == 0) {
        return chunk_limit;
    }
    return size;
}

static int test_utf8_chunking(void)
{
    /* Test 1: Plain ASCII does not back up */
    char ascii_buf[100];
    memset(ascii_buf, 'A', sizeof(ascii_buf));
    ascii_buf[99] = '\0';
    size_t chunk_sz = get_next_chunk_size_test(ascii_buf, 0, 99, 50);
    TEST_ASSERT(chunk_sz == 50);

    /* Test 2: Turkish 'ş' (2 bytes: \xc5\x9f) right at the boundary */
    /* If the boundary (index 5) falls on the continuation byte \x9f (index 5) */
    char utf8_buf[20] = "abcde\xc5\x9fghijk"; /* \xc5 is at index 5, \x9f is at index 6 */
    /* Let's construct it specifically:
       Index 0,1,2,3,4: a, b, c, d, e
       Index 5: \xc5
       Index 6: \x9f
       Index 7: g
    */
    /* If limit is 6, index 6 of utf8_buf is \x9f, which is 0x9f (continuation byte: 0x9f & 0xC0 = 0x80) */
    chunk_sz = get_next_chunk_size_test(utf8_buf, 0, strlen(utf8_buf), 6);
    /* It should back up by 1 and return 5, splitting before \xc5 */
    TEST_ASSERT(chunk_sz == 5);

    /* Test 3: Rocket emoji (4 bytes: \xf0\x9f\x9a\x80) */
    /* "abcde" (5 bytes) + "\xf0\x9f\x9a\x80" (4 bytes) + "fgh" */
    char emoji_buf[30] = "abcde\xf0\x9f\x9a\x80" "fgh";
    /* Rocket starts at index 5. Continuation bytes are at 6, 7, 8.
       If limit is 8 (continuation byte \x9a at index 7), it should back up to 5.
       If limit is 7 (continuation byte \x9f at index 6), it should back up to 5.
       If limit is 6 (continuation byte \xf0 at index 5? No, \xf0 & 0xC0 = 0xC0, so index 5 is not a continuation byte!)
       Wait, index 6 is \x9f (continuation byte), so limit 6 points to index 6 which is continuation byte -> back up to 5.
       If limit is 9 (index 9 is 'f', not continuation byte), it returns 9.
    */
    TEST_ASSERT(get_next_chunk_size_test(emoji_buf, 0, strlen(emoji_buf), 8) == 5);
    TEST_ASSERT(get_next_chunk_size_test(emoji_buf, 0, strlen(emoji_buf), 7) == 5);
    TEST_ASSERT(get_next_chunk_size_test(emoji_buf, 0, strlen(emoji_buf), 6) == 5);
    TEST_ASSERT(get_next_chunk_size_test(emoji_buf, 0, strlen(emoji_buf), 9) == 9);

    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void)
{
    fprintf(stderr, "\n=== test_network ===\n\n");

    RUN_TEST(test_frame_roundtrip);
    RUN_TEST(test_frame_endian);
    RUN_TEST(test_frame_bad_magic);
    RUN_TEST(test_frame_overflow);
    RUN_TEST(test_frame_all_types);
    RUN_TEST(test_listener_create);
    RUN_TEST(test_utf8_chunking);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
