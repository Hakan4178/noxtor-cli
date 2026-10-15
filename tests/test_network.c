/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_network.c — Network modülü birim testleri
 *
 * Testler:
 *   1. Frame header encode/decode round-trip
 *   2. Frame header endianness doğrulama
 *   3. Frame magic hatalı → NOX_ERR_PROTO
 *   4. Frame payload overflow → NOX_ERR_PROTO
 *   5. Tüm msg_type değerleri round-trip
 *   6. Listener create + AF_UNIX socket + 0600 izin
 *
 * Not: UTF-8 chunk sınırı sözleşmesi ayrı dosyada (test_chunk_size.c)
 * gerçek nox_next_chunk_size ile test edilir — burada kopya barındırılmaz.
 */

#include "common.h"
#include "types.h"
#include "network.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_common.h"


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
 * TEST: Listener create + AF_UNIX socket + cleanup
 * ================================================================ */
static int test_listener_create(void)
{
    char listen_path[512] = {0};
    int fd = -1;

    /* Geçici dizin oluştur */
    char tmp_dir[] = "/tmp/noxtor_test_XXXXXX";
    if (mkdtemp(tmp_dir) == NULL)
        return 1;

    nox_err_t err = listener_create(tmp_dir, listen_path, &fd);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(fd >= 0);
    TEST_ASSERT(listen_path[0] != '\0');

    /* Socket dosyası var mı kontrol et */
    struct stat st;
    TEST_ASSERT(stat(listen_path, &st) == 0);
    TEST_ASSERT(S_ISSOCK(st.st_mode));

    /* İzinleri kontrol et (0600) */
    TEST_ASSERT((st.st_mode & 0777) == 0600);

    close(fd);

    /* Cleanup */
    unlink(listen_path);
    rmdir(tmp_dir);
    return 0;
}

/* UTF-8 chunking testi bilinçli olarak kaldırıldı: eski kopya fonksiyon
 * (get_next_chunk_size_test) üretim kodunu DEĞİL test içindeki kopyasını
 * test ediyordu — yanıltıcı. Sözleşme artık gerçek nox_next_chunk_size
 * üzerinde test_chunk_size.c'de kilitli. */

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

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
