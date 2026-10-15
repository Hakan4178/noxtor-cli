/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_chunk_size.c — nox_next_chunk_size UTF-8 sınır sözleşmesi (D)
 *
 * get_next_chunk_size üretim sınırında kodpoint bölmüyordu (kanitlanmamış
 * varsayım) — bu test hem mevcut davranışı kilitler hem de 4000 sınırına
 * tam oturan karakterlerin (2/3/4 byte) güvenli bölünmesini belgeler.
 *
 * Sınır: chunk_limit = 4000 (stdin_handler.c). Sözleşme:
 *   - remaining <= 4000 → kalanın tamamı
 *   - kodpoint ortasına denk gelen sınır → sınır LEAD byte'ın ÖNÜNE çekilir
 *   - tamamen continuation garbage (geçersiz UTF-8) → 1 (progress garantisi)
 *   - offset >= total → 0
 *   - reassembly property: parçalar birleşince orijinal + hiçbir sınır
 *     geçerli UTF-8 girişte kodpoint bölmez
 */

#include "common.h"
#include "types.h"
#include "stdin_handler.h"

#include <stdio.h>
#include <string.h>

#include "test_common.h"


#define CHUNK_LIMIT 4000U

static int is_cont(uint8_t b) { return (b & 0xC0) == 0x80; }

/* 1) Kısa mesaj → tek parça, tam uzunluk */
static int test_short_message(void)
{
    TEST_ASSERT(nox_next_chunk_size("abc", 0, 3) == 3);
    TEST_ASSERT(nox_next_chunk_size("", 0, 0) == 0);
    return 0;
}

/* 2) offset uçta: offset >= total_len → 0 */
static int test_offset_at_end(void)
{
    TEST_ASSERT(nox_next_chunk_size("abc", 3, 3) == 0);
    TEST_ASSERT(nox_next_chunk_size("abc", 99, 3) == 0);
    return 0;
}

/* 3) Tam sınır ve sınır+1 (ASCII) */
static int test_exact_boundary_ascii(void)
{
    char buf[CHUNK_LIMIT + 2];
    memset(buf, 'A', sizeof(buf));
    TEST_ASSERT(nox_next_chunk_size(buf, 0, CHUNK_LIMIT) == CHUNK_LIMIT);
    TEST_ASSERT(nox_next_chunk_size(buf, 0, CHUNK_LIMIT + 1) == CHUNK_LIMIT);
    return 0;
}

/* 4) 3-byte UTF-8 (€ = E2 82 AC) sınırda STRADDLE: son 1 ASCII + € →
 *    sınır lead'in önüne çekilir (3999), € tam taşınır */
static int test_euro_straddle(void)
{
    char buf[CHUNK_LIMIT + 4];
    memset(buf, 'A', CHUNK_LIMIT - 1);
    buf[CHUNK_LIMIT - 1] = '\xE2';
    buf[CHUNK_LIMIT]     = '\x82';
    buf[CHUNK_LIMIT + 1] = '\xAC';
    buf[CHUNK_LIMIT + 2] = 'Z';
    TEST_ASSERT(nox_next_chunk_size(buf, 0, CHUNK_LIMIT + 2) ==
                CHUNK_LIMIT - 1);
    return 0;
}

/* 5) 4-byte emoji (😀 = F0 9F 98 80) sınırda STRADDLE: 3 ASCII + emoji →
 *    sınır 3997'ye çekilir */
static int test_emoji_straddle(void)
{
    char buf[CHUNK_LIMIT + 8];
    memset(buf, 'A', CHUNK_LIMIT - 3);
    buf[CHUNK_LIMIT - 3] = '\xF0';
    buf[CHUNK_LIMIT - 2] = '\x9F';
    buf[CHUNK_LIMIT - 1] = '\x98';
    buf[CHUNK_LIMIT]     = '\x80';
    buf[CHUNK_LIMIT + 1] = 'Z';
    TEST_ASSERT(nox_next_chunk_size(buf, 0, CHUNK_LIMIT + 1) ==
                CHUNK_LIMIT - 3);
    return 0;
}

/* 6) Karakter TAM sınırda BAŞLIYOR (lead byte offset+4000'de) → sınır
 *    kilitlenir (4000), karakter sonraki parçada bütün kalır */
static int test_char_starts_at_boundary(void)
{
    char buf[CHUNK_LIMIT + 4];
    memset(buf, 'A', CHUNK_LIMIT);
    buf[CHUNK_LIMIT]     = '\xE2';   /* € lead — chunk sınırında */
    buf[CHUNK_LIMIT + 1] = '\x82';
    buf[CHUNK_LIMIT + 2] = '\xAC';
    TEST_ASSERT(nox_next_chunk_size(buf, 0, CHUNK_LIMIT + 3) ==
                CHUNK_LIMIT);
    return 0;
}

/* 7) Degenerate: 5000 byte saf continuation (geçersiz UTF-8) → sonuca
 *    VARMALI (infinite-loop yok), 1 döner (progress garantisi) */
static int test_all_continuation_progress(void)
{
    static char buf[5000];
    memset(buf, '\x80', sizeof(buf));
    TEST_ASSERT(nox_next_chunk_size(buf, 0, sizeof(buf)) == 1);
    return 0;
}

/* 8) Reassembly property: geçerli UTF-8 karışımı 10000 byte → parçalar
 *    birleşince orijinal + HİÇBİR sınır kodpoint bölmez */
static int test_reassembly_no_split(void)
{
    static char buf[10000];
    size_t pos = 0;
    /* "Şifre ✓€😀" blokları + ASCII dolgu ile 10000 doldur */
    const char *block = "Şifre ✓€😀 ";   /* karışık 2/3/4 byte */
    size_t blen = strlen(block);
    while (pos + blen <= sizeof(buf)) {
        memcpy(buf + pos, block, blen);
        pos += blen;
    }
    memset(buf + pos, 'x', sizeof(buf) - pos);
    pos = sizeof(buf);

    size_t offset = 0;
    while (offset < pos) {
        size_t chunk = nox_next_chunk_size(buf, offset, pos);
        TEST_ASSERT(chunk > 0);                       /* progress */
        TEST_ASSERT(chunk <= CHUNK_LIMIT);            /* sınır aşılmaz */
        offset += chunk;
        /* sınır bir sonraki parçanın İLK byte'ı: continuation olamaz
         * (kodpoint bölünmüş olurdu) — tek parça (chunk==total) dahil */
        if (offset < pos)
            TEST_ASSERT(!is_cont((uint8_t)buf[offset]));
    }
    TEST_ASSERT(offset == pos);                       /* tam reassembly */
    return 0;
}

int main(void)
{
    fprintf(stderr, "=== UTF-8 chunk sınırı sözleşmesi (D) ===\n");

    RUN_TEST(test_short_message);
    RUN_TEST(test_offset_at_end);
    RUN_TEST(test_exact_boundary_ascii);
    RUN_TEST(test_euro_straddle);
    RUN_TEST(test_emoji_straddle);
    RUN_TEST(test_char_starts_at_boundary);
    RUN_TEST(test_all_continuation_progress);
    RUN_TEST(test_reassembly_no_split);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
