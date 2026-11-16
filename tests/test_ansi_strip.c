/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_ansi_strip.c — ui_strip_ansi korpusu (tek kanonik strip davranışı).
 * Kapsam: CSI/OSC/DCS/ESC, C0/DEL/C1/bidi, çıktıda CR/LF vs stdin EOL,
 * UTF-8 bütünlüğü. T-02 + K-33 regresyonu.
 */

#include "common.h"
#include "frontend.h"

#include <stdio.h>
#include <string.h>

#include "test_common.h"


/* girdiyi kopyala, çıktı sanitizer'ından geçir, beklenenle karşılaştır */
static int expect_stripped(const char *in, const char *want)
{
    char buf[1024];
    size_t n = strlen(in);
    if (n >= sizeof(buf)) return -1;
    memcpy(buf, in, n + 1);
    ui_strip_ansi(buf);
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "\n  strip mismatch:\n    in  = [%s]\n    got = [%s]\n"
                        "    want= [%s]\n", in, buf, want);
        return 1;
    }
    return 0;
}

/* stdin yolu: ESC/C0/C1/bidi temizlenir, CR/LF KORUNUR */
static int expect_input_stripped(const char *in, const char *want)
{
    char buf[1024];
    size_t n = strlen(in);
    if (n >= sizeof(buf)) return -1;
    memcpy(buf, in, n + 1);
    ui_strip_input(buf);
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "\n  input strip mismatch:\n    in  = [%s]\n"
                        "    got = [%s]\n    want= [%s]\n", in, buf, want);
        return 1;
    }
    return 0;
}

/* 1) CSI temel — renk kodları + sıfırlama */
static int test_csi_basic(void)
{
    TEST_ASSERT(expect_stripped("\033[1;31mKırmızı\033[0m", "Kırmızı") == 0);
    return 0;
}

/* 2) CSI parametre sınıfı (0-?) + space (/) sınıfı + final byte */
static int test_csi_classes(void)
{
    TEST_ASSERT(expect_stripped("a\033[10;20mx", "ax") == 0);  /* param + final */
    TEST_ASSERT(expect_stripped("a\033[1;2Hb", "ab") == 0);   /* H final */
    return 0;
}

/* 2b) CSI ? mod geçişi: ESC [ ? 2 5 l — '?' param sınıfı, 'l' final */
static int test_csi_private_mode(void)
{
    TEST_ASSERT(expect_stripped("a\033[?25lb", "ab") == 0);
    return 0;
}

/* 3) CSI SONLANMAMIŞ (string sonunda) — yutulur, yarım escape kopyalanmaz */
static int test_csi_truncated(void)
{
    TEST_ASSERT(expect_stripped("abc\033[1;", "abc") == 0);
    return 0;
}

/* 4) OSC BEL sonlandırmalı */
static int test_osc_bel(void)
{
    TEST_ASSERT(expect_stripped("\033]0;başlık\agettext", "gettext") == 0);
    return 0;
}

/* 5) OSC ST (ESC \) sonlandırmalı */
static int test_osc_st(void)
{
    TEST_ASSERT(expect_stripped("\033]0;t\033\\text", "text") == 0);
    return 0;
}

/* 6) OSC sonlanmamış kısa — NUL'a kadar yutulur (limit altında) */
static int test_osc_unterminated_short(void)
{
    TEST_ASSERT(expect_stripped("\033]0;abc", "") == 0);
    return 0;
}

/* 7) OSC sonlanmamış UZUN — 256 tarama limiti: tarama durur, artak
 *    kopyalanır (sınırsız frontend kopyasının eski davranışı: her şeyi
 *    yutmak — B drift'inin ta kendisi). Kilit: bounded + deterministik. */
static int test_osc_scan_limit(void)
{
    char in[512];
    size_t pos = 0;
    in[pos++] = '\033'; in[pos++] = ']';
    memset(in + pos, 'A', 300); pos += 300;
    memcpy(in + pos, "END", 3); pos += 3;
    in[pos] = '\0';

    /* ESC ] sonrası 256 byte tarama → 300-256=44 'A' + "END" kalır */
    char want[64];
    memset(want, 'A', 44);
    memcpy(want + 44, "END", 4);
    want[48] = '\0';

    TEST_ASSERT(expect_stripped(in, want) == 0);
    return 0;
}

/* 8) DCS — ST'ye kadar yutma */
static int test_dcs(void)
{
    TEST_ASSERT(expect_stripped("\033Pqdata\033\\after", "after") == 0);
    return 0;
}

/* 9) Bare ESC (string sonu) — tek kaçış, çıplak kalmaz */
static int test_bare_esc(void)
{
    TEST_ASSERT(expect_stripped("abc\033", "abc") == 0);
    return 0;
}

/* 10) ESC + diğer sınıf (ör. charset seçimi ESC ( 0) — ESC ve sınıf
 *     byte'ı düşer, artak korunur (kanonik davranış kilidi) */
static int test_esc_other_class(void)
{
    TEST_ASSERT(expect_stripped("\033(0line", "0line") == 0);
    return 0;
}

/* 11) C0 drop (TAB hariç), CR/LF tek satıra katlanır, DEL drop */
static int test_c0_and_del(void)
{
    TEST_ASSERT(expect_stripped("a\001\002b", "ab") == 0);
    TEST_ASSERT(expect_stripped("a\tb\nc\rd", "a\tb c d") == 0);
    TEST_ASSERT(expect_stripped("a\r\nb", "a  b") == 0);
    TEST_ASSERT(expect_stripped("a\177b", "ab") == 0);
    return 0;
}

/* 11b) K-33: saldırgan CR/LF ile sahte sistem satırı üretemez */
static int test_line_injection_neutralized(void)
{
    TEST_ASSERT(expect_stripped(
        "peer\r\n[✓] Dosya alındı: /etc/shadow\r\nSen: parola?",
        "peer  [✓] Dosya alındı: /etc/shadow  Sen: parola?") == 0);
    return 0;
}

/* 11c) K-33: C1 + bidi kontrol kodları görünmez yön sahteciliği yapamaz */
static int test_c1_bidi_dropped(void)
{
    TEST_ASSERT(expect_stripped("a\xC2\x9B" "31mb", "a31mb") == 0);
    TEST_ASSERT(expect_stripped("a\xE2\x80\xAE" "dcba", "adcba") == 0);
    TEST_ASSERT(expect_stripped("a\xE2\x80\xAE\xE2\x81\xA6", "a") == 0);
    TEST_ASSERT(expect_stripped("a\xD8\x9C" "b", "ab") == 0);
    return 0;
}

/* 11d) K-33 stdin: satır sonları korunur; ESC/C1/bidi yine geçmez. */
static int test_input_preserves_eol(void)
{
    TEST_ASSERT(expect_input_stripped("yardim\n", "yardim\n") == 0);
    TEST_ASSERT(expect_input_stripped("a\r\nb\n", "a\r\nb\n") == 0);
    TEST_ASSERT(expect_input_stripped("\033[2Jmsg\n", "msg\n") == 0);
    TEST_ASSERT(expect_input_stripped("a\xC2\x9B" "b\n", "ab\n") == 0);
    TEST_ASSERT(expect_input_stripped("a\xE2\x80\xAE" "b\n", "ab\n") == 0);
    TEST_ASSERT(expect_input_stripped("a\001b\n", "ab\n") == 0);
    return 0;
}

/* 12) UTF-8 butunluğu — Türkçe + emoji + EU para birimi aynen kalmalı
 *     (continuation byte'lar 0x80-0xBF C0 drop'a girmez) */
static int test_utf8_preserved(void)
{
    TEST_ASSERT(expect_stripped("Şifreleme ✓ — €uro 😀 ğüşıöç",
                                "Şifreleme ✓ — €uro 😀 ğüşıöç") == 0);
    return 0;
}

/* 13) Attacker mesajı: escape ile ekran silme/sıfırlama denemesi —
 *     nötralize edilir, metin tam kalır (asıl güvenlik özü) */
static int test_attacker_screen_clear(void)
{
    TEST_ASSERT(expect_stripped("mesaj\033[2Jsilinemez", "mesajsilinemez") == 0);
    TEST_ASSERT(expect_stripped("\033[H\033[2J\033[3Jdump", "dump") == 0);
    return 0;
}

/* 14) Saf metin + boş + kimlik */
static int test_plain_identity(void)
{
    TEST_ASSERT(expect_stripped("hello world", "hello world") == 0);
    TEST_ASSERT(expect_stripped("", "") == 0);
    return 0;
}

/* 15) NULL guard — crash yok */
static int test_null_guard(void)
{
    ui_strip_ansi(NULL);   /* no-op */
    return 0;
}

int main(void)
{
    fprintf(stderr, "=== ui_strip_ansi korpusu (B: drift kilit) ===\n");

    RUN_TEST(test_csi_basic);
    RUN_TEST(test_csi_classes);
    RUN_TEST(test_csi_private_mode);
    RUN_TEST(test_csi_truncated);
    RUN_TEST(test_osc_bel);
    RUN_TEST(test_osc_st);
    RUN_TEST(test_osc_unterminated_short);
    RUN_TEST(test_osc_scan_limit);
    RUN_TEST(test_dcs);
    RUN_TEST(test_bare_esc);
    RUN_TEST(test_esc_other_class);
    RUN_TEST(test_c0_and_del);
    RUN_TEST(test_line_injection_neutralized);
    RUN_TEST(test_c1_bidi_dropped);
    RUN_TEST(test_input_preserves_eol);
    RUN_TEST(test_utf8_preserved);
    RUN_TEST(test_attacker_screen_clear);
    RUN_TEST(test_plain_identity);
    RUN_TEST(test_null_guard);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
