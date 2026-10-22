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
 *   7. Derived HS: ServiceID ↔ beklenen pub eşleşmesi kabul
 *   8. Ghost HS: rastgele seed pub'ı ↔ ServiceID eşleşmesi kabul
 *   9. Yabancı ama geçerli ServiceID → derived HS reddi
 *  10. Yabancı ama geçerli ServiceID → ghost HS reddi
 *
 * Not: UTF-8 chunk sınırı sözleşmesi ayrı dosyada (test_chunk_size.c)
 * gerçek nox_next_chunk_size ile test edilir — burada kopya barındırılmaz.
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "crypto.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sodium.h>
#include "test_common.h"


/* ================================================================
 * SAHTE TOR CONTROL SUNUCUSU
 *
 * Gerçek Tor olmadan ADD_ONION yanıtını üretir. İki mod:
 *   MATCH_REQUEST: gelen ED25519-V3:<b64> komutundan pub'ı türetip
 *                  o pub'a ait geçerli v3 adresi döndürür.
 *   FIXED_ADDR:    verilen adresi aynen döndürür (yabancı anahtar testi).
 * ================================================================ */
enum fake_tor_mode {
    FAKE_TOR_MATCH_REQUEST = 0,
    FAKE_TOR_FIXED_ADDR    = 1,
};

struct fake_tor {
    int fd;
    pid_t pid;
};

static const uint8_t TEST_MASTER_A[NOX_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t TEST_MASTER_B[NOX_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

/* pub → v3 onion adresi (checksum + version dahil) üret. */
static int test_make_onion_addr(char out[NOX_ONION_LEN + 1],
                                const uint8_t pub[NOX_KEY_LEN])
{
    uint8_t body[NOX_ONION_BODY_LEN];
    uint8_t ck_in[15 + NOX_KEY_LEN + 1];
    uint8_t digest[crypto_hash_sha3256_BYTES];

    memcpy(body, pub, NOX_KEY_LEN);
    body[NOX_ONION_BODY_LEN - 1] = 0x03;

    memcpy(ck_in, ".onion checksum", 15);
    memcpy(ck_in + 15, pub, NOX_KEY_LEN);
    ck_in[15 + NOX_KEY_LEN] = 0x03;

    if (crypto_hash_sha3256(digest, ck_in, sizeof(ck_in)) != 0) {
        sodium_memzero(body, sizeof(body));
        sodium_memzero(ck_in, sizeof(ck_in));
        return 1;
    }
    memcpy(body + NOX_KEY_LEN, digest, 2);
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(ck_in, sizeof(ck_in));

    nox_test_base32_encode(body, NOX_ONION_BODY_LEN, out);
    memcpy(out + NOX_ONION_B32_LEN, ".onion", 7);
    sodium_memzero(body, sizeof(body));
    return 0;
}

static int test_derive_expected_onion(char out[NOX_ONION_LEN + 1],
                                      const uint8_t master[NOX_KEY_LEN])
{
    uint8_t seed[NOX_KEY_LEN];
    uint8_t expanded[64];
    uint8_t pub[NOX_KEY_LEN];
    int rc = 1;

    if (crypto_derive_onion_seed(seed, master) != NOX_OK)
        goto cleanup;
    if (derive_tor_expanded_key(expanded, pub, seed) != NOX_OK)
        goto cleanup;

    rc = test_make_onion_addr(out, pub);

cleanup:
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(expanded, sizeof(expanded));
    sodium_memzero(pub, sizeof(pub));
    return rc;
}

static int test_buffer_is_value(const void *buf, size_t len, uint8_t value)
{
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != value)
            return 0;
    }
    return 1;
}

/* Child tarafı: ADD_ONION satırını oku, uygun ServiceID yanıtını yaz. */
static void fake_tor_child(int fd, int mode, const char *fixed_addr)
{
    char line[512];
    size_t n = 0;

    while (n < sizeof(line) - 1) {
        char c;
        ssize_t r;
        do {
            r = read(fd, &c, 1);
        } while (r < 0 && errno == EINTR);
        if (r <= 0)
            _exit(1);
        line[n++] = c;
        if (c == '\n')
            break;
    }
    line[n] = '\0';
    if (n == 0 || line[n - 1] != '\n')
        _exit(1);

    char addr[NOX_ONION_LEN + 1];

    if (mode == FAKE_TOR_MATCH_REQUEST) {
        const char *key = strstr(line, "ED25519-V3:");
        if (!key)
            _exit(1);
        key += strlen("ED25519-V3:");

        const char *end = strchr(key, ' ');
        if (!end)
            _exit(1);

        size_t b64_len = (size_t)(end - key);
        char b64[128];
        if (b64_len == 0 || b64_len >= sizeof(b64))
            _exit(1);
        memcpy(b64, key, b64_len);
        b64[b64_len] = '\0';

        uint8_t expanded[64];
        uint8_t pub[NOX_KEY_LEN];
        size_t bin_len = 0;
        if (sodium_base642bin(expanded, sizeof(expanded), b64, b64_len,
                              NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) != 0 ||
            bin_len != sizeof(expanded)) {
            sodium_memzero(expanded, sizeof(expanded));
            _exit(1);
        }
        if (crypto_scalarmult_ed25519_base(pub, expanded) != 0 ||
            test_make_onion_addr(addr, pub) != 0) {
            sodium_memzero(expanded, sizeof(expanded));
            sodium_memzero(pub, sizeof(pub));
            _exit(1);
        }
        sodium_memzero(expanded, sizeof(expanded));
        sodium_memzero(pub, sizeof(pub));
    } else {
        if (!fixed_addr || strlen(fixed_addr) != NOX_ONION_LEN)
            _exit(1);
        memcpy(addr, fixed_addr, NOX_ONION_LEN + 1);
    }

    char resp[256];
    int rn = snprintf(resp, sizeof(resp),
                      "250-ServiceID=%.*s\r\n250 OK\r\n",
                      (int)NOX_ONION_B32_LEN, addr);
    if (rn <= 0 || (size_t)rn >= sizeof(resp))
        _exit(1);

    size_t off = 0;
    while (off < (size_t)rn) {
        ssize_t w;
        do {
            w = write(fd, resp + off, (size_t)rn - off);
        } while (w < 0 && errno == EINTR);
        if (w <= 0)
            _exit(1);
        off += (size_t)w;
    }
    _exit(0);
}

static int fake_tor_start(struct fake_tor *ft, int mode, const char *fixed_addr)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    if (pid == 0) {
        close(sv[0]);
        fake_tor_child(sv[1], mode, fixed_addr);
    }

    close(sv[1]);
    ft->fd = sv[0];
    ft->pid = pid;
    return 0;
}

static int fake_tor_finish(struct fake_tor *ft)
{
    (void)close(ft->fd);

    int status = 0;
    pid_t r;
    do {
        r = waitpid(ft->pid, &status, 0);
    } while (r < 0 && errno == EINTR);

    if (r != ft->pid)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}


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

    /* H2: AD üreticisi, alıcının ham header olarak gördüğü byte'ların
     * birebir aynısını üretmeli. */
    uint8_t ad[FRAME_HEADER_WIRE_SIZE];
    frame_ad(&orig, ad);
    TEST_ASSERT(memcmp(wire, ad, sizeof(wire)) == 0);

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

/* ================================================================
 * TEST: Derived HS — ServiceID gerçekten bizim pub'ımıza bağlı mı?
 * ================================================================ */
static int test_service_id_matches_derived_pub(void)
{
    char expected[NOX_ONION_LEN + 1];
    TEST_ASSERT(test_derive_expected_onion(expected, TEST_MASTER_A) == 0);

    struct fake_tor ft;
    TEST_ASSERT(fake_tor_start(&ft, FAKE_TOR_MATCH_REQUEST, NULL) == 0);

    char out[NOX_ONION_LEN + 1] = {0};
    nox_err_t err = tor_create_derived_hs(ft.fd, "/tmp/noxtor-test-hs.sock",
                                          TEST_MASTER_A, out, sizeof(out));
    int child_ok = fake_tor_finish(&ft);

    TEST_ASSERT(child_ok == 0);
    TEST_ASSERT(err == NOX_OK);
    TEST_ASSERT(strcmp(out, expected) == 0);
    return 0;
}

/* ================================================================
 * TEST: Ghost HS — rastgele seed'den türeyen pub ↔ ServiceID bağı
 * ================================================================ */
static int test_service_id_matches_ghost_pub(void)
{
    struct fake_tor ft;
    TEST_ASSERT(fake_tor_start(&ft, FAKE_TOR_MATCH_REQUEST, NULL) == 0);

    uint8_t seed[NOX_KEY_LEN] = {0};
    char out[NOX_ONION_LEN + 1] = {0};
    nox_err_t err = tor_create_new_hs(ft.fd, "/tmp/noxtor-test-hs.sock",
                                      seed, out, sizeof(out));
    int child_ok = fake_tor_finish(&ft);

    TEST_ASSERT(child_ok == 0);
    TEST_ASSERT(err == NOX_OK);

    uint8_t expanded[64];
    uint8_t pub[NOX_KEY_LEN];
    char expected[NOX_ONION_LEN + 1];
    int match = 0;
    if (derive_tor_expanded_key(expanded, pub, seed) == NOX_OK &&
        test_make_onion_addr(expected, pub) == 0) {
        match = (strcmp(out, expected) == 0);
    }

    sodium_memzero(expanded, sizeof(expanded));
    sodium_memzero(pub, sizeof(pub));
    sodium_memzero(seed, sizeof(seed));

    TEST_ASSERT(match == 1);
    return 0;
}

/* ================================================================
 * TEST: Yabancı ama geçerli ServiceID — derived HS reddetmeli
 * ================================================================ */
static int test_service_id_foreign_pub_rejected_derived(void)
{
    char foreign[NOX_ONION_LEN + 1];
    TEST_ASSERT(test_derive_expected_onion(foreign, TEST_MASTER_B) == 0);

    struct fake_tor ft;
    TEST_ASSERT(fake_tor_start(&ft, FAKE_TOR_FIXED_ADDR, foreign) == 0);

    char out[NOX_ONION_LEN + 1];
    memset(out, 0xA5, sizeof(out));

    nox_err_t err = tor_create_derived_hs(ft.fd, "/tmp/noxtor-test-hs.sock",
                                          TEST_MASTER_A, out, sizeof(out));
    int child_ok = fake_tor_finish(&ft);

    TEST_ASSERT(child_ok == 0);
    TEST_ASSERT(err == NOX_ERR_ONION);
    TEST_ASSERT(test_buffer_is_value(out, sizeof(out), 0xA5));
    return 0;
}

/* ================================================================
 * TEST: Yabancı ama geçerli ServiceID — ghost HS reddetmeli
 * ================================================================ */
static int test_service_id_foreign_pub_rejected_ghost(void)
{
    char foreign[NOX_ONION_LEN + 1];
    TEST_ASSERT(test_derive_expected_onion(foreign, TEST_MASTER_B) == 0);

    struct fake_tor ft;
    TEST_ASSERT(fake_tor_start(&ft, FAKE_TOR_FIXED_ADDR, foreign) == 0);

    uint8_t seed[NOX_KEY_LEN] = {0};
    char out[NOX_ONION_LEN + 1];
    memset(out, 0xA5, sizeof(out));

    nox_err_t err = tor_create_new_hs(ft.fd, "/tmp/noxtor-test-hs.sock",
                                      seed, out, sizeof(out));
    int child_ok = fake_tor_finish(&ft);

    TEST_ASSERT(child_ok == 0);
    TEST_ASSERT(err == NOX_ERR_ONION);
    TEST_ASSERT(test_buffer_is_value(seed, sizeof(seed), 0));
    TEST_ASSERT(test_buffer_is_value(out, sizeof(out), 0xA5));
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
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init başarısız\n");
        return 1;
    }

    fprintf(stderr, "\n=== test_network ===\n\n");

    RUN_TEST(test_frame_roundtrip);
    RUN_TEST(test_frame_endian);
    RUN_TEST(test_frame_bad_magic);
    RUN_TEST(test_frame_overflow);
    RUN_TEST(test_frame_all_types);
    RUN_TEST(test_listener_create);
    RUN_TEST(test_service_id_matches_derived_pub);
    RUN_TEST(test_service_id_matches_ghost_pub);
    RUN_TEST(test_service_id_foreign_pub_rejected_derived);
    RUN_TEST(test_service_id_foreign_pub_rejected_ghost);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n\n",
            tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
