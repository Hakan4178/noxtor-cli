/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_event_frames.c — event_loop frame dağıtım sözleşmesi (harness)
 *
 * process_peer_frames: recv_buf → header doğrula → (decrypt) →
 * dağıt → seq ilerlet. event_loop.c'nin kalbi; ilk kez izole test
 * ediliyor (loopback Noise çifti + socketpair, TÜM kripto gerçek).
 *
 * Kilitlenen sözleşmeler:
 *   - find_peer_by_fd: fd → slot eşlemesi, bulunamazsa NULL
 *   - hs_build_claim_payload: [ver|onion(62)|sig(64)]; seed/pub yoksa
 *     fail-closed; imza onion-adresinden verify edilebilir olmalı
 *   - TEXT happy: decrypt → rx_seq++ → buffer tüketilir
 *   - SEQ mismatch/replay (H2): IDLE + cleanup (fd kapandı, session
 *     serbest). Fix sonrası da aynı gözlem — tag fail ile tek yola düşer.
 *   - Yarım frame bekletilir; iki frame tek buffer'da slide edilir (M-3)
 *   - Session yokken TEXT bekletilir (TOFU sonrası drain kilidi)
 *   - CTRL (msg_index>=3) sessizce düşürülür (Y-2 — peer'ı öldürmesin)
 *
 * [H2/H3 FIX HEDEFİ — KIRMIZI] Auth fail artık sessiz yutulmaz:
 *   log + UI + EV_CRYPTO_FAIL → ST_IDLE. Nonce invariantı gereği
 *   başarısız decrypt kurtarılamaz ("devam" = zombi: rx_seq takılır,
 *   last_active recv'de tazelenir, sınırsız sessiz kayıp). Hedef
 *   sözleşme: ilk fail = kopma. Fix gelene kadar FAIL eden testler:
 *     test_mac_fail_disconnects              (bozuk MAC)
 *     test_len_tamper_disconnects            (len=0/aşırı → fail-closed kopma)
 *     test_header_junk_disconnects           (magic/tip 1-byte → fail-closed)
 *     test_file_decrypt_fail_disconnects     (FILE yolu)
 *     test_forged_probe_disconnects          (H3 oracle probe)
 *     test_type_flip_disconnects             (H2 type tamper → AD)
 *     test_file_type_flip_shows_garbage      (FILE→TEXT: içerik mesaj olur)
 *     test_text_into_active_transfer_corrupts(TEXT→FILE: indirmeye yazılır)
 *     test_ctrl_type_flip_eats_message       (TEXT→CTRL: sessiz yenir)
 *     test_old_ciphertext_splice             (eski ct + yeni seq)
 *     test_len_grow_tamper                   (len şişirme: çerçeve kayması)
 *     test_probe_storm_first_fail_disconnect (probe fırtınası: fail-fast)
 *     test_empty_payload_consumed            (auth başarısı = tüket; boş pt dahil)
 *   AD bağlama + fail-closed decode + fatal handler sonrası bu on üçü
 *   yeşile döner.
 */

#include "common.h"
#include "types.h"
#include "network.h"
#include "event_loop.h"
#include "noise.h"
#include "state_machine.h"
#include "file_transfer.h"
#include "crypto.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>
#include "test_common.h"

/* ================================================================
 * FIXTURE — loopback Noise çifti (test_file_transfer kalıbı)
 * ================================================================ */
static struct app_state st;
static struct noise_session *g_sess_i = NULL;  /* sender (encrypt) */
static int g_sv[2] = {-1, -1};

/* Loopback Noise XX: initiator stack, responder sodium_malloc. Split
 * her hs'yi tüketir (zeroize) — çağrı iki complete hs ister. */
static int make_split_pair(struct noise_session *sess_i,
                           struct noise_session *sess_r)
{
    uint8_t i_priv[NOX_KEY_LEN], i_pub[NOX_KEY_LEN];
    uint8_t r_priv[NOX_KEY_LEN], r_pub[NOX_KEY_LEN];
    crypto_box_curve25519xsalsa20poly1305_keypair(i_pub, i_priv);
    crypto_box_curve25519xsalsa20poly1305_keypair(r_pub, r_priv);

    struct noise_handshake hs_i;
    struct noise_handshake *hs_r = sodium_malloc(sizeof(*hs_r));
    if (!hs_r) return -1;

    if (handshake_init(&hs_i, true, i_priv, i_pub) != NOX_OK ||
        handshake_init(hs_r, false, r_priv, r_pub) != NOX_OK) {
        sodium_free(hs_r);
        return -1;
    }

    uint8_t msg[NOISE_MAX_HANDSHAKE_LEN], pl[64];
    size_t len, pl_len;
    nox_err_t err = NOX_OK;

    len = sizeof(msg);
    if (handshake_write(&hs_i, NULL, 0, msg, &len) == NOX_OK) {
        pl_len = sizeof(pl);
        if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) == NOX_OK) {
            len = sizeof(msg);
            if (handshake_write(hs_r, NULL, 0, msg, &len) == NOX_OK) {
                pl_len = sizeof(pl);
                if (handshake_read(&hs_i, msg, len, pl, sizeof(pl), &pl_len) == NOX_OK) {
                    len = sizeof(msg);
                    if (handshake_write(&hs_i, NULL, 0, msg, &len) == NOX_OK) {
                        pl_len = sizeof(pl);
                        if (handshake_read(hs_r, msg, len, pl, sizeof(pl), &pl_len) != NOX_OK)
                            err = NOX_ERR_CRYPTO;
                    } else err = NOX_ERR_CRYPTO;
                } else err = NOX_ERR_CRYPTO;
            } else err = NOX_ERR_CRYPTO;
        } else err = NOX_ERR_CRYPTO;
    } else err = NOX_ERR_CRYPTO;

    if (err == NOX_OK &&
        (!handshake_is_complete(&hs_i) || !handshake_is_complete(hs_r)))
        err = NOX_ERR_CRYPTO;

    if (err == NOX_OK)
        err = handshake_split(&hs_i, sess_i);   /* initiator → sender */
    if (err == NOX_OK)
        err = handshake_split(hs_r, sess_r);    /* responder → receiver */

    sodium_free(hs_r);
    return err == NOX_OK ? 0 : -1;
}

/* Temel state: slot0 ACTIVE + gerçek fd; session YOK */
static int fixture_base(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx = -1;
    st.epoll_fd = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++)
        st.peers[i].fd = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_sv) != 0)
        return -1;

    struct peer_session *ps = &st.peers[0];
    ps->state = ST_ACTIVE;
    ps->fd = g_sv[0];
    clock_gettime(CLOCK_MONOTONIC, &ps->last_active);
    return 0;
}

/* Session ekle: sender (g_sess_i) ↔ receiver (ps->session) */
static int attach_session(void)
{
    struct peer_session *ps = &st.peers[0];
    ps->session = sodium_malloc(sizeof(struct noise_session));
    g_sess_i = sodium_malloc(sizeof(struct noise_session));
    if (!ps->session || !g_sess_i)
        return -1;
    if (make_split_pair(g_sess_i, ps->session) != 0)
        return -1;
    ps->peer_verified = true;   /* doğrulanmış — kuyruk flush serbest */
    ps->queue_flushed = true;   /* kuyruk işini bu test kapsamaz */
    ps->rx_seq = 0;
    ps->tx_seq = 0;
    return 0;
}

static void fixture_teardown(void)
{
    struct peer_session *ps = &st.peers[0];
    if (ps->session) { sodium_free(ps->session); ps->session = NULL; }
    if (ps->hs)      { sodium_free(ps->hs);      ps->hs = NULL; }
    if (g_sess_i)    { sodium_free(g_sess_i);    g_sess_i = NULL; }
    if (g_sv[0] >= 0) close(g_sv[0]);   /* cleanup kapattıysa EBADF — zararsız */
    if (g_sv[1] >= 0) close(g_sv[1]);
    g_sv[0] = g_sv[1] = -1;
}

/* Aktif RX transfer kurulumu (test_text_into_active_transfer_corrupts):
 * gerçek dosya + downloads_dir_fd + başlatılmış hash state. */
#define EVF_DIR "tests/.tmp_evf"
static int setup_active_rx(struct peer_session *ps)
{
    mkdir(EVF_DIR, 0700);   /* EEXIST göz ardı */
    st.downloads_dir_fd = open(EVF_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (st.downloads_dir_fd < 0)
        return -1;

    ps->rx_file.fd = openat(st.downloads_dir_fd, "recv.bin",
                            O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (ps->rx_file.fd < 0)
        return -1;

    ps->rx_file.active = true;
    ps->rx_file.expected_size = 1000;
    ps->rx_file.received_bytes = 0;
    strncpy(ps->rx_file.local_name, "recv.bin",
            sizeof(ps->rx_file.local_name) - 1);
    strncpy(ps->rx_file.filename, "recv.bin",
            sizeof(ps->rx_file.filename) - 1);
    clock_gettime(CLOCK_MONOTONIC, &ps->rx_file.last_chunk_ts);
    if (crypto_generichash_init(&ps->rx_file.hash_state, NULL, 0, 32) != 0)
        return -1;
    return 0;
}

static void teardown_active_rx(struct peer_session *ps)
{
    if (ps->rx_file.fd >= 0) {
        close(ps->rx_file.fd);
        ps->rx_file.fd = -1;
    }
    if (st.downloads_dir_fd >= 0) {
        close(st.downloads_dir_fd);
        st.downloads_dir_fd = -1;
    }
    unlink(EVF_DIR "/recv.bin");
    rmdir(EVF_DIR);
}

/* ================================================================
 * YARDIMCILAR
 * ================================================================ */

/* recv_buf'a tam frame yerleştir (header + ct) */
static void frame_put(struct peer_session *ps, uint8_t type, uint32_t seq,
                      const uint8_t *ct, uint32_t ct_len)
{
    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = type,
        .seq = seq,
        .len = ct_len,
    };
    frame_header_encode(&fh, ps->recv_buf);
    if (ct_len > 0)
        memcpy(ps->recv_buf + FRAME_HEADER_WIRE_SIZE, ct, ct_len);
    ps->recv_pos = FRAME_HEADER_WIRE_SIZE + ct_len;
}

static uint32_t enc_text(const char *msg, uint8_t *ct)
{
    ssize_t n = noise_encrypt(g_sess_i, (const uint8_t *)msg,
                              strlen(msg), ct);
    return n > 0 ? (uint32_t)n : 0;
}

/* v3 adres: base32(pub(32) || checksum(2) || 0x03) + ".onion" */
static void build_v3_addr(const uint8_t pub[32], char out[63])
{
    uint8_t salted[15 + 32 + 1];
    uint8_t checksum[32];
    memcpy(salted, ".onion checksum", 15);
    memcpy(salted + 15, pub, 32);
    salted[47] = 0x03;
    crypto_hash_sha3256(checksum, salted, sizeof(salted));

    uint8_t body[35];
    memcpy(body, pub, 32);
    body[32] = checksum[0];
    body[33] = checksum[1];
    body[34] = 0x03;

    char b32[57];
    nox_test_base32_encode(body, 35, b32);
    snprintf(out, 63, "%s.onion", b32);
}

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 1) fd → peer eşlemesi */
static int test_find_peer_by_fd(void)
{
    static struct app_state s;   /* 172KB — stack'e sığdırmayalım */
    memset(&s, 0, sizeof(s));
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++)
        s.peers[i].fd = -1;
    s.peers[0].fd = 3;
    s.peers[1].fd = 7;

    TEST_ASSERT(find_peer_by_fd(&s, 7) == &s.peers[1]);
    TEST_ASSERT(find_peer_by_fd(&s, 3) == &s.peers[0]);
    TEST_ASSERT(find_peer_by_fd(&s, 99) == NULL);
    return 0;
}

/* 2) Claim payload — fail-closed yollar */
static int test_claim_payload_fail_closed(void)
{
    static struct app_state s;
    memset(&s, 0, sizeof(s));
    uint8_t pl[NOX_HS_PAYLOAD_V1_LEN];

    TEST_ASSERT(hs_build_claim_payload(NULL, &s) == NOX_ERR_CRYPTO);
    TEST_ASSERT(hs_build_claim_payload(pl, NULL) == NOX_ERR_CRYPTO);
    /* seed/pub yok → imzalanamaz */
    TEST_ASSERT(hs_build_claim_payload(pl, &s) == NOX_ERR_STATE);
    return 0;
}

/* 3) Claim roundtrip: [ver|onion|sig] — imza adres pubkey'inden verify */
static int test_claim_payload_roundtrip(void)
{
    uint8_t seed[32], pub[32], sk[64];
    randombytes_buf(seed, sizeof(seed));
    crypto_sign_seed_keypair(pub, sk, seed);

    uint8_t static_pub[NOX_KEY_LEN];
    randombytes_buf(static_pub, sizeof(static_pub));

    static struct app_state s;
    memset(&s, 0, sizeof(s));
    s.my_onion_seed = seed;
    s.my_static_pub = static_pub;
    build_v3_addr(pub, s.onion_addr);
    TEST_ASSERT(strlen(s.onion_addr) == NOX_ONION_LEN);

    uint8_t pl[NOX_HS_PAYLOAD_V1_LEN];
    TEST_ASSERT(hs_build_claim_payload(pl, &s) == NOX_OK);
    TEST_ASSERT(pl[0] == NOX_HS_PAYLOAD_V1_VER);
    TEST_ASSERT(memcmp(pl + 1, s.onion_addr, NOX_ONION_LEN) == 0);

    /* İmza, adresten çıkarılan pubkey ile geçerli olmalı */
    TEST_ASSERT(crypto_onion_verify(pl + 1 + NOX_ONION_LEN,
                                    s.onion_addr, static_pub) == NOX_OK);

    /* Tek bit bozulması → AUTH reddi (fail-closed kanıtı) */
    pl[1 + NOX_ONION_LEN] ^= 0x01;
    TEST_ASSERT(crypto_onion_verify(pl + 1 + NOX_ONION_LEN,
                                    s.onion_addr, static_pub) != NOX_OK);
    return 0;
}

/* 4) TEXT happy path: decrypt → rx_seq++ → buffer tüketildi */
static int test_text_frame_happy(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("merhaba", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->rx_seq == 1);
    TEST_ASSERT(ps->recv_pos == 0);
    TEST_ASSERT(ps->state == ST_ACTIVE);
    TEST_ASSERT(ps->session != NULL);
    fixture_teardown();
    return 0;
}

/* 5) İleri seq atlaması → IDLE + cleanup (fd gerçekten kapandı,
 *    session serbest). Fix sonrası da aynı gözlem: decrypt-öncesi
 *    kontrol silinince bu frame tag fail ile aynı tek yola düşer
 *    (seq authenticated olur; ayrı "saldırı çarpanı" kalmaz). */
static int test_seq_mismatch_disconnects(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];
    int raw_fd = ps->fd;

    uint8_t ct[64];
    uint32_t n = enc_text("troll", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 7, ct, n);   /* rx_seq=0 beklerken 7 */

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);        /* cleanup serbest bıraktı */
    TEST_ASSERT(ps->fd == -1);
    TEST_ASSERT(fcntl(raw_fd, F_GETFD) == -1 && errno == EBADF);
    fixture_teardown();
    return 0;
}

/* 6) REPLAY: aynı seq ikinci kez → disconnect (kabul edilen frame
 *    sonrası rx_seq=1; tekrar seq=0 gönderilir). Fix sonrası: eski
 *    frame'in replay'i implicit nonce tekrarı → tag fail; ayrı replay
 *    mekanizmasına gerek kalmaz, gözlem aynı (IDLE). */
static int test_replay_same_seq_disconnects(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("ilk", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);
    TEST_ASSERT(ps->rx_seq == 1);
    TEST_ASSERT(ps->state == ST_ACTIVE);

    n = enc_text("ikinci", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);   /* replay */
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    fixture_teardown();
    return 0;
}

/* 7) [H2/H3 FIX HEDEFİ — KIRMIZI] MAC fail artık sessiz yutulmaz:
 *    log + UI + EV_CRYPTO_FAIL → ST_IDLE. Nonce invariantı gereği
 *    fail kurtarılamaz ("devam" = zombi); eski davranış (sessiz drop,
 *    ACTIVE kalır, last_active tazelenir) hedeflenen davranış DEĞİL.
 *    Bu test fix gelene kadar FAIL eder. */
static int test_mac_fail_disconnects(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("bozulacak", ct);
    TEST_ASSERT(n > 0);
    ct[n - 1] ^= 0x01;                       /* MAC boz */

    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);       /* görünür kopma */
    TEST_ASSERT(ps->session == NULL);        /* cleanup serbest bıraktı */
    TEST_ASSERT(ps->rx_seq == 0);            /* başarısız frame seq ilerletmez */
    fixture_teardown();
    return 0;
}

/* 8) [H2/H3 FIX HEDEFİ — KIRMIZI] len manipülasyonu (0 / aşırı):
 *    kurulu oturumda kimlik-doğrulanamaz çerçeve → fail-closed KOPMA.
 *    Eski davranış: sessiz recv_pos=0 — aynı buffer'da arkadan gelen
 *    frame'ler de yanar, oturum yaşar (izsiz bastırma yüzeyi).
 *    İki alt-vaka ayrı fixture ister (ilki oturumu koparır). */
static int test_len_tamper_disconnects(void)
{
    /* (a) len=0: payload yok → tag yok, doğrulanamaz */
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    frame_put(ps, NOX_MSG_TEXT, 0, NULL, 0);
    process_peer_frames(ps, &st, ps->fd);
    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();

    /* (b) aşırı len: header-only, decode reddi */
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    ps = &st.peers[0];

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC, .type = NOX_MSG_TEXT, .seq = 0,
        .len = 4096 + NOX_MAC_LEN + 1,
    };
    frame_header_encode(&fh, ps->recv_buf);
    ps->recv_pos = FRAME_HEADER_WIRE_SIZE;
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 9) [H2/H3 FIX HEDEFİ — KIRMIZI] En ucuz tamper: header'da 1 byte
 *    (magic / tip). Eski davranış: decode PROTO → sessiz recv_pos=0;
 *    frame — ve aynı buffer'daki ardılları — izsiz yutulur, oturum
 *    yaşar. Hedef: kurulu oturumda çerçeve seviyesi ihlal = fail-closed
 *    kopma (TLS/SSH kayıt katmanı emsali: malformed record = fatal).
 *    İki alt-vaka ayrı fixture ister (ilki oturumu koparır). */
static int test_header_junk_disconnects(void)
{
    /* (a) magic bozuk */
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    struct frame_header fh = {
        .magic = 0xDEADBEEF, .type = NOX_MSG_TEXT, .seq = 0, .len = 16,
    };
    frame_header_encode(&fh, ps->recv_buf);
    ps->recv_pos = FRAME_HEADER_WIRE_SIZE;
    process_peer_frames(ps, &st, ps->fd);
    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();

    /* (b) bilinmeyen tip (99) */
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    ps = &st.peers[0];

    fh = (struct frame_header){
        .magic = NOX_FRAME_MAGIC, .type = 99, .seq = 0, .len = 16,
    };
    frame_header_encode(&fh, ps->recv_buf);
    ps->recv_pos = FRAME_HEADER_WIRE_SIZE;
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 10) Yarım frame bekletilir; tamamlanınca işlenir (cross-call) */
static int test_partial_frame_buffered(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("parça parça", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);
    size_t full = ps->recv_pos;

    ps->recv_pos = full - 1;                 /* son byte eksik */
    process_peer_frames(ps, &st, ps->fd);
    TEST_ASSERT(ps->rx_seq == 0);
    TEST_ASSERT(ps->recv_pos == full - 1);   /* bekletildi */

    ps->recv_pos = full;                     /* byte tamamlandı */
    process_peer_frames(ps, &st, ps->fd);
    TEST_ASSERT(ps->rx_seq == 1);
    TEST_ASSERT(ps->recv_pos == 0);
    fixture_teardown();
    return 0;
}

/* 11) İki frame tek buffer'da → ikisi de işlenir, slide bozulmaz (M-3) */
static int test_two_frames_single_buffer(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct1[64], ct2[64];
    uint32_t n1 = enc_text("bir", ct1);
    uint32_t n2 = enc_text("iki", ct2);
    TEST_ASSERT(n1 > 0 && n2 > 0);

    frame_put(ps, NOX_MSG_TEXT, 0, ct1, n1);
    size_t first = ps->recv_pos;

    /* ikinci frame'i birincinin hemen ardına koy */
    struct peer_session tmp;                 /* encode yardımcı sadece buffer'a yazar */
    memset(&tmp, 0, sizeof(tmp));
    frame_put(&tmp, NOX_MSG_TEXT, 1, ct2, n2);
    memcpy(ps->recv_buf + first, tmp.recv_buf, tmp.recv_pos);
    ps->recv_pos = first + tmp.recv_pos;

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->rx_seq == 2);
    TEST_ASSERT(ps->recv_pos == 0);
    TEST_ASSERT(ps->state == ST_ACTIVE);
    fixture_teardown();
    return 0;
}

/* 12) Session yokken TEXT BEKLETİLİR (drain kilidi — drop değil) */
static int test_text_without_session_waits(void)
{
    TEST_ASSERT(fixture_base() == 0);   /* session yok */
    struct peer_session *ps = &st.peers[0];

    uint8_t junk[32];
    randombytes_buf(junk, sizeof(junk));
    frame_put(ps, NOX_MSG_TEXT, 0, junk, sizeof(junk));
    size_t full = ps->recv_pos;

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->recv_pos == full);  /* tüketilmedi — bekliyor */
    TEST_ASSERT(ps->rx_seq == 0);
    fixture_teardown();
    return 0;
}

/* 13) CTRL (msg_index>=3) sessizce düşürülür — peer ölmez (Y-2) */
static int test_ctrl_after_handshake_dropped(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];
    ps->hs = sodium_malloc(sizeof(struct noise_handshake));
    TEST_ASSERT(ps->hs != NULL);
    memset(ps->hs, 0, sizeof(struct noise_handshake));
    ps->hs->msg_index = 3;              /* handshake bitmiş sayılır */

    uint8_t dummy[8] = {0};
    frame_put(ps, NOX_MSG_CTRL, 0, dummy, sizeof(dummy));
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->recv_pos == 0);     /* tüketildi */
    TEST_ASSERT(ps->rx_seq == 0);       /* CTRL seq ilerletmez */
    TEST_ASSERT(ps->state == ST_ACTIVE);
    TEST_ASSERT(ps->hs != NULL);        /* hs'e dokunulmadı */
    fixture_teardown();
    return 0;
}

/* 14) [H2/H3 FIX HEDEFİ — KIRMIZI] FILE yolu: transfer dışı FILE
 *     frame'inde decrypt fail artık "tüketilip senkron korunur" DEĞİL
 *     → görünür kopma. (Eski davranış: return true → rx_seq++ → oturum
 *     yaşar; fail'in kaynağı belirsizken bunu sürdürmek güvensiz.) */
static int test_file_decrypt_fail_disconnects(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t junk[32];
    randombytes_buf(junk, sizeof(junk));
    frame_put(ps, NOX_MSG_FILE, 0, junk, sizeof(junk));

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    TEST_ASSERT(ps->rx_seq == 0);            /* başarısız frame seq ilerletmez */
    fixture_teardown();
    return 0;
}

/* 15) [H2/H3 FIX HEDEFİ — KIRMIZI] Sahte/probe frame (H3 oracle):
 *     saldırgan doğru seq ile rastgele ciphertext gönderir. Eski
 *     davranış: sessiz drop, cezasız probe, iz yok. Yeni: log + UI +
 *     kopma — probe'un gözlemlenebilir sonucu bağlantı kaybı olur.
 *     (Eski zombi kanıtı bu davranışın hedefiydi: ilk fail'de kopma
 *     olduğundan seq-rewrite ile zombi sahnelenemez.) */
static int test_forged_probe_disconnects(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t junk[64];
    randombytes_buf(junk, sizeof(junk));
    frame_put(ps, NOX_MSG_TEXT, 0, junk, sizeof(junk));  /* seq eşleşiyor */

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 16) [H2 FIX HEDEFİ — KIRMIZI] type alanı tamper'ı: TEXT frame'inin
 *     header type'ı FILE'a çevrilirse eski kodda seq check geçer,
 *     decrypt BAŞARILI olur (payload aynı), mesaj sessizce bastırılır
 *     ve oturum sağlam kalırdı. AD bağlama sonrası: type authenticated
 *     → tag fail → görünür kopma. */
static int test_type_flip_disconnects(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("gorunmeyen mesaj", ct);
    TEST_ASSERT(n > 0);
    /* TEXT olarak şifrelendi ama header type=FILE (saldırgan 1 byte) */
    frame_put(ps, NOX_MSG_FILE, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    TEST_ASSERT(ps->rx_seq == 0);
    fixture_teardown();
    return 0;
}

/* ================================================================
 * SALDIRGAN SENARYOLARI — [H2/H3 FIX HEDEFİ, KIRMIZI]
 * Header (type/seq/len) AEAD dışı olduğundan aşağıdaki manipulasyonlar
 * bugün ya sessizce yutuluyor ya da içerik sızıntısı/bastırma üretiyor.
 * AD bağlama + fatal handler sonrası hepsi "görünür kopma"ya dönmeli.
 * ================================================================ */

/* 17) FILE→TEXT flip: dosya içeriği sohbet mesajı olarak gösterilir.
 *     Saldırgan FILE frame'inin type byte'ını TEXT yapar: decrypt
 *     başarılı (payload aynı), ui_print_incoming binary chunk'ı
 *     "mesaj" diye basar, rx_seq ilerler, oturum sağlam kalır.
 *     Hedef: type authenticated → tag fail → kopma. */
static int test_file_type_flip_shows_garbage(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("dosya-parcasi-icerik", ct);
    TEST_ASSERT(n > 0);
    /* FILE olarak şifrelendi ama header type=TEXT */
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 18) TEXT→FILE flip + AKTİF transfer: sohbet metni indirmeye yazılır.
 *     Saldırgan TEXT frame'inin type'ını FILE yapar; aktif RX varsa
 *     data-chunk dalı çalışır → mesaj byte'ları hedef dosyaya yazılır,
 *     hash'e girer, received_bytes ilerler. Sonuç: dosya bozulur
 *     (tamamlanınca hash fail → silinir) ve mesaj yok olur — hiç iz yok.
 *     Hedef: type tamper → tag fail → kopma; transfer state dokunulmaz. */
static int test_text_into_active_transfer_corrupts(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];
    TEST_ASSERT(setup_active_rx(ps) == 0);

    uint8_t ct[64];
    uint32_t n = enc_text("gizli sohbet mesaji", ct);
    TEST_ASSERT(n > 0);
    /* TEXT olarak şifrelendi ama header type=FILE (saldırgan 1 byte) */
    frame_put(ps, NOX_MSG_FILE, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);

    /* Bugün: received_bytes = n (metin dosyaya yazıldı), state ACTIVE.
     * Hedef: kopma — hiçbir byte dosyaya/hash'e girmemeli.
     * (Kırmızı dönemde sızıntı olmasın: teardown assert'lerden önce.) */
    peer_state_t final_state = ps->state;
    uint32_t final_rx = ps->rx_seq;
    struct noise_session *final_sess = ps->session;
    teardown_active_rx(ps);
    fixture_teardown();
    TEST_ASSERT(final_state == ST_IDLE);
    TEST_ASSERT(final_rx == 0);
    TEST_ASSERT(final_sess == NULL);
    return 0;
}

/* 19) TEXT→CTRL flip (handshake bitmiş, hs=NULL): mesaj SESSİZCE yenir.
 *     CTRL dalı ps->hs ister; hs=NULL olunca hiçbir branch'e girmez →
 *     payload free, rx_seq İLERLEMEZ, oturum yaşar. Peer'in sonraki
 *     frame'i seq k+1 taşıyacağından kopma gecikmeli ve yanıltıcı
 *     ("replay") olur. Hedef: post-handshake beklenmeyen CTRL =
 *     protokol ihlali → fail-fast kopma (hs dönemi: test 13 dokunulmaz). */
static int test_ctrl_type_flip_eats_message(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("kaybolan mesaj", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_CTRL, 0, ct, n);   /* type=CTRL, hs NULL */
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 20) Cut&paste splice: eski ciphertext + yeni seq.
 *     Saldırgan daha önce akan frame 0'ın ct'sini saklar; frame 1
 *     geldiğinde header seq=1 yazıp eski ct'yi iliştirir. Seq check
 *     bugün geçer (1==rx_seq), decrypt nonce-1 ile eski ct'yi açamaz →
 *     SESSİZ yutulur, oturum yaşar (mesaj kaybı izsiz). Hedef: tag
 *     fail → kopma. */
static int test_old_ciphertext_splice(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("ilk mesaj", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);
    TEST_ASSERT(ps->rx_seq == 1);
    TEST_ASSERT(ps->state == ST_ACTIVE);

    /* splice: eski ct, yeni seq (1) — rx_seq ile eşleşiyor */
    frame_put(ps, NOX_MSG_TEXT, 1, ct, n);
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 21) len şişirme: header len += 8, ardına 8 çöp byte.
 *     Çerçeve "tamamlanır", ct dilimi eski ct + çöp olur → tag fail.
 *     Bugün sessiz yutulur (desync izsiz). Hedef: len authenticated
 *     → tag fail → kopma; çerçeve kaymasına izin verilmez. */
static int test_len_grow_tamper(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("olculu mesaj", ct);
    TEST_ASSERT(n > 0);
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);

    ps->recv_buf[12] = (uint8_t)(ps->recv_buf[12] + 8);   /* len BE alt byte */
    uint8_t pad[8];
    randombytes_buf(pad, sizeof(pad));
    memcpy(ps->recv_buf + FRAME_HEADER_WIRE_SIZE + n, pad, sizeof(pad));
    ps->recv_pos = FRAME_HEADER_WIRE_SIZE + n + sizeof(pad);

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 22) Probe fırtınası: tek buffer'da 3 sahte frame (hepsi seq=0).
 *     Bugün üçü de sessizce yutulur (rx_seq sabit kalır, seq'ler
 *     eşleşmeye devam eder) — izsiz, cezasız probe. Hedef: İLK fail'de
 *     kopma + kalan frame'ler İŞLENMEZ (fail-fast; fix döngüyü kırmalı,
 *     kopmuş oturumla devam etmemeli). */
static int test_probe_storm_first_fail_disconnect(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    struct peer_session tmp;
    memset(&tmp, 0, sizeof(tmp));
    size_t off = 0;
    for (int i = 0; i < 3; i++) {
        uint8_t junk[32];
        randombytes_buf(junk, sizeof(junk));
        frame_put(&tmp, NOX_MSG_TEXT, 0, junk, sizeof(junk));  /* hepsi seq=0 */
        memcpy(ps->recv_buf + off, tmp.recv_buf, tmp.recv_pos);
        off += tmp.recv_pos;
    }
    ps->recv_pos = off;

    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->state == ST_IDLE);       /* ilk fail'de kopma */
    TEST_ASSERT(ps->session == NULL);
    fixture_teardown();
    return 0;
}

/* 23) Boş payload tüketimi ("auth başarısı = tüket" sözleşmesi):
 *     geçerli MAC'li boş TEXT frame bugün nonce'u İLERLETİYOR ama
 *     rx_seq'i ilerletmiyor (pt_len > 0 koşulu) → sonraki frame (seq=1)
 *     pre-check'te takılır, oturum kendiliğinden kopar. Saldırgan
 *     erişemez (anahtar gerekir) — peer-bug interop desync'i; yine de
 *     fix sözleşmesinin parçası: başarılı decrypt = tüket, boş pt'de
 *     dispatch yok ama rx_seq++ olmalı. */
static int test_empty_payload_consumed(void)
{
    TEST_ASSERT(fixture_base() == 0);
    TEST_ASSERT(attach_session() == 0);
    struct peer_session *ps = &st.peers[0];

    uint8_t ct[64];
    uint32_t n = enc_text("", ct);
    TEST_ASSERT(n == NOX_MAC_LEN);   /* pt_len=0 → çıktı sadece tag */
    frame_put(ps, NOX_MSG_TEXT, 0, ct, n);
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->rx_seq == 1);    /* RED: bugün 0 (nonce ilerledi) */
    TEST_ASSERT(ps->state == ST_ACTIVE);

    uint8_t ct2[64];
    uint32_t n2 = enc_text("sonraki mesaj", ct2);
    frame_put(ps, NOX_MSG_TEXT, 1, ct2, n2);
    process_peer_frames(ps, &st, ps->fd);

    TEST_ASSERT(ps->rx_seq == 2);
    TEST_ASSERT(ps->state == ST_ACTIVE);
    fixture_teardown();
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== event_loop frame dağıtım sözleşmesi ===\n");

    RUN_TEST(test_find_peer_by_fd);
    RUN_TEST(test_claim_payload_fail_closed);
    RUN_TEST(test_claim_payload_roundtrip);
    RUN_TEST(test_text_frame_happy);
    RUN_TEST(test_seq_mismatch_disconnects);
    RUN_TEST(test_replay_same_seq_disconnects);
    RUN_TEST(test_mac_fail_disconnects);
    RUN_TEST(test_len_tamper_disconnects);
    RUN_TEST(test_header_junk_disconnects);
    RUN_TEST(test_partial_frame_buffered);
    RUN_TEST(test_two_frames_single_buffer);
    RUN_TEST(test_text_without_session_waits);
    RUN_TEST(test_ctrl_after_handshake_dropped);
    RUN_TEST(test_file_decrypt_fail_disconnects);
    RUN_TEST(test_forged_probe_disconnects);
    RUN_TEST(test_type_flip_disconnects);
    RUN_TEST(test_file_type_flip_shows_garbage);
    RUN_TEST(test_text_into_active_transfer_corrupts);
    RUN_TEST(test_ctrl_type_flip_eats_message);
    RUN_TEST(test_old_ciphertext_splice);
    RUN_TEST(test_len_grow_tamper);
    RUN_TEST(test_probe_storm_first_fail_disconnect);
    RUN_TEST(test_empty_payload_consumed);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
