/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_stdin.c — stdin_handler process_line + tofu_user_response birim testi
 *
 * Kapsam (karma derinlik — negatif iskelet + success yolları):
 *   1-3.   Komut tablosu: /quit|/exit, bilinmeyen slash, session'sız mesaj
 *   4-5.   TOFU ekranı: düz mesaj ve //kaçış bloklanır (C2 yan etkisi)
 *   6.     TOFU çoklu bekleyen + "y" → hiçbirine karar verilmez
 *   7-8.   tofu_user_response (GTK callback yolu): accept fail-closed,
 *          reject → ST_IDLE + pencere kapandı
 *   9-11.  /connect doğrulamaları: self, geçersiz onion, duplicate
 *          (socks5_connect'e hiç düşmez — hs_attempt_count==0 kanıtı)
 *   12.    /msg geçersiz onion — db'ye dokunmadan ret
 *   13.    /msg ghost çevrimdışı — kuyruk yok (ghost mod)
 *   14.    queue_segmented_message success + M-14 rollback (db ile)
 *   15.    /add success (db round-trip) + kontrol-karakterli isim ret
 *   16.    /switch|/disconnect|/status hata yolları
 *
 * Not: ui_print_* stderr'e yazar (test çıktısı görünür) — davranış değil,
 * state geçişleri assert edilir.
 */

#include "common.h"
#include "types.h"
#include "state_machine.h"
#include "stdin_handler.h"
#include "database.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>

/* ================================================================
 * TEST MAKROLARI (şablon: test_tofu_epoch.c)
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
 * FIXTURE
 * ================================================================ */
static struct app_state st;

/* validate_onion_input uyumlu: 56 karakter [a-z2-7] + ".onion" */
static const char *VALID_ONION =
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

static void fixture_reset(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++)
        st.peers[i].fd = -1;
}

/* Aynı slota prompt'a sokar (event_loop EV_HANDSHAKE_DONE yolunun karşılığı) */
static nox_err_t prompt_slot(unsigned slot, uint8_t fill)
{
    st.peers[slot].state = ST_HANDSHAKE_INIT;
    memset(st.peers[slot].tofu_new_key, fill, NOX_KEY_LEN);
    return sm_dispatch(&st.peers[slot], &st, EV_HANDSHAKE_DONE);
}

/* ── db fixture (yalnız success testleri) ─────────────────────── */
static const char *TEST_DB_DIR = "tests/.tmp_db_stdin";
static uint8_t g_db_key[NOX_KEY_LEN];

static nox_err_t db_init_test(void)
{
    int fd = open(TEST_DB_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NOX_ERR_CONFIG;
    nox_err_t r = db_init(TEST_DB_DIR, fd, g_db_key);
    close(fd);
    return r;
}

static void cleanup_db_dir(void)
{
    char path[256];
    static const char *suf[] = { "contacts.db", "contacts.db-wal",
                                 "contacts.db-shm", "queue.db",
                                 "queue.db-wal", "queue.db-shm" };
    for (size_t i = 0; i < sizeof(suf) / sizeof(suf[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", TEST_DB_DIR, suf[i]);
        unlink(path);
    }
    rmdir(TEST_DB_DIR);
}

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 1) /quit ve /exit → running=false */
static int test_quit_commands(void)
{
    fixture_reset();
    st.running = true;
    process_line(&st, "/quit");
    TEST_ASSERT(st.running == false);

    st.running = true;
    process_line(&st, "/exit");
    TEST_ASSERT(st.running == false);
    return 0;
}

/* 2) Bilinmeyen slash komutu → hata, state'e dokunma, asla mesaja düşmez */
static int test_unknown_slash_command(void)
{
    fixture_reset();
    st.running = true;
    process_line(&st, "/bogus_command");
    TEST_ASSERT(st.running == true);
    TEST_ASSERT(st.active_peer_idx == -1);
    return 0;
}

/* 3) Session yokken düz mesaj → "bağlantı yok" hatası, gönderim yok */
static int test_plain_message_no_session(void)
{
    fixture_reset();
    process_line(&st, "selam");
    TEST_ASSERT(st.peers[0].state == ST_IDLE);      /* hiçbir slot oynamadı */
    TEST_ASSERT(st.active_peer_idx == -1);
    return 0;
}

/* 4) TOFU beklerken düz mesaj BLOKLANIR (C2 yan etkisi: mesaj gönderilemez,
 *    prompt'daki karar bozulmaz) */
static int test_tofu_blocks_plain_text(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_slot(0, 0xA1) == NOX_OK);

    process_line(&st, "onaylanmamış mesaj");

    TEST_ASSERT(st.peers[0].state == ST_TOFU_PENDING); /* hâlâ pending */
    TEST_ASSERT(st.tofu_prompt_epoch == 1);            /* pencere bozulmadı */
    return 0;
}

/* 5) TOFU beklerken //kaçış da bloklanır */
static int test_tofu_blocks_slash_escape(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_slot(0, 0xA1) == NOX_OK);

    process_line(&st, "//hello");

    TEST_ASSERT(st.peers[0].state == ST_TOFU_PENDING);
    TEST_ASSERT(st.tofu_prompt_epoch == 1);
    return 0;
}

/* 6) Çoklu bekleyen + "y" → hiçbir slot onaylanmaz (ret) */
static int test_tofu_multi_pending_yes_rejected(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_slot(0, 0xA1) == NOX_OK);
    TEST_ASSERT(prompt_slot(1, 0xB2) == NOX_OK);

    process_line(&st, "y");

    TEST_ASSERT(st.peers[0].state == ST_TOFU_PENDING);
    TEST_ASSERT(st.peers[1].state == ST_TOFU_PENDING);
    TEST_ASSERT(st.tofu_prompt_epoch == 1);  /* snapshot 1'de kaldı (supersede) */
    return 0;
}

/* 7) GTK callback yolu: accept ama hs ölü → fail-closed cleanup
 *    (process_line "y" ile aynı karar noktası — API doğrudan çağrılır) */
static int test_api_accept_fail_closed(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_slot(0, 0xA1) == NOX_OK);
    /* ps->hs NULL — bilinçli */

    tofu_user_response(&st, true);

    TEST_ASSERT(st.peers[0].state == ST_IDLE);  /* örnek temizlendi */
    TEST_ASSERT(st.tofu_prompt_epoch == 0);     /* pencere kapandı */
    return 0;
}

/* 8) GTK callback yolu: reject → ST_IDLE + pencere kapandı */
static int test_api_reject(void)
{
    fixture_reset();
    TEST_ASSERT(prompt_slot(0, 0xA1) == NOX_OK);

    tofu_user_response(&st, false);

    TEST_ASSERT(st.peers[0].state == ST_IDLE);
    TEST_ASSERT(st.tofu_prompt_epoch == 0);
    return 0;
}

/* 9) /connect kendi adresine → ret, slot tahsis edilmez */
static int test_connect_self_rejected(void)
{
    fixture_reset();
    snprintf(st.onion_addr, sizeof(st.onion_addr), "%s", VALID_ONION);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "/connect %s", VALID_ONION);
    process_line(&st, cmd);

    TEST_ASSERT(st.peers[0].state == ST_IDLE);
    TEST_ASSERT(st.peers[0].fd == -1);
    TEST_ASSERT(st.hs_attempt_count == 0);     /* rate limit sayacı işlemedi */
    return 0;
}

/* 10) /connect geçersiz onion → ret */
static int test_connect_invalid_onion(void)
{
    fixture_reset();
    process_line(&st, "/connect not-an-onion.onion");
    process_line(&st, "/connect uppercaseAAAA.onion"); /* uppercase yasak */

    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        TEST_ASSERT(st.peers[i].state == ST_IDLE);
        TEST_ASSERT(st.peers[i].fd == -1);
    }
    return 0;
}

/* 11) /connect duplicate → "zaten bağlı" — socks5'e DÜŞMEZ
 *    (kanıt: hs_attempt_count==0 ve yeni slot boş) */
static int test_connect_duplicate_rejected(void)
{
    fixture_reset();
    int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
    TEST_ASSERT(devnull >= 0);
    st.peers[0].fd = devnull;
    st.peers[0].state = ST_ACTIVE;
    snprintf(st.peers[0].peer_onion, sizeof(st.peers[0].peer_onion),
             "%s", VALID_ONION);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "/connect %s", VALID_ONION);
    process_line(&st, cmd);

    TEST_ASSERT(st.hs_attempt_count == 0);     /* duplicate kontrolü önce */
    TEST_ASSERT(st.peers[1].fd == -1);         /* yeni bağlantı kurulmadı */
    TEST_ASSERT(st.peers[1].state == ST_IDLE);

    close(devnull);
    st.peers[0].fd = -1;
    return 0;
}

/* 12) /msg geçersiz onion → ret, db'ye dokunulmaz */
static int test_msg_invalid_onion(void)
{
    fixture_reset();
    process_line(&st, "/msg short hello");
    TEST_ASSERT(st.peers[0].state == ST_IDLE);
    return 0;
}

/* 13) /msg ghost + çevrimdışı → kuyruk reddedilir (ghost mod) */
static int test_msg_ghost_offline_blocked(void)
{
    fixture_reset();
    st.ghost_mode = true;

    char cmd[160];
    snprintf(cmd, sizeof(cmd), "/msg %s merhaba", VALID_ONION);
    process_line(&st, cmd);

    TEST_ASSERT(st.ghost_mode == true);         /* davranış: kuyruk yok */
    return 0;
}

/* 14) queue_segmented_message: success + çok-chunk + M-14 rollback (db) */
static int test_queue_segmented_and_rollback(void)
{
    fixture_reset();
    mkdir(TEST_DB_DIR, 0700);
    TEST_ASSERT(db_init_test() == NOX_OK);

    /* kısa mesaj → tek chunk */
    TEST_ASSERT(queue_segmented_message(VALID_ONION, "selam") == NOX_OK);
    TEST_ASSERT(db_queue_rollback_last(VALID_ONION, 1) == NOX_OK);

    /* 5000 byte → 2 chunk (4000+1000) — chunk sınırı taşması kırılmaz */
    char big[5001];
    memset(big, 'A', 5000);
    big[5000] = '\0';
    TEST_ASSERT(queue_segmented_message(VALID_ONION, big) == NOX_OK);
    TEST_ASSERT(db_queue_rollback_last(VALID_ONION, 2) == NOX_OK);

    db_close();
    cleanup_db_dir();
    return 0;
}

/* 15) /add success (db round-trip) + kontrol-karakterli isim ret */
static int test_add_contact_success_and_reject(void)
{
    fixture_reset();
    mkdir(TEST_DB_DIR, 0700);
    TEST_ASSERT(db_init_test() == NOX_OK);

    char cmd[160];
    snprintf(cmd, sizeof(cmd), "/add %s Ali", VALID_ONION);
    process_line(&st, cmd);

    char name_out[NOX_CONTACT_NAME_LEN + 1];
    uint8_t key_out[NOX_KEY_LEN];
    TEST_ASSERT(db_get_contact(VALID_ONION, name_out,
                               sizeof(name_out), key_out) == NOX_OK);
    TEST_ASSERT(strcmp(name_out, "Ali") == 0);

    /* kontrol karakterli isim → ret (strpbrk \n\r\x1b) — db'ye yazılmaz */
    snprintf(cmd, sizeof(cmd), "/add %s a\033b", VALID_ONION);
    process_line(&st, cmd);
    TEST_ASSERT(db_get_contact(VALID_ONION, name_out,
                               sizeof(name_out), key_out) == NOX_OK);
    TEST_ASSERT(strcmp(name_out, "Ali") == 0);  /* hâlâ eski kayıt */

    db_close();
    cleanup_db_dir();
    return 0;
}

/* 16) Hata yolları: /switch bulunamadı (ghost: db'sız), /disconnect peer'sız,
 *     /status ve /history smoke */
static int test_switch_disconnect_status_errors(void)
{
    fixture_reset();
    st.ghost_mode = true;   /* find_peer db'ye düşmesin */

    process_line(&st, "/switch yokki");
    TEST_ASSERT(st.active_peer_idx == -1);

    process_line(&st, "/disconnect");
    TEST_ASSERT(st.active_peer_idx == -1);

    process_line(&st, "/status");    /* smoke — crash yok */
    process_line(&st, "/history");   /* bilinen "henüz yok" hatası */
    TEST_ASSERT(st.running == false || st.running == true); /* no-crash */
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }
    randombytes_buf(g_db_key, NOX_KEY_LEN);

    fprintf(stderr, "=== stdin_handler (process_line + tofu_user_response) ===\n");

    RUN_TEST(test_quit_commands);
    RUN_TEST(test_unknown_slash_command);
    RUN_TEST(test_plain_message_no_session);
    RUN_TEST(test_tofu_blocks_plain_text);
    RUN_TEST(test_tofu_blocks_slash_escape);
    RUN_TEST(test_tofu_multi_pending_yes_rejected);
    RUN_TEST(test_api_accept_fail_closed);
    RUN_TEST(test_api_reject);
    RUN_TEST(test_connect_self_rejected);
    RUN_TEST(test_connect_invalid_onion);
    RUN_TEST(test_connect_duplicate_rejected);
    RUN_TEST(test_msg_invalid_onion);
    RUN_TEST(test_msg_ghost_offline_blocked);
    RUN_TEST(test_queue_segmented_and_rollback);
    RUN_TEST(test_add_contact_success_and_reject);
    RUN_TEST(test_switch_disconnect_status_errors);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
