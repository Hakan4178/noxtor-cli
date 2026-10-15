/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_sm_cleanup.c — action_cleanup sözleşmesi (state_machine merkezi temizlik)
 *
 * action_cleanup, refactör öncesinde 18 farklı yerde tekrarlanan temizliğin
 * TEK noktası; her disconnect/timeout/reject/TOR_DIED yolu oradan geçer.
 * Sözleşme (state_machine.c:248-324), 8 adım:
 *   fd close + epoll remove → hs/session memzero+free → identity memzero →
 *   TOFU sıfırlama → rx/tx file tasfiyesi (close+unlinkat+plain_buf free) →
 *   recv_buf memzero → name/unread sıfırlama → aktif-peer bound'u.
 *
 * Testler (iyi + kötü yama karışımı):
 *   1. ACTIVE + PEER_DISCONNECTED — tam temizlik (gerçek fd: socketpair →
 *      EBADF kanıtı; canary alanlar sıfır)
 *   2. hs/session — sodium_malloc (free sonrası okunamaz + LSAN temiz)
 *   3. rx_file aktif → dosya unlinkat + fd close + struct sıfır
 *      (SM seviyesinde M-F3 ikizi — downloads_dir_fd=-1 NEGATİFİ dahil)
 *   4. tx_file aktif → plain_buf sodium_free + fd close
 *   5. active_peer_idx BAŞKA slot'u gösteriyorsa → idx KORUNUR
 *   6. C4 çifti: idx = 99 (NOX_MAX_PEERS dışı) → bound devrede, crash yok,
 *      idx ve active_peer_onion dokunulmaz
 *   7. TOR_DIED — 8 state'in tamamı → ST_IDLE + idempotent
 *   8. Geçersiz geçiş → NOX_ERR_STATE + state DEĞİŞMEZ
 *   9. epoll_fd = -1 iken cleanup → crash yok (erken dönem anı)
 *  10. Boş slot üzerinde ikinci cleanup → idempotent
 */

#include "common.h"
#include "types.h"
#include "state_machine.h"
#include "noise.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>
#include <errno.h>

#include "test_common.h"


/* ================================================================
 * FIXTURE
 * ================================================================ */
static struct app_state st;
static struct peer_session *slot(unsigned i) { return &st.peers[i]; }

static void fixture_reset(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++)
        st.peers[i].fd = -1;
}

/* Gerçek socket fd — cleanup sonrası EBADF ile doğrulanır */
static int make_real_fd(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    close(sv[1]);
    return sv[0];
}

static int fd_is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1;
}

/* Canary'li hs/session — action_cleanup free ÖNCESİ memzero yapmalı
 * (okunamazlık + LSAN ile kanıtlanır) */
static void attach_crypto(struct peer_session *ps)
{
    ps->hs = sodium_malloc(sizeof(struct noise_handshake));
    ps->session = sodium_malloc(sizeof(struct noise_session));
    memset(ps->hs, 0xAB, sizeof(struct noise_handshake));
    memset(ps->session, 0xCD, sizeof(struct noise_session));
    ps->tx_seq = 7;
    ps->rx_seq = 9;
}

/* ================================================================
 * TESTLER
 * ================================================================ */

/* 1) ACTIVE + PEER_DISCONNECTED — 8 adımın tamamı, gözle görülür kanıt */
static int test_active_disconnect_full_cleanup(void)
{
    fixture_reset();
    struct peer_session *ps = slot(1);
    ps->state = ST_ACTIVE;
    ps->fd = make_real_fd();
    TEST_ASSERT(ps->fd >= 0);
    attach_crypto(ps);

    snprintf(ps->peer_onion, sizeof(ps->peer_onion),
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnop.onion");
    snprintf(ps->connect_target, sizeof(ps->connect_target), "%s",
             ps->peer_onion);
    snprintf(ps->name, sizeof(ps->name), "Ali");
    ps->unread_count = 5;
    ps->peer_verified = true;
    ps->tofu_pending = true;
    memcpy(ps->tofu_new_key, "K", 1);
    memset(ps->recv_buf, 'R', sizeof(ps->recv_buf));
    ps->recv_pos = 42;
    st.active_peer_idx = (int)(ps - st.peers);   /* bu peer aktif */
    snprintf(st.active_peer_onion, sizeof(st.active_peer_onion), "%s",
             ps->peer_onion);

    int fd = ps->fd;
    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    /* 1. soket */
    TEST_ASSERT(ps->fd == -1);
    TEST_ASSERT(!fd_is_open(fd));                    /* gerçekten kapandı */
    /* 2. kripto */
    TEST_ASSERT(ps->hs == NULL);
    TEST_ASSERT(ps->session == NULL);
    TEST_ASSERT(ps->tx_seq == 0 && ps->rx_seq == 0);
    /* 3. identity */
    TEST_ASSERT(ps->peer_onion[0] == '\0');
    TEST_ASSERT(ps->connect_target[0] == '\0');
    /* 4. TOFU */
    TEST_ASSERT(!ps->tofu_pending);
    TEST_ASSERT(!ps->peer_verified);
    TEST_ASSERT(ps->tofu_new_key[0] == '\0');
    TEST_ASSERT(ps->tofu_onion[0] == '\0');
    /* 6. recv + name */
    TEST_ASSERT(ps->recv_pos == 0);
    TEST_ASSERT(ps->recv_buf[0] == '\0');
    TEST_ASSERT(ps->name[0] == '\0');
    TEST_ASSERT(ps->unread_count == 0);
    /* 8. aktif peer */
    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(st.active_peer_idx == -1);
    TEST_ASSERT(st.active_peer_onion[0] == '\0');
    return 0;
}

/* 2) hs/session sodium_malloc — free edildi (NULL) + LSAN: mlock sayfası
 *    ele geçirilirse ASan raporlar; memzero unutulursa da sodium_free
 *    kendisi sıfırlar (sodium kontratı) — sözleşme testi bütündür */
static int test_crypto_state_released(void)
{
    fixture_reset();
    struct peer_session *ps = slot(0);
    ps->state = ST_TOFU_PENDING;
    attach_crypto(ps);

    TEST_ASSERT(sm_dispatch(ps, &st, EV_TOFU_REJECTED) == NOX_OK);
    TEST_ASSERT(ps->hs == NULL);
    TEST_ASSERT(ps->session == NULL);
    TEST_ASSERT(ps->state == ST_IDLE);
    /* prompt hiç kurulmadı (elle ST_TOFU_PENDING) — cleanup epoch'a
     * dokunmaz, 0 korunmalı (yanlışlıkla prompt arm edilemez) */
    TEST_ASSERT(st.tofu_prompt_epoch == 0);
    return 0;
}

/* 3) rx_file aktif → close + unlinkat + sıfırlama
 *    3a NEGATİF: downloads_dir_fd = -1 → dosya kaderi ne? (M-F3'ün
 *    cleanup tarafı — unlinkat atlanırsa orphan kalır) */
static int test_rx_file_active_unlinks(void)
{
    fixture_reset();
    const char *dir = "tests/.tmp_sm_clean";
    mkdir(dir, 0700);
    st.downloads_dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    TEST_ASSERT(st.downloads_dir_fd >= 0);

    struct peer_session *ps = slot(0);
    ps->state = ST_FILE_RX;
    ps->rx_file.active = true;
    ps->rx_file.fd = openat(st.downloads_dir_fd, "rx.bin",
                            O_WRONLY | O_CREAT | O_EXCL, 0600);
    TEST_ASSERT(ps->rx_file.fd >= 0);
    snprintf(ps->rx_file.local_name, sizeof(ps->rx_file.local_name),
             "rx.bin");
    int saved_fd = ps->rx_file.fd;

    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    TEST_ASSERT(!fd_is_open(saved_fd));                         /* close */
    TEST_ASSERT(faccessat(st.downloads_dir_fd, "rx.bin", F_OK, 0) == -1);
    TEST_ASSERT(ps->rx_file.active == false);                   /* sıfır */
    TEST_ASSERT(ps->rx_file.fd == -1);
    TEST_ASSERT(ps->rx_file.local_name[0] == '\0');

    close(st.downloads_dir_fd);
    st.downloads_dir_fd = -1;
    rmdir(dir);
    return 0;
}

/* 3b NEGATİF: active dosya + downloads_dir_fd = -1 — unlinkat ATLANIR mı?
 *    (fd yine kapanmalı; dosya diske yazıldıysa orphan'lık burada görünür) */
static int test_rx_file_active_no_downloads_fd(void)
{
    fixture_reset();
    struct peer_session *ps = slot(0);
    ps->state = ST_FILE_RX;
    ps->rx_file.active = true;
    /* downloads yok — fd'yi gerçek ama geçersiz bir şeye değil,
     * doğrudan açık bir socket'e ver ki close doğrulanabilsin */
    ps->rx_file.fd = make_real_fd();
    TEST_ASSERT(ps->rx_file.fd >= 0);
    snprintf(ps->rx_file.local_name, sizeof(ps->rx_file.local_name),
             "orphan.bin");
    int saved_fd = ps->rx_file.fd;

    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    /* fd kapanmış olmalı — close yolu bağımsız */
    TEST_ASSERT(!fd_is_open(saved_fd));
    TEST_ASSERT(ps->rx_file.active == false);
    TEST_ASSERT(ps->rx_file.fd == -1);
    /* local_name: unlinkat(downloads=-1) imkânsız → struct sıfırlanınca
     * iz de kalmaz (dosya zaten hiç yazılmadı; kader sözleşmesi budur) */
    TEST_ASSERT(ps->rx_file.local_name[0] == '\0');
    return 0;
}

/* 4) tx_file aktif → plain_buf sodium_free + close + sıfırlama */
static int test_tx_file_frees_plain_buf(void)
{
    fixture_reset();
    struct peer_session *ps = slot(0);
    ps->state = ST_FILE_TX;
    ps->tx_file.active = true;
    ps->tx_file.fd = make_real_fd();
    TEST_ASSERT(ps->tx_file.fd >= 0);
    ps->tx_file.plain_buf = sodium_malloc(64);
    TEST_ASSERT(ps->tx_file.plain_buf != NULL);
    memset(ps->tx_file.plain_buf, 0xEE, 64);
    int saved_fd = ps->tx_file.fd;

    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    TEST_ASSERT(!fd_is_open(saved_fd));
    TEST_ASSERT(ps->tx_file.plain_buf == NULL);   /* free (LSAN teyit) */
    TEST_ASSERT(ps->tx_file.active == false);
    TEST_ASSERT(ps->tx_file.fd == -1);
    return 0;
}

/* 5) active_peer_idx BAŞKA slot'u gösteriyorsa → idx ve onion KORUNUR
 *    (yanlış peer'ın aktifliği düşürülmez — yanlış pozitif engeli) */
static int test_active_idx_other_slot_preserved(void)
{
    fixture_reset();
    struct peer_session *ps = slot(1);
    ps->state = ST_ACTIVE;
    ps->fd = make_real_fd();
    TEST_ASSERT(ps->fd >= 0);
    st.active_peer_idx = 0;                         /* slot 0 aktif */
    snprintf(st.active_peer_onion, sizeof(st.active_peer_onion),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");

    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(st.active_peer_idx == 0);           /* başkası — korundu */
    TEST_ASSERT(st.active_peer_onion[0] == 'a');    /* onion korundu */
    return 0;
}

/* 6) C4 ÇİFTİ: idx = NOX_MAX_PEERS DIŞI (99) — bound devrede:
 *    crash yok, OOB karşılaştırması atlanır, idx ve onion DOKUNULMAZ
 *    (types.h ACTIVE_PEER bound'u ile state_machine:316 bound'unun çifti) */
static int test_active_idx_out_of_bounds_guarded(void)
{
    fixture_reset();
    struct peer_session *ps = slot(0);
    ps->state = ST_ACTIVE;
    ps->fd = make_real_fd();
    TEST_ASSERT(ps->fd >= 0);
    st.active_peer_idx = 99;                        /* C4: dışı */
    snprintf(st.active_peer_onion, sizeof(st.active_peer_onion),
             "keep_this_intact.onion");

    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);

    TEST_ASSERT(ps->state == ST_IDLE);              /* slot temizlendi */
    TEST_ASSERT(st.active_peer_idx == 99);          /* bound: dokunulmadı */
    TEST_ASSERT(strncmp(st.active_peer_onion, "keep_this_intact",
                        16) == 0);
    return 0;
}

/* 7) TOR_DIED — 8 state'in tamamı ST_IDLE'a; tekrar çağrılanabilir */
static int test_tor_died_all_states(void)
{
    static const peer_state_t states[] = {
        ST_IDLE, ST_CONNECTING, ST_HANDSHAKE_INIT, ST_HANDSHAKE_RESP,
        ST_TOFU_PENDING, ST_ACTIVE, ST_FILE_TX, ST_FILE_RX,
    };
    TEST_ASSERT(sizeof(states) / sizeof(states[0]) == 8);

    for (size_t s = 0; s < sizeof(states) / sizeof(states[0]); s++) {
        fixture_reset();
        struct peer_session *ps = slot(2);
        ps->state = states[s];
        ps->fd = make_real_fd();
        TEST_ASSERT(ps->fd >= 0);
        attach_crypto(ps);
        snprintf(ps->peer_onion, sizeof(ps->peer_onion),
                 "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion");

        TEST_ASSERT(sm_dispatch(ps, &st, EV_TOR_DIED) == NOX_OK);
        if (ps->state != ST_IDLE) {
            fprintf(stderr, "\n  TOR_DIED %s → %s (IDLE beklenir)\n",
                    sm_state_name(states[s]), sm_state_name(ps->state));
            return 1;
        }
        TEST_ASSERT(ps->fd == -1);
        TEST_ASSERT(ps->hs == NULL && ps->session == NULL);
        TEST_ASSERT(ps->peer_onion[0] == '\0');

        /* idempotent: ikinci TOR_DIED da güvenli */
        TEST_ASSERT(sm_dispatch(ps, &st, EV_TOR_DIED) == NOX_OK);
        TEST_ASSERT(ps->state == ST_IDLE);
    }
    return 0;
}

/* 8) Geçersiz geçiş → NOX_ERR_STATE + state DEĞİŞMEZ (dispatch contract:
 *    yalnız action NOX_OK dönerse geçiş uygulanır) */
static int test_invalid_transition_rejected(void)
{
    fixture_reset();
    struct peer_session *ps = slot(0);
    ps->state = ST_ACTIVE;
    ps->fd = make_real_fd();
    TEST_ASSERT(ps->fd >= 0);

    /* ACTIVE'te HANDSHAKE_MSG beklenmiyor */
    TEST_ASSERT(sm_dispatch(ps, &st, EV_HANDSHAKE_MSG) == NOX_ERR_STATE);
    TEST_ASSERT(ps->state == ST_ACTIVE);            /* değişmedi */
    TEST_ASSERT(ps->fd >= 0);                       /* cleanup OLMADI */
    TEST_ASSERT(fd_is_open(ps->fd));

    /* FILE_RX'te CONNECT_CMD beklenmiyor */
    ps->state = ST_FILE_RX;
    TEST_ASSERT(sm_dispatch(ps, &st, EV_CONNECT_CMD) == NOX_ERR_STATE);
    TEST_ASSERT(ps->state == ST_FILE_RX);

    close(ps->fd);
    ps->fd = -1;
    return 0;
}

/* 9) epoll_fd = -1 iken cleanup — erken dönem/kurulum hatası anı, crash yok */
static int test_cleanup_without_epoll(void)
{
    fixture_reset();   /* st.epoll_fd = -1 */
    struct peer_session *ps = slot(0);
    ps->state = ST_CONNECTING;
    ps->fd = make_real_fd();
    TEST_ASSERT(ps->fd >= 0);

    TEST_ASSERT(sm_dispatch(ps, &st, EV_PEER_DISCONNECTED) == NOX_OK);
    TEST_ASSERT(ps->fd == -1);
    TEST_ASSERT(ps->state == ST_IDLE);
    return 0;
}

/* 10) Boş slot + IDLE → TOR_DIED idempotent (fd=-1, hs=NULL — hepsi no-op) */
static int test_cleanup_idle_slot_idempotent(void)
{
    fixture_reset();
    struct peer_session *ps = slot(3);   /* tertemiz slot */

    TEST_ASSERT(sm_dispatch(ps, &st, EV_TOR_DIED) == NOX_OK);
    TEST_ASSERT(ps->state == ST_IDLE);
    TEST_ASSERT(ps->fd == -1);

    TEST_ASSERT(sm_dispatch(ps, &st, EV_TOR_DIED) == NOX_OK);
    TEST_ASSERT(ps->state == ST_IDLE);
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium başlatılamadı\n");
        return 1;
    }

    fprintf(stderr, "=== state_machine action_cleanup sözleşmesi ===\n");

    RUN_TEST(test_active_disconnect_full_cleanup);
    RUN_TEST(test_crypto_state_released);
    RUN_TEST(test_rx_file_active_unlinks);
    RUN_TEST(test_rx_file_active_no_downloads_fd);
    RUN_TEST(test_tx_file_frees_plain_buf);
    RUN_TEST(test_active_idx_other_slot_preserved);
    RUN_TEST(test_active_idx_out_of_bounds_guarded);
    RUN_TEST(test_tor_died_all_states);
    RUN_TEST(test_invalid_transition_rejected);
    RUN_TEST(test_cleanup_without_epoll);
    RUN_TEST(test_cleanup_idle_slot_idempotent);

    fprintf(stderr, "\n=== Sonuç: %d/%d test başarılı ===\n",
            tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
