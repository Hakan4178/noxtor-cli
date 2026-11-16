/* SPDX-License-Identifier: GPL-3.0-or-later
 * test_state_machine_matrix.c — 8×18 geçiş matrisinin tamamı.
 * Tanımlı çift hedefe geçer; tanımsız çift NOX_ERR_STATE + state korunur.
 * K-38/K-23 regresyonu; ST_CONNECTING ölü state, TOFU timeout disconnect.
 */

#include "common.h"
#include "types.h"
#include "state_machine.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "test_common.h"

/* Spesifikasyon — geçiş tablosunun test içindeki kopyası sözleşmedir:
 * uygulama tablosu birebir uyuşmalı; satır değişirse test kırmızıya döner. */

typedef enum {
    EXPECT_OK,           /* geçiş olur, hedef state'e geçilir            */
    EXPECT_FAIL_CLOSED,  /* geçiş VAR ama action fail-closed döner      */
    EXPECT_REJECT,       /* geçiş YOK → NOX_ERR_STATE                    */
} expect_kind_t;

typedef struct {
    peer_state_t from;
    peer_event_t event;
    peer_state_t to;
    expect_kind_t kind;
} spec_t;

static const spec_t SPEC[] = {
    /* ── IDLE → Bağlantı başlangıcı ── */
    { ST_IDLE,           EV_CONNECT_CMD,      ST_HANDSHAKE_INIT, EXPECT_OK },
    { ST_IDLE,           EV_PEER_ACCEPTED,    ST_HANDSHAKE_RESP, EXPECT_OK },

    /* ── HANDSHAKE → mesaj işleme (state değişmez) ── */
    { ST_HANDSHAKE_INIT, EV_HANDSHAKE_MSG,    ST_HANDSHAKE_INIT, EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_HANDSHAKE_MSG,    ST_HANDSHAKE_RESP, EXPECT_OK },

    /* ── HANDSHAKE → tamamlanma ── */
    { ST_HANDSHAKE_INIT, EV_SESSION_READY,    ST_ACTIVE,         EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_SESSION_READY,    ST_ACTIVE,         EXPECT_OK },
    { ST_HANDSHAKE_INIT, EV_HANDSHAKE_DONE,   ST_TOFU_PENDING,   EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_HANDSHAKE_DONE,   ST_TOFU_PENDING,   EXPECT_OK },

    /* ── TOFU → karar ── */
    /* action_tofu_accept gerçek kod: token eşleşmezse veya hs yoksa
     * NOX_ERR_PROTO döner → state DEĞİŞMEZ (fail-closed). */
    { ST_TOFU_PENDING,   EV_TOFU_ACCEPTED,    ST_ACTIVE,         EXPECT_FAIL_CLOSED },
    { ST_TOFU_PENDING,   EV_TOFU_REJECTED,    ST_IDLE,           EXPECT_OK },

    /* ── ACTIVE → dosya transferi ── */
    { ST_ACTIVE,         EV_FILE_START,       ST_FILE_TX,        EXPECT_OK },
    { ST_ACTIVE,         EV_FILE_RX_START,    ST_FILE_RX,        EXPECT_OK },
    { ST_FILE_TX,        EV_FILE_DONE,        ST_ACTIVE,         EXPECT_OK },
    { ST_FILE_RX,        EV_FILE_DONE,        ST_ACTIVE,         EXPECT_OK },

    /* ── Her durumdan disconnect ── */
    { ST_CONNECTING,     EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_INIT, EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },
    { ST_TOFU_PENDING,   EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },
    { ST_ACTIVE,         EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },
    { ST_FILE_TX,        EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },
    { ST_FILE_RX,        EV_PEER_DISCONNECTED, ST_IDLE,          EXPECT_OK },

    /* ── Handshake timeout ── */
    { ST_HANDSHAKE_INIT, EV_HANDSHAKE_TIMEOUT, ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_HANDSHAKE_TIMEOUT, ST_IDLE,          EXPECT_OK },

    /* ── Handshake error ── */
    { ST_HANDSHAKE_INIT, EV_HANDSHAKE_ERROR,   ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_HANDSHAKE_ERROR,   ST_IDLE,          EXPECT_OK },

    /* ── Sequence mismatch ── */
    { ST_ACTIVE,         EV_SEQ_MISMATCH,      ST_IDLE,          EXPECT_OK },
    { ST_FILE_TX,        EV_SEQ_MISMATCH,      ST_IDLE,          EXPECT_OK },
    { ST_FILE_RX,        EV_SEQ_MISMATCH,      ST_IDLE,          EXPECT_OK },

    /* ── Arena fail ── */
    { ST_HANDSHAKE_INIT, EV_ARENA_FAIL,        ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_ARENA_FAIL,        ST_IDLE,          EXPECT_OK },

    /* ── Tor died — her durumdan idle ── */
    { ST_IDLE,           EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_CONNECTING,     EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_INIT, EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_TOFU_PENDING,   EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_ACTIVE,         EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_FILE_TX,        EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },
    { ST_FILE_RX,        EV_TOR_DIED,          ST_IDLE,          EXPECT_OK },

    /* ── Crypto/protocol fail — her durumdan idle ── */
    { ST_IDLE,           EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_CONNECTING,     EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_INIT, EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_TOFU_PENDING,   EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_ACTIVE,         EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_FILE_TX,        EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },
    { ST_FILE_RX,        EV_CRYPTO_FAIL,       ST_IDLE,          EXPECT_OK },

    /* ── Rate limit ── */
    { ST_HANDSHAKE_INIT, EV_RATE_LIMIT,         ST_IDLE,          EXPECT_OK },
    { ST_HANDSHAKE_RESP, EV_RATE_LIMIT,         ST_IDLE,          EXPECT_OK },
};

#define SPEC_COUNT (sizeof(SPEC) / sizeof(SPEC[0]))

static struct app_state st;

static void fixture_reset(void)
{
    memset(&st, 0, sizeof(st));
    st.active_peer_idx  = -1;   /* memset 0 → peers[0]'a işaret ederdi */
    st.epoll_fd         = -1;
    st.downloads_dir_fd = -1;
    st.tor_pid          = -1;
    for (unsigned i = 0; i < NOX_MAX_PEERS; i++) {
        st.peers[i].fd = -1;           /* memset 0 → stdin olurdu! */
        st.peers[i].tofu_peer_fd = -1;
        st.peers[i].rx_file.fd = -1;
        st.peers[i].tx_file.fd = -1;
        st.peers[i].state = ST_IDLE;
    }
}

static const spec_t *spec_lookup(peer_state_t from, peer_event_t ev)
{
    for (size_t i = 0; i < SPEC_COUNT; i++) {
        if (SPEC[i].from == from && SPEC[i].event == ev)
            return &SPEC[i];
    }
    return NULL;
}


/* 1) Tam matris: 8 state × 18 event = 144 çift, her biri bağımsız fixture.
 * Tanımlı çift → NOX_OK + hedef state; tanımsız → NOX_ERR_STATE + state
 * değişmez. */
static int test_matrix_full_sweep(void)
{
    int checked = 0;
    int rejected = 0;

    for (unsigned s = 0; s < (unsigned)ST_COUNT; s++) {
        for (unsigned e = 0; e < (unsigned)EV_COUNT; e++) {
            const peer_state_t from = (peer_state_t)s;
            const peer_event_t ev   = (peer_event_t)e;
            const spec_t *sp = spec_lookup(from, ev);

            fixture_reset();
            struct peer_session *ps = &st.peers[0];
            ps->state = from;

            nox_err_t rc = sm_dispatch(ps, &st, ev);
            checked++;

            if (!sp) {
                /* Tanımsız çift → reddedilmeli, state DOKUNULMAMALI */
                rejected++;
                if (rc != NOX_ERR_STATE) {
                    fprintf(stderr,
                            "\n  [%s + %s] tanımsız geçiş reddedilmedi (rc=%d)\n",
                            sm_state_name(from), sm_event_name(ev), (int)rc);
                    return 1;
                }
                if (ps->state != from) {
                    fprintf(stderr,
                            "\n  [%s + %s] geçersiz geçişte state DEĞİŞTİ: %s\n",
                            sm_state_name(from), sm_event_name(ev),
                            sm_state_name(ps->state));
                    return 1;
                }
                continue;
            }

            if (sp->kind == EXPECT_FAIL_CLOSED) {
                /* Geçiş tanımlı ama action fail-closed → state DEĞİŞMEZ */
                if (rc == NOX_OK || rc == NOX_ERR_STATE) {
                    fprintf(stderr,
                            "\n  [%s + %s] fail-closed bekleniyordu (rc=%d)\n",
                            sm_state_name(from), sm_event_name(ev), (int)rc);
                    return 1;
                }
                if (ps->state != from) {
                    fprintf(stderr,
                            "\n  [%s + %s] fail-closed'da state DEĞİŞTİ: %s\n",
                            sm_state_name(from), sm_event_name(ev),
                            sm_state_name(ps->state));
                    return 1;
                }
                continue;
            }

            /* EXPECT_OK */
            if (rc != NOX_OK) {
                fprintf(stderr,
                        "\n  [%s + %s] geçiş bekleniyordu (rc=%d)\n",
                        sm_state_name(from), sm_event_name(ev), (int)rc);
                return 1;
            }
            if (ps->state != sp->to) {
                fprintf(stderr,
                        "\n  [%s + %s] hedef state %s bekleniyordu, %s bulundu\n",
                        sm_state_name(from), sm_event_name(ev),
                        sm_state_name(sp->to), sm_state_name(ps->state));
                return 1;
            }
        }
    }

    /* Matrisin tamamı gerçekten gezilmiş olmalı */
    TEST_ASSERT(checked == (int)ST_COUNT * (int)EV_COUNT);
    fprintf(stderr, "        (%d çift: %d geçerli, %d geçersiz)\n",
            checked, checked - rejected, rejected);
    return 0;
}

/* 2) Ulaşılabilirlik: sweep sırasında hedef state kümesi toplanır.
 * ST_CONNECTING ölü (SOCKS5 SM dışında kurulur); diğer tüm state'ler
 * ulaşılabilir olmalı. */
static int test_state_reachability(void)
{
    bool reachable[ST_COUNT];
    memset(reachable, 0, sizeof(reachable));
    reachable[ST_IDLE] = true;

    for (unsigned s = 0; s < (unsigned)ST_COUNT; s++) {
        for (unsigned e = 0; e < (unsigned)EV_COUNT; e++) {
            const peer_state_t from = (peer_state_t)s;
            const peer_event_t ev   = (peer_event_t)e;

            fixture_reset();
            struct peer_session *ps = &st.peers[0];
            ps->state = from;
            if (sm_dispatch(ps, &st, ev) == NOX_OK)
                reachable[(unsigned)ps->state] = true;
        }
    }

    /* Bilinen ölü state — kaldırılırsa bu test kırmızıya döner ve
     * gerekçesi/spec güncellenir. */
    TEST_ASSERT(reachable[(unsigned)ST_CONNECTING] == false);
    fprintf(stderr, "        (ST_CONNECTING ulaşılamaz — bilinen ölü state)\n");

    /* Diğer hiçbir state ölü olmamalı */
    for (unsigned s = 0; s < (unsigned)ST_COUNT; s++) {
        if ((peer_state_t)s == ST_CONNECTING)
            continue;
        if (!reachable[s]) {
            fprintf(stderr, "\n  ÖLÜ STATE: %s hiçbir geçişle ulaşılamıyor\n",
                    sm_state_name((peer_state_t)s));
            return 1;
        }
    }
    return 0;
}

/* 3) TOFU token fail-closed (C2): eski prompt epoch'u yeni slot'a
 * taşınmışsa onay reddedilir, session kurulmaz. */
static int test_tofu_accept_token_fail_closed(void)
{
    fixture_reset();
    struct peer_session *ps = &st.peers[0];
    ps->state = ST_TOFU_PENDING;

    /* Prompt başka bir slot'a ait (epoch uyuşmuyor) */
    st.tofu_prompt_epoch = 42;
    ps->tofu_epoch = 7;
    memset(ps->tofu_new_key, 0xAA, NOX_KEY_LEN);
    memset(st.tofu_prompt_fp, 0xBB, NOX_KEY_LEN);

    nox_err_t rc = sm_dispatch(ps, &st, EV_TOFU_ACCEPTED);
    TEST_ASSERT(rc != NOX_OK);
    TEST_ASSERT(rc != NOX_ERR_STATE);   /* geçiş tanımlı */
    TEST_ASSERT(ps->state == ST_TOFU_PENDING);  /* ACTIVE olmadı */
    TEST_ASSERT(ps->session == NULL);           /* session kurulmadı */
    return 0;
}

/* 4) TOFU onay handshake yokken fail-closed: token eşleşse de
 * ps->hs==NULL → NOX_ERR_PROTO. */
static int test_tofu_accept_without_handshake(void)
{
    fixture_reset();
    struct peer_session *ps = &st.peers[0];
    ps->state = ST_TOFU_PENDING;

    st.tofu_prompt_epoch = 1;
    ps->tofu_epoch = 1;
    memset(ps->tofu_new_key, 0x11, NOX_KEY_LEN);
    memcpy(st.tofu_prompt_fp, ps->tofu_new_key, NOX_KEY_LEN);
    TEST_ASSERT(ps->hs == NULL);

    nox_err_t rc = sm_dispatch(ps, &st, EV_TOFU_ACCEPTED);
    TEST_ASSERT(rc == NOX_ERR_PROTO);
    TEST_ASSERT(ps->state == ST_TOFU_PENDING);
    TEST_ASSERT(ps->session == NULL);
    return 0;
}

/* 5) sm_state_name/sm_event_name: geçerli enum isim döner, enum dışı
 * "UNKNOWN" (log çökmez). */
static int test_name_functions(void)
{
    for (unsigned s = 0; s < (unsigned)ST_COUNT; s++) {
        const char *n = sm_state_name((peer_state_t)s);
        TEST_ASSERT(n != NULL);
        TEST_ASSERT(strcmp(n, "UNKNOWN") != 0);
    }
    for (unsigned e = 0; e < (unsigned)EV_COUNT; e++) {
        const char *n = sm_event_name((peer_event_t)e);
        TEST_ASSERT(n != NULL);
        TEST_ASSERT(strcmp(n, "UNKNOWN") != 0);
    }

    /* Enum dışı değerler → "UNKNOWN" (sentinel koruması) */
    TEST_ASSERT(strcmp(sm_state_name((peer_state_t)ST_COUNT), "UNKNOWN") == 0);
    TEST_ASSERT(strcmp(sm_event_name((peer_event_t)EV_COUNT), "UNKNOWN") == 0);
    TEST_ASSERT(strcmp(sm_state_name((peer_state_t)9999), "UNKNOWN") == 0);
    TEST_ASSERT(strcmp(sm_event_name((peer_event_t)9999), "UNKNOWN") == 0);
    return 0;
}

/* 6) Disconnect matrisi: her durumdan ST_IDLE (action_cleanup tek nokta).
 * İSTİSNA: ST_IDLE'da geçiş yok — temizlenecek state yok (fd=-1,
 * hs/session NULL); reddedilir (NOX_ERR_STATE), state zaten IDLE. */
static int test_disconnect_from_every_state(void)
{
    for (unsigned s = 0; s < (unsigned)ST_COUNT; s++) {
        fixture_reset();
        struct peer_session *ps = &st.peers[0];
        ps->state = (peer_state_t)s;

        nox_err_t rc = sm_dispatch(ps, &st, EV_PEER_DISCONNECTED);

        if ((peer_state_t)s == ST_IDLE) {
            TEST_ASSERT(rc == NOX_ERR_STATE);   /* geçiş tanımsız */
            TEST_ASSERT(ps->state == ST_IDLE);   /* zararsız */
            continue;
        }
        TEST_ASSERT(rc == NOX_OK);
        TEST_ASSERT(ps->state == ST_IDLE);
    }
    return 0;
}

/* 7) TOR_DIED/CRYPTO_FAIL: her durumdan ST_IDLE. K-08: AEAD/protokol
 * hatası sessiz yutulmaz. */
static int test_fatal_events_from_every_state(void)
{
    const peer_event_t fatal[] = { EV_TOR_DIED, EV_CRYPTO_FAIL };

    for (unsigned f = 0; f < sizeof(fatal) / sizeof(fatal[0]); f++) {
        for (unsigned s = 0; s < (unsigned)ST_COUNT; s++) {
            fixture_reset();
            struct peer_session *ps = &st.peers[0];
            ps->state = (peer_state_t)s;

            nox_err_t rc = sm_dispatch(ps, &st, fatal[f]);
            TEST_ASSERT(rc == NOX_OK);
            TEST_ASSERT(ps->state == ST_IDLE);
        }
    }
    return 0;
}

/* 8) TOFU timeout yolu EV_PEER_DISCONNECTED'dır; event_loop sweeper'ı
 * EV_HANDSHAKE_TIMEOUT göndermez. ST_TOFU_PENDING'te HANDSHAKE_TIMEOUT
 * reddedilmeli (yanlış yol kullanılmasın). */
static int test_tofu_timeout_path(void)
{
    fixture_reset();
    struct peer_session *ps = &st.peers[0];
    ps->state = ST_TOFU_PENDING;

    nox_err_t rc = sm_dispatch(ps, &st, EV_HANDSHAKE_TIMEOUT);
    TEST_ASSERT(rc == NOX_ERR_STATE);
    TEST_ASSERT(ps->state == ST_TOFU_PENDING);

    /* Doğru yol: disconnect → IDLE */
    rc = sm_dispatch(ps, &st, EV_PEER_DISCONNECTED);
    TEST_ASSERT(rc == NOX_OK);
    TEST_ASSERT(ps->state == ST_IDLE);
    return 0;
}

int main(void)
{
    fprintf(stderr, "=== State Machine Geçiş Matrisi Testi ===\n");
    fprintf(stderr, "8 state × 18 event = 144 çift; spec tablosu test içinde\n\n");

    RUN_TEST(test_matrix_full_sweep);
    RUN_TEST(test_state_reachability);
    RUN_TEST(test_tofu_accept_token_fail_closed);
    RUN_TEST(test_tofu_accept_without_handshake);
    RUN_TEST(test_name_functions);
    RUN_TEST(test_disconnect_from_every_state);
    RUN_TEST(test_fatal_events_from_every_state);
    RUN_TEST(test_tofu_timeout_path);

    fprintf(stderr, "\nSonuç: %d/%d test başarılı\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
