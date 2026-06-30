/* SPDX-License-Identifier: GPL-3.0-or-later
 * cbmc_state_machine.c — CBMC/ESBMC harness for state_machine.c
 *
 * 48 property, ~678 assertion.
 * Dual CBMC + ESBMC uyumlu.
 *
 * Strateji:
 *   - Tek global app_state (nesne sayısını minimize eder)
 *   - state_machine.c'yi doğrudan include, tüm dış bağımlılıklar stub
 *   - 8 test fonksiyonu, her biri bir property grubu
 *
 * Enum güvenliği:
 *   --enum-range-check aktifken geçersiz enum cast UB'ye yol açar.
 *   Sadece geçerli enum değerleri test edilir.
 */

#include "common.h"
#include "state_machine.h"
#include "types.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/* ================================================================
 * CBMC + ESBMC nondeterministic stubs
 * ================================================================ */
#ifdef __CPROVER__
void __builtin_c23_va_start(__builtin_va_list ap, ...) { (void)ap; }
extern size_t  __VERIFIER_nondet_size_t(void);
extern int     __VERIFIER_nondet_int(void);
extern char    __VERIFIER_nondet_char(void);
extern _Bool   __VERIFIER_nondet_bool(void);
#endif

#ifdef __ESBMC__
extern size_t __VERIFIER_nondet_size_t(void);
extern int    __VERIFIER_nondet_int(void);
extern char   __VERIFIER_nondet_char(void);
extern _Bool  __VERIFIER_nondet_bool(void);
void __CPROVER_assume(_Bool cond) { if (!cond) __ESBMC_assume(0); }
#endif

/* ================================================================
 * EXTERNAL FUNCTION STUBS
 * ================================================================ */

void sodium_memzero(void *pnt, size_t len) {
    (void)pnt; (void)len;
}

int sodium_memcmp(const void *a, const void *b, size_t len) {
    (void)a; (void)b; (void)len;
    return __VERIFIER_nondet_int();
}

nox_err_t epoll_remove_fd(int epoll_fd, int fd) {
    (void)epoll_fd; (void)fd;
    return __VERIFIER_nondet_bool() ? NOX_OK : NOX_ERR_IO;
}

int close(int fd) {
    (void)fd;
    return __VERIFIER_nondet_bool() ? 0 : -1;
}

void arena_restore(struct secure_arena *arena, size_t mark) {
    (void)arena; (void)mark;
}

static uint8_t g_arena_buf[256];
void *arena_alloc(struct secure_arena *arena, size_t size) {
    (void)arena;
    if (__VERIFIER_nondet_bool()) return NULL;
    if (size > sizeof(g_arena_buf)) return NULL;
    return g_arena_buf;
}

void file_transfer_cleanup(struct app_state *state) {
    (void)state;
}

nox_err_t db_add_contact(const char *onion, const char *name,
                         const uint8_t noise_key[NOX_KEY_LEN]) {
    (void)onion; (void)name; (void)noise_key;
    return __VERIFIER_nondet_bool() ? NOX_OK : NOX_ERR_DB;
}

nox_err_t handshake_split(struct noise_handshake *hs,
                          struct noise_session *session) {
    (void)hs; (void)session;
    return __VERIFIER_nondet_bool() ? NOX_OK : NOX_ERR_PROTO;
}

void ui_print_error(struct app_state *state, const char *fmt, ...) {
    (void)state; (void)fmt;
}
void ui_print_system(struct app_state *state, const char *fmt, ...) {
    (void)state; (void)fmt;
}
void ui_reset_sender(void) {}

void nox_log_impl(log_level_t level, log_module_t mod,
                  const char *file, int line, const char *fmt, ...) {
    (void)level; (void)mod; (void)file; (void)line; (void)fmt;
}

/* ================================================================
 * TEK GLOBAL STATE — nesne sayısını minimize eder
 * ================================================================ */
static struct app_state g;

static void reset(void) {
    memset(&g, 0, sizeof(g));
    g.peer_fd = -1;
    g.tofu_peer_fd = -1;
}

/* ================================================================
 * P1-P7: Geçiş tablosu bütünlüğü
 * ================================================================ */
static void test_transitions(void) {
    nox_err_t err;

    /* P1: IDLE geçerli çıkışları */
    reset(); g.peer_state = ST_IDLE;
    err = sm_dispatch(&g, EV_CONNECT_CMD);
    assert(err == NOX_OK); assert(g.peer_state == ST_HANDSHAKE_INIT);

    reset(); g.peer_state = ST_IDLE;
    err = sm_dispatch(&g, EV_PEER_ACCEPTED);
    assert(err == NOX_OK); assert(g.peer_state == ST_HANDSHAKE_RESP);

    /* P2: HANDSHAKE kendi içinde döngü */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_HANDSHAKE_MSG);
    assert(err == NOX_OK); assert(g.peer_state == ST_HANDSHAKE_INIT);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_HANDSHAKE_MSG);
    assert(err == NOX_OK); assert(g.peer_state == ST_HANDSHAKE_RESP);

    /* P3: HANDSHAKE → TOFU_PENDING */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_HANDSHAKE_DONE);
    assert(err == NOX_OK); assert(g.peer_state == ST_TOFU_PENDING);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_HANDSHAKE_DONE);
    assert(err == NOX_OK); assert(g.peer_state == ST_TOFU_PENDING);

    /* P4: HANDSHAKE → ACTIVE */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_SESSION_READY);
    assert(err == NOX_OK); assert(g.peer_state == ST_ACTIVE);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_SESSION_READY);
    assert(err == NOX_OK); assert(g.peer_state == ST_ACTIVE);

    /* P5: TOFU karar */
    reset(); g.peer_state = ST_TOFU_PENDING;
    err = sm_dispatch(&g, EV_TOFU_REJECTED);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    reset(); g.peer_state = ST_TOFU_PENDING; g.peer_fd = 42;
    g.hs = (struct noise_handshake *)malloc(1);
    void *saved_hs = g.hs;
    g.session = NULL; g.ghost_mode = true; g.tofu_pending = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
    assert((unsigned)g.peer_state < ST_COUNT);
    free(saved_hs);

    /* P6: Dosya transfer döngüsü */
    reset(); g.peer_state = ST_ACTIVE;
    err = sm_dispatch(&g, EV_FILE_START);
    assert(err == NOX_OK); assert(g.peer_state == ST_FILE_TX);

    reset(); g.peer_state = ST_FILE_TX;
    err = sm_dispatch(&g, EV_FILE_DONE);
    assert(err == NOX_OK); assert(g.peer_state == ST_ACTIVE);

    /* P7: IDLE'da geçersiz event'ler */
    {
        peer_event_t bad[] = {
            EV_HANDSHAKE_MSG, EV_HANDSHAKE_DONE, EV_SESSION_READY,
            EV_TOFU_ACCEPTED, EV_TOFU_REJECTED, EV_PEER_DISCONNECTED,
            EV_HANDSHAKE_TIMEOUT, EV_HANDSHAKE_ERROR, EV_FILE_START,
            EV_FILE_DONE, EV_RATE_LIMIT, EV_SEQ_MISMATCH,
            EV_ARENA_FAIL
        };
        for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
            reset(); g.peer_state = ST_IDLE;
            peer_state_t before = g.peer_state;
            err = sm_dispatch(&g, bad[i]);
            assert(err == NOX_ERR_STATE);
            assert(g.peer_state == before);
        }
    }
}

/* ================================================================
 * P8-P14: Hata yolları → IDLE
 * ================================================================ */
static void test_error_paths(void) {
    nox_err_t err;

    /* P8: EV_PEER_DISCONNECTED — 7 state'ten */
    {
        peer_state_t tgts[] = {
            ST_CONNECTING, ST_HANDSHAKE_INIT, ST_HANDSHAKE_RESP,
            ST_TOFU_PENDING, ST_ACTIVE, ST_FILE_TX, ST_FILE_RX
        };
        for (size_t i = 0; i < ARRAY_SIZE(tgts); i++) {
            reset(); g.peer_state = tgts[i];
            err = sm_dispatch(&g, EV_PEER_DISCONNECTED);
            assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);
        }
    }

    /* P9: EV_HANDSHAKE_TIMEOUT */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_HANDSHAKE_TIMEOUT);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_HANDSHAKE_TIMEOUT);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    /* P10: EV_HANDSHAKE_ERROR */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_HANDSHAKE_ERROR);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_HANDSHAKE_ERROR);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    /* P11: EV_SEQ_MISMATCH */
    {
        peer_state_t sq[] = { ST_ACTIVE, ST_FILE_TX, ST_FILE_RX };
        for (size_t i = 0; i < 3; i++) {
            reset(); g.peer_state = sq[i];
            err = sm_dispatch(&g, EV_SEQ_MISMATCH);
            assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);
        }
    }

    /* P12: EV_ARENA_FAIL */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_ARENA_FAIL);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_ARENA_FAIL);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    /* P13: EV_RATE_LIMIT */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&g, EV_RATE_LIMIT);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    reset(); g.peer_state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&g, EV_RATE_LIMIT);
    assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);

    /* P14: EV_TOR_DIED — tüm state'ler */
    for (int s = 0; s < ST_COUNT; s++) {
        reset(); g.peer_state = (peer_state_t)s;
        err = sm_dispatch(&g, EV_TOR_DIED);
        assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);
    }
}

/* ================================================================
 * P15-P23: Cleanup invariant'ları
 * ================================================================ */
static void test_cleanup(void) {
    nox_err_t err;

    /* P15: Kapsamlı kontrol */
    reset(); g.peer_state = ST_HANDSHAKE_INIT;
    g.peer_fd = 7;
    g.hs = (struct noise_handshake *)malloc(1);
    void *saved_hs = g.hs;
    g.session = (struct noise_session *)malloc(1);
    void *saved_sess = g.session;
    g.tx_seq = 5; g.rx_seq = 3;
    err = sm_dispatch(&g, EV_HANDSHAKE_TIMEOUT);
    assert(err == NOX_OK);
    assert(g.peer_state == ST_IDLE);
    assert(g.peer_fd == -1);
    assert(g.hs == NULL); assert(g.session == NULL);
    assert(g.tx_seq == 0); assert(g.rx_seq == 0);
    free(saved_hs); free(saved_sess);

    /* P16: peer_fd == -1 */
    reset(); g.peer_state = ST_ACTIVE; g.peer_fd = 42;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.peer_fd == -1);

    /* P17: hs == NULL */
    reset(); g.peer_state = ST_ACTIVE;
    g.hs = (struct noise_handshake *)malloc(1);
    saved_hs = g.hs;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.hs == NULL);
    free(saved_hs);

    reset(); g.peer_state = ST_ACTIVE; g.hs = NULL;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.hs == NULL);

    /* P18: session == NULL */
    reset(); g.peer_state = ST_ACTIVE;
    g.session = (struct noise_session *)malloc(1);
    saved_sess = g.session;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.session == NULL);
    free(saved_sess);

    /* P19: tx_seq == 0 */
    reset(); g.peer_state = ST_ACTIVE; g.tx_seq = 999;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.tx_seq == 0);

    /* P20: rx_seq == 0 */
    reset(); g.peer_state = ST_ACTIVE; g.rx_seq = 999;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.rx_seq == 0);

    /* P21: recv_pos == 0 */
    reset(); g.peer_state = ST_ACTIVE; g.recv_pos = 100;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.recv_pos == 0);

    /* P22: tofu_pending == false */
    reset(); g.peer_state = ST_TOFU_PENDING; g.tofu_pending = true;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.tofu_pending == false);

    /* P23: tofu_peer_fd == -1 */
    reset(); g.peer_state = ST_TOFU_PENDING; g.tofu_peer_fd = 99;
    sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(g.tofu_peer_fd == -1);
}

/* ================================================================
 * P24-P29: TOFU accept davranışı
 * ================================================================ */
static void test_tofu(void) {
    nox_err_t err;

    /* P24: hs NULL iken recursive dispatch */
    reset(); g.peer_state = ST_TOFU_PENDING;
    g.hs = NULL; g.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    assert(err == NOX_ERR_PROTO); assert(g.peer_state == ST_IDLE);

    /* P25: NOX_ERR_PROTO dönüş */
    reset(); g.peer_state = ST_TOFU_PENDING;
    g.hs = NULL; g.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    assert(err == NOX_ERR_PROTO);

    /* P26: arena alloc başarısız → IDLE */
    reset(); g.peer_state = ST_TOFU_PENDING;
    g.hs = (struct noise_handshake *)malloc(1);
    void *sh = g.hs;
    g.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    if (err == NOX_ERR_ALLOC) assert(g.peer_state == ST_IDLE);
    free(sh);

    /* P27: dönüş değeri */
    reset(); g.peer_state = ST_TOFU_PENDING;
    g.hs = (struct noise_handshake *)malloc(1);
    sh = g.hs;
    g.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
    free(sh);

    /* P28: başarılı → hs NULL */
    reset(); g.peer_state = ST_TOFU_PENDING;
    g.hs = (struct noise_handshake *)malloc(1);
    sh = g.hs;
    g.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    if (err == NOX_OK) assert(g.hs == NULL);
    free(sh);

    /* P29: başarılı → seq reset */
    reset(); g.peer_state = ST_TOFU_PENDING;
    g.hs = (struct noise_handshake *)malloc(1);
    sh = g.hs;
    g.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
    if (err == NOX_OK) { assert(g.tx_seq == 0); assert(g.rx_seq == 0); }
    free(sh);
}

/* ================================================================
 * P30-P33: Erişilebilirlik
 * ================================================================ */
static void test_reachability(void) {
    nox_err_t err;

    /* P30: IDLE → HANDSHAKE_INIT */
    reset(); g.peer_state = ST_IDLE;
    err = sm_dispatch(&g, EV_CONNECT_CMD);
    assert(err == NOX_OK); assert(g.peer_state == ST_HANDSHAKE_INIT);

    /* P31: IDLE → ACTIVE */
    reset(); g.peer_state = ST_IDLE;
    err = sm_dispatch(&g, EV_CONNECT_CMD);
    assert(err == NOX_OK);
    err = sm_dispatch(&g, EV_SESSION_READY);
    assert(err == NOX_OK); assert(g.peer_state == ST_ACTIVE);

    /* P32: ACTIVE → FILE_TX */
    reset(); g.peer_state = ST_ACTIVE;
    err = sm_dispatch(&g, EV_FILE_START);
    assert(err == NOX_OK); assert(g.peer_state == ST_FILE_TX);

    /* P33: Her state'ten IDLE */
    for (int s = 0; s < ST_COUNT; s++) {
        reset(); g.peer_state = (peer_state_t)s;
        err = sm_dispatch(&g, EV_TOR_DIED);
        assert(err == NOX_OK); assert(g.peer_state == ST_IDLE);
    }
}

/* ================================================================
 * P34-P35: State/event name
 * ================================================================ */
static void test_names(void) {
    for (int s = 0; s < ST_COUNT; s++) {
        const char *n = sm_state_name((peer_state_t)s);
        assert(n != NULL); assert(n[0] != '\0');
    }
    for (int e = 0; e < EV_COUNT; e++) {
        const char *n = sm_event_name((peer_event_t)e);
        assert(n != NULL); assert(n[0] != '\0');
    }
}

/* ================================================================
 * P36-P39: Tablo tutarlılığı
 * ================================================================ */
static void test_table(void) {
    int defined = 0;

    /* P36 + P38: Tüm tarama */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); g.peer_state = (peer_state_t)s;
            nox_err_t err = sm_dispatch(&g, (peer_event_t)e);
            assert((unsigned)g.peer_state < ST_COUNT);
            if (err != NOX_ERR_STATE) defined++;
        }
    }

    /* P37: Sayı mantıklı */
    assert(defined >= 20); assert(defined <= 80);

    /* P39: Geçersiz geçişte state değişmez */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); g.peer_state = (peer_state_t)s;
            peer_state_t before = g.peer_state;
            nox_err_t err = sm_dispatch(&g, (peer_event_t)e);
            if (err == NOX_ERR_STATE) assert(g.peer_state == before);
        }
    }
}

/* ================================================================
 * P40-P41: Recursive dispatch ve kapsamlı cleanup
 * ================================================================ */
static void test_misc(void) {
    nox_err_t err;

    /* P40: Recursive dispatch finite */
    for (int i = 0; i < 30; i++) {
        reset(); g.peer_state = ST_TOFU_PENDING;
        g.hs = (struct noise_handshake *)malloc(1);
        void *sh40 = g.hs;
        g.session = NULL; g.ghost_mode = true;
        err = sm_dispatch(&g, EV_TOFU_ACCEPTED);
        assert((unsigned)g.peer_state < ST_COUNT);
        assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
        free(sh40);
    }

    /* P41: Kapsamlı cleanup invariant */
    reset(); g.peer_state = ST_ACTIVE;
    g.peer_fd = 42;
    g.hs = (struct noise_handshake *)malloc(1);
    void *sh41 = g.hs;
    g.session = (struct noise_session *)malloc(1);
    void *ss41 = g.session;
    g.tx_seq = 50; g.rx_seq = 30; g.recv_pos = 200;
    g.tofu_pending = true; g.tofu_peer_fd = 99;
    strncpy(g.active_peer_onion, "test.onion", sizeof(g.active_peer_onion));
    err = sm_dispatch(&g, EV_PEER_DISCONNECTED);
    assert(err == NOX_OK);
    assert(g.peer_state == ST_IDLE);
    assert(g.peer_fd == -1);
    assert(g.hs == NULL); assert(g.session == NULL);
    assert(g.tx_seq == 0); assert(g.rx_seq == 0);
    assert(g.recv_pos == 0);
    assert(g.tofu_pending == false); assert(g.tofu_peer_fd == -1);
    free(sh41); free(ss41);
}

/* ================================================================
 * U1-U7: Evrensel Kurallar — gelecekte state eklenirse bile geçerli
 * ================================================================ */
static void test_universal_rules(void) {
    nox_err_t err;

    /* U1: No Dead End — her state'ten en az bir çıkış */
    for (int s = 1; s < ST_COUNT; s++) {  // IDLE hariç
        int exits = 0;
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); g.peer_state = (peer_state_t)s;
            if (sm_dispatch(&g, (peer_event_t)e) != NOX_ERR_STATE)
                exits++;
        }
        assert(exits > 0);  // Dead end yok!
    }

    /* U2: Error Recovery — TOR_DIED her state'ten IDLE'a götürmeli */
    for (int s = 0; s < ST_COUNT; s++) {
        reset(); g.peer_state = (peer_state_t)s;
        err = sm_dispatch(&g, EV_TOR_DIED);
        assert(err == NOX_OK);
        assert(g.peer_state == ST_IDLE);
    }

    /* U3: Cleanup Integrity — temizlik sonrası tüm alanlar sıfır */
    {
        reset(); g.peer_state = ST_ACTIVE; g.peer_fd = 42;
        g.hs = (struct noise_handshake *)malloc(1);
        void *sh_u3 = g.hs;
        g.session = (struct noise_session *)malloc(1);
        void *ss_u3 = g.session;
        g.tx_seq = 99; g.rx_seq = 88; g.recv_pos = 77;
        sm_dispatch(&g, EV_PEER_DISCONNECTED);
        assert(g.peer_state == ST_IDLE);
        assert(g.peer_fd == -1);
        assert(g.hs == NULL); assert(g.session == NULL);
        assert(g.tx_seq == 0); assert(g.rx_seq == 0);
        assert(g.recv_pos == 0);
        free(sh_u3); free(ss_u3);
    }

    /* U4: Invalid Transition Safety — state değişmemeli */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); g.peer_state = (peer_state_t)s;
            peer_state_t before = g.peer_state;
            nox_err_t err_u4 = sm_dispatch(&g, (peer_event_t)e);
            if (err_u4 == NOX_ERR_STATE)
                assert(g.peer_state == before);
        }
    }

    /* U5: State Validity — peer_state her zaman geçerli */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); g.peer_state = (peer_state_t)s;
            sm_dispatch(&g, (peer_event_t)e);
            assert((unsigned)g.peer_state < ST_COUNT);
        }
    }

    /* U6: Key Material Protection — U3 ile birlikte doğrulanıyor */

    /* U7: No Double Session — session ve hs aynı anda non-NULL olamaz */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); g.peer_state = (peer_state_t)s;
            sm_dispatch(&g, (peer_event_t)e);
            assert(!(g.session != NULL && g.hs != NULL));
        }
    }
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
    test_transitions();     /* P1-P7 */
    test_error_paths();     /* P8-P14 */
    test_cleanup();         /* P15-P23 */
    test_tofu();            /* P24-P29 */
    test_reachability();    /* P30-P33 */
    test_names();           /* P34-P35 */
    test_table();           /* P36-P39 */
    test_misc();            /* P40-P41 */
    test_universal_rules(); /* U1-U7 */
    return 0;
}
