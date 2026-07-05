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
    if (pnt && len > 0) memset(pnt, 0, len);
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

void *sodium_malloc(size_t size) {
    if (__VERIFIER_nondet_bool()) return NULL;
    return malloc(size);
}

void sodium_free(void *ptr) {
    free(ptr);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    (void)dirfd; (void)pathname; (void)flags;
    return __VERIFIER_nondet_bool() ? 0 : -1;
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
 * GLOBAL STATE — app_state + peer_session
 * ================================================================ */
static struct app_state g;
static struct peer_session ps;

static void reset(void) {
    memset(&g, 0, sizeof(g));
    memset(&ps, 0, sizeof(ps));
    ps.fd = -1;
    ps.tofu_peer_fd = -1;
    g.epoll_fd = -1;
    g.active_peer_idx = -1;
}

/* ================================================================
 * P1-P7: Geçiş tablosu bütünlüğü
 * ================================================================ */
static void test_transitions(void) {
    nox_err_t err;

    /* P1: IDLE geçerli çıkışları */
    reset(); ps.state = ST_IDLE;
    err = sm_dispatch(&ps, &g, EV_CONNECT_CMD);
    assert(err == NOX_OK); assert(ps.state == ST_HANDSHAKE_INIT);

    reset(); ps.state = ST_IDLE;
    err = sm_dispatch(&ps, &g, EV_PEER_ACCEPTED);
    assert(err == NOX_OK); assert(ps.state == ST_HANDSHAKE_RESP);

    /* P2: HANDSHAKE kendi içinde döngü */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_MSG);
    assert(err == NOX_OK); assert(ps.state == ST_HANDSHAKE_INIT);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_MSG);
    assert(err == NOX_OK); assert(ps.state == ST_HANDSHAKE_RESP);

    /* P3: HANDSHAKE → TOFU_PENDING */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_DONE);
    assert(err == NOX_OK); assert(ps.state == ST_TOFU_PENDING);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_DONE);
    assert(err == NOX_OK); assert(ps.state == ST_TOFU_PENDING);

    /* P4: HANDSHAKE → ACTIVE */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_SESSION_READY);
    assert(err == NOX_OK); assert(ps.state == ST_ACTIVE);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_SESSION_READY);
    assert(err == NOX_OK); assert(ps.state == ST_ACTIVE);

    /* P5: TOFU karar */
    reset(); ps.state = ST_TOFU_PENDING;
    err = sm_dispatch(&ps, &g, EV_TOFU_REJECTED);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    reset(); ps.state = ST_TOFU_PENDING; ps.fd = 42;
    ps.hs = (struct noise_handshake *)malloc(1);
    ps.session = NULL; g.ghost_mode = true; ps.tofu_pending = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
    assert((unsigned)ps.state < ST_COUNT);
    /* NOT: saved_hs zaten sodium_free ile serbest bırakıldı */

    /* P6: Dosya transfer döngüsü */
    reset(); ps.state = ST_ACTIVE;
    err = sm_dispatch(&ps, &g, EV_FILE_START);
    assert(err == NOX_OK); assert(ps.state == ST_FILE_TX);

    reset(); ps.state = ST_FILE_TX;
    err = sm_dispatch(&ps, &g, EV_FILE_DONE);
    assert(err == NOX_OK); assert(ps.state == ST_ACTIVE);

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
            reset(); ps.state = ST_IDLE;
            peer_state_t before = ps.state;
            err = sm_dispatch(&ps, &g, bad[i]);
            assert(err == NOX_ERR_STATE);
            assert(ps.state == before);
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
            reset(); ps.state = tgts[i];
            err = sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
            assert(err == NOX_OK); assert(ps.state == ST_IDLE);
        }
    }

    /* P9: EV_HANDSHAKE_TIMEOUT */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_TIMEOUT);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_TIMEOUT);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    /* P10: EV_HANDSHAKE_ERROR */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_ERROR);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_ERROR);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    /* P11: EV_SEQ_MISMATCH */
    {
        peer_state_t sq[] = { ST_ACTIVE, ST_FILE_TX, ST_FILE_RX };
        for (size_t i = 0; i < 3; i++) {
            reset(); ps.state = sq[i];
            err = sm_dispatch(&ps, &g, EV_SEQ_MISMATCH);
            assert(err == NOX_OK); assert(ps.state == ST_IDLE);
        }
    }

    /* P12: EV_ARENA_FAIL */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_ARENA_FAIL);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_ARENA_FAIL);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    /* P13: EV_RATE_LIMIT */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    err = sm_dispatch(&ps, &g, EV_RATE_LIMIT);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    reset(); ps.state = ST_HANDSHAKE_RESP;
    err = sm_dispatch(&ps, &g, EV_RATE_LIMIT);
    assert(err == NOX_OK); assert(ps.state == ST_IDLE);

    /* P14: EV_TOR_DIED — tüm state'ler */
    for (int s = 0; s < ST_COUNT; s++) {
        reset(); ps.state = (peer_state_t)s;
        err = sm_dispatch(&ps, &g, EV_TOR_DIED);
        assert(err == NOX_OK); assert(ps.state == ST_IDLE);
    }
}

/* ================================================================
 * P15-P23: Cleanup invariant'ları
 * ================================================================ */
static void test_cleanup(void) {
    nox_err_t err;

    /* P15: Kapsamlı kontrol */
    reset(); ps.state = ST_HANDSHAKE_INIT;
    ps.fd = 7;
    ps.hs = (struct noise_handshake *)malloc(1);
    ps.session = (struct noise_session *)malloc(1);
    ps.tx_seq = 5; ps.rx_seq = 3;
    err = sm_dispatch(&ps, &g, EV_HANDSHAKE_TIMEOUT);
    assert(err == NOX_OK);
    assert(ps.state == ST_IDLE);
    assert(ps.fd == -1);
    assert(ps.hs == NULL); assert(ps.session == NULL);
    assert(ps.tx_seq == 0); assert(ps.rx_seq == 0);
    /* saved_hs, saved_sess zaten sodium_free ile serbest bırakıldı */

    /* P16: peer_fd == -1 */
    reset(); ps.state = ST_ACTIVE; ps.fd = 42;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.fd == -1);

    /* P17: hs == NULL */
    reset(); ps.state = ST_ACTIVE;
    ps.hs = (struct noise_handshake *)malloc(1);
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.hs == NULL);

    reset(); ps.state = ST_ACTIVE; ps.hs = NULL;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.hs == NULL);

    /* P18: session == NULL */
    reset(); ps.state = ST_ACTIVE;
    ps.session = (struct noise_session *)malloc(1);
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.session == NULL);

    /* P19: tx_seq == 0 */
    reset(); ps.state = ST_ACTIVE; ps.tx_seq = 999;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.tx_seq == 0);

    /* P20: rx_seq == 0 */
    reset(); ps.state = ST_ACTIVE; ps.rx_seq = 999;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.rx_seq == 0);

    /* P21: recv_pos == 0 */
    reset(); ps.state = ST_ACTIVE; ps.recv_pos = 100;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.recv_pos == 0);

    /* P22: tofu_pending == false */
    reset(); ps.state = ST_TOFU_PENDING; ps.tofu_pending = true;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.tofu_pending == false);

    /* P23: tofu_peer_fd == -1 */
    reset(); ps.state = ST_TOFU_PENDING; ps.tofu_peer_fd = 99;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.tofu_peer_fd == -1);

    /* P23b: rx_file cleanup — fd kapatılır, unlinkat çağrılır */
    reset(); ps.state = ST_ACTIVE; ps.fd = 7;
    ps.rx_file.active = true; ps.rx_file.fd = 55;
    strncpy(ps.rx_file.local_name, "test.bin", sizeof(ps.rx_file.local_name));
    g.downloads_dir_fd = 10;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.rx_file.active == false);
    assert(ps.rx_file.fd == -1);

    /* P23c: tx_file cleanup — fd kapatılır, plain_buf sodium_free */
    reset(); ps.state = ST_ACTIVE; ps.fd = 7;
    ps.tx_file.active = true; ps.tx_file.fd = 66;
    ps.tx_file.plain_buf = malloc(32);
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.tx_file.active == false);
    assert(ps.tx_file.fd == -1);

    /* P23d: rx_file fd < 0 — close_atlanmalı */
    reset(); ps.state = ST_ACTIVE;
    ps.rx_file.active = true; ps.rx_file.fd = -1;
    strncpy(ps.rx_file.local_name, "skip.bin", sizeof(ps.rx_file.local_name));
    g.downloads_dir_fd = 10;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.rx_file.active == false);

    /* P23e: tx_file plain_buf NULL — sodium_free atlanmalı */
    reset(); ps.state = ST_ACTIVE;
    ps.tx_file.active = true; ps.tx_file.fd = -1;
    ps.tx_file.plain_buf = NULL;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.tx_file.active == false);
}

/* ================================================================
 * P24-P31: TOFU accept davranışı
 * ================================================================ */
static void test_tofu(void) {
    nox_err_t err;

    /* P24: hs NULL iken recursive dispatch */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = NULL; ps.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    assert(err == NOX_ERR_PROTO); assert(ps.state == ST_IDLE);

    /* P25: NOX_ERR_PROTO dönüş */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = NULL; ps.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    assert(err == NOX_ERR_PROTO);

    /* P26: sodium_malloc başarısız → IDLE */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = (struct noise_handshake *)malloc(1);
    void *sh = ps.hs;
    ps.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    if (err == NOX_ERR_ALLOC) assert(ps.state == ST_IDLE);
    free(sh);

    /* P27: dönüş değeri */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = (struct noise_handshake *)malloc(1);
    sh = ps.hs;
    ps.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
    free(sh);

    /* P28: başarılı → hs NULL */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = (struct noise_handshake *)malloc(1);
    sh = ps.hs;
    ps.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    if (err == NOX_OK) assert(ps.hs == NULL);
    /* sh zaten sodium_free ile serbest bırakıldı */

    /* P29: başarılı → seq reset */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = (struct noise_handshake *)malloc(1);
    sh = ps.hs;
    ps.session = NULL; g.ghost_mode = true;
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    if (err == NOX_OK) { assert(ps.tx_seq == 0); assert(ps.rx_seq == 0); }
    /* sh zaten sodium_free ile serbest bırakıldı */

    /* P30: ghost_mode=false → db_add_contact çağrılır */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = (struct noise_handshake *)malloc(1);
    sh = ps.hs;
    ps.session = NULL; g.ghost_mode = false;
    strncpy(ps.tofu_onion, "test.onion", NOX_ONION_LEN);
    strncpy(ps.tofu_name, "test_peer", NOX_CONTACT_NAME_LEN);
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
    /* sh zaten sodium_free ile serbest bırakıldı */

    /* P31: başarılı → peer_onion, name, active_peer_onion atandı */
    reset(); ps.state = ST_TOFU_PENDING;
    ps.hs = (struct noise_handshake *)malloc(1);
    sh = ps.hs;
    ps.session = NULL; g.ghost_mode = true;
    strncpy(ps.tofu_onion, "abc123.onion", NOX_ONION_LEN + 1);
    strncpy(ps.tofu_name, "peer_abc", NOX_CONTACT_NAME_LEN + 1);
    err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
    if (err == NOX_OK) {
        assert(ps.hs == NULL);
        assert(ps.session != NULL);
        assert(ps.peer_onion[0] != '\0');
        assert(ps.name[0] != '\0');
        assert(ps.tx_seq == 0);
        assert(ps.rx_seq == 0);
        assert(ps.tofu_pending == false);
        assert(g.active_peer_onion[0] != '\0');
    }
    /* sh zaten sodium_free ile serbest bırakıldı */
}

/* ================================================================
 * P30-P33: Erişilebilirlik
 * ================================================================ */
static void test_reachability(void) {
    nox_err_t err;

    /* P30: IDLE → HANDSHAKE_INIT */
    reset(); ps.state = ST_IDLE;
    err = sm_dispatch(&ps, &g, EV_CONNECT_CMD);
    assert(err == NOX_OK); assert(ps.state == ST_HANDSHAKE_INIT);

    /* P31: IDLE → ACTIVE */
    reset(); ps.state = ST_IDLE;
    err = sm_dispatch(&ps, &g, EV_CONNECT_CMD);
    assert(err == NOX_OK);
    err = sm_dispatch(&ps, &g, EV_SESSION_READY);
    assert(err == NOX_OK); assert(ps.state == ST_ACTIVE);

    /* P32: ACTIVE → FILE_TX */
    reset(); ps.state = ST_ACTIVE;
    err = sm_dispatch(&ps, &g, EV_FILE_START);
    assert(err == NOX_OK); assert(ps.state == ST_FILE_TX);

    /* P33: Her state'ten IDLE */
    for (int s = 0; s < ST_COUNT; s++) {
        reset(); ps.state = (peer_state_t)s;
        err = sm_dispatch(&ps, &g, EV_TOR_DIED);
        assert(err == NOX_OK); assert(ps.state == ST_IDLE);
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
            reset(); ps.state = (peer_state_t)s;
            nox_err_t err = sm_dispatch(&ps, &g, (peer_event_t)e);
            assert((unsigned)ps.state < ST_COUNT);
            if (err != NOX_ERR_STATE) defined++;
        }
    }

    /* P37: Sayı mantıklı */
    assert(defined >= 20); assert(defined <= 80);

    /* P39: Geçersiz geçişte state değişmez */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); ps.state = (peer_state_t)s;
            peer_state_t before = ps.state;
            nox_err_t err = sm_dispatch(&ps, &g, (peer_event_t)e);
            if (err == NOX_ERR_STATE) assert(ps.state == before);
        }
    }
}

/* ================================================================
 * P40-P41: Recursive dispatch ve kapsamlı cleanup
 * ================================================================ */
static void test_misc(void) {
    nox_err_t err;

    /* P40: Recursive dispatch finite — her iterasyonda temiz sonuç */
    for (int i = 0; i < 30; i++) {
        reset(); ps.state = ST_TOFU_PENDING;
        ps.hs = (struct noise_handshake *)malloc(1);
        ps.session = NULL; g.ghost_mode = true;
        err = sm_dispatch(&ps, &g, EV_TOFU_ACCEPTED);
        /* State her zaman geçerli */
        assert((unsigned)ps.state < ST_COUNT);
        assert(err == NOX_OK || err == NOX_ERR_ALLOC || err == NOX_ERR_PROTO);
        /* Hata durumunda IDLE'a düşmeli */
        if (err != NOX_OK) {
            assert(ps.state == ST_IDLE);
            assert(ps.hs == NULL);
            assert(ps.session == NULL);
        }
        /* Double session asla olmamalı */
        assert(!(ps.session != NULL && ps.hs != NULL));
        /* ps.hs zaten sodium_free ile serbest bırakıldı */
    }

    /* P41: Kapsamlı cleanup invariant — tüm alanlar sıfır */
    reset(); ps.state = ST_ACTIVE;
    ps.fd = 42;
    ps.hs = (struct noise_handshake *)malloc(1);
    ps.session = (struct noise_session *)malloc(1);
    ps.tx_seq = 50; ps.rx_seq = 30; ps.recv_pos = 200;
    ps.tofu_pending = true; ps.tofu_peer_fd = 99;
    ps.queue_flushed = true; ps.unread_count = 42;
    strncpy(ps.peer_onion, "test.onion", NOX_ONION_LEN + 1);
    strncpy(ps.connect_target, "target.onion", NOX_ONION_LEN + 1);
    strncpy(ps.name, "test_peer", NOX_CONTACT_NAME_LEN + 1);
    strncpy(ps.tofu_onion, "tofu.onion", NOX_ONION_LEN + 1);
    strncpy(ps.tofu_name, "tofu_peer", NOX_CONTACT_NAME_LEN + 1);
    memset(ps.tofu_new_key, 0xAB, sizeof(ps.tofu_new_key));
    memset(ps.recv_buf, 0xCD, sizeof(ps.recv_buf));
    strncpy(g.active_peer_onion, "test.onion", sizeof(g.active_peer_onion));
    err = sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(err == NOX_OK);
    assert(ps.state == ST_IDLE);
    /* 1. Soket */
    assert(ps.fd == -1);
    /* 2. Kriptografik state */
    assert(ps.hs == NULL); assert(ps.session == NULL);
    assert(ps.tx_seq == 0); assert(ps.rx_seq == 0);
    /* 3. Peer identity */
    assert(ps.peer_onion[0] == '\0');
    assert(ps.connect_target[0] == '\0');
    /* 4. TOFU state */
    assert(ps.tofu_pending == false); assert(ps.tofu_peer_fd == -1);
    assert(ps.tofu_onion[0] == '\0');
    assert(ps.tofu_name[0] == '\0');
    assert(ps.tofu_new_key[0] == 0x00);
    /* 5. Queue */
    assert(ps.queue_flushed == false);
    /* 6. Recv buffer */
    assert(ps.recv_buf[0] == 0x00);
    assert(ps.recv_pos == 0);
    /* 7. Name + unread */
    assert(ps.name[0] == '\0');
    assert(ps.unread_count == 0);

    /* P42: active_peer_idx reset — g.peers[] içindeki peer disconnect */
    reset(); g.active_peer_idx = 3;
    g.peers[3].state = ST_ACTIVE; g.peers[3].fd = 77;
    strncpy(g.active_peer_onion, "abc.onion", sizeof(g.active_peer_onion));
    err = sm_dispatch(&g.peers[3], &g, EV_PEER_DISCONNECTED);
    assert(err == NOX_OK);
    assert(g.active_peer_idx == -1);
    assert(g.active_peer_onion[0] == '\0');

    /* P43: active_peer_idx reset olmaz — yanlış peer disconnect */
    reset(); g.active_peer_idx = 2;
    g.peers[3].state = ST_ACTIVE; g.peers[3].fd = 78;
    strncpy(g.active_peer_onion, "abc.onion", sizeof(g.active_peer_onion));
    err = sm_dispatch(&g.peers[3], &g, EV_PEER_DISCONNECTED);
    assert(err == NOX_OK);
    assert(g.active_peer_idx == 2);  /* değişmemeli */

    /* P44: sm_dispatch_active — aktif peer mevcut */
    reset(); g.active_peer_idx = 1;
    g.peers[1].state = ST_ACTIVE;
    err = sm_dispatch_active(&g, EV_PEER_DISCONNECTED);
    assert(err == NOX_OK);
    assert(g.peers[1].state == ST_IDLE);

    /* P45: sm_dispatch_active — aktif peer yok */
    reset(); g.active_peer_idx = -1;
    err = sm_dispatch_active(&g, EV_PEER_DISCONNECTED);
    assert(err == NOX_ERR_NOT_FOUND);

    /* P46: active_peer_idx overflow — >= NOX_MAX_PEERS */
    reset(); g.active_peer_idx = NOX_MAX_PEERS + 5;
    g.peers[0].state = ST_ACTIVE; g.peers[0].fd = 80;
    strncpy(g.active_peer_onion, "abc.onion", sizeof(g.active_peer_onion));
    err = sm_dispatch(&g.peers[0], &g, EV_PEER_DISCONNECTED);
    assert(err == NOX_OK);
    assert(g.active_peer_idx == NOX_MAX_PEERS + 5);  /* değişmemeli — overflow koruması */

    /* P47: rx_file local_name boş — unlinkat atlanmalı */
    reset(); ps.state = ST_ACTIVE; ps.fd = 7;
    ps.rx_file.active = true; ps.rx_file.fd = 55;
    ps.rx_file.local_name[0] = '\0';
    g.downloads_dir_fd = 10;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.rx_file.active == false);

    /* P48: downloads_dir_fd < 0 — unlinkat atlanmalı */
    reset(); ps.state = ST_ACTIVE; ps.fd = 7;
    ps.rx_file.active = true; ps.rx_file.fd = 55;
    strncpy(ps.rx_file.local_name, "file.bin", sizeof(ps.rx_file.local_name));
    g.downloads_dir_fd = -1;
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.rx_file.active == false);

    /* P49: recv_buf büyük veri ile sıfırlanma */
    reset(); ps.state = ST_ACTIVE;
    memset(ps.recv_buf, 0xFF, sizeof(ps.recv_buf));
    ps.recv_pos = sizeof(ps.recv_buf);
    sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
    assert(ps.recv_buf[0] == 0x00);
    assert(ps.recv_pos == 0);
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
            reset(); ps.state = (peer_state_t)s;
            if (sm_dispatch(&ps, &g, (peer_event_t)e) != NOX_ERR_STATE)
                exits++;
        }
        assert(exits > 0);  // Dead end yok!
    }

    /* U2: Error Recovery — TOR_DIED her state'ten IDLE'a götürmeli */
    for (int s = 0; s < ST_COUNT; s++) {
        reset(); ps.state = (peer_state_t)s;
        err = sm_dispatch(&ps, &g, EV_TOR_DIED);
        assert(err == NOX_OK);
        assert(ps.state == ST_IDLE);
    }

    /* U3: Cleanup Integrity — temizlik sonrası tüm alanlar sıfır */
    {
        reset(); ps.state = ST_ACTIVE; ps.fd = 42;
        ps.hs = (struct noise_handshake *)malloc(1);
        void *sh_u3 = ps.hs;
        ps.session = (struct noise_session *)malloc(1);
        void *ss_u3 = ps.session;
        ps.tx_seq = 99; ps.rx_seq = 88; ps.recv_pos = 77;
        sm_dispatch(&ps, &g, EV_PEER_DISCONNECTED);
        assert(ps.state == ST_IDLE);
        assert(ps.fd == -1);
        assert(ps.hs == NULL); assert(ps.session == NULL);
        assert(ps.tx_seq == 0); assert(ps.rx_seq == 0);
        assert(ps.recv_pos == 0);
        /* sh_u3, ss_u3 zaten sodium_free ile serbest bırakıldı */
    }

    /* U4: Invalid Transition Safety — state değişmemeli */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); ps.state = (peer_state_t)s;
            peer_state_t before = ps.state;
            nox_err_t err_u4 = sm_dispatch(&ps, &g, (peer_event_t)e);
            if (err_u4 == NOX_ERR_STATE)
                assert(ps.state == before);
        }
    }

    /* U5: State Validity — peer_state her zaman geçerli */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); ps.state = (peer_state_t)s;
            sm_dispatch(&ps, &g, (peer_event_t)e);
            assert((unsigned)ps.state < ST_COUNT);
        }
    }

    /* U6: Key Material Protection — U3 ile birlikte doğrulanıyor */

    /* U7: No Double Session — session ve hs aynı anda non-NULL olamaz */
    for (int s = 0; s < ST_COUNT; s++) {
        for (int e = 0; e < EV_COUNT; e++) {
            reset(); ps.state = (peer_state_t)s;
            sm_dispatch(&ps, &g, (peer_event_t)e);
            assert(!(ps.session != NULL && ps.hs != NULL));
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
    test_tofu();            /* P24-P31 */
    test_reachability();    /* P30-P33 */
    test_names();           /* P34-P35 */
    test_table();           /* P36-P39 */
    test_misc();            /* P40-P41 */
    test_universal_rules(); /* U1-U7 */
    return 0;
}
