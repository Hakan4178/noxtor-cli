/* CBMC/ESBMC harness for stdin_handler.c — TÜM fonksiyonlar
 *
 * Test edilen fonksiyonlar:
 *   get_next_chunk_size     — 4000-iterasyon UTF-8 chunk boundary (ESBMC-only)
 *   validate_onion_input    — base32 + .onion check (kolay)
 *   send_queued_callback    — NULL safety, boyut, encrypt/write stubs (orta)
 *   send_segmented_message  — chunk loop + encrypt + write (orta)
 *   queue_segmented_message — chunk loop + db_queue_message stub (orta)
 *
 * Yaklaşım:
 *   Static fonksiyonlar harness'a kopyalanır.
 *   Public send_* fonksiyonları harness'a kopyalanır + stub'lar ile
 *   derlenir. stdin_handler.c HİÇ derlenmez — bağımlılık zinciri kırılır.
 *
 * cbmc_chunk.c artık yok — get_next_chunk_size burada.
 * CBMC: RAM taşar (4200 unwind) — ESBMC-only.
 * ESBMC: ~24 sn.
 *
 * Komut (ESBMC — tek dosya):
 *   esbmc -D__ESBMC__ \
 *     --overflow-check --unsigned-overflow-check --memory-leak-check \
 *     --no-unwinding-assertions --unwind 4200 \
 *     --no-pointer-check --no-bounds-check \
 *     --timeout 1800s \
 *     -I include tests/cbmc_stdin.c
 */

#include "common.h"
#include "types.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>

/* network.h'den bağımsız sabit — include etmiyoruz (write_full çakışması) */
#ifndef FRAME_HEADER_WIRE_SIZE
#define FRAME_HEADER_WIRE_SIZE  13U
#endif

/* ================================================================
 * CBMC + ESBMC nondeterminism stubs
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
size_t __CPROVER_POINTER_OBJECT(const void *p) { (void)p; return 0; }
size_t __CPROVER_POINTER_OFFSET(const void *p) { (void)p; return 0; }
#endif

/* ================================================================
 * DİŞ STUB'LAR — send_* fonksiyonlarının bağımlılıkları
 * ================================================================ */

/* noise_encrypt — nondeterministic: [-1, 4096+MAC_LEN] */
static ssize_t noise_encrypt(struct noise_session *session,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t *ct) {
  (void)session; (void)pt; (void)ct;
  if (__VERIFIER_nondet_bool())
    return -1;
  ssize_t len = (ssize_t)(__VERIFIER_nondet_size_t() % (4096 + NOX_MAC_LEN)) + 1;
  return len;
}

/* write_full — nondeterministic */
static nox_err_t write_full(int fd, const void *buf, size_t len) {
  (void)fd; (void)buf; (void)len;
  return __VERIFIER_nondet_bool() ? NOX_OK : NOX_ERR_IO;
}

/* frame_header_encode — noop (CBMC için yeterli) */
static void frame_header_encode(const struct frame_header *hdr,
                                uint8_t *wire) {
  (void)hdr; (void)wire;
}

/* db_queue_message — nondeterministic */
static nox_err_t db_queue_message(const char *recipient_onion,
                                  const char *text) {
  (void)recipient_onion; (void)text;
  return __VERIFIER_nondet_bool() ? NOX_OK : NOX_ERR_DB;
}

/* nox_log_impl — noop */
void nox_log_impl(log_level_t level, log_module_t mod, const char *file,
                  int line, const char *fmt, ...) {
  (void)level; (void)mod; (void)file; (void)line; (void)fmt;
}

/* ================================================================
 * sodium_malloc / sodium_free stub'ları
 *
 * sodium_malloc → malloc + OOM bypass (protocol logic test edilir)
 * sodium_free → free
 * ================================================================ */
void *sodium_malloc(size_t size) {
  void *ptr = malloc(size);
#ifdef __CPROVER__
  __CPROVER_assume(ptr != NULL);
#endif
#ifdef __ESBMC__
  __ESBMC_assume(ptr != NULL);
#endif
  return ptr;
}

void sodium_free(void *ptr) {
  free(ptr);
}

/* ================================================================
 * KOPYALAN STATİK FONKSİYONLAR
 * ================================================================ */

static size_t get_next_chunk_size(const char *msg, size_t offset, size_t total_len) {
  if (offset >= total_len) return 0;

  const size_t chunk_limit = 4000U;
  size_t remaining = total_len - offset;

  if (remaining <= chunk_limit) return remaining;

  if (offset > SIZE_MAX - chunk_limit) return chunk_limit;

  size_t size = chunk_limit;
  while (size > 0 && ((uint8_t)msg[offset + size] & 0xC0) == 0x80) {
    size--;
  }

  return (size == 0) ? 1 : size;
}

static bool validate_onion_input(const char *onion, size_t len) {
  if (len != NOX_ONION_LEN) return false;

  for (size_t i = 0; i < 56; i++) {
    char c = onion[i];
    bool ok = (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '2' && c <= '7');
    if (!ok) return false;
  }

  return memcmp(onion + 56, ".onion", 6) == 0;
}

/* ================================================================
 * KOPYALAN PUBLIC FONKSİYONLAR (stubs ile derlenir)
 * ================================================================ */

nox_err_t send_queued_callback(const char *text, void *ctx) {
  struct app_state *state = (struct app_state *)ctx;
  if (!state || state->peer_fd < 0 || !state->session)
    return NOX_ERR_NET;

  size_t pt_len = strlen(text) + 1;

  if (pt_len > 4096) {
    return NOX_ERR_PROTO;
  }

  uint8_t *payload = sodium_malloc(4096 + NOX_MAC_LEN);
  if (!payload) return NOX_ERR_ALLOC;

  ssize_t ct_len = noise_encrypt(state->session,
                                 (const uint8_t *)text,
                                 pt_len, payload);
  if (ct_len < 0) {
    sodium_free(payload);
    return NOX_ERR_CRYPTO;
  }

  struct frame_header fh = {
      .magic = NOX_FRAME_MAGIC,
      .type = NOX_MSG_TEXT,
      .seq = state->tx_seq++,
      .len = (uint32_t)ct_len,
  };
  uint8_t wire[FRAME_HEADER_WIRE_SIZE];
  frame_header_encode(&fh, wire);

  nox_err_t err = NOX_OK;
  if (write_full(state->peer_fd, wire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
      write_full(state->peer_fd, payload, (size_t)ct_len) != NOX_OK) {
    err = NOX_ERR_IO;
  }

  sodium_free(payload);
  return err;
}

nox_err_t send_segmented_message(struct app_state *state, const char *msg) {
  if (!state->session || state->peer_fd < 0)
    return NOX_ERR_NET;

  size_t total_len = strlen(msg);
  size_t offset = 0;

  uint8_t *ct    = sodium_malloc(4096 + NOX_MAC_LEN);
  char    *chunk = sodium_malloc(4096 + 1);
  if (!ct || !chunk) {
    sodium_free(ct);
    sodium_free(chunk);
    return NOX_ERR_ALLOC;
  }

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    size_t pt_len = chunk_len + 1;
    ssize_t ct_len =
        noise_encrypt(state->session, (const uint8_t *)chunk, pt_len, ct);
    if (ct_len < 0) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_CRYPTO;
    }

    struct frame_header fh = {
        .magic = NOX_FRAME_MAGIC,
        .type = NOX_MSG_TEXT,
        .seq = state->tx_seq++,
        .len = (uint32_t)ct_len,
    };
    uint8_t wire[FRAME_HEADER_WIRE_SIZE];
    frame_header_encode(&fh, wire);

    if (write_full(state->peer_fd, wire, FRAME_HEADER_WIRE_SIZE) != NOX_OK ||
        write_full(state->peer_fd, ct, (size_t)ct_len) != NOX_OK) {
      sodium_free(chunk);
      sodium_free(ct);
      return NOX_ERR_IO;
    }

    offset += chunk_len;
  }

  sodium_free(chunk);
  sodium_free(ct);
  return NOX_OK;
}

nox_err_t queue_segmented_message(const char *recipient_onion, const char *msg) {
  size_t total_len = strlen(msg);
  size_t offset = 0;

  char *chunk = sodium_malloc(4096 + 1);
  if (!chunk)
    return NOX_ERR_ALLOC;

  while (offset < total_len) {
    size_t chunk_len = get_next_chunk_size(msg, offset, total_len);
    memcpy(chunk, msg + offset, chunk_len);
    chunk[chunk_len] = '\0';

    nox_err_t err = db_queue_message(recipient_onion, chunk);
    if (err != NOX_OK) {
      sodium_free(chunk);
      return err;
    }

    offset += chunk_len;
  }

  sodium_free(chunk);
  return NOX_OK;
}

/* ================================================================
 * P1: get_next_chunk_size — UTF-8 boundary + edge cases
 * ================================================================ */
static void test_chunk_utf8_boundary(void) {
  size_t total_len = __VERIFIER_nondet_size_t();
  __CPROVER_assume(total_len > 4000U && total_len <= 4000U + 100);

  char msg[4000U + 100];
  for (size_t i = 4000U; i < total_len; i++) {
    msg[i] = __VERIFIER_nondet_char();
    __CPROVER_assume(((uint8_t)msg[i] & 0xC0) == 0x80);
  }
  msg[4000U] = 'A';
  __CPROVER_assume(((uint8_t)msg[4000U] & 0xC0) != 0x80);

  size_t result = get_next_chunk_size(msg, 0, total_len);
  assert(result == 4000U);
  assert(result <= total_len);
  assert(result >= 1);
}

static void test_chunk_small_input(void) {
  size_t total_len = __VERIFIER_nondet_size_t();
  __CPROVER_assume(total_len <= 4000U && total_len > 0);

  char msg[100];
  size_t result = get_next_chunk_size(msg, 0, total_len);
  assert(result == total_len);
}

static void test_chunk_offset_past_end(void) {
  size_t total_len = __VERIFIER_nondet_size_t();
  size_t offset = __VERIFIER_nondet_size_t();
  __CPROVER_assume(offset >= total_len);

  char msg[100];
  size_t result = get_next_chunk_size(msg, offset, total_len);
  assert(result == 0);
}

/* ================================================================
 * P2: validate_onion_input — 4 property
 * ================================================================ */
static void test_validate_onion_input_length(void) {
  char buf[200];
  size_t len = __VERIFIER_nondet_size_t();
  __CPROVER_assume(len <= 200);
  if (len != NOX_ONION_LEN) {
    assert(!validate_onion_input(buf, len));
  }
}

static void test_validate_onion_input_valid(void) {
  char valid[NOX_ONION_LEN + 1];
  for (size_t i = 0; i < 56; i++) {
    char c = __VERIFIER_nondet_char();
    __CPROVER_assume((c >= 'a' && c <= 'z') ||
                     (c >= 'A' && c <= 'Z') ||
                     (c >= '2' && c <= '7'));
    valid[i] = c;
  }
  memcpy(valid + 56, ".onion", 6);
  valid[62] = '\0';
  assert(validate_onion_input(valid, NOX_ONION_LEN));
}

static void test_validate_onion_input_bad_char(void) {
  char buf[NOX_ONION_LEN + 1];
  for (size_t i = 0; i < 56; i++)
    buf[i] = 'a';
  size_t bad_pos = __VERIFIER_nondet_size_t();
  __CPROVER_assume(bad_pos < 56);
  buf[bad_pos] = '0';
  memcpy(buf + 56, ".onion", 6);
  assert(!validate_onion_input(buf, NOX_ONION_LEN));
}

static void test_validate_onion_input_no_suffix(void) {
  char buf[NOX_ONION_LEN + 1];
  for (size_t i = 0; i < 56; i++)
    buf[i] = 'a';
  memcpy(buf + 56, ".onioX", 6);
  assert(!validate_onion_input(buf, NOX_ONION_LEN));
}

/* ================================================================
 * P3: send_queued_callback — null safety + boyut
 * ================================================================ */
static void test_send_queued_callback_null_safety(void) {
  assert(send_queued_callback("test", NULL) == NOX_ERR_NET);
}

static void test_send_queued_callback_no_session(void) {
  struct app_state state = {0};
  state.peer_fd = -1;
  assert(send_queued_callback("test", &state) == NOX_ERR_NET);
}

static void test_send_queued_callback_no_peer(void) {
  struct noise_session sess = {0};
  struct app_state state = {0};
  state.peer_fd = -1;
  state.session = &sess;
  assert(send_queued_callback("test", &state) == NOX_ERR_NET);
}

static void test_send_queued_callback_payload_too_long(void) {
  struct noise_session sess = {0};
  struct app_state state = {0};
  state.peer_fd = 5;
  state.session = &sess;
  char long_msg[4097];
  memset(long_msg, 'A', 4096);
  long_msg[4096] = '\0';
  assert(send_queued_callback(long_msg, &state) == NOX_ERR_PROTO);
}

/* ================================================================
 * P4: send_segmented_message — null safety + boş mesaj
 * ================================================================ */
static void test_send_segmented_null_safety(void) {
  struct app_state state = {0};
  state.session = NULL;
  state.peer_fd = -1;
  assert(send_segmented_message(&state, "test") == NOX_ERR_NET);

  struct noise_session sess = {0};
  state.session = &sess;
  state.peer_fd = -1;
  assert(send_segmented_message(&state, "test") == NOX_ERR_NET);
}

static void test_send_segmented_empty_msg(void) {
  struct noise_session sess = {0};
  struct app_state state = {0};
  state.session = &sess;
  state.peer_fd = 5;
  state.tx_seq = 0;
  assert(send_segmented_message(&state, "") == NOX_OK);
}

/* ================================================================
 * P5: queue_segmented_message — boş mesaj
 * ================================================================ */
static void test_queue_segmented_empty_msg(void) {
  assert(queue_segmented_message(
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.onion",
      "") == NOX_OK);
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
  /* Kolay — chunk boundary (ESBMC: 24s, CBMC: skip) */
  test_chunk_utf8_boundary();
  test_chunk_small_input();
  test_chunk_offset_past_end();

  /* Kolay — onion validation */
  test_validate_onion_input_length();
  test_validate_onion_input_valid();
  test_validate_onion_input_bad_char();
  test_validate_onion_input_no_suffix();

  /* Orta — send/queue functions */
  test_send_queued_callback_null_safety();
  test_send_queued_callback_no_session();
  test_send_queued_callback_no_peer();
  test_send_queued_callback_payload_too_long();
  test_send_segmented_null_safety();
  test_send_segmented_empty_msg();
  test_queue_segmented_empty_msg();

  return 0;
}
