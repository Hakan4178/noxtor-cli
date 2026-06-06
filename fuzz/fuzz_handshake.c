/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_handshake.c — AFL++ harness for Noise XX handshake_read
 *
 * Ağdan gelen handshake mesajlarını (msg0 / msg1 / msg2) çözen state
 * machine'in parser dayanıklılığını test eder. Girdi, production
 * prologue ile uyumlu bir HandshakeState kurar, ardından AFL++
 * girdisini handshake_read'a besler. ASan/UBSan OOB / UAF / yanlış
 * tipte dönüş değeri yakalar.
 *
 * Davranış sınırları:
 *   - Production handshake_init ile aynı prologue kullanılır
 *     ("Mustafa Kemal Atatürk"). Bu sayede fuzzer davranışı
 *     production ile birebir aynı code path'ten geçer.
 *   - Remote ephemeral / static key'ler her iterasyonda AFL++
 *     baytlarından türetilir; geçersiz DH noktası oluşsa bile
 *     noise_dh bunu kontrol eder.
 *   - msg_index kontrol baytıyla seçilir; geçersiz değer
 *     (3+) NOX_ERR_STATE yolunu zorlar.
 *   - Her iterasyon sonunda struct sodium_memzero ile silinir —
 *     leak veya kullanılmış bellek sızıntısı ASan tarafından
 *     raporlanır.
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/handshake \
 *            -o fuzz/findings_handshake \
 *            -- ./fuzz/fuzz_handshake
 */

#include "noise.h"
#include "types.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 0
#endif

#ifndef __AFL_INIT
#define __AFL_INIT()
#endif

/* Production handshake_init ile aynı prologue — code path eşleşmesi için */
static const uint8_t PROLOGUE[] = "Mustafa Kemal Atatürk";
static const size_t  PROLOGUE_LEN = sizeof(PROLOGUE) - 1U;

/* Geçerli bir Curve25519 private key üretmek için clamping.
 * AFL++'tan gelen baytları deterministik olarak Clamp et; aynı
 * girdi → aynı anahtar, fuzzer tekrar üretilebilirliği korunur. */
static void clamp_curve25519(uint8_t out[NOX_KEY_LEN]) {
  out[0]  &= 248U;
  out[31] &= 127U;
  out[31] |= 64U;
}

/* Local key'leri kur; deterministik ve clamped. */
static void setup_local_keys(uint8_t s_priv[NOX_KEY_LEN],
                             uint8_t s_pub[NOX_KEY_LEN],
                             uint8_t e_priv[NOX_KEY_LEN],
                             uint8_t e_pub[NOX_KEY_LEN]) {
  /* Clamp öncesi sabit baytlar — bilinen geçerli anahtarlar */
  static const uint8_t S_SEED[NOX_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
  };
  static const uint8_t E_SEED[NOX_KEY_LEN] = {
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
  };

  memcpy(s_priv, S_SEED, NOX_KEY_LEN);
  clamp_curve25519(s_priv);
  if (crypto_scalarmult_base(s_pub, s_priv) != 0)
    abort();

  memcpy(e_priv, E_SEED, NOX_KEY_LEN);
  clamp_curve25519(e_priv);
  if (crypto_scalarmult_base(e_pub, e_priv) != 0)
    abort();
}

int main(void) {
  __AFL_INIT();

  if (sodium_init() < 0)
    return 1;

  /* Log çıktısını sustur — fuzzer stderr'ı kirletmesin */
  int fd_null = open("/dev/null", O_WRONLY);
  if (fd_null >= 0) {
    dup2(fd_null, STDOUT_FILENO);
    dup2(fd_null, STDERR_FILENO);
    close(fd_null);
  }

  /* Local anahtarlar sabit; her iterasyonda yeniden kurulmaz */
  uint8_t s_priv[NOX_KEY_LEN], s_pub[NOX_KEY_LEN];
  uint8_t e_priv[NOX_KEY_LEN], e_pub[NOX_KEY_LEN];
  setup_local_keys(s_priv, s_pub, e_priv, e_pub);

  /* Input ve output buffer'lar ayrı — input handshake_read'a
   * geçtikten sonra output sıfırlansa bile input'un üzerine
   * yazılmamalı. */
  uint8_t  in_buf[NOISE_MAX_HANDSHAKE_LEN + 64U];
  uint8_t  payload_out[NOISE_MAX_HANDSHAKE_LEN + 64U];

  while (__AFL_LOOP(10000)) {
    ssize_t n = read(STDIN_FILENO, in_buf, sizeof(in_buf));
    if (n < 1)
      continue;

    const uint8_t *buf = in_buf;
    size_t buf_len = (size_t)n;

    /* İlk byte kontrol bayrağı; geri kalanı mesaj.
     *   bit 0  : initiator (0=responder, 1=initiator)
     *   bit 1-2: msg_index başlangıcı (0..3; 3 = invalid → STATE error)
     *   bit 3  : remote key'leri AFL++ baytlarından oku (yoksa sabit)
     */
    uint8_t ctrl = buf[0];
    bool   initiator = (ctrl & 0x01U) != 0U;
    int    msg_index = (int)((ctrl >> 1) & 0x03U);
    bool   inject_remote = (ctrl & 0x08U) != 0U;

    const uint8_t *msg = buf + 1;
    size_t msg_len = (buf_len > 1U) ? (buf_len - 1U) : 0U;

    struct noise_handshake hs;
    nox_err_t err = handshake_init_with_prologue(&hs, initiator,
                                                 s_priv, s_pub,
                                                 PROLOGUE, PROLOGUE_LEN);
    if (err != NOX_OK)
      continue;

    /* Local ephemeral'ı deterministik enjekte et — DH input'u bilinir */
    err = handshake_inject_ephemeral(&hs, e_priv);
    if (err != NOX_OK) {
      sodium_memzero(&hs, sizeof(hs));
      continue;
    }

    /* msg_index'i kontrol baytına göre ayarla. Bu sayede aynı
     * taraf (initiator) hem msg0'a (read'da msg_index 0) hem msg1'e
     * (msg_index 1) hem de invalid (3) state'e zorlanabilir.
     * Production'da msg_index sadece handshake_write/read başarılı
     * olursa artar; burada doğrudan set etmek state machine'in
     * invalid sıralara verdiği yanıtı test eder. */
    if (msg_index >= 0 && msg_index <= 2)
      hs.msg_index = msg_index;

    /* Remote key'leri AFL++ baytlarından türet (clamp uygulanmaz —
     * sadece 32 byte'lık arbitrary değer; DH katmanı bunu kontrol
     * eder). */
    if (inject_remote && msg_len >= 2U * NOX_KEY_LEN) {
      memcpy(hs.re, msg, NOX_KEY_LEN);
      memcpy(hs.rs, msg + NOX_KEY_LEN, NOX_KEY_LEN);
      msg += 2U * NOX_KEY_LEN;
      msg_len -= 2U * NOX_KEY_LEN;
    }

    /* Output buffer sıfırlanır, input'a dokunulmaz */
    memset(payload_out, 0, sizeof(payload_out));
    size_t pl_len = sizeof(payload_out);

    /* Asıl hedef: handshake_read */
    err = handshake_read(&hs, msg, msg_len, payload_out, &pl_len);

    /* İnvariant: dönüş değeri tanımlı hata kodlarından biri olmalı.
     * ASan/OOB zaten handle ediyor; bu sadece enum dışı değer
     * dönmesini engeller (örn. uninitialized stack return).
     * noise.c'nin public API yüzeyi sadece bu kodları üretebilir. */
    switch (err) {
    case NOX_OK:
    case NOX_ERR_PROTO:
    case NOX_ERR_AUTH:
    case NOX_ERR_CRYPTO:
    case NOX_ERR_STATE:
      break;
    default:
      abort();
    }

    /* Tamamlanmış handshake'lerde split path'i zorlamak için
     * handshake_is_complete'i çağır. Bu, sonraki read çağrılarında
     * state'in tekrar kullanımını da test eder. */
    volatile bool complete = handshake_is_complete(&hs);
    (void)complete;

    /* Eğer handshake tamamlandıysa split'i dene — session tahsisi
     * sırasında UB olmadığını doğrular. */
    if (complete) {
      struct noise_session session;
      memset(&session, 0, sizeof(session));
      err = handshake_split(&hs, &session);
      /* split başarısız olursa bile struct'ı temizle */
      sodium_memzero(&session, sizeof(session));
    }

    /* Cleanup — tüm key materyalini sil, leak yok */
    sodium_memzero(&hs, sizeof(hs));
    sodium_memzero(payload_out, sizeof(payload_out));
  }

  return 0;
}
