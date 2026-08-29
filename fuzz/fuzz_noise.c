/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_noise.c — AFL++ harness for Noise handshake + transport
 */
#include "noise.h"
#include "types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sodium.h>

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 0
#endif

#ifndef __AFL_INIT
#define __AFL_INIT()
#endif

int main(void) {
  __AFL_INIT();

  if (sodium_init() < 0) {
    return 1;
  }

  uint8_t s_priv[32], s_pub[32];
  memset(s_priv, 0x41, 32);
  s_priv[0] &= 248;
  s_priv[31] &= 127;
  s_priv[31] |= 64;
  crypto_scalarmult_base(s_pub, s_priv);

  uint8_t e_priv[32], e_pub[32];
  memset(e_priv, 0x42, 32);
  e_priv[0] &= 248;
  e_priv[31] &= 127;
  e_priv[31] |= 64;
  crypto_scalarmult_base(e_pub, e_priv);

  while (__AFL_LOOP(10000)) {
    uint8_t buf[2048];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 5)
      continue;

    bool initiator = (buf[0] & 0x01) ? true : false;
    int msg_index = buf[1] % 3;

    struct noise_handshake hs;
    if (handshake_init(&hs, initiator, s_priv, s_pub) != NOX_OK) {
      continue;
    }

    hs.msg_index = msg_index;
    memcpy(hs.e, e_priv, 32);
    memcpy(hs.e_pub, e_pub, 32);
    memcpy(hs.rs, s_pub, 32);
    memcpy(hs.re, e_pub, 32);

    uint8_t payload_out[2048];
    size_t pl_len = sizeof(payload_out);
    handshake_read(&hs, buf + 2, (size_t)(n - 2), payload_out, &pl_len);

    /* Transport nonce oracle: fail'de n artmamali */
    {
      struct noise_handshake ha, hb;
      uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
      memset(a_priv, 0x11, 32); a_priv[0] &= 248; a_priv[31] &= 127; a_priv[31] |= 64;
      memset(b_priv, 0x22, 32); b_priv[0] &= 248; b_priv[31] &= 127; b_priv[31] |= 64;
      crypto_scalarmult_base(a_pub, a_priv);
      crypto_scalarmult_base(b_pub, b_priv);
      if (handshake_init(&ha, true, a_priv, a_pub) != NOX_OK) continue;
      if (handshake_init(&hb, false, b_priv, b_pub) != NOX_OK) continue;
      uint8_t tmp[512]; size_t tlen; uint8_t pl2[64]; size_t pll;
      tlen = sizeof(tmp); handshake_write(&ha, NULL, 0, tmp, &tlen); pll=sizeof(pl2); handshake_read(&hb, tmp, tlen, pl2, &pll);
      tlen = sizeof(tmp); handshake_write(&hb, NULL, 0, tmp, &tlen); pll=sizeof(pl2); handshake_read(&ha, tmp, tlen, pl2, &pll);
      tlen = sizeof(tmp); handshake_write(&ha, NULL, 0, tmp, &tlen); pll=sizeof(pl2); handshake_read(&hb, tmp, tlen, pl2, &pll);
      struct noise_session sa, sb;
      if (handshake_split(&ha, &sa) != NOX_OK) continue;
      if (handshake_split(&hb, &sb) != NOX_OK) continue;
      uint8_t msg[] = "fuzz";
      uint8_t ct[64]; ssize_t cl = noise_encrypt(&sa, msg, sizeof(msg), ct);
      if (cl <= 0) continue;
      uint64_t nb = atomic_load(&sb.rx.n);
      uint8_t bad[64]; memcpy(bad, ct, (size_t)cl); bad[0] ^= 1;
      uint8_t pt[64]; ssize_t r1 = noise_decrypt(&sb, bad, (size_t)cl, pt);
      if (r1 != -1) abort();
      if (atomic_load(&sb.rx.n) != nb) abort();
      ssize_t r2 = noise_decrypt(&sb, ct, (size_t)cl, pt);
      if (r2 != (ssize_t)sizeof(msg)) abort();
      if (atomic_load(&sb.rx.n) != nb + 1) abort();
    }
  }

  return 0;
}
