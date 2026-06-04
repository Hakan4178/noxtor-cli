/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_noise.c — AFL++ harness for the Noise handshake parser
(handshake_read)
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/noise \
 *            -o fuzz/findings_noise \
 *            -- ./fuzz/fuzz_noise


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

   Deterministik, geçerli Curve25519 anahtar çiftleri oluşturalım
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

    /* Konfigürasyon baytlarını çıkaralım
    bool initiator = (buf[0] & 0x01) ? true : false;
    int msg_index = buf[1] % 3;

    struct noise_handshake hs;
    if (handshake_init(&hs, initiator, s_priv, s_pub) != NOX_OK) {
      continue;
    }

    /* Durumu ve ephemeral anahtarları set edelim
    hs.msg_index = msg_index;
    memcpy(hs.e, e_priv, 32);
    memcpy(hs.e_pub, e_pub, 32);

    /* Diğer anahtarları geçerli noktalarla dolduralım ki DH hesaplamaları 0
dönüp hata vermesin memcpy(hs.rs, s_pub, 32); memcpy(hs.re, e_pub, 32);

    uint8_t payload_out[2048];
    size_t pl_len = sizeof(payload_out);

    // Handshake okuyucusunu fuzz edelim
    handshake_read(&hs, buf + 2, (size_t)(n - 2), payload_out, &pl_len);
  }

  return 0;
}
*/