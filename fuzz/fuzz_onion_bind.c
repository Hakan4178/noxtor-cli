/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_onion_bind.c — AFL++ harness: H-1/H-2 claim parse zinciri
 *
 * Hedef fonksiyonlar:
 *   crypto_onion_pubkey  — v3 onion adres parse: uzunluk + suffix +
 *                          base32 decode + version 0x03 + SHA3-256 checksum
 *   crypto_onion_verify  — tam claim parse: pubkey çıkar + imza verify
 *
 * Girdi düzeni (layout):
 *   [0..31]   static_pub  (32 byte, X25519)
 *   [32..95]  sig         (64 byte, Ed25519 detached)
 *   [96..n]   addr        (onion adres string, NUL-terminated)
 *
 * Buffer baştan memset(0) + buf[n]='\0' ile NUL garantisi — strlen
 * her zaman sonlanır. Fonksiyonlar crash/UB yerine yalnızca
 * NOX_OK / NOX_ERR_* dönmeli; aksi ASan/UBSan tarafından yakalanır.
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/onion_bind \
 *            -o fuzz/findings_onion_bind \
 *            -- ./fuzz/fuzz_onion_bind
 */

#include "common.h"
#include "types.h"
#include "crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

/* AFL++ persistent mode fallback'leri (diğer harness'larla aynı) */
#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 0
#endif

#ifndef __AFL_INIT
#define __AFL_INIT()
#endif

#define STATIC_OFF 0U
#define SIG_OFF    32U
#define ADDR_OFF   96U

int main(void) {
  if (sodium_init() < 0)
    return 1;

  __AFL_INIT();

  while (__AFL_LOOP(10000)) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf)); /* NUL garantisi + deterministik */

    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n < 1)
      continue;
    buf[n] = '\0';

    /* 1) Ham girdiyi onion adres olarak dene — charset/suffix/uzunluk
     *    reddi erken dönmeli, decode OOB yapmamalı */
    uint8_t pub[NOX_KEY_LEN];
    memset(pub, 0, sizeof(pub));
    nox_err_t e1 = crypto_onion_pubkey(pub, (const char *)buf);

    /* Başarılı çıkarsa parsed alan kullanılsın (optimizer silmesin) */
    if (e1 == NOX_OK) {
      volatile uint8_t sink = pub[0] ^ pub[31];
      (void)sink;
    }

    /* 2) Tam claim zinciri — statik alanlar + ayrı addr bölgesi */
    if ((size_t)n > ADDR_OFF) {
      const uint8_t *static_pub = buf + STATIC_OFF;
      const uint8_t *sig = buf + SIG_OFF;
      const char *addr = (const char *)(buf + ADDR_OFF);

      nox_err_t e2 = crypto_onion_verify(sig, addr, static_pub);

      /* NOX_OK yalnızca geçerli checksum + geçerli imza demek —
       * buraya girildiyse zincir baştan sona başarılı */
      if (e2 == NOX_OK) {
        volatile int sink = (int)e1; /* iki sonuç birbirini tüket */
        (void)sink;
      }
      /* e2 in {NOX_OK, NOX_ERR_PROTO, NOX_ERR_AUTH, NOX_ERR_CRYPTO} */
    }
  }

  return 0;
}
