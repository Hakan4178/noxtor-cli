/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_frame_decode.c — AFL++ harness: frame_header_decode
 *
 * AFL++ stdin'den rastgele byte dizisi besler.
 * Bu harness o byte'ları frame_header_decode'a verir ve
 * fonksiyonun her durumda güvenle dönüp dönmediğini test eder.
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/frame_decode \
 *            -o fuzz/findings \
 *            -- ./fuzz/fuzz_frame_decode
 */

#include "network.h"
#include "types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* AFL++ persistent mode — GCC deferred fork server.
 * __AFL_LOOP(N): Her N iterasyonda bir fork yerine aynı process
 * içinde döngü yaparak ~10x hız kazandırır.
 * AFL++ yokken (normal derleme) bu makro tanımsızdır,
 * o yüzden güvenli bir fallback sağlıyoruz. */
#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 0
#endif

#ifndef __AFL_INIT
#define __AFL_INIT()
#endif

int main(void) {
  __AFL_INIT();

  /* Persistent mode: fork etmeden tekrar tekrar çalış */
  while (__AFL_LOOP(10000)) {
    uint8_t buf[256]; /* frame header 13 byte, ama fazlasını da oku */
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

    if (n < 1)
      continue;

    /* Eğer girdi FRAME_HEADER_WIRE_SIZE'dan küçükse,
     * kalanı sıfırla — boundary kontrollerini test et */
    if ((size_t)n < FRAME_HEADER_WIRE_SIZE) {
      memset(buf + n, 0, sizeof(buf) - (size_t)n);
    }

    struct frame_header hdr;
    memset(&hdr, 0, sizeof(hdr));

    nox_err_t err = frame_header_decode(buf, &hdr);

    /* Fonksiyon ya NOX_OK ya da NOX_ERR_PROTO dönmeli.
     * Crash, UB veya diğer hatalar ASan/UBSan tarafından yakalanır. */
    if (err == NOX_OK) {
      /* Geçerli decode — parsed alanları kullanarak
       * potansiyel UB'yi tetikle (compiler optimize etmesin) */
      volatile uint32_t sink = hdr.magic ^ hdr.seq ^ hdr.len;
      volatile uint8_t  tsink = hdr.type;
      (void)sink;
      (void)tsink;
    }
  }

  return 0;
}
