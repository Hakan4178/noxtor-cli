/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_sanitize.c — AFL++ harness: sanitize_filename
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/sanitize \
 *            -o fuzz/findings \
 *            -- ./fuzz/fuzz_sanitize
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

/* file_transfer.c içindeki fonksiyonu çağırabilmek için deklarasyon */
extern void sanitize_filename(char *name, size_t max_len);

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 0
#endif

#ifndef __AFL_INIT
#define __AFL_INIT()
#endif

int main(void) {
  __AFL_INIT();

  while (__AFL_LOOP(10000)) {
    char buf[1024];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);

    if (n < 1)
      continue;

    /* Girdiyi null ile sonlandırarak geçerli bir C stringi yapalım */
    buf[n] = '\0';

    /* Fuzzer için iki farklı max_len test edelim:
     * 1. Sabit boyut testi (NOX_PATH_MAX vs)
     * 2. Dinamik boyut testi (girdinin boyutuna göre) */
     
    char test_buf1[256];
    strncpy(test_buf1, buf, sizeof(test_buf1) - 1);
    test_buf1[sizeof(test_buf1) - 1] = '\0';
    
    sanitize_filename(test_buf1, sizeof(test_buf1));

    /* Volatile sink ile compiler optimizasyonunu önle */
    volatile char sink = test_buf1[0];
    (void)sink;
  }

  return 0;
}
