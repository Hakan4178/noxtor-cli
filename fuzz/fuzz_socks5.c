/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_socks5.c — AFL++ harness for SOCKS5 response parser
 *
 * socks5_connect fonksiyonundaki SOCKS5 yanıt ayrıştırma mantığını
 * izole ederek test eder. Fuzzer girdisi pipe üzerinden fd'ye beslenir.
 * Gerçek ağ bağlantısı yapılmaz.
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/socks5 \
 *            -o fuzz/findings_socks5 \
 *            -- ./fuzz/fuzz_socks5
 */

#include "network.h"
#include "types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 0
#endif

#ifndef __AFL_INIT
#define __AFL_INIT()
#endif

/*
 * socks5_connect() fonksiyonundaki yanıt ayrıştırma mantığını
 * birebir kopyalıyoruz. Orijinal fonksiyon connect() + write()
 * yaptığı için doğrudan çağrılamaz; yalnızca read (parse) kısmını
 * izole ediyoruz.
 */
static nox_err_t fuzz_socks5_parse_response(int fd) {
  /* Faz 1: Greeting yanıtı — 2 byte (VER, METHOD) */
  uint8_t gresp[2];
  if (read_full(fd, gresp, 2) != NOX_OK)
    return NOX_ERR_NET;
  if (gresp[0] != 0x05 || gresp[1] != 0x00)
    return NOX_ERR_NET;

  /* Faz 2: CONNECT yanıtı — 4 byte (VER, REP, RSV, ATYP) */
  uint8_t sresp[4] = {0};
  nox_err_t io_err = read_full(fd, sresp, sizeof(sresp));
  if (io_err != NOX_OK)
    return NOX_ERR_NET;

  if (sresp[0] != 0x05 || sresp[1] != 0x00)
    return NOX_ERR_NET;

  /* Faz 3: ATYP'e göre BND.ADDR + BND.PORT okuma */
  uint8_t drain[256 + 2];
  size_t drain_len;
  switch (sresp[3]) {
  case 0x01: /* IPv4 */
    drain_len = 4 + 2;
    break;
  case 0x04: /* IPv6 */
    drain_len = 16 + 2;
    break;
  case 0x03: { /* Domain name */
    uint8_t dlen;
    if (read_full(fd, &dlen, 1) != NOX_OK)
      return NOX_ERR_NET;
    drain_len = (size_t)dlen + 2;
    break;
  }
  default:
    return NOX_ERR_NET;
  }

  if (read_full(fd, drain, drain_len) != NOX_OK)
    return NOX_ERR_NET;

  return NOX_OK;
}

int main(void) {
  __AFL_INIT();

  /* Çıktıları susturalım */
  int fd_null = open("/dev/null", O_WRONLY);
  if (fd_null >= 0) {
    dup2(fd_null, STDOUT_FILENO);
    dup2(fd_null, STDERR_FILENO);
    close(fd_null);
  }

  while (__AFL_LOOP(10000)) {
    /* Fuzzer girdisini okuyalım */
    uint8_t buf[2048];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 6) /* En az greeting(2) + response(4) */
      continue;

    /* Pipe oluşturalım: write end'e fuzzer verisini yazacağız */
    int pipefd[2];
    if (pipe(pipefd) != 0)
      continue;

    /* Fuzzer verisini pipe'ın write end'ine yazalım */
    ssize_t w = write(pipefd[1], buf, (size_t)n);
    (void)w;
    close(pipefd[1]); /* EOF sinyali gönderelim */

    /* SOCKS5 yanıt ayrıştırıcısını çalıştıralım */
    fuzz_socks5_parse_response(pipefd[0]);

    close(pipefd[0]);
  }

  return 0;
}
