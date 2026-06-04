/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_ctrl.c — AFL++ harness for Tor Control Protocol response parser
 *
 * ctrl_read_line ve ctrl_read_response fonksiyonlarının satır tabanlı
 * ayrıştırma mantığını test eder. Fuzzer girdisi pipe üzerinden
 * fd'ye beslenir.
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/ctrl \
 *            -o fuzz/findings_ctrl \
 *            -- ./fuzz/fuzz_ctrl
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
 * ctrl_read_response static olduğu için harness içinde
 * ctrl_read_line'ı kullanarak aynı mantığı replike ediyoruz.
 * Bu, orijinal kodla birebir aynı akışı test eder.
 */
static nox_err_t fuzz_ctrl_read_response(int fd, char *buf, size_t buf_size,
                                          int timeout_ms) {
  size_t total = 0;

  for (;;) {
    char line[256];
    nox_err_t err = ctrl_read_line(fd, line, sizeof(line), timeout_ms);
    if (err != NOX_OK)
      return err;

    size_t llen = strlen(line);

    /* Buffer taşma koruması */
    if (total + llen + 1 >= buf_size) {
      return NOX_ERR_OVERFLOW;
    }
    memcpy(buf + total, line, llen);
    total += llen;

    /* "250 " = son satır, "250-" = devam */
    if (llen >= 4 && line[0] == '2' && line[1] == '5' && line[2] == '0' &&
        line[3] == ' ')
      break;

    if (llen >= 3 && (line[0] == '4' || line[0] == '5')) {
      buf[total] = '\0';
      return NOX_ERR_TOR;
    }
  }

  buf[total] = '\0';
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
    uint8_t buf[4096];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 4) /* En az "250 " veya "5xx" + "\n" gerekli */
      continue;

    /* Konfigürasyon baytını çıkaralım */
    uint8_t cfg = buf[0];

    /* Pipe oluşturalım: write end'e fuzzer verisini yazacağız */
    int pipefd[2];
    if (pipe(pipefd) != 0)
      continue;

    /* Fuzzer verisini (cfg baytı hariç) pipe'ın write end'ine yazalım */
    ssize_t w = write(pipefd[1], buf + 1, (size_t)(n - 1));
    (void)w;
    close(pipefd[1]); /* EOF sinyali gönderelim */

    if (cfg & 0x01) {
      /* Mod 1: ctrl_read_line — tekil satır okuma */
      char line_buf[256];
      ctrl_read_line(pipefd[0], line_buf, sizeof(line_buf), 50);
    } else {
      /* Mod 2: ctrl_read_response — çok satırlı yanıt ayrıştırma */
      char resp_buf[1024];
      fuzz_ctrl_read_response(pipefd[0], resp_buf, sizeof(resp_buf), 50);
    }

    close(pipefd[0]);
  }

  return 0;
}
