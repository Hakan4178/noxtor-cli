/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_file_transfer.c — AFL++ harness for file transfer receiver (file_transfer_handle_rx)
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/file_transfer \
 *            -o fuzz/findings_file_transfer \
 *            -- ./fuzz/fuzz_file_transfer
 */

#include "file_transfer.h"
#include "types.h"
#include "arena.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
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

  /* Terminal I/O çıktılarını kapatmak için stdout ve stderr'i /dev/null'a yönlendirelim */
  int fd_null = open("/dev/null", O_WRONLY);
  if (fd_null >= 0) {
    dup2(fd_null, STDOUT_FILENO);
    dup2(fd_null, STDERR_FILENO);
    close(fd_null);
  }

  if (sodium_init() < 0) {
    return 1;
  }

  /* Gerekli dizini oluşturalım */
  mkdir("fuzz/tmp_downloads", 0700);
  int dir_fd = open("fuzz/tmp_downloads", O_RDONLY | O_DIRECTORY);
  if (dir_fd < 0) {
    return 1;
  }

  struct app_state state;
  memset(&state, 0, sizeof(state));
  state.downloads_dir_fd = dir_fd;

  /* Mock session oluşturalım (rx.has_key = false olunca pass-through yapar) */
  struct noise_session mock_session;
  memset(&mock_session, 0, sizeof(mock_session));
  state.session = &mock_session;

  while (__AFL_LOOP(10000)) {
    uint8_t buf[8192];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 2)
      continue;

    /* Her tur öncesi rx_file struct'ını sıfırlayalım */
    memset(&state.rx_file, 0, sizeof(state.rx_file));
    state.rx_file.fd = -1;

    /* Konfigürasyon baytını çıkaralım */
    uint8_t cfg = buf[0];
    if (cfg & 0x01) {
      /* Aktif bir dosya transferi simüle edelim */
      state.rx_file.active = true;
      state.rx_file.expected_size = 100000;
      state.rx_file.received_bytes = (cfg & 0x02) ? 99000 : 50000;
      memset(state.rx_file.expected_hash, 0xAA, 32);
      strncpy(state.rx_file.filename, "fuzz_test.dat", sizeof(state.rx_file.filename) - 1);
      strncpy(state.rx_file.local_name, "received_fuzz_test.dat", sizeof(state.rx_file.local_name) - 1);

      /* Dosyayı downloads_dir_fd içinde açalım */
      int fd = openat(state.downloads_dir_fd, state.rx_file.local_name,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
      if (fd >= 0) {
        state.rx_file.fd = fd;
        crypto_generichash_init(&state.rx_file.hash_state, NULL, 0, 32);
      } else {
        state.rx_file.active = false;
      }
    }

    /* Alıcı fonksiyonu çalıştıralım (buf + 1 ile fuzzer girdisini besleyelim) */
    file_transfer_handle_rx(&state, buf + 1, (uint32_t)(n - 1));

    /* Kalan tüm kaynakları ve oluşturulan dosyayı temizleyelim */
    file_transfer_cleanup(&state);
  }

  close(dir_fd);
  return 0;
}
