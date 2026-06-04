/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_stdin.c — AFL++ harness for the command line parser (process_line)
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/stdin \
 *            -o fuzz/findings_stdin \
 *            -- ./fuzz/fuzz_stdin
 */

#include "stdin_handler.h"
#include "types.h"
#include "arena.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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

  struct app_state state;
  memset(&state, 0, sizeof(state));

  if (arena_init(&state.arena, 64 * 1024) != NOX_OK) {
    return 1;
  }

  /* Statik anahtar alanlarını oluşturup dolduralım */
  state.my_static_priv = arena_alloc(&state.arena, 32);
  state.my_static_pub = arena_alloc(&state.arena, 32);
  if (state.my_static_priv && state.my_static_pub) {
    memset(state.my_static_priv, 0x41, 32);
    memset(state.my_static_pub, 0x42, 32);
  }

  /* Kendi varsayılan adresimizi set edelim */
  snprintf(state.onion_addr, sizeof(state.onion_addr),
           "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion");

  /* Persistent loop başlangıcı */
  while (__AFL_LOOP(10000)) {
    uint8_t buf[1024];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n < 2)
      continue;

    /* Durum değişkenlerini her iterasyonda sıfırlayalım */
    state.hs = NULL;
    state.session = NULL;
    state.peer_fd = -1;
    state.tofu_pending = false;
    state.ghost_mode = false;
    state.epoll_fd = -1;
    memset(state.tofu_onion, 0, sizeof(state.tofu_onion));
    memset(state.tofu_name, 0, sizeof(state.tofu_name));
    memset(state.active_peer_onion, 0, sizeof(state.active_peer_onion));

    /* Arena üzerinde dinamik oluşan öğeler için başlangıç offsetini kaydedelim */
    size_t loop_mark = arena_save(&state.arena);

    /* İlk byte'ı konfigürasyon olarak kullanalım */
    uint8_t cfg = buf[0];
    state.ghost_mode = (cfg & 0x01) ? true : false;
    state.tofu_pending = (cfg & 0x02) ? true : false;

    if (cfg & 0x04) {
      /* Aktif şifreli oturum varmış gibi simüle edelim */
      state.session = arena_alloc(&state.arena, sizeof(struct noise_session));
      if (state.session) {
        state.session->tx.has_key = true;
        state.session->rx.has_key = true;
        memset(state.session->tx.k, 0xAA, 32);
        memset(state.session->rx.k, 0xBB, 32);
        snprintf(state.active_peer_onion, sizeof(state.active_peer_onion),
                 "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion");
      }
    }

    if (cfg & 0x08) {
      /* Bağlantı kurulmuş gibi simüle edelim (dummy FD) */
      state.peer_fd = 100;
    }

    /* Geri kalan veriyi parse edilecek komut satırı yapalım */
    char line_buf[1024];
    size_t line_len = n - 1;
    if (line_len >= sizeof(line_buf))
      line_len = sizeof(line_buf) - 1;
    memcpy(line_buf, buf + 1, line_len);
    line_buf[line_len] = '\0';

    /* Satır sonundaki yeni satır karakterlerini (\r, \n) temizleyelim */
    while (line_len > 0 && (line_buf[line_len - 1] == '\n' || line_buf[line_len - 1] == '\r')) {
      line_buf[line_len - 1] = '\0';
      line_len--;
    }

    /* Parser fonksiyonunu çalıştıralım */
    process_line(&state, line_buf);

    /* Arena durumunu loop başlangıcına geri alalım (sızıntıyı önler) */
    arena_restore(&state.arena, loop_mark);
  }

  arena_destroy(&state.arena);
  return 0;
}
