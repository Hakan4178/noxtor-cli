/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_stdin_events.c — AFL++ harness for process_stdin_events
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/stdin_events \
 *            -o fuzz/findings_stdin_events \
 *            -- ./fuzz/fuzz_stdin_events
 *
 * Bu harness, process_stdin_events fonksiyonunun stdin tamponlama
 * ve satır parçalama mantığını test eder. process_line çağrıları
 * sırasında gerçek ağ/DB bağımlılıklarına çarpmasını engellemek
 * için ghost_mode etkindir ve peer_fd -1'dir.
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
#include <errno.h>

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
    /* Stdin'i non-blocking moda alalım (AFL++ her iterasyonda resetlediği için loop içinde olmalı) */
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags >= 0) {
      fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    }

    /* Durum değişkenlerini ve stdin buffer'ını her iterasyonda temizleyelim */
    state.hs = NULL;
    state.session = NULL;
    state.peer_fd = -1;
    state.tofu_pending = false;
    state.ghost_mode = true; /* DB operasyonlarından kaçınmak için */
    state.epoll_fd = -1;
    state.socks_port = 0;

    state.stdin_buf = NULL;
    state.stdin_len = 0;
    state.stdin_cap = 0;
    state.input_saved = false;

    /* Tor ctrl fd geçersiz */
    state.tor_ctrl_fd = -1;
    state.listen_fd = -1;

    memset(state.tofu_onion, 0, sizeof(state.tofu_onion));
    memset(state.tofu_name, 0, sizeof(state.tofu_name));
    memset(state.active_peer_onion, 0, sizeof(state.active_peer_onion));

    /* Arena üzerinde dinamik oluşan öğeler için başlangıç offsetini kaydedelim */
    size_t loop_mark = arena_save(&state.arena);

    /* Olayları ve tamponlamayı okuyan ana döngüyü çağırıyoruz */
    process_stdin_events(&state);

    /* Tampon bellek sızıntısını önlemek için serbest bırakalım */
    if (state.stdin_buf) {
      sodium_free(state.stdin_buf);
      state.stdin_buf = NULL;
    }

    /* Arena durumunu loop başlangıcına geri alalım */
    arena_restore(&state.arena, loop_mark);

    /* Persistent loop'ta stdin fd'si AFL++ tarafından yenilendiğinden,
     * offset'i sıfırlamak veya okuma konumunu başa sarmak gerekebilir.
     * AFL++ stdin'i sanal olarak beslediğinden lseek hatasız dönerse offset sıfırlanır. */
    lseek(STDIN_FILENO, 0, SEEK_SET);
  }

  arena_destroy(&state.arena);
  return 0;
}
