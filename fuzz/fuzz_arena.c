/* SPDX-License-Identifier: GPL-3.0-or-later
 * fuzz/fuzz_arena.c — AFL++ harness for the secure arena allocator
 *
 * Derleme: make fuzz
 * Çalıştırma:
 *   afl-fuzz -i fuzz/corpus/arena \
 *            -o fuzz/findings_arena \
 *            -- ./fuzz/fuzz_arena
 */

#include "arena.h"
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
    fprintf(stderr, "libsodium init hatasi\n");
    return 1;
  }

  struct secure_arena arena;
  memset(&arena, 0, sizeof(arena));

  /* 64 KB usable boyutunda bir arena oluşturalım */
  if (arena_init(&arena, 64 * 1024) != NOX_OK) {
    fprintf(stderr, "arena_init hatasi\n");
    return 1;
  }

  while (__AFL_LOOP(10000)) {
    uint8_t buf[2048];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

    if (n < 1)
      continue;

    /* Döngü başlangıcındaki offset'i saklayalım */
    size_t start_mark = arena_save(&arena);

    size_t saved_offsets[16];
    size_t num_offsets = 0;

    size_t pos = 0;
    while (pos < (size_t)n) {
      uint8_t cmd = buf[pos++];

      /* Komut tipini belirle (cmd & 0x03) */
      switch (cmd & 0x03) {
        case 0x00: { /* ALLOCATE */
          if (pos + 2 > (size_t)n)
            break;
          
          uint16_t alloc_size = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
          pos += 2;

          void *ptr = arena_alloc(&arena, alloc_size);
          if (ptr != NULL && alloc_size > 0) {
            /* Ayrılan yere girdi verisinden yazalım (Out-of-bounds tespiti için) */
            size_t write_bytes = (pos + alloc_size <= (size_t)n) ? alloc_size : ((size_t)n - pos);
            if (write_bytes > 0) {
              memcpy(ptr, buf + pos, write_bytes);
              pos += write_bytes;
            }
          }
          break;
        }

        case 0x01: { /* SAVE OFFSET */
          if (num_offsets < 16) {
            saved_offsets[num_offsets++] = arena_save(&arena);
          }
          break;
        }

        case 0x02: { /* RESTORE OFFSET */
          if (pos + 1 > (size_t)n)
            break;
          uint8_t idx = buf[pos++];
          if (num_offsets > 0) {
            size_t offset_idx = idx % num_offsets;
            arena_restore(&arena, saved_offsets[offset_idx]);
            num_offsets = offset_idx; /* bu offsetten sonrakiler geçersiz oldu */
          }
          break;
        }

        case 0x03: { /* CHECK CANARY */
          arena_check_canary(&arena);
          break;
        }
      }
    }

    /* Arena durumunu loop başlangıcına restore et */
    arena_restore(&arena, start_mark);
  }

  arena_destroy(&arena);
  return 0;
}
