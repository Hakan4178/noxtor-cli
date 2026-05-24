/* SPDX-License-Identifier: GPL-3.0-or-later
 * arena.c — Secure memory arena implementasyonu
 *
 * Key materyali için mmap + MAP_LOCKED tabanlı arena.
 *
 * Bellek topolojisi:
 *   [Lower Guard Page (PROT_NONE)] PAGE_SIZE
 *   [Usable Area + Canary]         usable_size
 *   [Upper Guard Page (PROT_NONE)] PAGE_SIZE
 *
 * Guard page'lere erişim → SIGSEGV (donanımsal MMU tetikleme).
 * Bump allocator: 16-byte aligned, free yok, toplu destroy.
 */

#include "arena.h"
#include "common.h"

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>   /* abort */
#include <string.h>   /* explicit_bzero */
#include <stdio.h>    /* fprintf (fallback uyarı için) */

/* libsodium — canary üretimi için */
#include <sodium.h>

/* ================================================================
 * YARDIMCI — Sayfa boyutuna yuvarla
 * ================================================================ */
static size_t page_align(size_t size)
{
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0)
        ps = 4096;
    size_t page_size = (size_t)ps;
    return (size + page_size - 1) & ~(page_size - 1);
}

static size_t get_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    return (ps > 0) ? (size_t)ps : 4096U;
}

/* ================================================================
 * arena_init — Güvenli arena oluştur
 * ================================================================ */
nox_err_t arena_init(struct secure_arena *a, size_t size)
{
    if (!a || size == 0)
        return NOX_ERR_ALLOC;

    size_t page_size = get_page_size();

    /* Usable alanı sayfa hizasına yuvarla (canary alanı dahil) */
    size_t usable = page_align(size + NOX_CANARY_LEN);

    /* Toplam: lower guard + usable + upper guard */
    size_t total = page_size + usable + page_size;

    /* 1. mmap — MAP_LOCKED ile dene */
    void *base = mmap(NULL, total,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
                      -1, 0);

    bool locked = true;

    if (base == MAP_FAILED) {
        /*
         * MAP_LOCKED başarısız — RLIMIT_MEMLOCK aşılmış olabilir.
         * Fallback: MAP_LOCKED olmadan dene, sonra mlock() ile
         * kısmi koruma.
         */
        NOX_WARN(LOG_MOD_ARENA,
                 "MAP_LOCKED başarısız (errno=%d). "
                 "Swap riski var, CAP_IPC_LOCK gerekebilir.", errno);

        base = mmap(NULL, total,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);

        if (base == MAP_FAILED) {
            NOX_ERROR(LOG_MOD_ARENA,
                      "mmap başarısız: %s", strerror(errno));
            return NOX_ERR_ALLOC;
        }

      /* ← YENİ: fallback branch */
#ifdef MADV_DONTFORK
         if (madvise(base, total, MADV_DONTFORK) != 0)
            NOX_WARN(LOG_MOD_ARENA, "MADV_DONTFORK: %s", strerror(errno));
  
#endif
#ifdef MADV_DONTDUMP
        if (madvise(base, total, MADV_DONTDUMP) != 0)
            NOX_WARN(LOG_MOD_ARENA, "MADV_DONTDUMP: %s", strerror(errno));
#endif
        
        /* Kısmi koruma — usable alanı kilitlemeye çalış */
        uint8_t *usable_start = (uint8_t *)base + page_size;
        if (mlock(usable_start, usable) != 0) {
            NOX_WARN(LOG_MOD_ARENA,
                     "mlock kısmi koruma başarısız: %s. "
                     "Devam ediliyor, swap riski var.", strerror(errno));
            locked = false;
        }
    }  else {
        /* MAP_LOCKED başarılı branch — buraya da ekle */
#ifdef MADV_DONTFORK
        if (madvise(base, total, MADV_DONTFORK) != 0)
            NOX_WARN(LOG_MOD_ARENA, "MADV_DONTFORK: %s", strerror(errno));
#endif
#ifdef MADV_DONTDUMP
        if (madvise(base, total, MADV_DONTDUMP) != 0)
            NOX_WARN(LOG_MOD_ARENA, "MADV_DONTDUMP: %s", strerror(errno));
#endif
    }

    uint8_t *bptr = (uint8_t *)base;

    /* 2. Lower guard page — PROT_NONE */
    if (mprotect(bptr, page_size, PROT_NONE) != 0) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "lower guard page mprotect başarısız: %s",
                  strerror(errno));
        munmap(base, total);
        return NOX_ERR_ALLOC;
    }

    /* 3. Upper guard page — PROT_NONE */
    if (mprotect(bptr + page_size + usable, page_size, PROT_NONE) != 0) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "upper guard page mprotect başarısız: %s",
                  strerror(errno));
        munmap(base, total);
        return NOX_ERR_ALLOC;
    }

    /* 4. Struct'ı doldur */
    a->base        = base;
    a->total_size  = total;
    a->usable_size = usable - NOX_CANARY_LEN; /* canary alanını çıkar */
    a->offset      = 0;

    /* 5. Rastgele canary üret ve usable alanın sonuna yaz */
    randombytes_buf(a->canary, NOX_CANARY_LEN);
    uint8_t *canary_pos = bptr + page_size + a->usable_size;
    memcpy(canary_pos, a->canary, NOX_CANARY_LEN);

    NOX_INFO(LOG_MOD_ARENA,
             "arena başlatıldı: %zu KB kullanılabilir, "
             "guard page'ler aktif, %s",
             a->usable_size / 1024,
             locked ? "MAP_LOCKED aktif" : "MAP_LOCKED KAPALI (swap riski)");

    return NOX_OK;
}

/* ================================================================
 * arena_alloc — 16-byte aligned bump allocator
 * ================================================================ */
void *arena_alloc(struct secure_arena *a, size_t size)
{
    if (!a || !a->base || size == 0)
        return NULL;

    /* Canary kontrolü — her alloc öncesi */
    arena_check_canary(a);

    /* 16-byte alignment (libsodium SIMD: AVX2/AVX-512) */
    size = (size + 15U) & ~15UL;

    /* Taşma kontrolü */
    if (a->offset + size > a->usable_size) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "arena taşması: istenen=%zu, kalan=%zu",
                  size, a->usable_size - a->offset);
        return NULL;
    }

    size_t page_size = get_page_size();
    uint8_t *bptr = (uint8_t *)a->base;
    void *ptr = bptr + page_size + a->offset;
    a->offset += size;

    NOX_DEBUG(LOG_MOD_ARENA,
              "alloc: %zu byte (offset=%zu/%zu, kalan=%zu)",
              size, a->offset, a->usable_size,
              a->usable_size - a->offset);

    return ptr;
}

/* ================================================================
 * arena_check_canary — Taşma tespiti
 * ================================================================ */
void arena_check_canary(const struct secure_arena *a)
{
    if (!a || !a->base)
        return;

    size_t page_size = get_page_size();
    const uint8_t *bptr = (const uint8_t *)a->base;
    const uint8_t *canary_pos = bptr + page_size + a->usable_size;

    /*
     * Sabit zamanlı karşılaştırma — timing side-channel'ı engeller.
     * sodium_memcmp() kullanılır.
     */
    if (sodium_memcmp(canary_pos, a->canary, NOX_CANARY_LEN) != 0) {
        /*
         * Canary bozulmuş — buffer overflow tespit edildi.
         * Güvenli çıkış: abort() — core dump'sız (PR_SET_DUMPABLE=0 ise).
         */
        fprintf(stderr,
                "\n[FATAL] Arena canary bozulmuş! "
                "Buffer overflow tespit edildi.\n"
                "[FATAL] Güvenlik ihlali — program sonlandırılıyor.\n");
        fflush(stderr);
        abort();
    }
}

/* ================================================================
 * arena_destroy — Güvenli temizlik
 * ================================================================ */
void arena_destroy(struct secure_arena *a)
{
    if (!a || !a->base)
        return;

    /* 1. Son canary kontrolü */
    arena_check_canary(a);

    size_t page_size = get_page_size();
    uint8_t *bptr = (uint8_t *)a->base;

    /* 2. Usable alanı sıfırla — canary dahil */
    uint8_t *usable_start = bptr + page_size;
    size_t wipe_size = a->usable_size + NOX_CANARY_LEN;
    explicit_bzero(usable_start, wipe_size);

    /* 3. Memory barrier — derleyicinin sıfırlamayı optimize etmesini engelle */
    __asm__ __volatile__("" ::: "memory");

    NOX_DEBUG(LOG_MOD_ARENA,
              "arena temizlendi: %zu byte sıfırlandı", wipe_size);

    /* 4. Guard page'leri tekrar PROT_READ | PROT_WRITE yap (munmap için) */
    mprotect(bptr, page_size, PROT_READ | PROT_WRITE);
    mprotect(bptr + page_size + a->usable_size + NOX_CANARY_LEN,
             page_size, PROT_READ | PROT_WRITE);

    /* 5. munmap — tüm alanı serbest bırak */
    munmap(a->base, a->total_size);

    /* 6. Struct'ı sıfırla */
    explicit_bzero(a, sizeof(*a));

    NOX_INFO(LOG_MOD_ARENA, "arena yok edildi");
}

/* ================================================================
 * DURUM SORGU FONKSİYONLARI
 * ================================================================ */
size_t arena_bytes_used(const struct secure_arena *a)
{
    return a ? a->offset : 0;
}

size_t arena_bytes_free(const struct secure_arena *a)
{
    return (a && a->offset <= a->usable_size)
       ? (a->usable_size - a->offset) : 0;
}

/* ================================================================
 * SAVE / RESTORE — session scope bellek yönetimi
 * ================================================================ */
size_t arena_save(const struct secure_arena *a)
{
    return a ? a->offset : 0;
}

void arena_restore(struct secure_arena *a, size_t saved_offset)
{
    if (!a || saved_offset >= a->offset) return;

    /* Geri alınan alanı güvenle sıfırla */
    long page_size = sysconf(_SC_PAGESIZE);
    uint8_t *usable = (uint8_t *)a->base + page_size;

    size_t wipe_len = a->offset - saved_offset;
    explicit_bzero(usable + saved_offset, wipe_len);
    __asm__ __volatile__("" ::: "memory");

    NOX_DEBUG(LOG_MOD_ARENA, "arena restore: %zu → %zu (%zu byte sıfırlandı)",
              a->offset, saved_offset, wipe_len);
    a->offset = saved_offset;
}
