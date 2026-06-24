/* SPDX-License-Identifier: GPL-3.0-or-later
 * arena.c — Secure memory arena implementasyonu
 *
 * Key materyali için mmap + MAP_LOCKED tabanlı arena.
 *
 * Bellek topolojisi:
 *   [Lower Guard Page (PROT_NONE)] PAGE_SIZE
 *   [Usable Area]                  usable_size  (16-byte aligned bump)
 *   [Canary Zone]                  NOX_CANARY_LEN
 *   [Upper Guard Page (PROT_NONE)] PAGE_SIZE
 *
 * Guard page'lere erişim → SIGSEGV (donanımsal MMU tetikleme).
 * Bump allocator: 16-byte aligned, free yok, toplu destroy.
 *
 * Düzeltilen güvenlik açıkları:
 *   P1  — size + NOX_CANARY_LEN integer overflow koruması eklendi
 *   P2  — arena_alloc() alignment + offset overflow koruması eklendi
 *   P3  — arena_restore() sysconf() -1 dönüş değeri koruması eklendi
 *   P4  — arena_restore() canary kontrolü eklendi
 *   P5  — mlock() başarısız → isteğe bağlı STRICT modda abort()
 *   P6  — abort() öncesi PR_SET_DUMPABLE=0 ayarlanıyor
 *   P7  — sodium_init() guard eklendi
 *   P8  — explicit_bzero() → sodium_memzero() ile değiştirildi
 *   P9  — destroy() içinde guard page'ler için mprotect() kaldırıldı,
 *          doğrudan munmap() kullanıldı
 *   P10 — munmap() dönüş değeri kontrol ediliyor
 */

#include "arena.h"
#include "common.h"

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>      /* abort */
#include <string.h>      /* strerror, memcpy */
#include <stdio.h>       /* fprintf */
#include <stdint.h>      /* SIZE_MAX */
#include <errno.h>
#include <assert.h>      /* assert */

/* libsodium — canary üretimi + sabit zamanlı karşılaştırma */
#include <sodium.h>

/* ================================================================
 * KOMPİLASYON ZAMANI SEÇENEKLER
 *
 *  NOX_ARENA_STRICT_LOCK
 *      Tanımlıysa: mlock() başarısız → arena_init() hata döner.
 *      Tanımsızsa: uyarı verilir, devam edilir (swap riski belgelenir).
 *
 * ================================================================ */
#define NOX_ARENA_STRICT_LOCK

/* ================================================================
 * YARDIMCI — Sayfa boyutu
 * ================================================================ */

/**
 * get_page_size() — Sistem sayfa boyutunu döner.
 *
 * sysconf() hata dönerse 4096 kullanılır (x86/ARM varsayılan).
 * Dönüş değeri her zaman 2'nin kuvvetidir (güvenli ~mask operasyonu için).
 */
static size_t get_page_size(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    return (ps > 0) ? (size_t)ps : 4096U;
}

/**
 * page_align() — size'ı bir sonraki sayfa sınırına yuvarlar.
 *
 * Overflow güvenlidir: size > SIZE_MAX - page_size + 1 ise 0 döner.
 * Çağıran 0 dönüşünü hata olarak ele almalıdır.
 */
static size_t page_align(size_t size, size_t page_size)
{
    /* page_size 2'nin kuvveti olmak zorunda */
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0)
        return 0;

    /* P1 — page_size - 1 eklenmesindeki overflow kontrolü */
    if (size > SIZE_MAX - (page_size - 1U))
        return 0; /* overflow sinyali */
    return (size + page_size - 1U) & ~(page_size - 1U);
}

/* ================================================================
 * YARDIMCI — Güvenli abort
 *
 * PR_SET_DUMPABLE=0 main'de seccomp ÖNCESİ ayarlandı (fork ile child'a
 * miras kalır). Bu fonksiyonda tekrar prctl çağırmıyoruz — seccomp
 * stage 1 prctl'i engeller, SIGSYS ile ölüm gereksiz.
 *
 * Bu fonksiyon wipe + abort gerçekleştirir.
 * ================================================================ */
static void secure_abort(const struct secure_arena *a, const char *msg) {
    fprintf(stderr,
            "\n[FATAL] %s\n"
            "[FATAL] Güvenlik ihlali — program sonlandırılıyor.\n",
            msg ? msg : "(bilinmeyen hata)");
    fflush(stderr);

    /*
     * Struct bozuksa wipe tehlikeli olabilir.
     * Sanity check: total > 2*page_size, usable < total.
     */
    if (a && a->base && a->page_size > 0 && a->usable_size > 0
        && a->total_size > a->page_size
        && a->total_size - a->page_size > a->page_size
        && a->usable_size < a->total_size)
    {
        size_t wipe = a->usable_size + NOX_CANARY_LEN;

        /* Savunmacı üst sınır: 256 MB'dan fazlasını silme */
        const size_t MAX_WIPE = 256U * 1024U * 1024U;
        if (wipe > MAX_WIPE) wipe = MAX_WIPE;

        uint8_t *usable_start = (uint8_t *)a->base + a->page_size;

        /* Wipe bölgesi total_size içine sığıyor mu? */
        if (usable_start + wipe <= (uint8_t *)a->base + a->total_size) {
            sodium_memzero(usable_start, wipe);
        }
    }

    abort();
}
/* ================================================================
 * arena_init — Güvenli arena oluştur
 *
 * Hata durumlarında NOX_ERR_ALLOC döner; kısmi tahsisler temizlenir.
 * NOX_ARENA_STRICT_LOCK tanımlıysa mlock başarısızliğinde de NOX_ERR_ALLOC döner.
 * ================================================================ */
nox_err_t arena_init(struct secure_arena *a, size_t size)
{
    if (!a || size == 0)
        return NOX_ERR_ALLOC;

    /* P7 — sodium_init() guard
     *
     * sodium_init() çoklu çağrıya güvenlidir (1 döner),
     * -1 dönerse kütüphane kullanılamaz durumda demektir.
     */
    if (sodium_init() < 0) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "sodium_init() başarısız — libsodium kullanılamıyor");
        return NOX_ERR_ALLOC;
    }

    size_t page_size = get_page_size();

    /* ----------------------------------------------------------------
     * P1 — Güvenli boyut hesabı (integer overflow koruması)
     *
     * Adımlar:
     *   1. size + NOX_CANARY_LEN → overflow?
     *   2. page_align(sonuç)     → overflow?
     *   3. page_size + usable + page_size → overflow?
     * ---------------------------------------------------------------- */

    /* Adım 1: usable ham boyut = istenen + canary */
    if (size > SIZE_MAX - NOX_CANARY_LEN) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "boyut taşması: size=%zu + canary=%zu > SIZE_MAX",
                  size, (size_t)NOX_CANARY_LEN);
        return NOX_ERR_ALLOC;
    }
    size_t raw = size + NOX_CANARY_LEN;

    /* Adım 2: sayfa hizalı usable boyut */
    size_t usable = page_align(raw, page_size);
    if (usable == 0) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "page_align taşması: raw=%zu", raw);
        return NOX_ERR_ALLOC;
    }

    /* Adım 3: toplam = lower guard + usable + upper guard */
    if (usable > SIZE_MAX - 2U * page_size) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "toplam boyut taşması: usable=%zu", usable);
        return NOX_ERR_ALLOC;
    }
    size_t total = page_size + usable + page_size;

    /* ----------------------------------------------------------------
     * 1. mmap — MAP_LOCKED ile dene
     * ---------------------------------------------------------------- */
    void *base = mmap(NULL, total,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
                      -1, 0);

    bool locked = true;

    if (base == MAP_FAILED) {
        /*
         * MAP_LOCKED başarısız olabilir:
         *   • RLIMIT_MEMLOCK aşıldı
         *   • CAP_IPC_LOCK eksik
         *
         * Fallback: MAP_LOCKED olmadan tahsis, ardından mlock().
         */
        NOX_WARN(LOG_MOD_ARENA,
                 "MAP_LOCKED başarısız (errno=%d). "
                 "Fallback: MAP_ANONYMOUS. CAP_IPC_LOCK gerekebilir.",
                 errno);

        base = mmap(NULL, total,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);

        if (base == MAP_FAILED) {
            NOX_ERROR(LOG_MOD_ARENA,
                      "mmap başarısız: %s", strerror(errno));
            return NOX_ERR_ALLOC;
        }

        /* Usable alanı kilitlemeyi dene (guard page'ler hariç) */
        uint8_t *usable_start = (uint8_t *)base + page_size;
        if (mlock(usable_start, usable) != 0) {
            NOX_WARN(LOG_MOD_ARENA,
                     "mlock başarısız: %s — swap riski mevcut.",
                     strerror(errno));

#ifdef NOX_ARENA_STRICT_LOCK
            /*
             * P5 — STRICT mod: kilitleme başarısız → hata döner.
             * Key materyalinin swap'a yazılması kabul edilemez.
             */
            NOX_ERROR(LOG_MOD_ARENA,
                      "NOX_ARENA_STRICT_LOCK: mlock zorunlu, "
                      "arena başlatma iptal edildi.");
            munmap(base, total);
            sodium_memzero(a, sizeof(*a));
            return NOX_ERR_ALLOC;
#else
            locked = false;
            /* Non-strict: devam et, swap riski loglandı */
#endif
        }
    }

    /* ----------------------------------------------------------------
     * 2. Bellek önerileri — her iki branch için ortak
     *    Fork sırasında ve core dump'ta hassas belleği gizle.
     * ---------------------------------------------------------------- */
    a->fork_safe = true;
    a->dump_safe = true;

#ifdef MADV_DONTFORK
    if (madvise(base, total, MADV_DONTFORK) != 0) {
        NOX_WARN(LOG_MOD_ARENA,
                 "MADV_DONTFORK başarısız: %s", strerror(errno));
        a->fork_safe = false; /* caller karar versin */
    }
#endif

#ifdef MADV_DONTDUMP
    if (madvise(base, total, MADV_DONTDUMP) != 0) {
        NOX_WARN(LOG_MOD_ARENA,
                 "MADV_DONTDUMP başarısız: %s", strerror(errno));
        a->dump_safe = false; /* caller karar versin */
    }
#endif

    uint8_t *bptr = (uint8_t *)base;

    /* ----------------------------------------------------------------
     * 3. Lower guard page — PROT_NONE
     *    Underflow → SIGSEGV
     * ---------------------------------------------------------------- */
    if (mprotect(bptr, page_size, PROT_NONE) != 0) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "lower guard page mprotect başarısız: %s",
                  strerror(errno));
        munmap(base, total);
        sodium_memzero(a, sizeof(*a));
        return NOX_ERR_ALLOC;
    }

    /* ----------------------------------------------------------------
     * 4. Upper guard page — PROT_NONE
     *    Overflow → SIGSEGV
     *    Konum: base + page_size + usable
     * ---------------------------------------------------------------- */
    if (mprotect(bptr + page_size + usable, page_size, PROT_NONE) != 0) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "upper guard page mprotect başarısız: %s",
                  strerror(errno));
        munmap(base, total);
        sodium_memzero(a, sizeof(*a));
        return NOX_ERR_ALLOC;
    }

    /* ----------------------------------------------------------------
     * 5. Struct'ı doldur
     *
     *    usable_size = sayfa hizalı toplam - canary alanı
     *    Bu alan bump allocator'ın kullanabileceği maksimum alandır.
     * ---------------------------------------------------------------- */
    a->base        = base;
    a->total_size  = total;
    a->usable_size = usable - NOX_CANARY_LEN;
    a->offset      = 0;
    a->page_size   = page_size;
    a->locked      = locked;

    /* ----------------------------------------------------------------
     * 6. Canary üret ve usable alanın hemen ardına yaz
     *
     *    Konum: base + page_size + usable_size
     *    (canary, usable ile upper guard arasında yer alır)
     * ---------------------------------------------------------------- */
    randombytes_buf(a->canary, NOX_CANARY_LEN);
    uint8_t *canary_pos = bptr + page_size + a->usable_size;
    memcpy(canary_pos, a->canary, NOX_CANARY_LEN);

    /* Canary yazımının sıralanmasını garanti et */
    __asm__ __volatile__("" ::: "memory");

    NOX_INFO(LOG_MOD_ARENA,
             "arena başlatıldı: %zu KB kullanılabilir, "
             "guard page'ler aktif, %s",
             a->usable_size / 1024,
             locked ? "MAP_LOCKED aktif" : "MAP_LOCKED KAPALI (swap riski)");

    return NOX_OK;
}

/* ================================================================
 * arena_alloc — 16-byte aligned bump allocator
 *
 * Her çağrı öncesi canary kontrolü yapılır.
 * NULL dönüşü: alan yetersiz veya struct bozuk.
 * ================================================================ */
void *arena_alloc(struct secure_arena *a, size_t size)
{
    if (!a || !a->base || size == 0)
        return NULL;

    /* Canary kontrolü — her alloc öncesi (overflow erken tespiti) */
    arena_check_canary(a);

    /* H-5: arena_alloc tek thread'lidir (bump allocator).
     * Multi-peer (Phase 6.3+) veya multi-thread kullanımı için
     * arena mutex veya thread-local arena gereklidir.
     * Şu an tüm arena erişimi main() ve main() çağrısı altındadır. */
    assert(a->offset <= a->usable_size && "arena offset bozulmuş");

    /* ----------------------------------------------------------------
     * P2 — 16-byte alignment ile overflow koruması
     *
     * (size + 15) işlemi taşabilir; önce kontrol et.
     * ---------------------------------------------------------------- */
    if (size > SIZE_MAX - 15U) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "alloc hizalama taşması: size=%zu", size);
        return NULL;
    }
    size_t aligned_size = (size + 15U) & ~(size_t)15;

    /* ----------------------------------------------------------------
     * P2 — offset + aligned_size overflow koruması
     *
     * İki ayrı kontrol:
     *   1. Toplam offset aritmetiği taşıyor mu?
     *   2. Usable sınırı aşılıyor mu?
     * ---------------------------------------------------------------- */
    if (aligned_size > SIZE_MAX - a->offset) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "alloc offset taşması: offset=%zu, istenen=%zu",
                  a->offset, aligned_size);
        return NULL;
    }

    if (a->offset + aligned_size > a->usable_size) {
        NOX_ERROR(LOG_MOD_ARENA,
                  "arena kapasitesi aşıldı: istenen=%zu, kalan=%zu",
                  aligned_size,
                  a->usable_size > a->offset
                      ? a->usable_size - a->offset
                      : 0U);
        return NULL;
    }

    size_t page_size = a->page_size;
    uint8_t *bptr    = (uint8_t *)a->base;
    void    *ptr     = bptr + page_size + a->offset;
    a->offset       += aligned_size;

    NOX_DEBUG(LOG_MOD_ARENA,
              "alloc: %zu byte → hizalanmış=%zu "
              "(offset=%zu/%zu, kalan=%zu)",
              size, aligned_size,
              a->offset, a->usable_size,
              a->usable_size - a->offset);

    return ptr;
}

/* ================================================================
 * arena_alloc_canary — Canary (honeypot) allocation
 *
 * Key'lerin arasına sahte key'ler yerleştirir.
 * Rastgele byte'lar ile doldurulur — gerçek key'den ayırt edilemez.
 *
 * RCE sonrası memory scanning'i zorlaştırır:
 *   - Saldırgan hangisinin gerçek hangisinin sahte olduğunu bilemez
 *   - Honeypot'lar gerçek anahtarlarla aynı bellek düzeninde yer alır
 *
 * Not: Honeypot'lar normal arena bloklarıdır — üzerlerine yazılabilir.
 * Korum mekanizması "kullanılamazlık" değil, "ayırt edilemezlik"tir.
 *
 * @a:    Aktif arena
 * @size: Canary boyutu (genellikle NOX_KEY_LEN = 32)
 *
 * Return: Rastgele byte'larla dolu pointer veya NULL (taşma/NULL guard)
 * ================================================================ */
void *arena_alloc_canary(struct secure_arena *a, size_t size)
{
    void *ptr = arena_alloc(a, size);
    if (ptr)
        randombytes_buf(ptr, size);
    return ptr;
}

/* ================================================================
 * arena_check_canary — Buffer overflow tespiti
 *
 * Sabit zamanlı karşılaştırma ile timing side-channel koruması.
 * Canary bozulmuşsa: secure_abort() ile temizlik + abort().
 * ================================================================ */
void arena_check_canary(const struct secure_arena *a)
{
    if (!a || !a->base)
        return;

    /* Struct bütünlüğü ÖNCE — bozuksa pointer arithmetic SIGSEGV tetikler */
    bool struct_ok = (a->page_size > 0 && a->usable_size > 0 &&
                      a->total_size > a->page_size &&
                      a->total_size - a->page_size > a->page_size &&
                      a->usable_size < a->total_size);
    if (!struct_ok) {
        secure_abort(a, "Arena struct bozuk — canary okunamaz.");
        /* NOTREACHED */
    }

    size_t         page_size  = a->page_size;
    const uint8_t *bptr       = (const uint8_t *)a->base;
    const uint8_t *canary_pos = bptr + page_size + a->usable_size;

    /*
     * sodium_memcmp() — sabit zamanlı karşılaştırma.
     * memcmp() kullanmak timing saldırısına zemin hazırlar.
     */
    if (sodium_memcmp(canary_pos, a->canary, NOX_CANARY_LEN) != 0) {
        /* secure_abort(): wipe + abort() — PR_SET_DUMPABLE=0 main'de ayarlandı */
        secure_abort(a, "Arena canary bozulmuş! Buffer overflow tespit edildi.");
        /* NOTREACHED */
    }
}

/* ================================================================
 * arena_destroy — Güvenli temizlik
 *
 * Sıra:
 *   1. Son canary kontrolü
 *   2. Usable + canary alanını sodium_memzero() ile sıfırla
 *   3. Memory barrier
 *   4. munmap() — guard page'ler dahil tüm alanı serbest bırak
 *   5. Struct'ı sıfırla
 *
 * P9: Guard page mprotect() kaldırıldı.
 *     munmap() guard page'lerin iznini değiştirmeden doğrudan
 *     işletim sistemine iade eder; kısa süreli PROT_WRITE
 *     açığı oluşmaz.
 * ================================================================ */
void arena_destroy(struct secure_arena *a)
{
    if (!a || !a->base)
        return;

    /* 1. Yapısal bütünlük ÖNCE — bozuksa pointer arithmetic SIGSEGV tetikler */
    bool struct_ok = (a->page_size > 0 && a->usable_size > 0 &&
                      a->total_size > a->page_size &&
                      a->total_size - a->page_size > a->page_size &&
                      a->usable_size < a->total_size);

    if (!struct_ok) {
        fprintf(stderr, "[FATAL] Arena struct bozuk — güvenli kapanış!\n");
        fflush(stderr);
        abort(); /* munmap ve wipe atlanır, OS process ölünce temizler */
    }

    /* Artık struct'ın sağlam olduğunu biliyoruz, güvenle canary okuyabiliriz */
    uint8_t *bptr         = (uint8_t *)a->base;
    const uint8_t *canary_pos = bptr + a->page_size + a->usable_size;
    bool canary_ok = (sodium_memcmp(canary_pos, a->canary, NOX_CANARY_LEN) == 0);

    if (!canary_ok) {
        fprintf(stderr, "[FATAL] Arena canary bozulmuş!\n");
        fflush(stderr);
    }

    size_t   page_size    = a->page_size;
    uint8_t *usable_start = bptr + page_size;

    /*
     * 2. Usable + canary alanını sıfırla
     *
     * P8: sodium_memzero() kullanılıyor.
     *     • Derleyici optimizasyonuna karşı güçlüdür
     *       (volatile yazım + memory barrier içerir).
     *     • explicit_bzero() ile işlevsel olarak eşdeğer,
     *       ancak libsodium bağımlılığıyla tutarlı.
     *
     * wipe_size: usable_size (bump alanı) + NOX_CANARY_LEN
     * Sayfa hizası garantili, guard page'e taşmaz.
     *
     * Yapısal bütünlük kontrolü: struct bozuksa wipe → SIGSEGV
     * → munmap atlanır → veri sızar. Bozuksa wipe'ı atla.
     * (struct_ok başında hesaplandı — burada tekrar hesaplamaya gerek yok)
     */
    if (struct_ok) {
        size_t wipe_size = a->usable_size + NOX_CANARY_LEN;
        /* Savunmacı üst sınır: 256 MB'dan fazlasını silme */
        const size_t MAX_WIPE = 256U * 1024U * 1024U;
        if (wipe_size > MAX_WIPE) wipe_size = MAX_WIPE;
        if (usable_start + wipe_size <= bptr + a->total_size) {
            sodium_memzero(usable_start, wipe_size);
        }
    } else {
        NOX_WARN(LOG_MOD_ARENA, "arena struct bozuk — wipe atlanıyor, munmap deneniyor");
    }

    /* 3. Memory barrier — sıfırlama tamamlanmadan munmap() olmaz */
    __asm__ __volatile__("" ::: "memory");

    NOX_DEBUG(LOG_MOD_ARENA,
              "arena yıkılıyor: %zu byte", a->total_size);

    /*
     * 4. munmap — tüm alanı (guard page'ler dahil) serbest bırak.
     *
     * P9: mprotect(PROT_READ|PROT_WRITE) çağrısı burada YOK.
     *     Kernel, munmap() sırasında sayfa tablosu girdilerini
     *     doğrudan kaldırır; guard page iznini değiştirmeye
     *     gerek yoktur.
     *
     * P10: munmap() dönüş değeri kontrol ediliyor.
     *      Başarısız olması nadir ama mümkün (örn. çift-free).
     *
     * Not: Canary bozulmuş olsa bile munmap her durumda yapılır.
     *      abort() öncesi bile olsa bellek OS'e iade edilir.
     */
    if (munmap(a->base, a->total_size) != 0) {
        NOX_WARN(LOG_MOD_ARENA,
                 "munmap başarısız: %s", strerror(errno));
        /*
         * munmap başarısız olsa da struct'ı sıfırlayarak
         * dangling pointer erişimini engelle.
         */
    }

    /* 5. Struct'ı sıfırla — P8: sodium_memzero() */
    sodium_memzero(a, sizeof(*a));

    NOX_INFO(LOG_MOD_ARENA, "arena yok edildi");

    /* 6. Canary bozuksa şimdi öldür — önce her şeyi temizle */
    if (!canary_ok) {
        abort();
    }
}

/* ================================================================
 * DURUM SORGU FONKSİYONLARI
 * ================================================================ */

/** Kullanılan byte sayısı. */
size_t arena_bytes_used(const struct secure_arena *a)
{
    return a ? a->offset : 0U;
}

/** Kalan kullanılabilir byte sayısı. */
size_t arena_bytes_free(const struct secure_arena *a)
{
    if (!a || a->offset > a->usable_size)
        return 0U;
    return a->usable_size - a->offset;
}

/* ================================================================
 * SAVE / RESTORE — Session-scope bellek yönetimi
 *
 * Kullanım: geçici hesaplamalar için offset kaydet, sonra geri al.
 * Geri alınan alan sodium_memzero() ile sıfırlanır.
 * ================================================================ */

/** Mevcut offset'i kaydet (arena_restore() için referans noktası). */
size_t arena_save(const struct secure_arena *a)
{
    return a ? a->offset : 0U;
}

/**
 * arena_restore — Offset'i geri al, aradaki alanı güvenle sıfırla.
 *
 * @param a             Arena pointer'ı
 * @param saved_offset  arena_save() ile alınan offset
 */
void arena_restore(struct secure_arena *a, size_t saved_offset)
{
    if (!a || !a->base)
        return;

    /* P4 — Restore öncesi canary kontrolü */
    arena_check_canary(a);

    /* Alignment kontrolü: 16 byte hizalı olmayan offset reddedilir */
    if (saved_offset % 16 != 0) {
        NOX_WARN(LOG_MOD_ARENA,
                 "arena_restore: saved_offset (%zu) 16-byte hizalı değil!",
                 saved_offset);
        return;
    }

    /* saved_offset geçerlilik kontrolü */
    if (saved_offset > a->offset) {
        NOX_WARN(LOG_MOD_ARENA,
                 "arena_restore: saved_offset=%zu > current offset=%zu, "
                 "işlem iptal edildi.",
                 saved_offset, a->offset);
        return;
    }

    if (saved_offset == a->offset) {
        /* Sıfırlanacak alan yok */
        return;
    }

    /*
     * a->page_size kullanılıyor (arena_init tarafından ayarlandı).
     */
    size_t   page_size = a->page_size;
    uint8_t *usable    = (uint8_t *)a->base + page_size;

    size_t wipe_len = a->offset - saved_offset;

    /* P8: sodium_memzero() */
    sodium_memzero(usable + saved_offset, wipe_len);
    __asm__ __volatile__("" ::: "memory");

    NOX_DEBUG(LOG_MOD_ARENA,
              "arena restore: %zu → %zu (%zu byte sıfırlandı)",
              a->offset, saved_offset, wipe_len);

    a->offset = saved_offset;
}
