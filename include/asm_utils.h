/* SPDX-License-Identifier: GPL-3.0-or-later
 * asm_utils.h — x86-64 inline assembly yardımcıları
 *
 * Gerçek kazanç sağlayan yerlerde kullanılır (~80 satır).
 * IBT uyumlu: indirect branch/call kullanılmaz.
 *
 * İçerik:
 *   memory_barrier()    — explicit_bzero öncesi derleyici bariyeri
 *   rdtsc_ordered()     — mfence ile sıralı timestamp counter
 *   cpu_has_shstk()     — CPUID: shadow stack (CET) desteği
 *   cpu_has_ibt()       — CPUID: indirect branch tracking desteği
 */

#ifndef PARANOID_ASM_UTILS_H
#define PARANOID_ASM_UTILS_H

#include <stdint.h>
#include <stdbool.h>

/* ================================================================
 * MEMORY BARRIER
 *
 * Derleyicinin explicit_bzero çağrısını yeniden sıralamasını veya
 * register/cache optimizasyonlarını uygulamasını engeller.
 * Anti-DSE savunmasının ikinci katmanı.
 * ================================================================ */
static inline void memory_barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/* ================================================================
 * RDTSC — Ordered Timestamp Counter
 *
 * mfence ile sıralama garantisi. GCC'nin ürettiği RDTSC sıralaması
 * güvenilmez — speculation üzerinden yanlış zamanlama verebilir.
 * Timing ölçümleri (Argon2id benchmark, handshake süresi) için.
 * ================================================================ */
static inline uint64_t rdtsc_ordered(void)
{
    uint32_t lo, hi;

    /* mfence: tüm önceki bellek işlemlerini tamamla */
    __asm__ __volatile__("mfence");

    /* RDTSC: timestamp counter'ı oku */
    __asm__ __volatile__(
        "rdtsc"
        : "=a"(lo), "=d"(hi)
    );

    return ((uint64_t)hi << 32) | lo;
}

/* ================================================================
 * CPUID WRAPPER
 *
 * Leaf ve sub-leaf ile CPUID çağrısı.
 * ================================================================ */
static inline void cpuid(uint32_t leaf, uint32_t sub,
                         uint32_t *eax, uint32_t *ebx,
                         uint32_t *ecx, uint32_t *edx)
{
    __asm__ __volatile__(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(sub)
    );
}

/* ================================================================
 * CPU_HAS_SHSTK — Shadow Stack (CET-SS) desteği kontrolü
 *
 * CPUID leaf 7, sub-leaf 0, ECX bit 7.
 * Linux 6.6+ kernelde tam desteklenir.
 * ================================================================ */
static inline bool cpu_has_shstk(void)
{
    uint32_t eax, ebx, ecx, edx;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    return (ecx >> 7) & 1U;
}

/* ================================================================
 * CPU_HAS_IBT — Indirect Branch Tracking (CET-IBT) desteği
 *
 * CPUID leaf 7, sub-leaf 0, EDX bit 20.
 * ENDBR64 landing pad gerektiren modda çalışır.
 * ================================================================ */
static inline bool cpu_has_ibt(void)
{
    uint32_t eax, ebx, ecx, edx;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    return (edx >> 20) & 1U;
}

#endif /* PARANOID_ASM_UTILS_H */
