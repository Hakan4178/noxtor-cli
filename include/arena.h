/* SPDX-License-Identifier: GPL-3.0-or-later
 * arena.h — Secure arena public API
 *
 * Key materyali için mmap + MAP_LOCKED tabanlı arena.
 * Normal malloc kullanılmaz — swap'a gitmeyi engeller.
 * 16-byte aligned bump allocator (libsodium SIMD uyumu).
 * Guard page'ler buffer overflow'u SIGSEGV'ye çevirir.
 */

#ifndef PARANOID_ARENA_H
#define PARANOID_ARENA_H

#include "types.h"

/* Arena varsayılan boyutu — 64 KB usable (RLIMIT_MEMLOCK sınırı) */
#define NOX_ARENA_DEFAULT_SIZE  (64U * 1024U)

/*
 * arena_init — Güvenli arena oluştur
 *
 * @a:    Boş arena struct'ı
 * @size: İstenen kullanılabilir alan (guard page'ler hariç)
 *
 * Yaptıkları:
 *   1. mmap(MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED)
 *   2. Alt guard page: mprotect(PROT_NONE)
 *   3. Üst guard page: mprotect(PROT_NONE)
 *   4. Rastgele canary üret
 *   5. Canary'yi usable alanın sonuna yaz
 *
 * MAP_LOCKED başarısız olursa (RLIMIT_MEMLOCK):
 *   - Uyarı verir, MAP_LOCKED olmadan tekrar dener
 *   - mlock() ile kısmi koruma dener
 *
 * Return: NOX_OK veya NOX_ERR_ALLOC / NOX_ERR_LOCKED
 */
nox_err_t arena_init(struct secure_arena *a, size_t size);

/*
 * arena_alloc — Arena'dan bellek ayır (bump allocator)
 *
 * @a:    Aktif arena
 * @size: İstenen byte sayısı (16-byte'a yuvarlanır)
 *
 * Return: Hizalanmış pointer veya NULL (taşma durumunda)
 *
 * Not: free() yoktur — arena bir bütün olarak destroy edilir.
 */
void *arena_alloc(struct secure_arena *a, size_t size);

/*
 * arena_alloc_canary — Canary (honeypot) allocation
 *
 * Key'lerin arasına sahte key'ler yerleştirir.
 * Rastgele byte'lar ile doldurulur — gerçek key'den ayırt edilemez.
 * RCE sonrası memory scanning'i zorlaştırır.
 *
 * Return: Rastgele byte'larla dolu pointer veya NULL
 */
void *arena_alloc_canary(struct secure_arena *a, size_t size);

/*
 * arena_check_canary — Canary bütünlük kontrolü
 *
 * Taşma tespiti. Canary bozulmuşsa programı sonlandırır (abort).
 * Kritik noktalarda çağrılmalı (alloc öncesi, destroy öncesi).
 */
void arena_check_canary(const struct secure_arena *a);

/*
 * arena_destroy — Arena'yı güvenli şekilde yok et
 *
 * Yaptıkları:
 *   1. Canary kontrolü
 *   2. explicit_bzero(usable alan)
 *   3. Memory barrier
 *   4. munmap(tüm alan)
 *   5. struct'ı sıfırla
 */
void arena_destroy(struct secure_arena *a);

/*
 * arena_bytes_used — Kullanılan byte sayısı
 * arena_bytes_free — Kalan byte sayısı
 */
size_t arena_bytes_used(const struct secure_arena *a);
size_t arena_bytes_free(const struct secure_arena *a);

/*
 * arena_save — Mevcut offset'i kaydet (session scope başlangıcı)
 * arena_restore — Kaydedilen offset'e geri dön
 *
 * Geri alınan bellek explicit_bzero ile sıfırlanır.
 * Session bittiğinde hs/session belleğini geri kazanır.
 */
size_t arena_save(const struct secure_arena *a);
void   arena_restore(struct secure_arena *a, size_t saved_offset);

#endif /* PARANOID_ARENA_H */
