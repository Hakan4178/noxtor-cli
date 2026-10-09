/* SPDX-License-Identifier: GPL-3.0-or-later
 * cet_shstk.h — CET-SS (shadow stack) kilidi + self-test — init 4b
 *
 * Referans/ASSUMPTION/INVARIANT ve exit protokolü: src/cet_shstk.c
 */

#ifndef NOX_CET_SHSTK_H
#define NOX_CET_SHSTK_H

typedef enum {
  CET_SS_UNSUPPORTED = 0, /* CPU veya kernel shadow stack desteklemiyor */
  CET_SS_ENFORCED,        /* aktif + kilitli + self-test #CP ile engellendi */
  CET_SS_NOT_ENFORCED,    /* pasif — self-test temiz döndü (enforcement yok) */
  CET_SS_BROKEN           /* destek varsayılıyor ama doğrulanamadı */
} cet_ss_state;

/* arch_prctl(ARCH_SHSTK_LOCK) + /proc iki-satır doğrulaması + fork-CP
 * self-test. main init sırasının 4b adımı: PIN'den ÖNCE çağrılır. */
cet_ss_state cet_ss_lock_and_verify(void);

const char *cet_ss_state_str(cet_ss_state st);

#endif /* NOX_CET_SHSTK_H */
