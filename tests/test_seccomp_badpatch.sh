#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# test_seccomp_badpatch.sh — K-01 "bad patch" negatif kontrolü
#
# Amaç: stage-2 clone matrisinin K-01 tipi bir regresyonu GERÇEKTEN
# yakaladığını kanıtlamak. src/seccomp.c'nin iki kopyası derlenir:
#   iyi kopya : 0x00010000 (CLONE_THREAD — <sched.h> gerçek değeri)
#   bad patch : 0x00100000 (K-01 hatası: CLONE_PARENT_SETTID)
# ve aynı 2 vakalı clone matrisi her ikisine karşı koşulur:
#   vaka 1: fork-benzeri taşıyıcı  clone(SIGCHLD | 0x00100000)
#   vaka 2: gerçek thread          clone(CLONE_VM|CLONE_SIGHAND|CLONE_THREAD)
#
# Beklenen (matris ayırt edici ise):
#   iyi kopya → vaka1 SIGSYS, vaka2 yaşar
#   bad patch → vaka1 yaşar (kaçış!), vaka2 SIGSYS   ← sapma görünür olmalı
# İki davranış kümesi farklı çıkıyorsa stage2 test seti bad patch'te
# kırmızıya döner; yani dedektörün çalıştığı kanıtlanmış olur.
#
# Not: probe ham clone çağrısını TRAMPOLİN ile yapar — çocuk/thread yeni
# yığında asla `ret` çalıştırmaz (yoksa yarışlı SIGSEGV: eski desen 40
# koşuda 28 kez çöktü; ayrıntı probe.c yorumunda).
#
# Kullanım: make test (otomatik) veya tests/test_seccomp_badpatch.sh
# Gereksinim: cc + libseccomp (build bağımlılığı)

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)/src"
SECCOMP_C="$SRC_DIR/seccomp.c"
WORKDIR="$(mktemp -d /tmp/nox_seccomp_badpatch_XXXXXX)"
FAIL=0
trap 'rm -rf "$WORKDIR"' EXIT

fail() { echo "HATA: $1"; FAIL=1; }

echo "=== test_seccomp_badpatch.sh (K-01 negatif kontrol) ==="

# 0) Kaynakta düzeltme duruyor mu? (K-01 geri gelmişse hemen anlaşılır)
if ! grep -q '0x00010000' "$SECCOMP_C"; then
    fail "kaynakta 0x00010000 yok — K-01 düzeltmesi geri alınmış olabilir"
    exit 1
fi

# 1) Stub header'lar — gerçek seccomp.c include/ ağacına bağlanmadan
#    derlenebilsin (sbtest doğrulama yöntemiyle aynı: tek çeviri birimi)
cat > "$WORKDIR/common.h" <<'EOF'
#ifndef NOX_COMMON_STUB_H
#define NOX_COMMON_STUB_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <stdint.h>
typedef enum { NOX_OK = 0, NOX_ERR_CRYPTO = 1 } nox_err_t;
enum { LOG_MOD_MAIN = 0 };
#define NOX_INFO(mod, ...)  do { (void)(mod); } while (0)
#define NOX_WARN(mod, ...)  do { (void)(mod); } while (0)
#define NOX_ERROR(mod, ...) do { (void)(mod); } while (0)
#endif
EOF

cat > "$WORKDIR/seccomp_policy.h" <<'EOF'
#ifndef NOX_SECCOMP_POLICY_STUB_H
#define NOX_SECCOMP_POLICY_STUB_H
#include "common.h"
nox_err_t seccomp_policy_load(int stage);
#endif
EOF

# 2) Probe — stage 2 yükler, tek ham clone çağrısı yapar, sonucu yazar
cat > "$WORKDIR/probe.c" <<'EOF'
/* probe.c — clone matrisi: 1 = fork-benzeri (SIGCHLD|0x00100000), 2 = gerçek thread */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "seccomp_policy.h"

#define STR_(x) #x
#define STR(x) STR_(x)

/* Ham clone trampolini — çocuk/thread yeni yığında asla `ret` çalıştırmaz.
 * syscall(SYS_clone...)+if(r==0) deseni, çocuğun glibc syscall() wrapper
 * `ret`'iyle yeni yığından çöp adres çekmesine yol açar → yarışlı SIGSEGV. */
__attribute__((naked, noinline, used))
static long raw_clone_exit(unsigned long flags __attribute__((unused)),
                           void *stack __attribute__((unused)),
                           int *ptid __attribute__((unused))) {
  __asm__(
    "movq $" STR(__NR_clone) ", %rax\n\t"
    "syscall\n\t"
    "testq %rax, %rax\n\t"
    "jz 1f\n\t"
    "ret\n\t"
    /* Çocuk/thread — burada %rsp = stack; asla ret yok: */
    "1:\n\t"
    "xorl %edi, %edi\n\t"
    "movq $" STR(__NR_exit) ", %rax\n\t"
    "syscall\n\t"
    "ud2\n\t"
  );
}

int main(int argc, char **argv) {
  int mode = (argc > 1) ? atoi(argv[1]) : 1;
  if (seccomp_policy_load(2) != NOX_OK) return 3;

  static char stk[1 << 20] __attribute__((aligned(64)));
  int ptid = 0;
  unsigned long flags = 0;
  void *stack = NULL;
  if (mode == 1) {
    flags = (unsigned long)(SIGCHLD) | 0x00100000UL; /* fork-benzeri taşıyıcı */
  } else if (mode == 2) {
    flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
    stack = (void *)(stk + sizeof(stk) - 64);
  } else {
    return 9;
  }

  long r = raw_clone_exit(flags, stack, &ptid);
  if (r < 0) { printf("ERROR errno=%d\n", errno); return 4; }
  printf("SURVIVED mode=%d\n", mode);
  return 0;
}
EOF

# 3) İki kopya: iyi + bad patch (K-01'in ta kendisi)
cp "$SECCOMP_C" "$WORKDIR/seccomp_good.c"
sed 's/0x00010000/0x00100000/' "$SECCOMP_C" > "$WORKDIR/seccomp_bad.c"

if cmp -s "$WORKDIR/seccomp_good.c" "$WORKDIR/seccomp_bad.c"; then
    fail "bad patch uygulanamadı (sed eşleşmedi)"
    exit 1
fi

CC="${CC:-cc}"
# shellcheck disable=SC2086
$CC -O1 -I"$WORKDIR" "$WORKDIR/probe.c" "$WORKDIR/seccomp_good.c" -lseccomp -o "$WORKDIR/probe_good" \
    || { fail "iyi politika derlenemedi"; exit 1; }
# shellcheck disable=SC2086
$CC -O1 -I"$WORKDIR" "$WORKDIR/probe.c" "$WORKDIR/seccomp_bad.c" -lseccomp -o "$WORKDIR/probe_bad" \
    || { fail "bad patch kopyası derlenemedi"; exit 1; }

# 4) Matris koşumu
run_expect_killed() { # $1=bin $2=mode $3=etiket
    OUT="$("$1" "$2" 2>&1)"; RC=$?
    if [ "$RC" -ge 128 ] && ! printf '%s' "$OUT" | grep -q SURVIVED; then
        echo "  [OK] $3 → SIGSYS (rc=$RC)"
    else
        fail "$3 → SIGSYS bekleniyordu (rc=$RC, out='$OUT')"
    fi
}

run_expect_survived() { # $1=bin $2=mode $3=etiket
    OUT="$("$1" "$2" 2>&1)"; RC=$?
    if [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q SURVIVED; then
        echo "  [OK] $3 → yaşadı ($OUT)"
    else
        fail "$3 → yaşaması bekleniyordu (rc=$RC, out='$OUT')"
    fi
}

echo "-- iyi kopya (düzeltilmiş politika) --"
run_expect_killed   "$WORKDIR/probe_good" 1 "fork-benzeri clone(SIGCHLD|0x00100000)"
run_expect_survived "$WORKDIR/probe_good" 2 "gerçek thread clone(CLONE_THREAD)"

echo "-- bad patch kopyası (0x00100000 = K-01 hatası) --"
run_expect_survived "$WORKDIR/probe_bad" 1 "fork-benzeri clone (bad patch'te serbest — regresyon)"
run_expect_killed   "$WORKDIR/probe_bad" 2 "gerçek thread clone (bad patch'te SIGSYS — regresyon)"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "=== bad patch dedektörü: BAŞARILI (clone matrisi sapmayı görüyor) ==="
    exit 0
else
    echo "=== bad patch dedektörü: BAŞARISIZ ==="
    exit 1
fi
