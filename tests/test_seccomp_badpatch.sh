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
# İKİNCİ MATRİS — S-1 socket() allowlist (13 Kasım 2026):
#   iyi kopya  : socket(AF_UNIX) yaşar, socket(AF_INET) SIGSYS,
#                socket(AF_PPPOX) SIGSYS (kernel destekliyorsa)
#   bad patch  : allowlist karşılaştırması ters çevrilir
#                (SCMP_CMP_NE → SCMP_CMP_EQ) → AF_UNIX öldürülür,
#                diğer ailelere izin verilir → sapma görünür olmalı.
#   Bu matris kernel'e bağımlı değildir (AF_UNIX her yerde var).
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

# ── S-1: socket() allowlist matrisi ───────────────────────────────
cat > "$WORKDIR/probe_socket.c" <<'EOF'
/* probe_socket.c — socket matrisi:
 *   mode 1 = AF_INET  (kilitli olmalı → SIGSYS)
 *   mode 2 = AF_UNIX  (serbest olmalı → yaşamalı)
 *   mode 3 = AF_PPPOX (allowlist sayesinde kilitli → SIGSYS) */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "seccomp_policy.h"

#ifndef AF_PPPOX
#define AF_PPPOX 24
#endif

int main(int argc, char **argv) {
  int mode = (argc > 1) ? atoi(argv[1]) : 1;
  if (seccomp_policy_load(3) != NOX_OK) return 3;
  int fd;
  if (mode == 1)      fd = socket(AF_INET, SOCK_STREAM, 0);
  else if (mode == 2) fd = socket(AF_UNIX, SOCK_STREAM, 0);
  else if (mode == 3) fd = socket(AF_PPPOX, SOCK_STREAM, 0);
  else return 9;
  if (fd >= 0) { close(fd); printf("SURVIVED mode=%d\n", mode); return 0; }
  if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
    printf("UNSUPPORTED mode=%d errno=%d\n", mode, errno);
    return 5;
  }
  printf("ERROR mode=%d errno=%d\n", mode, errno);
  return 4;
}
EOF

# allowlist karşılaştırmasını ters çeviren bad patch
sed 's/SCMP_CMP_NE/SCMP_CMP_EQ/' "$SECCOMP_C" > "$WORKDIR/seccomp_bad_socket.c"
if cmp -s "$SECCOMP_C" "$WORKDIR/seccomp_bad_socket.c"; then
    fail "socket bad patch uygulanamadı (sed eşleşmedi — allowlist kuralı kaldırılmış olabilir)"
    exit 1
fi

# shellcheck disable=SC2086
$CC -O1 -I"$WORKDIR" "$WORKDIR/probe_socket.c" "$WORKDIR/seccomp_good.c" -lseccomp -o "$WORKDIR/probe_sock_good" \
    || { fail "socket probu (iyi politika) derlenemedi"; exit 1; }
# shellcheck disable=SC2086
$CC -O1 -I"$WORKDIR" "$WORKDIR/probe_socket.c" "$WORKDIR/seccomp_bad_socket.c" -lseccomp -o "$WORKDIR/probe_sock_bad" \
    || { fail "socket probu (bad patch) derlenemedi"; exit 1; }

run_expect_killed_opt() { # $1=bin $2=mode $3=etiket — kernel desteklemiyorsa SKIP
    OUT="$("$1" "$2" 2>&1)"; RC=$?
    if printf '%s' "$OUT" | grep -q UNSUPPORTED; then
        echo "  [SKIP] $3 → kernel bu aileyi desteklemiyor"
    elif [ "$RC" -ge 128 ] && ! printf '%s' "$OUT" | grep -q SURVIVED; then
        echo "  [OK] $3 → SIGSYS (rc=$RC)"
    else
        fail "$3 → SIGSYS bekleniyordu (rc=$RC, out='$OUT')"
    fi
}

run_expect_survived_opt() { # $1=bin $2=mode $3=etiket — kernel desteklemiyorsa SKIP
    OUT="$("$1" "$2" 2>&1)"; RC=$?
    if printf '%s' "$OUT" | grep -q UNSUPPORTED; then
        echo "  [SKIP] $3 → kernel bu aileyi desteklemiyor"
    elif [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q SURVIVED; then
        echo "  [OK] $3 → yaşadı ($OUT)"
    else
        fail "$3 → yaşaması bekleniyordu (rc=$RC, out='$OUT')"
    fi
}

echo "-- socket matrisi: iyi kopya (allowlist NE AF_UNIX) --"
run_expect_killed   "$WORKDIR/probe_sock_good" 1 "socket(AF_INET) kilitli"
run_expect_survived "$WORKDIR/probe_sock_good" 2 "socket(AF_UNIX) serbest"
run_expect_killed_opt "$WORKDIR/probe_sock_good" 3 "socket(AF_PPPOX) kilitli"

echo "-- socket matrisi: bad patch (allowlist EQ AF_UNIX → sapma) --"
# Sapma 1: allowlist ters çevrilince AF_UNIX öldürülür (app ölür).
run_expect_killed "$WORKDIR/probe_sock_bad" 2 "socket(AF_UNIX) bad patch'te öldürüldü — regresyon"
# AF_INET hâlâ öldürülür: aşama-2 aile kuralı ayrıca kapatıyor (sapma DEĞİL).
run_expect_killed "$WORKDIR/probe_sock_bad" 1 "socket(AF_INET) bad patch'te de öldürüldü (aşama-2 aile kuralı)"
# Sapma 2: allowlist ters çevrilince S-1'in motivasyonu olan aile açılır.
run_expect_survived_opt "$WORKDIR/probe_sock_bad" 3 "socket(AF_PPPOX) bad patch'te serbest — regresyon"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "=== bad patch dedektörü: BAŞARILI (clone + socket matrisleri sapmayı görüyor) ==="
    exit 0
else
    echo "=== bad patch dedektörü: BAŞARISIZ ==="
    exit 1
fi
