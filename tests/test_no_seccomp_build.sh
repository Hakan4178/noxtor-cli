#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# test_no_seccomp_build.sh — K-07/T-01: NO_SECCOMP=1 build regresyonu
#
# Amaç: seccomp politikası derlemeden çıkarıldığında (NO_SECCOMP=1)
# `seccomp_policy_load()` çağrılarının link hatasına yol açmadığını
# kanıtlamak. Bu test, kaynak ağacını geçici bir dizine kopyalayıp
# gerçek `make NO_SECCOMP=1` build'ini çalıştırır; çalışma ağacındaki
# nesne/binary'leri ezmez.
#
# Kırmızı→yeşil kanıtı:
#   - Stub yokken: `undefined reference to seccomp_policy_load`
#   - Stub eklendikten sonra: build başarılı, binary libseccomp'a bağlı değil.
#
# Kullanım: make test (otomatik) veya tests/test_no_seccomp_build.sh
# Gereksinim: make + gcc + proje bağımlılıkları (libsodium, libsqlite3)

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/nox_no_seccomp_XXXXXX)"
LOG="$WORKDIR/build.log"
FAIL=0
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
    echo "HATA: $1"
    FAIL=1
}

echo "=== test_no_seccomp_build.sh (K-07/T-01) ==="

if [ ! -f "$ROOT/Makefile" ] || [ ! -d "$ROOT/src" ] || [ ! -d "$ROOT/include" ]; then
    fail "proje kökü beklenen yapıda değil: $ROOT"
    exit 1
fi

# Yalnız ana binary için gerekli kaynakları kopyala; nesne/bağımlılık
# artefaktlarını taşımadan temiz bir build garantile.
tar -C "$ROOT" \
    --exclude='*.o' --exclude='*.d' --exclude='*.test.o' --exclude='*.test.d' \
    -cf - Makefile src include | tar -C "$WORKDIR" -xf -

if [ ! -f "$WORKDIR/Makefile" ] || [ ! -d "$WORKDIR/src" ]; then
    fail "geçici kaynak kopyası oluşturulamadı"
    exit 1
fi

# Gerçek build: NO_SECCOMP=1 seccomp.c'yi kaynak listesinden çıkarır,
# -DNO_SECCOMP tanımlar ve -lseccomp bağlamaz.
if ! timeout 300 make -C "$WORKDIR" NO_SECCOMP=1 >"$LOG" 2>&1; then
    fail "NO_SECCOMP=1 build başarısız"
    tail -40 "$LOG" >&2
    exit 1
fi

if [ ! -x "$WORKDIR/noxtor-cli" ]; then
    fail "build sonrası noxtor-cli üretilmedi"
    exit 1
fi

# Seccomp kütüphanesi hâlâ linklenmişse NO_SECCOMP sözleşmesi ihlal edilmiş olur.
if ldd "$WORKDIR/noxtor-cli" 2>/dev/null | grep -q 'libseccomp'; then
    fail "NO_SECCOMP=1 binary hâlâ libseccomp'a bağlı"
    exit 1
fi

# Çözülmemiş seccomp sembolü kalmamalı (stub/link sözleşmesi).
if nm -u "$WORKDIR/noxtor-cli" 2>/dev/null | grep -q 'seccomp_policy_load'; then
    fail "NO_SECCOMP=1 binary'de çözülmemiş seccomp_policy_load sembolü var"
    exit 1
fi

if [ "$FAIL" -eq 0 ]; then
    echo "PASS: NO_SECCOMP=1 build başarılı (libseccomp yok, sembol çözülmüş)"
fi

exit "$FAIL"
