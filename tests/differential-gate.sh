#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# differential-gate.sh — noise.c ↔ noise-c diferansiyel doğrulama kapısı
#
# Derler, koşar ve denetlenebilir bir kanıt kaydı üretir:
#   run.log       — tüm koşu çıktısı (tohum, ilerleme, sonuç)
#   build.log     — derleme çıktısı
#   metadata.txt  — commit, kaynak/harness/kütüphane SHA-256, tohum, süre
#   summary.txt   — tek satır PASS/FAIL
#
# Uyuşmazlıkta (veya derleme/kütüphane hatasında) sıfırdan farklı çıkar.
#
# Kullanım:
#   tests/differential-gate.sh [kayıt_dizini]
#
# Ortam:
#   NOX_DIFF_SEED    koşuyu sabitler (boşsa rastgele üretilir ve kayda yazılır)
#   NOISE_C_PREFIX   noise-c kurulum öneki (varsayılan: /usr/local)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${1:-$ROOT/docs-priv/kanit/noise-differential-$(date +%F)}"
PREFIX="${NOISE_C_PREFIX:-/usr/local}"
BIN="$ROOT/tests/fuzz_noise_differential"
RUNLOG="$OUTDIR/run.log"
BUILDLOG="$OUTDIR/build.log"
META="$OUTDIR/metadata.txt"
SUMMARY="$OUTDIR/summary.txt"

mkdir -p "$OUTDIR"

die() {
    local code="$1"; shift
    echo "HATA: $*" >&2
    printf 'FAIL: %s\n' "$*" > "$SUMMARY"
    exit "$code"
}

# ── 1. Referans kütüphane ──────────────────────────────────────────
LIB=""
for cand in \
    "$PREFIX/lib/libnoiseprotocol.a" "$PREFIX/lib/libnoiseprotocol.so" \
    "$PREFIX/lib64/libnoiseprotocol.a" "$PREFIX/lib64/libnoiseprotocol.so"
do
    if [ -f "$cand" ]; then LIB="$cand"; break; fi
done
[ -n "$LIB" ] || die 2 \
    "libnoiseprotocol bulunamadı ($PREFIX/lib) — noise-c kurun veya NOISE_C_PREFIX verin."

# ── 2. Derle ───────────────────────────────────────────────────────
make -C "$ROOT" tests/fuzz_noise_differential NOISE_C_PREFIX="$PREFIX" \
    CC="${CC:-gcc}" >"$BUILDLOG" 2>&1 || die 3 "derleme başarısız — $BUILDLOG"
[ -x "$BIN" ] || die 3 "ikili üretilemedi: $BIN"

# ── 3. Koş ─────────────────────────────────────────────────────────
START=$(date +%s)
if [ -n "${NOX_DIFF_SEED:-}" ]; then
    export NOX_DIFF_SEED
fi
"$BIN" >"$RUNLOG" 2>&1
RC=$?
END=$(date +%s)

# ── 4. Kanıt kaydı ─────────────────────────────────────────────────
SEED=$(sed -n 's/.*seed=\(0x[0-9a-fA-F]*\).*/\1/p' "$RUNLOG" | head -1)
RESULT=$(grep -E '^\[diff\] Results:' "$RUNLOG" | tail -1 | sed 's/^\[diff\] //')
[ -n "$RESULT" ] || RESULT="(sonuç satırı yok — $RUNLOG)"

SHA_SRC=$(sha256sum "$ROOT/src/noise.c" | cut -d' ' -f1)
SHA_HARNESS=$(sha256sum "$ROOT/tests/fuzz_noise_differential.c" | cut -d' ' -f1)
SHA_LIB=$(sha256sum "$LIB" | cut -d' ' -f1)
COMMIT=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo "?")
BRANCH=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "?")
DIRTY=$(git -C "$ROOT" status --porcelain -- src/noise.c tests/fuzz_noise_differential.c 2>/dev/null | wc -l | tr -d ' ')

{
    echo "tarih: $(date -Is)"
    echo "süre_s: $((END - START))"
    echo "commit: $COMMIT"
    echo "branch: $BRANCH"
    echo "ilgili_dosya_kirli: $DIRTY"
    echo "seed: ${SEED:-?}"
    echo "sonuç: $RESULT"
    echo "çıkış_kodu: $RC"
    echo "kaynak_sha256: $SHA_SRC"
    echo "harness_sha256: $SHA_HARNESS"
    echo "referans: $LIB"
    echo "referans_sha256: $SHA_LIB"
    echo "cc: $(${CC:-gcc} --version 2>/dev/null | head -1)"
    echo "kernel: $(uname -sr)"
} > "$META"

if [ "$RC" -eq 0 ]; then
    printf 'PASS: %s | seed=%s | commit=%s | süre=%ss\n' \
        "$RESULT" "${SEED:-?}" "$COMMIT" "$((END - START))" > "$SUMMARY"
else
    printf 'FAIL: %s (rc=%s) | seed=%s | commit=%s | log=%s\n' \
        "$RESULT" "$RC" "${SEED:-?}" "$COMMIT" "$RUNLOG" > "$SUMMARY"
fi

cat "$SUMMARY"
exit "$RC"
