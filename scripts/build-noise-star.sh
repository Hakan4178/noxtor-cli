#!/usr/bin/env bash
# build-noise-star.sh — Noise* ikinci oracle için pinli HACL* + suite derlemesi.
#
# HACL* repoya girmez: $HACL_DIR altına (varsayılan /tmp) sparse clone yapılır.
# Doğru pin 349b052'dir: vendored Hacl.h 5 argümanlı blake2b_init bekler;
# sonraki sürümler (be4a57c, 16c4798, main) 3 argümana indirdiği için sessizce
# yanlış handshake hash'i üretir. Ayrıntı: third_party/noise-star/README.md.
#
# Kullanım:
#   scripts/build-noise-star.sh            # HACL + suite derle
#   HACL_DIR=/tmp/foo scripts/build-noise-star.sh
#   FORCE=1 scripts/build-noise-star.sh    # mevcut clone'u sıfırla

set -euo pipefail

HACL_PIN="${HACL_PIN:-349b0521d5e326caa7a43df0d2f6fd9b18812daf}"
HACL_DIR="${HACL_DIR:-/tmp/hacl-349b052}"
FORCE="${FORCE:-0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="$REPO_ROOT/third_party/noise-star/XX_25519_ChaChaPoly_BLAKE2b"

if [[ ! -d "$SUITE" ]]; then
    echo "HATA: suite bulunamadı: $SUITE" >&2
    exit 1
fi

if [[ -d "$HACL_DIR" ]]; then
    if [[ "$FORCE" == "1" ]]; then
        echo "== FORCE: $HACL_DIR siliniyor"
        rm -rf "$HACL_DIR"
    else
        echo "== Mevcut HACL ağacı kullanılıyor: $HACL_DIR"
    fi
fi

if [[ ! -d "$HACL_DIR/.git" ]]; then
    echo "== HACL* sparse clone ($HACL_PIN)"
    git init -q "$HACL_DIR"
    git -C "$HACL_DIR" remote add origin \
        https://github.com/project-everest/hacl-star.git
    git -C "$HACL_DIR" fetch -q --depth 1 --filter=blob:none origin "$HACL_PIN"
    git -C "$HACL_DIR" checkout -q FETCH_HEAD
    git -C "$HACL_DIR" sparse-checkout init --cone
    git -C "$HACL_DIR" sparse-checkout set dist

    ACTUAL="$(git -C "$HACL_DIR" rev-parse HEAD)"
    if [[ "$ACTUAL" != "$HACL_PIN" ]]; then
        echo "HATA: pin uyuşmadı: beklenen $HACL_PIN, bulunan $ACTUAL" >&2
        exit 1
    fi
    echo "   pin doğrulandı: $ACTUAL"
fi

DIST="$HACL_DIR/dist"

# Eski HACL 'kremlin/' başlıkları kullanır; Noise* üretilmiş kodu 'krml/'
# yollarını include eder. Yalnızca tip tanımları olan bu alias ABI'yi etkilemez.
if [[ ! -e "$DIST/karamel" ]]; then
    echo "== krml/ alias'i oluşturuluyor"
    mkdir -p "$DIST/karamel/include" "$DIST/karamel/krmllib/dist"
    ln -sfn ../../kremlin/include/kremlin "$DIST/karamel/include/krml"
    ln -sfn ../../../kremlin/kremlib/dist/minimal \
        "$DIST/karamel/krmllib/dist/minimal"
fi

# Statik C kütüphanesi (çıplak make OCaml binding'lerini de ister).
if [[ ! -f "$DIST/gcc-compatible/libevercrypt.a" ]]; then
    echo "== libevercrypt.a derleniyor"
    ( cd "$DIST/gcc-compatible"
      ./configure > "$HACL_DIR/configure.log" 2>&1
      make -j"$(nproc)" libevercrypt.a USER_CFLAGS="-Wno-error" \
          > "$HACL_DIR/build.log" 2>&1 )
fi

# Gerekli semboller (vendored Hacl.h'nin tümü).
# Not: nm çıktısını önce değişkene alıyoruz — grep -q ile doğrudan pipe,
# pipefail altında nm'i SIGPIPE ile öldürür ve yanlış "sembol yok" verir.
echo "== sembol doğrulaması"
NM_OUT="$(nm -g --defined-only "$DIST/gcc-compatible/libevercrypt.a")"
for sym in \
    Hacl_Streaming_Blake2_blocks_state_len \
    Hacl_Blake2b_32_blake2b_init \
    Hacl_Blake2b_32_blake2b \
    Hacl_HMAC_compute_blake2b_32 \
    Hacl_Streaming_Blake2_blake2b_32_no_key_update \
    Hacl_Streaming_Blake2_blake2b_32_no_key_finish \
    Hacl_Chacha20Poly1305_32_aead_encrypt \
    Hacl_Chacha20Poly1305_32_aead_decrypt \
    Hacl_Curve25519_64_secret_to_public \
    Hacl_Curve25519_64_ecdh \
    Lib_RandomBuffer_System_crypto_random \
    Lib_Memzero0_memzero
do
    if ! grep -qE " T ${sym}$" <<<"$NM_OUT"; then
        echo "HATA: sembol yok: $sym" >&2
        exit 1
    fi
done
echo "   12/12 sembol mevcut"

# 5 argümanlı init imzasını teyit et (ABI'nin kalbı).
INIT_SIG="$(grep -A6 '^Hacl_Blake2b_32_blake2b_init' \
    "$DIST/gcc-compatible/Hacl_Hash_Blake2.h" | tr '\n' ' ')"
if [[ "$INIT_SIG" != *"uint64_t *wv"* ]]; then
    echo "HATA: blake2b_init 5 argümanlı değil! $INIT_SIG" >&2
    exit 1
fi
echo "   blake2b_init 5 argümanlı (doğru ABI)"

# Suite derlemesi.
echo "== libnoiseapi.a derleniyor"
K="$DIST/kremlin"
( cd "$SUITE"
  rm -f *.o *.d *.d.* libnoiseapi.a libnoiseapi.so
  make HACL_HOME="$HACL_DIR" \
       USER_CFLAGS="-Wno-error -I$K/include -I$K/kremlib/dist/minimal" \
       -j"$(nproc)" )

COUNT="$(nm -g --defined-only "$SUITE/libnoiseapi.a" | grep -c ' T Noise_XX')"
echo "== Bitti: libevercrypt.a + libnoiseapi.a ($COUNT Noise_XX_* sembolü)"
echo
echo "Bağlama sırası: libnoiseapi.a SONRA libevercrypt.a"
echo "  cc ... harness.c $SUITE/libnoiseapi.a $DIST/gcc-compatible/libevercrypt.a -lsodium"
