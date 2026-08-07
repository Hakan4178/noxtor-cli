#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# test_onion_derive.sh — Onion determinizm + canlı Tor e2e testi
#
# Kapsam (docs/onion-key-derived-plan.md §5):
#   1. Determinizm: aynı master_key → 2× aynı adres
#   2. Ayrım: farklı master_key → farklı adres
#   3. KRİTİK e2e: üretilen expanded key'i CANLI Tor'a ADD_ONION ile ver,
#      dönen ServiceID == pub'tan hesaplanan v3 adresi (3. tur düzeltme
#      kanıtı — libsodium [seed||pub] formatı Tor'da YANLIŞ adres verirdi)
#
# Kullanım: make test (otomatik) veya tests/test_onion_derive.sh
# Gereksinim: tor binary (yoksa 3. adım SKIP — 1/2 yine koşar)

set -u

TEST_BIN="$(cd "$(dirname "$0")" && pwd)/test_onion_derive"
TOR_BIN="$(command -v tor || true)"
WORKDIR="$(mktemp -d /tmp/nox_onion_e2e_XXXXXX)"
MK1="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
MK2="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

FAIL=0
trap 'pkill -f "$WORKDIR" 2>/dev/null; rm -rf "$WORKDIR"' EXIT

fail() { echo "HATA: $1"; FAIL=1; }

echo "=== test_onion_derive.sh ==="

# ---- 1. Determinizm ----
A1="$("$TEST_BIN" --emit-addr "$MK1")"
A2="$("$TEST_BIN" --emit-addr "$MK1")"
if [ "$A1" = "$A2" ] && [ -n "$A1" ]; then
    echo "  [1] determinizm: $A1 == $A2 (OK)"
else
    fail "determinizm: $A1 != $A2"
fi

# ---- 2. Farklı master_key → farklı adres ----
B="$("$TEST_BIN" --emit-addr "$MK2")"
if [ -n "$B" ] && [ "$A1" != "$B" ]; then
    echo "  [2] master_key ayrımı: $A1 != $B (OK)"
else
    fail "master_key ayrımı: $A1 == $B"
fi

# ---- 3. KRİTİK e2e: canlı Tor ADD_ONION ----
if [ -z "$TOR_BIN" ]; then
    echo "  [3] tor bulunamadı — e2e SKIP (make test için tor gerekli)"
else
    KEY="$("$TEST_BIN" --emit-key "$MK1")"
    ADDR="${A1%.onion}"   # 56 char base32 (v3 adres çekirdeği)

    # Geçici Tor instance — ControlPort: rastgele yüksek port
    # -f boş torrc: sistem /etc/tor/torrc'deki User satırını yoksay (root gerekmez)
    # CookieAuthentication 0: test ortamı (localhost, geçici), boş AUTHENTICATE yeterli
    CTRL_PORT=$((20000 + RANDOM % 20000))
    : > "$WORKDIR/torrc"
    "$TOR_BIN" -f "$WORKDIR/torrc" \
               --DataDirectory "$WORKDIR" \
               --ControlPort "$CTRL_PORT" \
               --CookieAuthentication 0 \
               --SocksPort 0 \
               --Log "notice stderr" \
               >"$WORKDIR/tor.log" 2>&1 &
    TOR_PID=$!

    # Tor hazır olana kadar bekle (kontrol bağlantısı kabul edilir hale gelmeli)
    for _ in $(seq 1 100); do
        kill -0 $TOR_PID 2>/dev/null || break
        if (echo > "/dev/tcp/127.0.0.1/$CTRL_PORT") 2>/dev/null; then
            break
        fi
        sleep 0.1
    done

    if ! kill -0 $TOR_PID 2>/dev/null; then
        fail "Tor başlatılamadı (tor.log: $(tail -1 "$WORKDIR/tor.log"))"
    else
        # Kontrol bağlantısı + ADD_ONION (boş AUTHENTICATE — CookieAuthentication 0)
        python3 - "$CTRL_PORT" "$KEY" "$ADDR" <<'PYEOF'
import socket, sys

port, key, expect = sys.argv[1], sys.argv[2], sys.argv[3]

def recv(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\r\n") and b"250" in data:
            break
        if data.count(b"250 ") > 2:
            break
        if data.endswith(b"\r\n\r\n"):
            break
    return data.decode(errors="replace")

s = socket.create_connection(("127.0.0.1", int(port)), timeout=5)
s.settimeout(5)

s.sendall(b"AUTHENTICATE\r\n")
resp = recv(s)
if "250 OK" not in resp:
    print(f"FAIL: AUTHENTICATE yanıtı: {resp!r}")
    sys.exit(1)

# ADD_ONION — üretilen expanded key ile
s.sendall(f"ADD_ONION ED25519-V3:{key} Port=80,127.0.0.1:1\r\n".encode())
resp = recv(s)

service_id = None
for line in resp.splitlines():
    if line.startswith("250-ServiceID=") or line.startswith("250 ServiceID="):
        service_id = line.split("ServiceID=")[1].strip()
    elif line.startswith("250") and "ServiceID=" in line:
        service_id = line.split("ServiceID=")[1].split()[0]

if not service_id:
    print(f"FAIL: ADD_ONION ServiceID yok: {resp!r}")
    sys.exit(1)

print(f"      ServiceID: {service_id}")
print(f"      Beklenen : {expect}")
if service_id == expect:
    print("      EŞLEŞME: expanded key Tor'da doğru adresi üretti")
    sys.exit(0)
else:
    print("      UYUŞMAZ: expanded key yanlış adres üretti!")
    sys.exit(1)
PYEOF
        if [ $? -eq 0 ]; then
            echo "  [3] e2e ADD_ONION ServiceID eşleşmesi: A1 ($A1) (OK)"
        else
            fail "e2e ADD_ONION ServiceID eşleşmedi"
        fi
        kill $TOR_PID 2>/dev/null
    fi
fi

if [ $FAIL -eq 0 ]; then
    echo "=== test_onion_derive.sh: BAŞARILI ==="
    exit 0
fi
echo "=== test_onion_derive.sh: BAŞARISIZ ==="
exit 1
