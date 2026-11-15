#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# test_tor_detach.sh — F2 canlı Tor control-spec testi
#
# Kapsam (docs-priv/denetimler/f2-tor-control-fd-arastirmasi-2026-11-15.md):
#   T1: ADD_ONION ... Flags=Detach → control kapat → servis yaşıyor,
#       yeni bağlantıda GETINFO onions/detached içinde, DEL_ONION ile silinir.
#   T2: Flags=Detach KeyBlob'dan önce → Tor 512 ile reddeder.
#   T3: TAKEOWNERSHIP + kapat → Tor kapanır;
#       TAKEOWNERSHIP + DROPOWNERSHIP + kapat → Tor yaşar.
#   T4 (NOX_TEST_TOR_OWNING=1): __OwningControllerProcess + control kapat
#       → Tor yaşar; owner PID ölümü → Tor ~15 sn içinde kapanır.
#
# Ürün ADD_ONION komut biçimi tests/test_network.c'deki sahte Tor
# sunucusunda ayrıca kilitlenir. Bu betik Tor semantiğini doğrular.
#
# Kullanım: tests/test_tor_detach.sh
#           NOX_TEST_TOR_OWNING=1 tests/test_tor_detach.sh
# Gereksinim: tor binary (yoksa SKIP — çıkış 0)

set -u

TOR_BIN="$(command -v tor || true)"
WORKDIR="$(mktemp -d /tmp/nox_tor_detach_XXXXXX)"
FAIL=0

cleanup() {
    # Tor cmdline'i -f "$WORKDIR/.../torrc" içerir; kendi shell'imizi eşleştirme.
    pkill -f "$WORKDIR/.*/torrc" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "=== test_tor_detach.sh ==="

if [ -z "$TOR_BIN" ]; then
    echo "  SKIP: tor bulunamadı (canlı control-spec testi atlandı)"
    exit 0
fi

echo "  tor: $TOR_BIN ($("$TOR_BIN" --version | head -1))"

python3 - "$WORKDIR" "$TOR_BIN" <<'PYEOF'
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = sys.argv[1]
TOR = sys.argv[2]
OWING = os.environ.get("NOX_TEST_TOR_OWNING") == "1"
FAILS = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)


def read_resp(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("control EOF")
        data += chunk
        lines = data.split(b"\r\n")
        for line in lines[:-1]:
            if len(line) >= 4 and line[:3].isdigit() and line[3:4] == b" ":
                return data.decode("utf-8", "replace")
        if len(data) > 65536:
            raise RuntimeError("control yanıtı çok büyük")


class TorLab:
    def __init__(self, name, extra=()):
        self.dir = os.path.join(ROOT, name)
        os.makedirs(self.dir, mode=0o700)
        self.sock = os.path.join(self.dir, "control.sock")
        self.cookie = os.path.join(self.dir, "control_auth_cookie")
        self.torrc = os.path.join(self.dir, "torrc")
        lines = [
            f"DataDirectory {self.dir}",
            f"ControlSocket {self.sock}",
            "CookieAuthentication 1",
            "SocksPort 0",
            "Log notice file /dev/null",
        ]
        lines.extend(extra)
        with open(self.torrc, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(
            [TOR, "-f", self.torrc],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            # Control soketi cookie'den önce görülebilir; auth için ikisi de gerekli.
            if os.path.exists(self.sock) and os.path.exists(self.cookie):
                return
            if self.proc.poll() is not None:
                err = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(
                    f"Tor erken çıktı rc={self.proc.returncode}: {err[-400:]}"
                )
            time.sleep(0.05)
        raise RuntimeError("Tor control socket/cookie hazır olmadı")

    def auth(self):
        with open(self.cookie, "rb") as f:
            cookie_hex = f.read().hex()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(self.sock)
        s.sendall(f"AUTHENTICATE {cookie_hex}\r\n".encode())
        resp = read_resp(s)
        if not resp.startswith("250"):
            s.close()
            raise RuntimeError(f"AUTHENTICATE başarısız: {resp!r}")
        return s

    def cmd(self, sock, line):
        sock.sendall((line + "\r\n").encode())
        return read_resp(sock)

    def wait_exit(self, seconds):
        deadline = time.time() + seconds
        while time.time() < deadline:
            rc = self.proc.poll()
            if rc is not None:
                return rc
            time.sleep(0.05)
        return None

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.proc = None


def service_id(resp):
    for line in resp.splitlines():
        if line.startswith("250-ServiceID="):
            return line.split("=", 1)[1]
    return None


def t1_detach_persistence():
    lab = TorLab("t1")
    try:
        lab.start()
        s = lab.auth()
        resp = lab.cmd(
            s, "ADD_ONION NEW:ED25519-V3 Flags=Detach Port=80,127.0.0.1:1"
        )
        sid = service_id(resp)
        check("T1 ADD_ONION Flags=Detach kabul", "250 OK" in resp and sid is not None)
        if sid is None:
            return
        s.close()
        time.sleep(0.5)
        check("T1 control kapatınca Tor yaşıyor", lab.proc.poll() is None)

        s2 = lab.auth()
        detached = lab.cmd(s2, "GETINFO onions/detached")
        check("T1 detached servis listede", sid in detached, sid)
        resp = lab.cmd(s2, f"DEL_ONION {sid}")
        check("T1 DEL_ONION kabul", resp.startswith("250"))
        after = lab.cmd(s2, "GETINFO onions/detached")
        check("T1 detached liste boş", "onions/detached=" in after and sid not in after)
        s2.close()
    finally:
        lab.stop()


def t2_flag_order():
    lab = TorLab("t2")
    try:
        lab.start()
        s = lab.auth()
        # Yanlış sıra: Flags KeyBlob'dan önce.
        resp = lab.cmd(
            s, "ADD_ONION Flags=Detach NEW:ED25519-V3 Port=80,127.0.0.1:1"
        )
        check("T2 yanlış sıra 512 ile reddedildi", resp.startswith("512"), resp.splitlines()[0])
        s.close()
    finally:
        lab.stop()


def t3_ownership():
    lab = TorLab("t3-take")
    try:
        lab.start()
        s = lab.auth()
        resp = lab.cmd(s, "TAKEOWNERSHIP")
        check("T3 TAKEOWNERSHIP kabul", resp.startswith("250"))
        s.close()
        rc = lab.wait_exit(10)
        check("T3 TAKEOWNERSHIP + kapat → Tor kapandı", rc == 0, f"rc={rc}")
    finally:
        lab.stop()

    lab = TorLab("t3-drop")
    try:
        lab.start()
        s = lab.auth()
        resp = lab.cmd(s, "TAKEOWNERSHIP")
        if not resp.startswith("250"):
            check("T3 DROPOWNERSHIP senaryosu", False, "TAKEOWNERSHIP reddedildi")
            return
        resp = lab.cmd(s, "DROPOWNERSHIP")
        check("T3 DROPOWNERSHIP kabul", resp.startswith("250"))
        s.close()
        time.sleep(0.5)
        check("T3 TAKEOWNERSHIP + DROPOWNERSHIP + kapat → Tor yaşıyor",
              lab.proc.poll() is None)
    finally:
        lab.stop()


def t4_owning_controller_process():
    owner = subprocess.Popen(["sleep", "60"])
    lab = TorLab("t4", extra=[f"__OwningControllerProcess {owner.pid}"])
    try:
        lab.start()
        check("T4 owning PID ile Tor başladı", lab.proc.poll() is None)
        s = lab.auth()
        s.close()
        time.sleep(0.5)
        check("T4 control kapatınca Tor yaşıyor", lab.proc.poll() is None)

        owner.send_signal(signal.SIGKILL)
        owner.wait(timeout=5)
        rc = lab.wait_exit(25)
        check("T4 owner ölünce Tor ~15 sn içinde kapandı", rc == 0, f"rc={rc}")
    finally:
        lab.stop()
        if owner.poll() is None:
            owner.kill()
            owner.wait(timeout=5)


try:
    t1_detach_persistence()
    t2_flag_order()
    t3_ownership()
    if OWING:
        t4_owning_controller_process()
    else:
        print("  [SKIP] T4 owning PID (NOX_TEST_TOR_OWNING=1 ile koşar)")
except Exception as exc:
    check("beklenmeyen hata", False, repr(exc))

if FAILS:
    print(f"  SONUÇ: {len(FAILS)} başarısız: {', '.join(FAILS)}")
    sys.exit(1)
print("  SONUÇ: tüm kontroller PASS")
PYEOF
PY_RC=$?

if [ $PY_RC -ne 0 ]; then
    FAIL=1
fi

if [ $FAIL -eq 0 ]; then
    echo "=== test_tor_detach.sh: BAŞARILI ==="
    exit 0
fi
echo "=== test_tor_detach.sh: BAŞARISIZ ==="
exit 1
