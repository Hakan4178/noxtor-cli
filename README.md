
<p align="center">
  <pre align="center">
  ███╗   ██╗ ██████╗ ██╗  ██╗████████╗ ██████╗ ██████╗
  ████╗  ██║██╔═══██╗╚██╗██╔╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██╔██╗ ██║██║   ██║ ╚███╔╝    ██║   ██║   ██║██████╔╝
  ██║╚██╗██║██║   ██║ ██╔██╗    ██║   ██║   ██║██╔══██╗
  ██║ ╚████║╚██████╔╝██╔╝ ██╗   ██║   ╚██████╔╝██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
  </pre>
  <b>Tor-native · P2P · Minimal metadata · No server · No compromise</b><br>
  A serverless, encrypted messaging tool for those who need it most.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/lang-C23-blue" />
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey" />
  <img src="https://img.shields.io/badge/memory-ASan%2FUBSan%20clean-brightgreen" />
  <img src="https://img.shields.io/badge/crypto-Noise%20XX%20%2B%20libsodium-blueviolet" />
  <img src="https://img.shields.io/badge/status-experimental-orange" />
  <img src="https://img.shields.io/badge/license-GPL--3.0-green" />
</p>


---


![CBMC Succesfull](Ekran%20Görüntüsü%202026-06-08%2023-39-54.png)

CBMC VERIFICATION SUCCESSFUL (only log.c)


## What is Noxtor?

Noxtor is a **Linux-exclusive, terminal-based messaging tool** built for
activists, journalists, and individuals under censorship.

It routes all traffic through **Tor**, uses the **Noise XX handshake**
(with forward secrecy) for end-to-end encryption, and requires
**no central server** not even for key exchange.

> **⚠️ Early Stage:** Core messaging works and has been tested against
> non-official Noise XX (Cacophony) test vectors. Security hardening is
> still in progress. **This project has NOT been independently audited.**

---

## Why not Signal?

| | Signal | Noxtor |
|---|---|---|
| Central server | ✅ Required (prekey server) | ❌ None |
| Metadata | Knows who talks to whom | Zero metadata by design |
| Phone number | Required | Not required |
| Censorship resistance | Limited | Tor + obfs4 + Snowflake |
| Key exchange | Server-mediated | Direct P2P (Noise XX) |
| Trust model | Trust Signal Inc. | Trust the code only |

Signal is great for most people. Noxtor is for those who **can't afford
to trust any server** not even Signal's.

---

## Quick Start

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install gcc-14 libsodium-dev libsqlite3-dev libseccomp-dev tor obfs4proxy

# Build and run
git clone https://github.com/Hakan4178/noxtor-cli
cd noxtor-cli && make clean && make release
./noxtor-cli
```

> Also works experimentally on **Termux** (Android/ARM).

---

## Architecture

```
┌──────────┐         Tor Onion Service         ┌──────────┐
│  Alice   │◄──────────────────────────────────►│   Bob    │
│ noxtor   │   Noise XX Handshake (libsodium)   │ noxtor   │
│          │   Forward Secrecy · No Prekeys     │          │
└──────────┘         No Server. Ever.           └──────────┘
```

---

## Features

- 🧅 **Tor-native P2P** — All traffic routed through Tor onion services
- 🔐 **Noise XX + libsodium** — Forward-secret E2E encryption, verified
  against Cacophony test vectors
- 🕳 **Memory hygiene** — Critical keys and data are wiped from RAM
  immediately after use
- 👻 **Ghost mode** — Disable SQLite entirely; leave zero forensic trace
- 🛡️ **Seccomp sandboxing** — Minimal syscall surface via libseccomp
- ✊️ **Censorship evasion** — obfs4 and Snowflake bridge support
- 🧪 **Fuzz-tested parsers** — All external-input parsers individually
  fuzzed for memory safety
- 📏 **C23 · ASan/UBSan · -fanalyzer** Zero errors across all
  sanitizers

---

## Security

```
🔴 THIS SOFTWARE HAS NOT BEEN AUDITED.
   Do not rely on it in life threatening situation yet.
```

Security researchers are warmly invited to review the codebase.
Please report vulnerabilities responsibly.

**What has been done:**
- Noise XX implementation passes Cacophony test vectors ✅
- 0 errors under ASan / UBSan / -fanalyzer ✅
- All parsers handling external input have been fuzz-tested ✅
- Sensitive memory is actively wiped after use ✅

**What hasn't been done yet:**
- Independent third-party audit
- TOFU (Trust On First Use) verification + QR support
- Full seccomp policy hardening
- Kernel < 5.15 fallback paths

---

## Trust Note

The terminal emulator you run Noxtor in is also part of your attack
surface. Use a trusted, open-source terminal or run Noxtor directly
in a **Linux TTY** for maximum isolation.

---

## Requirements

| Dependency | Purpose |
|---|---|
| GCC 14+ | C23 compilation |
| Linux Kernel | Native platform |
| libsodium-dev | Cryptographic primitives |
| libsqlite3-dev | Local message storage |
| libseccomp-dev | Syscall sandboxing |
| tor | Onion routing |
| obfs4proxy | Bridge / DPI evasion |
| snowflake | Censorship circumvention |

---

## Contributing

Contributions are welcome especially in these areas:

| Area | Difficulty |
|---|---|
| Parser fuzzing (expand coverage, find crashes) | 🟢 Good first issue |
| obfs4 / Snowflake integration & testing | 🟡 Help wanted |
| Threat model review | 🔴 Security expertise |

---

## License

GPL-3.0

