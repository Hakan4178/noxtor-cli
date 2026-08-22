# Noxtor-CLI Threat Model

Mimari genel bakış `docs/architecture.md` içindedir.


> **Status: DRAFT — incremental review.** Built from source review of
> `tui.c`, `ui.c`, `network.c`, `event_loop.c`, `database.c`, `noise.c`,
> `state_machine.c` + architecture docs. Sections marked `[TODO: verify against
> source]` need confirmation against the remaining files; stub sections (§2.1,
> §3.1, §4.7, §7.1) are intentionally draft placeholders for a complete
> P2P threat model and require maintainer review before being considered
> authoritative. Last sync: `architecture.md` refreshed to match current
> codebase line counts and onion-key derivation (deterministic seed → Tor
> `ADD_ONION`) — this file's stale finding §4.2.1 is now marked RESOLVED
> accordingly.

## 1. Purpose & Scope

This document describes what Noxtor protects against, who it protects against,
and — just as importantly — who and what it does **not** protect against. It
is written for three audiences: people deciding whether Noxtor fits their
personal risk model, security researchers deciding where to spend review time,
and funders/auditors evaluating the project.

Noxtor is a Linux-native, terminal-based P2P messenger. It routes all traffic
over Tor, uses Noise XX (via libsodium) for end-to-end encryption with forward
secrecy, and has no central server or key-exchange authority of any kind.

## 1.1 Assumptions (DRAFT STUB — maintainer review required)

This section lists the premises the rest of the model depends on.
If an assumption is false, the corresponding mitigation claim is void.

| # | Assumption | If violated |
|---|---|---|
| A1 | **PIN entropy is user-responsible.** `crypto.c:180` derives `master_key` via Argon2id (`OPSLIMIT_MODERATE`/`MEMLIMIT_MODERATE`, 16-byte salt) — this slows brute-force but does **not** make a weak PIN strong. A 6-digit PIN (~20 bits) is crackable offline if `contacts.db` + salt file are seized; a 4-word diceware passphrase (~50 bits) or 12+ char mixed passphrase is the intended baseline. Weak PIN is a **user-risk, not a code bug** — document it as such and guide users accordingly (see guidance stub below). `[TODO: maintainer — confirm minimum PIN policy / warning UX on weak PIN]` | Seized DB decryptable offline; onion identity derivable (same `master_key` → `NOX_SUBKEY_ONION_SEED`). |
| A2 | **libsodium, libsqlite3, libseccomp, Tor behave as documented.** No formal verification of these dependencies; supply-chain compromise is out-of-model except as noted in §4.5. | All crypto/DB/sandbox claims collapse. |
| A3 | **Kernel ≥5.15 enforces seccomp-bpf + Landlock as implemented in `seccomp.c`/`landlock_sandbox.c`.** Older kernels fall back to degraded/no sandbox (§5.4). | Post-exploit blast radius larger (§10 in `architecture.md`). |
| A4 | **Tor provides anonymity; Noxtor adds no extra padding/cover traffic.** Message size/timing at Noxtor layer is visible to the guard as Tor cell volume/timing (§4.4). | Metadata minimization (§2) is aspirational until padding is added. |
| A5 | **Device is clean at launch.** No pre-existing implant reading `argv`/env/PIN keystrokes, and `main.c:141` early-constructor hardening (`PR_SET_DUMPABLE`, `RLIMIT_CORE`, seccomp stage 1) runs before attacker-controlled code in the same process. A tiny `execve → constructor` window remains — treated as residual, not in-scope. `[TODO: verify constructor ordering vs. `LD_PRELOAD` / early ptrace]` | PIN/keystroke exfiltration before hardening. |
| A6 | **Secure arena (`arena.c`) is mlock'd / `MADV_DONTDUMP` where available, and `sodium_memzero` + `strub` scrub keys on failure paths.** Swap-out and core-dump leakage are mitigated, not proven absent on all kernels. | Forensic RAM/swap recovery (see §4.3). |

**PIN / passphrase guidance (stub — to be moved to README/docs):**
- Minimum 8 bytes enforced by code is a floor, not a recommendation.
- Recommended: ≥12 chars mixed, or ≥4 diceware words, or 6+ words for high-risk users.
- Argon2id buys time (memory-hard), not miracles: `2^30` guesses against `OPSLIMIT_MODERATE` is still cheap for a 20-bit PIN; `2^50` is not.
- `[TODO: maintainer — decide whether to add a weak-PIN warning in `main.c` PIN prompt, e.g. zxcvbn-style check, or keep guidance docs-only]`

## 2. Assets (What We're Protecting)

| Asset | Description |
|---|---|
| Message confidentiality | Contents of messages/files in transit and, unless Ghost Mode is on, at rest |
| Message integrity | Detecting tampering or injection by a network-level attacker |
| Metadata minimization | Who is talking to whom, when, and how often |
| Forward secrecy | Past sessions stay safe if a long-term key is later compromised |
| Sender/peer authentication | Confidence you're talking to the peer you think you are (post-TOFU) |
| Availability under censorship | Ability to connect at all when Tor is blocked/throttled |
| Local plausible deniability | Ghost Mode: no data written to disk at all, vs. the encrypted-at-rest baseline that applies even with Ghost Mode off (confirmed in `database.c`, §4.3) |

## 3. Actors & Trust Boundaries

- **User's own device** — trusted, *except* for the terminal emulator (see
  §5.3) and anything below the OS (see §5.1).
- **The peer's device** — trusted for message content, **not** trusted to
  behave honestly at the protocol level (a peer can send malformed input,
  oversized frames, adversarial strings, etc.).
- **The network path** (ISP, national censor, Tor relays) — fully untrusted.
- **Noxtor's own dependencies** (libsodium, libsqlite3, libseccomp, Tor,
  obfs4proxy, Snowflake) — trusted-but-verify; see supply-chain in §4.5.

### 3.1 Attack Surface / Entry Points (DRAFT STUB — verify parser → handler routing)

Every row is an input boundary an adversary can influence. "Who controls it" is the
adversary who can craft it; "Worst case if parser fails" is what the TM must
assume.

| # | Entry point | Parser / handler | Who controls it | Worst case if unhandled |
|---|---|---|---|---|
| E1 | **Wire frame header** (13B: `0xDEADC0DE` + type + seq + len) | `network.c:1724` `frame_header_decode` → `event_loop.c:55` `process_peer_frames` | Malicious peer (remote) | OOB, buffer over-read, state-machine bypass |
| E2 | **Wire payload** (TEXT/FILE/CTRL/ACK, ≤4096+16) | `event_loop.c:355` seq check + `noise.c:892/899` decrypt | Malicious peer | Decrypt oracle, silent tamper (see §4.2.6), heap disclosure |
| E3 | **Noise handshake blobs** (XX `e`/`ee`/`es`/`se` + `s` + payload) | `noise.c:653`/`809` `handshake_write/read` + `symmetric_*` | Malicious peer (pre-auth) | Key-compromise, prologue bypass, DoS via `hs` exhaustion |
| E4 | **SOCKS5 reply** (Tor → Noxtor) | `network.c:1500` `socks5_connect` | Local Tor / network MitM on loopback | Peer impersonation, connection hijack |
| E5 | **Tor control channel** (`ADD_ONION` ServiceID, PrivateKey, cookie) | `network.c` `parse_service_id` / `validate_onion_address` / `ctrl_read_response` | Compromised Tor / control-socket injector (S3, §4.6) | Identity hijack, peer-handshake confusion |
| E6 | **File METADATA + chunks** (filename, size, BLAKE2b hash, DATA frames) | `file_transfer.c:104/510` `file_transfer_start/handle_rx` + `sanitize_filename` `file_transfer.c:29` | Verified peer (post-TOFU) — **untrusted content** | Path traversal, symlink TOCTOU, disk exhaustion, malicious content (user-executed — see §4.7) |
| E7 | **Downloaded file bytes** (written to `downloads/` via `openat(O_EXCL|O_NOFOLLOW)`) | `file_transfer.c:460` `open_recv_file` → `file_transfer.c:443` | Verified peer | User opens malware (Landlock limits write scope, not execution — user responsibility, §4.7) |
| E8 | **CLI args / env / config dir** | `main.c:1408` arg parsing + `crypto.c:349` salt load | Local user / co-tenant | Config injection, salt downgrade |
| E9 | **TTY / stdin input** (commands `/connect` `/msg` etc., TOFU `y/n`) | `stdin_handler.c:875` `process_stdin_events` → `stdin_handler.c:383` `process_line` + linenoise `src/linenoise.c:2347` | Local user + terminal emulator (§5.3) | Command injection, TOFU slot-recycling (see §7) |
| E10 | **SQLite rows** (contacts, history, queue — at-rest ciphertext) | `database.c` `crypto_secretbox_*` decrypt on load | Forensic examiner with DB file (±PIN) | Offline brute-force if PIN weak (A1); WAL/SSD remnants (§4.3.4) |

`[TODO: maintainer — confirm routing for E4/E5 (does any peer input ever reach control-channel parsers or vice versa?); confirm E6 max filename / size enforcement limits; confirm E9 TOFU binding is per-session not per-slot]`

## 4. Adversary Models (In Scope)

### 4.1 Network-level censor / ISP / national firewall
- **Goal:** block Noxtor traffic, or detect that it's in use.
- **Mitigation:** all traffic routed through Tor; obfs4 and Snowflake bridge
  support for DPI evasion when Tor itself is blocked.
- **Known gap:** `[TODO: verify]` — does bridge selection/rotation logic
  itself leak anything (timing, retry patterns) that a censor could
  fingerprint as "this is Noxtor" rather than generic Tor?

### 4.2 Malicious or compromised peer
- **Goal:** crash the client, corrupt local state, leak adjacent memory, or
  manipulate what's shown in the UI via malformed protocol input or crafted
  message content.
- **Mitigation:** fuzz-tested parsers for all external input; sandboxed
  process via seccomp so a parser bug can't easily escalate to code
  execution with network/filesystem access; ANSI escape stripping on
  peer-controlled message content before it reaches the terminal
  (`strip_ansi_escape` in `ui.c`).
- **Known gaps (ordered by severity):**

  1. **[RESOLVED — was HIGH, fixed in `13cbc75` / `src/ui.c:353`] Out-of-bounds read in `strip_ansi_escape` (`ui.c`).** Original finding: the fallback branch for "unrecognized 2-byte escape sequence" advanced by 2 (`src += 2`) without checking `src[1]` for NUL — a trailing `0x1b` caused OOB read/disclosure or crash. Current code (`src/ui.c:353-356`) now checks `if (src[1] != '\0') src+=2 else src++` (bare ESC → advance by 1). Verified against source; no longer exploitable. Kept for audit history; `strip_ansi_escape` remains only on the plain-terminal path — see #2 for the remaining TUI gap.

  2. **[MEDIUM] Sanitization asymmetry between TUI and non-TUI output
     paths.** `strip_ansi_escape` is applied in the plain-terminal
     (`atomic_message`) path but *not* on the `tui_is_active()` branch of
     `ui_print_incoming`/`ui_print_outgoing`/`ui_print_system`/
     `ui_print_error` — raw peer content goes straight into the termbox2
     chat buffer. This is currently believed to be safe only because
     termbox2 renders cell-by-cell rather than passing raw bytes to the
     terminal, which is an assumption about the rendering library's
     internals rather than a property Noxtor enforces itself. Any future
     non-termbox rendering path (plain fallback, alternate frontend) would
     silently inherit this gap. **Fix direction:** sanitize once, before the
     TUI/non-TUI branch, rather than relying on the renderer.

  3. **[LOW] Display-structure inference from rendered content.** The TUI's
     chat-rendering layer (`tui.c`) infers structure (sender prefix, color
     role) by pattern-matching on the *fully rendered* string — e.g.
     scanning for the last `"] "` or substrings like `"[!]"`. A peer who
     controls message content can influence this parsing and cause local
     misrendering (wrong color, broken word-wrap). Not a bounds violation,
     but the same class of problem as #2: untrusted content is used to
     infer trusted structure instead of structure being passed explicitly
     by the caller.

  4. **[LOW / partially verified] Format-string safety of caller sites.**
     `ui_print_error`/`ui_print_system` take a `fmt` + varargs and pass
     straight to `vsnprintf`. Checked in `event_loop.c`: every call site
     there uses a literal format string with proper `%s` placeholders for
     peer-derived data (onion address, contact name, fingerprint) — no
     tainted data reaches the `fmt` parameter itself in this file.
     `[TODO: verify main.c, stdin_handler.c, and remaining callers]` before
     closing this out project-wide.

  5. **[LOW, corrected after reviewing `event_loop.c`] `read_full`'s missing
     cumulative deadline does *not* apply to the peer-message path.**
     Originally flagged as likely single-thread DoS material, since
     `read_full` (`network.c`) re-arms a fresh 10s `poll()` window on every
     `EAGAIN` instead of using an absolute deadline like `ctrl_read_line`
     does. Having now seen `event_loop.c`: incoming peer frame data is read
     via `recv(fd, ..., MSG_DONTWAIT)` driven directly by `epoll_wait`, not
     via `read_full` — so a slow-trickling peer cannot stall the event
     loop through this path. `read_full`'s blocking behavior is confined to
     `socks5_connect`'s handshake reads (talking to the local Tor process,
     not a remote peer directly) and the various Tor control-protocol
     helpers, both lower-exposure than originally assumed. Downgraded from
     MEDIUM–HIGH to LOW; still worth the same fix for defense-in-depth
     consistency with `ctrl_read_line`, but it is not the peer-facing DoS
     vector it looked like in isolation.

  6. **[HIGH] Failed message decryption is silently swallowed —
     breaks tamper-detection for `NOX_MSG_TEXT` frames (`event_loop.c`,
     `process_peer_frames`).** When a `NOX_MSG_TEXT` frame's sequence
     number matches and decryption is attempted:
     ```c
     ssize_t pt_len = noise_decrypt(ps->session, payload, fh.len, pt);
     if (pt_len > 0 && (size_t)pt_len <= max_pt) {
         ... /* only path that logs/displays/advances rx_seq */
     }
     sodium_free(pt);
     ```
     If `noise_decrypt` fails (bad MAC — corrupted or actively tampered
     ciphertext), there is **no `else` branch**: no log line, no
     `ui_print_error`, no `sm_dispatch`, no session teardown, and — because
     `rx_seq` isn't touched — no visible side effect at all. Compare this
     to the sibling failure mode one branch up, `EV_SEQ_MISMATCH`, which is
     logged via `NOX_WARN`, surfaced to the user with an explicit
     "Replay Attack veya paket kaybı" warning, and dispatched to the state
     machine. A garbled or actively-injected ciphertext frame is a strictly
     more serious event than a sequence gap, yet it produces strictly less
     signal. This directly weakens the "message integrity: detecting
     tampering" asset listed in §2 — an on-path or malicious-relay actor
     probing the channel with forged ciphertext at the correct sequence
     number leaves no trace for the user or logs to notice. **Fix:** add an
     explicit failure branch — at minimum a `NOX_WARN`/log entry, ideally
     the same user-visible treatment as `EV_SEQ_MISMATCH`, and consider
     whether repeated MAC failures on one session should trigger
     disconnection. `[TODO: check whether `file_transfer_handle_rx` has the
     same silent-failure shape for `NOX_MSG_FILE`.]`

  7. **[MEDIUM] `recv_buf`-full disconnect check tests the wrong
     condition — spurious, peer-triggerable disconnects
     (`event_loop.c`).**
     ```c
     if (to_read == 0) {
       /* Buffer dolu — önce tamamlanmış frame'leri processing et */
       process_peer_frames(ps, state, fd);
       /* Hâlâ doluysa peer tıkanmış (DoS veya kapanma) — disconnect */
       if (ps->fd >= 0) {
         ...
         sm_dispatch(ps, state, EV_PEER_DISCONNECTED);
       }
       continue;
     }
     ```
     The comment says "if **still** full, disconnect," but the code never
     re-checks remaining buffer space after `process_peer_frames` runs —
     it disconnects whenever `ps->fd >= 0`, which is true whether or not
     processing freed the buffer. `to_read == 0` fires whenever
     `recv_pos` exactly equals `sizeof(recv_buf)`, which happens during
     entirely legitimate traffic (e.g. several complete frames arriving
     back-to-back that exactly fill the buffer before the next
     `epoll_wait`). Since frame sizes are attacker-influenced (subject only
     to the `4096 + NOX_MAC_LEN` cap checked earlier), a peer can craft
     frame sizes that reliably land the buffer exactly full and get
     itself — or, more relevantly, get a legitimate connection pattern —
     disconnected even though `process_peer_frames` successfully drained
     everything. **Fix:** recompute remaining space after
     `process_peer_frames` (e.g. `if (ps->recv_pos == sizeof(ps->recv_buf))`)
     before deciding to disconnect.

  8. **[LOW–MEDIUM] Handshake rate limiting is global, not per-peer
     (`event_loop.c`).** The 5-attempts-per-60-seconds throttle
     (`state->hs_attempt_count` / `hs_window_start`) is a single shared
     counter for *all* inbound connections, not scoped per source
     identity. Anyone who knows (or guesses) your `.onion` address can
     open 5 rapid connections and lock out legitimate incoming handshakes
     from every other contact for the remainder of the rolling window,
     repeatably. Onion addresses are meant to be shared with contacts, so
     this isn't a purely theoretical exposure. Lower severity than #6/#7
     since it only affects availability of new incoming connections, not
     confidentiality/integrity of existing ones.

  9. **[Informational — independently verified, positive finding]
     `noise.c`'s Noise_XX DH token sequence was traced line-by-line
     against the spec and is correct.** For each of the three handshake
     messages, on both initiator and responder sides: `ee` = DH(own
     ephemeral, remote ephemeral) on both sides; `es` = DH(e, rs) on the
     initiator / DH(s, re) on the responder; `se` = DH(s, re) on the
     initiator / DH(e, rs) on the responder — all four combinations
     checked out consistent with the spec and with each other via X25519
     commutativity. `EncryptAndHash`/`DecryptAndHash` ordering (encrypt
     with old `h`, *then* `MixHash(ciphertext)`; on decrypt failure, abort
     without advancing `h`) also matches spec exactly, including the
     defensive extra of zeroing `h` on a failed decrypt (stricter than the
     spec requires, not weaker). This is beyond what "tested against
     Cacophony vectors" alone establishes — it's an independent trace of
     the actual DH/KDF wiring, not just black-box vector matching — and
     materially increases confidence in the handshake's correctness.

  10. **[LOW] Two minor findings alongside the above:**
      - **Hardcoded, non-negotiating prologue.** `handshake_init` mixes a
        fixed literal string ("Mustafa Kemal Atatürk") into the handshake
        hash as the Noise prologue, identical for every connection between
        every pair of peers. This is cryptographically harmless — a public
        constant `MixHash`ed the same way by both sides has the same
        effect as extending `NOISE_PROTOCOL_NAME` — but a fixed prologue
        provides none of the protocol-version/downgrade-binding value that
        prologues are typically used for, and an external auditor will
        reasonably ask why an unexplained literal string is hardcoded into
        the crypto init path. **Recommendation:** either drop it (empty
        prologue) or replace it with something that actually does
        version-binding work (e.g. a protocol-version byte), and comment
        the rationale either way so it doesn't need re-explaining per
        audit.
      - **Asymmetric bounds-checking between write and read paths.** The
        `read_msgN` functions all validate both input length (`msg_len`)
        and output capacity (`out_cap`) before touching buffers. The
        `write_msgN` functions perform **no** capacity check on the `out`
        buffer at all — they trust the caller to have sized it correctly.
        Currently safe in practice because handshake payloads on the write
        side are fixed-size (the local onion address, not attacker-
        controlled), but it's an inconsistent API contract relative to the
        project's stated "trust nothing" posture, and would become a real
        overflow risk if a future change let write-side payload length
        vary based on untrusted input.

### 4.3 Device seizure & forensic examination
- **Goal:** recover message history, contacts, or key material from a seized
  device.
- **Mitigation:** **Confirmed via `database.c`:** contacts, message history,
  and the offline-delivery queue are not just gated by Ghost Mode — every
  row is stored as `nonce + XSalsa20-Poly1305 ciphertext`
  (`crypto_secretbox_easy`/`_open_easy`) under `db_key`, which per
  `event_loop.c` is itself re-derived from a user PIN on each run and lives
  only in the secure arena, never written to disk in the clear. So a seized
  `contacts.db` is useless without the PIN even when Ghost Mode is **off**
  — Ghost Mode's actual distinguishing effect is *not persisting history at
  all*, not "the only thing standing between a seizure and your messages."
  This is a meaningfully stronger baseline than the original stub assumed.
  Additionally, `db_init` sets `PRAGMA secure_delete=ON`, so SQLite
  overwrites deleted rows' storage rather than merely unlinking them (used
  by `db_delete_conversation`, `db_queue_delete`) — real defense-in-depth
  on top of the encryption.
- **Known gaps:**

  1. `[TODO: verify]` — exact scope of "wiped after use": does this cover
     the Noise XX static/ephemeral keys, the SQLite page cache when Ghost
     Mode is *off*, and any swap-out risk (is memory mlock'd against
     swap)? Does Ghost Mode also suppress shell history / process-list
     evidence (argv, environment) or only the DB layer?

  2. **Cleanup only happens on graceful shutdown.** `rm_rf(tor_data_dir)`
     and the torrc unlink both run inside `tor_shutdown()`, which is only
     reached on a clean exit path. On `SIGKILL`, an unhandled crash, or a
     power-loss/seizure scenario, the per-instance directory — including
     Tor's own `tor.log` (`Log notice file %s/tor.log`, timestamped) —
     survives on disk. `cleanup_stale_tor_dirs` will eventually remove it
     on a *future* run, but only once the owning PID is confirmed dead and
     not a live `tor` process, and only if the app is launched again. This
     is a real forensic-recovery window: a seized device from an
     ungracefully-terminated session can yield a timestamped log of when a
     hidden service was running.

   3. **[RESOLVED — onion-key derivation, `src/crypto.c:277` + `src/network.c:1301`] Persistent hidden-service identity is no longer a plaintext `onion.key` file.** Current design deterministically derives the onion seed from `master_key` (`crypto_derive_onion_seed`, `NOX_SUBKEY_ONION_SEED=4`) and expands it via `derive_tor_expanded_key` to the Tor `ADD_ONION ED25519-V3:<b64>` KeyBlob sent over the control port. No private key is persisted to disk at rest; a seized device without the PIN yields no onion identity. See `docs/onion-key-derived-plan.md` and `docs/architecture.md` §6.1. Remaining forensic question for this section is only the ephemeral per-run Tor working directory (`tor.log` gap, #2 above) — not a long-term identity file.

  4. **[LOW–MEDIUM] `secure_delete=ON` doesn't cover everything the name
     implies.** Two caveats worth documenting explicitly rather than
     letting the pragma name imply more than it delivers: (a) `db_init`
     also sets `PRAGMA journal_mode=WAL` — WAL mode keeps a separate
     write-ahead log containing historical page versions until a
     checkpoint runs, so a device seized between writes and a checkpoint
     could still yield a WAL file yielding "deleted" ciphertext (still
     encrypted, but existence/size/timing metadata about deleted
     conversations leaks even if content doesn't); (b) SQLite's
     secure-delete overwrite is a logical write from the app's
     perspective — on SSD/flash media, the FTL typically remaps writes
     copy-on-write, so the physically overwritten page may still exist,
     recoverable, on the underlying flash until garbage-collected. Neither
     caveat defeats the *encryption* (both remnants are still ciphertext
     under `db_key`), but both matter for anyone relying on "secure_delete"
     as a plaintext-shredding guarantee rather than what it actually is:
     defense-in-depth on top of encryption.

  5. **[LOW] Destructive handling of any queue-decrypt failure, not just
     tampering, in `db_process_queue`.** When a queued outgoing message
     fails to decrypt (bad MAC), the code path is identical whether the
     cause is an actively corrupted/tampered record *or* some transient
     issue on the reading side — the record is unconditionally and
     permanently deleted (`db_queue_delete`) after one `NOX_WARN`. Given
     `db_key` is fixed for the process lifetime this is unlikely to
     misfire in practice, but the pattern itself doesn't distinguish
     "safe to discard, this is attacker/corruption noise" from "something
     is wrong on our end and this message is now unrecoverably gone."

### 4.4 Tor-level traffic analysis
- **Goal:** de-anonymize a user via guard discovery, traffic correlation, or
  predecessor attacks — this is a known, unsolved-in-general Tor limitation,
  not something Noxtor can fully close on its own.
- **Mitigation:** inherits standard Tor onion-service protections; obfs4/
  Snowflake reduce some traffic-fingerprinting surface at the bridge layer.
- **Known gap:** no application-level padding or cover traffic; message
  timing/size at the Noxtor layer is not obfuscated beyond what Tor itself
  provides. `[TODO: confirm]` whether Vanguards-equivalent guard-discovery
  mitigations are planned/present.

### 4.5 Supply-chain compromise
- **Goal:** compromise Noxtor via a malicious dependency or build artifact
  (e.g. an xz-utils-style backdoor).
- **Mitigation:** source-only distribution, dependency pinning, GPG-signed
  releases (planned/partial — see Known Gaps in README: no releases are
  currently published).
- **Known gap:** no reproducible-build attestation yet; no SBOM.

### 4.6 Compromised or malicious local Tor process / control channel
- **Goal:** a compromised Tor binary, or something injecting into the local
  control socket, feeds Noxtor malformed or malicious control-protocol
  responses to corrupt state or leak data into the peer-facing protocol.
  This adversary is explicitly named in the source itself — `network.c`
  labels it `S3` in a comment ("S3 (threat-model): Tor'dan gelen ServiceID'yi
  validate et... compromised tor binary, control socket manipülasyonu...").
  Formalizing it here so it isn't only documented ad hoc in one comment.
- **Mitigation:** `parse_service_id` strictly validates the ServiceID
  returned by `ADD_ONION` (exact 56-char base32 shape, revalidated through
  `validate_onion_address`) before it's allowed anywhere near the
  peer-handshake path; the Tor cookie file's size is checked (`fstat` must
  read exactly 32 bytes) before being trusted as an auth secret;
  `ctrl_read_response` caps response length and line count
  (`MAX_RESPONSE_LINES = 64`) against a runaway/malicious control channel.
- **Known gap:** **[LOW–MEDIUM, hedged by `__attribute__((strub))`]**
  Private-key material read from the control channel
  (`tor_create_new_hs`'s `resp` buffer, containing `PrivateKey=ED25519-V3:...`)
  is only explicitly `explicit_bzero`'d on the full-success return path; the
  six earlier error-return paths (bad response, missing ServiceID, missing
  PrivateKey field, wrong length, etc.) return without scrubbing `resp`.
  The sibling function `tor_create_persistent_hs` does this correctly —
  it scrubs `cmd` (which holds the key being *sent*) immediately after
  the send, before any error check. Both functions carry
  `__attribute__((strub))`, which should cause the compiler to scrub the
  entire stack frame on every return path regardless of manual `bzero`
  calls — if that holds, this gap is already closed at the compiler level.
  `[TODO: verify with objdump/disassembly]` that `strub` actually emits
  scrubbing code on all six early-return paths, since relying on it without
  verifying contradicts the project's own "trust nothing, minimize
  everything" / defense-in-depth stance. If unverified, add the missing
  manual `explicit_bzero(resp, sizeof(resp))` on all paths for symmetry
  with `tor_create_persistent_hs`.

### 4.7 Post-TOFU malicious contact / file safety (DRAFT STUB)

- **Goal:** a *verified* contact (TOFU already accepted) abuses the trust
  relationship — sends spam, social-engineers a key-change prompt, or sends a
  malicious file that the recipient later opens. In a P2P messenger **file
  content is the most dangerous post-auth input** — the channel is encrypted
  and integrity-checked (BLAKE2b in `file_transfer.c:510`), but integrity
  ≠ safety.
- **Mitigation (existing):**
  - Transport integrity: every file chunk is inside the Noise session and
    BLAKE2b-verified end-to-end; truncated/corrupted transfers are discarded.
  - Filesystem containment: `file_transfer.c:460` `open_recv_file` uses
    `openat(O_EXCL|O_NOFOLLOW)` via `downloads_dir_fd` — no path traversal
    (`sanitize_filename` `file_transfer.c:29`), no symlink following, no
    overwrite, no TOCTOU via `verify_downloads_dir_fd` `file_transfer.c:83`.
    Landlock (`landlock_sandbox.c`) further restricts *where* Noxtor can
    write — downloads directory only.
- **What is NOT mitigated (by design — user responsibility):**
  - **File content execution is out of Noxtor's hands.** Noxtor never
    auto-executes a download; it only writes bytes. Whether the user opens a
    PDF/Office file, runs a binary, or previews a media file is a
    user/DE decision. Landlock limits *write* scope, not what the user does
    with the file afterwards — this is intentional and documented here so it
    isn't mistaken for a sandbox escape.
  - No content-type sniffing, no AV scan, no quarantine. A verified peer can
    still send `evil.pdf` that exploits the viewer's own parser.
  - Disk exhaustion via many/large files is bounded only by filesystem quota
    and the per-file size signalled in METADATA — no global quota yet.
    `[TODO: maintainer — define max total downloads / per-peer quota policy
    or explicitly document "quota is OS/filesystem responsibility"]`
- **Guidance to add (stub):** README/docs should state: "Downloads are
  untrusted even from verified contacts. Open with care; consider opening in a
  disposable VM / viewer sandbox. Noxtor verifies *who sent it* and *that it
  wasn't corrupted in transit* — not that it is safe to open." `[TODO:
  maintainer — decide wording and whether to add a first-download warning in
  `ui.c`/`tui.c` or keep it docs-only]`

### 4.8 Pre-hardening local race window (DRAFT STUB)

- **Goal:** a local unprivileged process wins a race before Noxtor's early
  hardening runs — e.g. `LD_PRELOAD` injection, early `ptrace` attach in the
  `execve → constructor` window before `main.c:141` `__attribute__((constructor))`
  hardening (`PR_SET_DUMPABLE`, `RLIMIT_CORE`, seccomp stage 1) executes.
- **Mitigation:** constructors run before `main` but after dynamic linker;
  `PR_SET_DUMPABLE=0` + `NO_NEW_PRIVS` + seccomp stage 1 close most post-launch
  attach paths. `LD_PRELOAD` for Noxtor's own binary is an OS/environment
  issue, not a Noxtor-code issue (see §5.1).
- **Residual:** a few microseconds of linker/constructor ordering remain
  theoretically raceable on a system where the attacker can already spawn
  processes as the same user and time `execve` precisely. Treated as
  **residual / out-of-scope-adjacent** — document, don't over-claim.
  `[TODO: verify constructor ordering vs. `LD_PRELOAD` stripping / `AT_SECURE`
  on this build; consider `DT_FLAGS_1 BIND_NOW` hardening already present via
  Makefile `HARDEN_COMMON`]`

## 5. Out of Scope

These are explicitly **not** defended against. Listing them isn't an
oversight — it's what makes the in-scope claims meaningful.

### 5.1 OS / kernel root compromise
If an adversary has root, or a kernel-level exploit, on the user's device,
Noxtor provides no protection. Seccomp reduces the *post-compromise* blast
radius of a bug *inside Noxtor's own process* — it is not a defense against
an adversary who already has root through some other route. **What we do
anyway:** `main.c:141` early-constructor hardening (`PR_SET_DUMPABLE=0`,
`RLIMIT_CORE=0`, `NO_NEW_PRIVS`), `arena.c:225/263` `mlock` + `MADV_DONTDUMP`
+ `MADV_DONTFORK`, and seccomp stage 1 (`process_vm_readv`, `ptrace`) raise
the bar for a *post-exploit* read of key material — but we treat these as
defense-in-depth, not as a root-adversary guarantee. If root is already
present at launch (`LD_PRELOAD`, early `ptrace` in the `execve→constructor`
window — see §4.8), no userspace mitigation can be relied upon.

### 5.2 Physical attacks
Cold-boot attacks, hardware implants, keyloggers, shoulder-surfing, and any
attack requiring physical access beyond what's needed to seize a device are
out of scope. **Partial vs. full:** cold-boot *is* partially mitigated where
the OS cooperates — `arena.c:225` `MAP_LOCKED`/`mlock` (with `STRICT`→abort),
`MADV_DONTDUMP`/`MADV_DONTFORK`, `sodium_memzero` + `strub` scrub on failure
paths, and `PR_SET_DUMPABLE=0` reduce RAM/core-dump/swap exposure — but on
non-STRICT builds or hosts with unencrypted swap this is best-effort, not a
guarantee. Hardware implants, keyloggers and shoulder-surfing have no
in-process mitigation and are fully out of scope.

### 5.3 Terminal emulator compromise
As noted in the README's Trust Note: the terminal emulator Noxtor runs in is
part of the attack surface and is not something Noxtor can secure. Users
wanting maximum isolation should use a Linux TTY directly.

### 5.4 Legacy kernels (< 5.13 Landlock / < 5.15 full hardening)
No fallback path that preserves the same guarantees exists for older
kernels. **Current behavior (fail-open with warning, not fail-closed):**
Landlock requires 5.13+ (ABI v1). On older kernels `landlock_sandbox_init`
returns `NOX_ERR_LANDLOCK_UNSUPPORTED` (`landlock_sandbox.c:76`) and file
writes are **not** restricted to `downloads/` — a warning is logged and the
process continues with seccomp alone. Seccomp TSYNC has a best-effort
fallback (`seccomp.c:257` — 32-bit compat removal if `TSYNC` unsupported).
CET/FORTIFY behavior is toolchain-dependent. Users on <5.15 should assume
reduced sandboxing; reference hardening is verified only on the reference
build environment (see §5.10).

### 5.5 Multi-user / shared-system races
Noxtor assumes a single-user Linux workstation. `config_dir` resolution and
symlink checks (`main.c` `ensure_config_dir`) protect against the leading
directory being swapped between check and open only insofar as the final
path component is concerned — a co-tenant on a shared/multi-user system
with write access to the parent of `$HOME` could still race the leading
path components. This is a TOCTOU class risk that is out of scope for the
single-user threat model this document assumes; hardening it is only
worthwhile if Noxtor is ever deployed on shared/multi-tenant systems, which
is not a supported configuration.

### 5.6 Terminal emulator scrollback of displayed plaintext
Every message rendered to the terminal (TUI or CLI) necessarily passes
through the terminal emulator's own scrollback buffer — this is true of
*any* terminal application and cannot be prevented from inside Noxtor.
`main.c`'s release-mode cleanup (`\033[2J\033[3J\033[H`) clears the
scrollback on clean shutdown, but plaintext displayed *during* a live
session sits in the terminal emulator's memory (and potentially the
emulator's own scrollback-to-disk cache, e.g. some terminals persist
scrollback across restarts) for the duration of the session. Users
requiring protection against this should use a terminal emulator with
scrollback disabled, or clear scrollback manually before backgrounding
the session. This is a restatement/extension of §5.3, called out
separately because it's a session-duration risk, not just a
compromised-emulator risk.

### 5.7 Malicious file content safety (cross-ref §4.7)
Noxtor verifies *who sent a file* and *that it was not altered in
transit* — it does not and will not scan, sandbox, or vet file content.
See §4.7 for the full adversary model; listed here because it is a
permanent design boundary, not a pending fix.

### 5.8 Group / multi-party messaging
The Noise XX pattern used throughout is a 1:1 handshake; Noxtor's
architecture (one static identity, one session per peer — see
`architecture.md` §5, 8 states / 40 transitions) does not support group
conversations, multi-device sync, or any topology beyond pairwise
sessions. A group protocol would require a fundamentally different design
(MLS-style group ratchet, per-member key distribution, transcript
consistency) and a new handshake pattern — not an incremental extension.
Not planned for the current architecture.

### 5.9 Comprehensive denial-of-service resilience
Individual DoS vectors are tracked as they're found (see §4.2.7,
§4.2.8), but no systematic resource-exhaustion testing (memory, fd,
disk, CPU amplification) has been performed. Noxtor should be assumed
vulnerable to DoS from a peer or network-level attacker who has not yet
been specifically tested against; this will be revisited as a dedicated
testing pass, not fixed incidentally as gaps are noticed. **Context:**
Tor itself is DoS-prone (guard/middle resource exhaustion, intro-point
pressure) — Noxtor cannot be more available than Tor. Partial mitigations
exist (`event_loop.c:762` 5/60s handshake throttle, 3600s idle timeout),
but they do not constitute comprehensive DoS resilience.

### 5.10 Build/toolchain environment drift
All hardening claims (stack protector, CET, `_FORTIFY_SOURCE`,
`-ftrivial-auto-var-init`, etc.) are verified only against the reference
build environment. Behavior on other distributions, older glibc
(`_FORTIFY_SOURCE=3` requires glibc ≥2.35), or non-GCC compilers is not
verified and may silently degrade hardening (see `architecture.md` hardening
flags section). **Reference build (TODO: fill with actual `gcc --version` /
`ldd --version` / `uname -r`):**

| Component | Reference |
|---|---|
| GCC | e.g. 13.2.0 (Ubuntu 24.04) — `_FORTIFY_SOURCE=3` needs ≥2.35 |
| glibc | e.g. 2.39 — older glibc silently downgrades to `_FORTIFY_SOURCE=2` |
| Kernel | e.g. 6.8 — Landlock ABI v1 (5.13+) / v3 (6.2+) feature-gated |
| Binutils/linker | CET `shstk` needs `ld` with `z shstk` support |

Until reproducible-build attestation exists, rebuilds on other toolchains
should be treated as unverified for hardening.

### 5.11 Coercion / compelled disclosure (rubber-hose)
Noxtor provides no deniable encryption or duress PIN. If a user is
compelled to reveal their PIN (legal coercion, border search, rubber-hose),
`contacts.db` decrypts and the current onion identity is derivable from the
same `master_key`. Ghost Mode prevents *future* persistence but does not
make existing ciphertext deniable, and there is no hidden volume / decoy
PIN. This is a deliberate non-goal: coercion resistance would require a
different storage design (deniable FS, panic wipe) and is not a supported
use-case.

### 5.12 System time / NTP manipulation
Noxtor's handshake/TOFU/idle timeouts use `CLOCK_MONOTONIC` (not wall-clock)
and do not defend against NTP/clock manipulation beyond that — Tor itself
requires roughly correct wall-clock for consensus; a skewed clock breaks Tor
before it breaks Noxtor. Noxtor does not run its own NTP verification and
treats time as an environment property.

### 5.13 Swap and core-dump on non-STRICT builds
`arena.c:225` `mlock` can fail in non-`STRICT` builds and the process
continues with a logged warning — key material may then be swappable to
disk. `MADV_DONTDUMP` (`arena.c:263`) and `PR_SET_DUMPABLE=0` are
best-effort. Users needing swap/core-dump guarantees must run with
`NOX_ARENA_STRICT_LOCK` (abort on `mlock` failure) and on a host with
encrypted swap / `ulimit -c 0` / `sysctl kernel.core_pattern=|/bin/false`.
Both are environment properties, not Noxtor code bugs, and are treated as
out-of-scope for the default workstation model (see §5.2 for the partial
vs. full distinction).

### 5.14 Speculative execution side channels (Spectre/Meltdown/L1TF/MDS)
Transient-execution attacks can leak `arena.c` key material via CPU
cache/timing even though `arena.c:225` `mlock`/`MADV_DONTFORK` and
`arena.c:437` constant-time compares are implemented. Mitigation is
microcode + kernel page-table isolation + `spectre_v2` mitigations — all
below Noxtor's privilege level. No userspace messenger can reliably close
this class; we treat it as out-of-scope and do not claim cache-side-channel
resistance.

### 5.15 DRAM disturbance (Rowhammer / bit-flip)
Repeated hammering of adjacent DRAM rows can flip bits in `arena.c:319`
canaries or live `my_static_priv` / `master_key` bits, breaking integrity
without any Noxtor bug. Defense requires ECC DRAM / TRR / physical
isolation. Consumer workstations typically lack ECC; we document the risk
but do not attempt in-process mitigation beyond canary checks (which a
targeted flip can also bypass).

### 5.16 Electromagnetic / TEMPEST / power / acoustic emanations
Plaintext rendered in `src/tui.c:380` / `src/ui.c:391` and PIN keystrokes
necessarily emit EM, power and acoustic signals (monitor cable, keyboard
sound, power draw). Capturing them requires lab-grade proximity/equipment.
Shielding (TEMPEST room, low-emanation hardware) is an environment
property — Noxtor cannot suppress emanations from the display/keyboard
itself.

### 5.17 Firmware / BIOS / Intel ME / AMD PSP / BMC
A compromised BIOS/UEFI, Intel ME/AMD PSP, or baseboard BMC operates
below the kernel and can DMA-read `arena.c` or bypass `src/seccomp.c:72`
`/proc/self/mem` / `process_vm_readv` blocks. This is the layer above
§5.1 (root) — §5.1 is OS-root, this is hardware-root. No userspace
mitigation is possible; verified boot (Secure Boot + measured boot) is the
only defense and is out-of-scope for Noxtor.

### 5.18 Compiler backdoor (Ken Thompson / trusting trust)
Even with clean source, a backdoored `gcc`/`ld` could inject code into the
`noxtor-cli` binary. Source-only distribution raises the bar but does not
prove the binary; reproducible-build attestation does not yet exist
(see §5.10). We do not claim binary transparency — verification requires an
independent reproducible build, which is currently out-of-scope.

### 5.19 Tor binary supply-chain
Noxtor spawns `src/network.c:980` `execv("/usr/bin/tor", …)` and trusts the
distro's `tor` package. An xz-utils-style backdoor in the `tor` binary
breaks all anonymity regardless of Noxtor's own code. Dependency pinning
covers `libsodium`/`libseccomp` source, not the preinstalled `tor` binary;
verifying the `tor` package (reproducible `tor`, distro sig) is an
environment responsibility.

### 5.20 Randomness correctness guarantee
All key material (`src/crypto.c:157` salt/nonce/`hs->e`, `src/arena.c:319`
canary) comes from `libsodium:randombytes_*` → kernel `getrandom`. Noxtor
does not implement its own entropy collection and cannot prove the kernel
RNG was not broken, backdoored, or VM-snapshot-cloned at the moment of
generation. Correct RNG is an explicit assumption (see §1.1 A2) — if the OS
RNG is compromised, every derived key (including the onion identity) is
predictable. We treat RNG correctness as an environmental guarantee, not a
Noxtor-verifiable property.

## 6. Per-Component Mitigation Summary

| Component | Threat addressed | Mitigation | Status |
|---|---|---|---|
| Noise XX handshake | Passive/active MITM, session compromise | Forward-secret E2E; DH token sequence (ee/es/se) independently traced against spec and confirmed correct, not just vector-tested | ✅ tested + independently verified, ❌ not externally/professionally audited |
| Handshake prologue (`noise.c`) | Protocol-version binding / downgrade protection | Fixed literal string mixed via `MixHash` | ⚠️ harmless but provides no actual version-binding value — see §4.2.10 |
| Handshake write-path bounds checking (`noise.c`) | Output buffer overflow on `write_msgN` | None — relies on caller sizing `out` correctly | ⚠️ safe today (fixed-size payloads), inconsistent with read-path rigor — see §4.2.10 |
| State machine transition safety (`state_machine.c`) | Centralized, auditable connection-state handling | Static transition table + action functions | 🔴 6 of 8 actions are no-op stubs; real logic lives in `event_loop.c` unconditionally — see residual risks |
| TOFU confirmation identity binding | Confirming trust for the correct peer, not a slot-recycled impostor | `ps->state == ST_TOFU_PENDING` gate + `if (!ps->hs)` guard | ⚠️ unconfirmed — depends on `stdin_handler.c`, see residual risks (highest-priority open question) |
| Seccomp (3-stage) | Post-exploitation escalation | Progressive syscall blacklist; blocks clearnet exfil after stage 3 | ✅ implemented |
| Ghost Mode | Forensic recovery | Disables SQLite, no persistent trace | ⚠️ scope needs source verification |
| Contact/message/queue at-rest encryption (`database.c`) | Forensic recovery when Ghost Mode is off | `crypto_secretbox_easy` (XSalsa20-Poly1305) under PIN-derived `db_key`; `PRAGMA secure_delete=ON` | ✅ confirmed — meaningfully stronger baseline than Ghost-Mode-only; WAL/SSD caveats apply (§4.3.4) |
| DB callback locking convention (`database.c`) | Deadlock avoidance during callback-driven I/O | `db_process_queue` unlocks before callback; other 3 visitor-based functions don't | ⚠️ inconsistent, latent footgun — see residual risks |
| Queue decrypt-failure handling (`database.c`) | Corrupted/tampered queued-message detection | MAC-verified decrypt, warn + delete on failure | ⚠️ same destructive path for tampering and transient failure — see §4.3.5 |
| Parser fuzzing | Memory corruption via malformed input | All external-input parsers fuzz-tested | ✅ ongoing, coverage TBD |
| UI output sanitization (`ui.c`) | Terminal escape injection from peer message content | `strip_ansi_escape` on plain-terminal path (`src/ui.c:353` guard now present) | ✅ OOB fixed (§4.2.1 RESOLVED); ⚠️ still not applied on TUI path (§4.2.2) |
| TOFU prompt (in-band) | Impersonation on first contact — trust decision | `ST_TOFU_PENDING` gate + `EV_TOFU_ACCEPTED/REJECTED` + `action_tofu_accept` | ✅ implemented — binding correctness is the open question (see §7, highest priority) |
| Out-of-band peer verification (QR / safety number) | MITM on first contact even with correct TOFU UX | — | ❌ not yet implemented (README-listed gap) — see §4.7 |
| obfs4 / Snowflake | Censorship / DPI blocking | Bridge support | 🟡 help-wanted per README |
| Control-channel response validation (`network.c`) | Compromised/malicious Tor process or control socket (S3) | `parse_service_id` strict format re-validation; cookie size check; response length/line caps | ✅ implemented |
| Peer-facing read deadline (`read_full`, `network.c`) | Slow-loris DoS via trickled bytes | Per-`EAGAIN` `poll()` timeout only, no cumulative deadline | ✅ not on peer path (uses `recv`+epoll instead) — low-priority hygiene fix only, see §4.2.5 |
| Tor process crash recovery | Availability after Tor dies mid-session | SIGCHLD + periodic `kill(pid,0)` poll → destroy all keys, require manual restart | ✅ verified, deliberate fail-closed design |
| Ephemeral HS private key memory hygiene (`tor_create_new_hs`) | Key material recoverable from process memory | `explicit_bzero` on success path; `strub` attribute on whole function | ⚠️ early-return paths unscrubbed manually — see §4.6 |
| Message MAC-failure handling (`event_loop.c`) | Tamper/forgery detection on `NOX_MSG_TEXT` | Noise MAC verification via `noise_decrypt` | 🔴 failure silently swallowed, no logging/disconnect — see §4.2.6 |
| `recv_buf` overflow/backpressure handling (`event_loop.c`) | Peer flooding / buffer exhaustion | Buffer-full check before `recv()`, drains via `process_peer_frames` | ⚠️ disconnect condition checks wrong variable, spurious disconnects — see §4.2.7 |
| Handshake attempt rate limiting (`event_loop.c`) | Handshake-spam DoS | 5 attempts / 60s throttle | ⚠️ global, not per-peer — see §4.2.8 |

## 7. Residual Risks / Open Questions

- **New from `state_machine.c` — the state machine is mostly not wired up
  yet, which matters for how much weight to put on it.** Despite the
  file's header claiming a compile-time-verifiable, centralized transition
  table ("Tablo statik, const — derleme zamanında doğrulanabilir"), 6 of
  its 8 action functions — `action_connect`, `action_accept`,
  `action_hs_process`, `action_tofu_prompt`, `action_session_up`,
  `action_file_begin`, `action_file_end`, `action_file_begin_rx` — are
  literal no-op stubs (`return NOX_OK;`), each commented with which future
  step will move real logic in ("Adım 3'te... taşınacak"). This is clearly
  an acknowledged, in-progress refactor, not a hidden defect — but it has
  a real consequence worth naming explicitly for anyone using this file to
  reason about safety: cross-referencing `event_loop.c`, the actual
  session-establishment work (`sodium_malloc`, `handshake_split`,
  `sodium_free(ps->hs)`, sequence-counter reset) happens **directly in the
  caller, unconditionally, before** `sm_dispatch(ps, state,
  EV_SESSION_READY)` is even called — so `action_session_up`'s "success ⇒
  apply transition" contract is currently vacuous for that path; the
  mutation already happened regardless of what the action returns. Only
  `action_cleanup` (thorough, well done) and `action_tofu_accept`
  (real, see below) currently carry real logic. **Practical implication:**
  don't treat this file as a completed formal-verification target yet —
  most of the safety properties it appears to encode aren't actually
  enforced by it today.
- **New from `state_machine.c` — recursive-dispatch invariant is implicit
  and unenforced.** `action_tofu_accept` recursively calls
  `sm_dispatch(ps, state, EV_PEER_DISCONNECTED)` on its two failure paths
  (allocation failure, `handshake_split` failure), then returns a non-OK
  error code so the *outer* `sm_dispatch` frame (still on the call stack)
  doesn't overwrite the state the recursive call just set. This is correct
  today, and the file's header comment acknowledges recursive dispatch is
  supported ("max 1 seviye: HS → SESSION"), but the actual safety
  invariant — *"if an action recurses into `sm_dispatch`, it must return
  non-`NOX_OK`, or the outer frame will clobber the state the recursive
  call just established"* — isn't spelled out or checked anywhere in
  `sm_dispatch` itself. Once the 6 stub actions above get real
  implementations (per the "Adım 3/4/5" comments), this is exactly the
  kind of implicit contract a future change could violate — e.g. an action
  that recurses to clean up but then mistakenly returns `NOX_OK`, leaving
  `ps->state` set to something like `ST_ACTIVE` with `fd == -1` and
  `session == NULL`. Worth an explicit assertion or documented contract in
  `sm_dispatch` before those stubs are filled in.
- **New from `state_machine.c` — `ST_CONNECTING` has no entry transition
  anywhere in the table.** The transition table defines what happens when
  `EV_PEER_DISCONNECTED` or `EV_TOR_DIED` fires *from* `ST_CONNECTING`, but
  nothing in `transitions[]` ever transitions a peer *into*
  `ST_CONNECTING` — the only entry point into an outbound connection
  visible here is `{ST_IDLE, EV_CONNECT_CMD, ST_HANDSHAKE_INIT,
  action_connect}`, which goes straight to `ST_HANDSHAKE_INIT`. Either
  `ps->state = ST_CONNECTING` is assigned directly somewhere outside this
  file (most likely `stdin_handler.c`'s `/connect` handler, bypassing the
  table — which undercuts the "table is the single source of truth"
  design this file is built around), or the state is vestigial and should
  be removed for clarity. `[TODO: verify in stdin_handler.c]` — same file
  as the higher-priority TOFU-binding question below, so worth checking
  in the same pass.
- **[HIGH-priority open question for `stdin_handler.c`] Does the TOFU
  yes/no confirmation bind to the specific peer session that generated the
  prompt, or to "whichever peer slot is currently active"?** This matters
  because `action_tofu_accept` is only reachable while `ps->state ==
  ST_TOFU_PENDING`, but peer slots are recycled — `event_loop.c` searches
  for `ps->fd == -1 && ps->state == ST_IDLE` when accepting new inbound
  connections — and the TOFU decision window is 2 minutes
  (`event_loop.c`'s TOFU timeout). If the confirmation handler dispatches
  via `sm_dispatch_active()` (i.e. against whatever peer is currently
  "active") rather than against a captured reference to the specific
  session that showed the prompt, then: peer A triggers a TOFU/key-change
  prompt → peer A disconnects (via `EV_PEER_DISCONNECTED`, which correctly
  resets that slot to `ST_IDLE` and wipes `tofu_*` fields) → a different
  peer C connects and is assigned the same now-free slot, entering its
  *own* legitimate `ST_TOFU_PENDING` → the user, unaware, finally answers
  "y" to what they believe is still peer A's prompt → the confirmation
  silently applies to peer C's key instead. This would defeat the TOFU/
  key-change-warning UX (the "Sender/peer authentication" asset in §2)
  precisely in the scenario it exists to catch. `action_tofu_accept`'s own
  `if (!ps->hs)` guard suggests *some* disconnect-during-TOFU race was
  considered, but as traced through the transition table, that specific
  check looks unreachable via the normal cleanup path (cleanup already
  nulls `ps->hs` and resets state to `ST_IDLE`, which has no
  `EV_TOFU_ACCEPTED` transition at all) — so it may be guarding a
  different, narrower case than the slot-reuse scenario above. **This is
  the single most important thing to check in `stdin_handler.c` next.**
- **New from `event_loop.c`:** failed MAC verification on `NOX_MSG_TEXT`
  frames produces zero signal (no log, no user-visible warning) — see
  §4.2.6. This is currently the most actionable finding across all files
  reviewed so far, since it directly undermines the "message integrity"
  asset in §2.
- **New from `database.c` — inconsistent callback-locking convention is a
  latent deadlock risk.** `db_process_queue` deliberately releases
  `DB_LOCK()` before invoking its `send_fn` callback (documented, and
  correct — I/O under the lock would risk deadlock). But its three
  siblings — `db_list_contacts`, `db_get_history`, and
  `db_list_contacts_with_summary` — all invoke their visitor callbacks
  **while still holding the lock** (the latter's own docstring even warns
  "visitor içinde DB operasyonu yapmamalı — deadlock riski," i.e. it knows
  the risk exists but enforces nothing). `g_state.lock` is a plain
  `PTHREAD_MUTEX_INITIALIZER` (non-recursive). Today, as far as reviewed
  so far, no visitor calls back into `db_*`, so this is inert — but it's
  an easy trap for a future contributor to fall into (call any `db_*`
  function from inside a `db_list_contacts` visitor and the process
  self-deadlocks). Same underlying theme as `ui.c`'s `g_theme`
  single-thread assumption: `database.c` already includes `pthread.h` and
  carries an unused `key_generation` field on `g_state` — signals that
  multi-threading (e.g. a future GUI thread) was anticipated but the
  locking discipline isn't yet uniform enough to survive it safely.
  **Fix direction:** either make the convention uniform (always unlocked
  callbacks) or add an assertion/re-entrancy guard that fires loudly
  instead of silently deadlocking.
- **New from `database.c` — minor documentation-accuracy issue.** The
  docstring in `db_list_contacts_with_summary` describes the contact
  payload as encrypted with "XChaCha20-Poly1305," but the actual primitive
  used throughout this file (`crypto_secretbox_easy`/`_open_easy`) is
  XSalsa20-Poly1305. Not a security weakness — XSalsa20-Poly1305 is a
  sound, well-audited construction with the same 24-byte nonce size — but
  worth correcting since a security audit or funding review that takes
  code comments at face value would be citing the wrong primitive.
- **New from `noise.c` — small items:**
  - **[RESOLVED]** `hs->e` (ephemeral private key) zeroing on a failed
    handshake was flagged as a `[TODO: verify state_machine.c]` item.
    Confirmed: `action_cleanup` (`state_machine.c`), which runs on
    `EV_HANDSHAKE_ERROR`/`EV_HANDSHAKE_TIMEOUT`/`EV_ARENA_FAIL`/etc.,
    unconditionally does `sodium_memzero(ps->hs, sizeof(struct
    noise_handshake))` followed by `sodium_free(ps->hs)` whenever `ps->hs`
    is non-NULL — covering the whole handshake struct (not just `e`),
    belt-and-suspenders on top of libsodium's own zero-on-free. No gap.
  - `hmac_blake2b` doesn't implement the RFC 2104 "hash the key down if
    it's longer than the block size" step — it rejects such keys outright.
    Harmless today since every call site passes a fixed 64-byte key
    (well under the 128-byte block size), but this makes the helper
    unsafe to repurpose as a general HMAC primitive without revisiting
    that path first.
  - **Cross-cutting pattern worth naming explicitly:** `ui.c` (`g_theme`),
    `database.c` (`pthread_mutex_t` + unused `key_generation`), and now
    `noise.c` (`_Atomic` nonce counters) all show the same shape —
    scaffolding for a future multi-threaded frontend (a GTK UI thread has
    come up in project discussion) laid down ahead of time, with the
    actual concurrency-safety discipline (locking convention, atomicity
    guarantees under real contention) not yet uniformly verified because
    nothing exercises it concurrently today. Worth a dedicated pass before
    any real second thread is introduced, rather than assuming the
    existing atomics/mutexes are sufficient by their mere presence.
- No TOFU/QR verification yet — first-contact key exchange currently has no
  out-of-band verification path, leaving a MITM window on initial connect.
- `[TODO]` Clarify whether the timing-safety of comparison operations
  (constant-time where it matters, e.g. any local auth/PIN if one exists)
  has been reviewed.
- **[RESOLVED — onion-key derivation]** Persistent hidden-service private key
  storage: see §4.3.3. No plaintext `onion.key` persists; identity is
  deterministically derived from `master_key` (`crypto_derive_onion_seed`
  `src/crypto.c:277` + `derive_tor_expanded_key`) and sent as `ADD_ONION`
  KeyBlob. A seized device without the PIN yields no long-term onion identity.
  (Was previously the single biggest unknown in §4.3.)
- Ungraceful termination (crash, `SIGKILL`, power loss/seizure mid-session)
  leaves the per-instance Tor working directory — including a timestamped
  `tor.log` — on disk. Cleanup is shutdown-path-only, not crash-safe.
- **[RESOLVED — was previously open]** What happens if the local Tor
  process dies mid-session? Confirmed in `event_loop.c`: a `SIGCHLD`
  handler flags death immediately, backed up by a periodic
  `kill(pid, 0)` liveness poll every 5s in case the signal is missed.
  On detection, every active peer session is dispatched `EV_TOR_DIED`,
  and — deliberately — the **entire crypto arena is destroyed**
  (master key, DB key, session key, static keypair all zeroed/freed),
  with the user told to restart the application manually. No
  auto-respawn is attempted, consistent with seccomp stage 2 blocking
  `fork`/`execve` after hidden-service setup. This is a considered
  design choice (fail closed, wipe keys, require explicit restart)
  rather than a gap — worth noting in the README/docs as expected
  behavior so users aren't surprised by it, but not a security issue.

### 7.1 Risk Prioritization — Top-5 (DRAFT STUB — maintainer to confirm ordering)

Ordered by `likelihood × impact` for a P2P messenger user. This is the
maintainer's fix-order suggestion, not a CVSS score — adjust after
`stdin_handler.c` / `file_transfer.c` review.

| Rank | Finding | Asset(s) hit | Likelihood | Impact | Current status |
|---|---|---|---|---|---|
| **1** | **Silent MAC-failure swallow** (§4.2.6, `event_loop.c:372`) — `NOX_MSG_TEXT` decrypt fail has no `else` (no log, no UI, no `sm_dispatch`) | Message integrity (§2) — tamper probing leaves zero trace | High (any on-path / malicious relay can inject at correct `seq`) | High (integrity detection completely bypassed) | 🔴 Open — most actionable |
| **2** | **TOFU slot-recycling race** (§7, highest-priority open question) — `y/n` may bind to "active slot" not the prompting session; 2-min window + slot reuse | Sender authentication (§2) — TOFU UX defeated exactly when needed | Medium (requires peer A disconnect + peer C connect in window + user timing) | High (wrong peer silently trusted) | ❓ Unconfirmed — needs `stdin_handler.c` verification (next) |
| **3** | **`recv_buf`-full spurious disconnect** (§4.2.7, `event_loop.c:164`) — checks `ps->fd>=0` not `recv_pos` after drain | Availability — peer-triggerable / legitimate-traffic disconnect | Medium (craft sizes to fill buffer exactly) | Medium (DoS, no confidentiality loss) | ⚠️ Open |
| **4** | **TUI-path missing ANSI sanitize** (§4.2.2, `src/ui.c:453`) — raw peer content → `tui_chat_append` without `strip_ansi_escape` | UI integrity (misrender; future renderer could become escape injection) | Low-Med (requires future renderer change or termbox2 assumption break) | Low (today) → High (if renderer changes) | ⚠️ Open — fix is "sanitize before branch" |
| **5** | **Forensic `tor.log` on ungraceful exit** (§4.3.2) — `tor.log` survives `SIGKILL`/crash until next run | Plausible deniability / metadata (§2) — timestamped HS activity recoverable | Medium (physical seizure after crash) | Medium (metadata only, content stays encrypted under `db_key`) | ⚠️ Known — shutdown-path-only cleanup |

`[TODO: maintainer — confirm this ordering; after `stdin_handler.c` review, #2 may move to #1 if the binding is indeed per-active-slot. Add CVSS/DREAD scores if funders require them; otherwise this ordered list is sufficient for planning.]`

## 8. Audit Status

🔴 **This software has not been independently audited.** Do not rely on it in
a life-threatening situation. Security researchers are invited to review the
code and report vulnerabilities responsibly.

## 9. Changelog

- `[DRAFT]` Initial stub, built from README + architecture description only.
- Reviewed `tui.c`: added display-structure-inference gap (§4.2.3).
- Reviewed `ui.c`: added OOB read in `strip_ansi_escape` (§4.2.1),
  TUI/non-TUI sanitization asymmetry (§4.2.2), format-string TODO (§4.2.4).
- Reviewed `network.c`: added slow-loris gap in `read_full` (§4.2.5), new
  adversary model for compromised/malicious local Tor process (§4.6),
  private-key scrub asymmetry hedged by `strub` (§4.6), forensic-recovery
  gap on ungraceful shutdown and open question on persistent-key-at-rest
  storage (§4.3).
- Reviewed `event_loop.c`: corrected/downgraded the `read_full` slow-loris
  finding after confirming peer data actually flows through non-blocking
  `recv`+epoll, not `read_full` (§4.2.5); added silent MAC-failure gap on
  `NOX_MSG_TEXT` decryption (§4.2.6, currently the highest-priority open
  finding); added `recv_buf`-full disconnect logic bug (§4.2.7); added
  global (non-per-peer) handshake rate-limit scope gap (§4.2.8); resolved
  the open question on Tor-crash handling — confirmed deliberate
  fail-closed design (§7); partially verified format-string safety of
  `ui_print_*` call sites for this file (§4.2.4).
- Reviewed `database.c`: confirmed contacts/messages/queue are encrypted at
  rest under a PIN-derived `db_key` independent of Ghost Mode, with
  `secure_delete=ON` (§4.3, §2 asset description updated); added WAL/SSD
  caveats on what "secure delete" actually guarantees (§4.3.4); added
  destructive-on-any-decrypt-failure pattern in `db_process_queue`
  (§4.3.5); flagged an inconsistent callback-locking convention across
  sibling functions as a latent, non-recursive-mutex deadlock footgun
  (residual risks); noted a documentation-accuracy nit (XChaCha20 claimed
  in a comment vs. XSalsa20 actually used — same security margin, wrong
  name).
- Reviewed `noise.c`: independently traced the Noise_XX DH token sequence
  (ee/es/se) against spec on both initiator and responder sides and
  confirmed correctness — upgraded confidence in the handshake row beyond
  "tested against vectors" (§4.2.9); flagged a hardcoded non-negotiating
  prologue string and an asymmetry between rigorously-bounds-checked read
  paths and unchecked write paths as low-severity audit-hygiene items
  (§4.2.10); noted ephemeral-key zeroing on handshake failure depends on
  `state_machine.c` (still pending); named the recurring
  scaffolding-for-future-multithreading pattern now visible across
  `ui.c`, `database.c`, and `noise.c` as a residual risk worth a dedicated
  pass later.
- Reviewed `state_machine.c`: flagged that 6 of 8 action functions are
  still no-op stubs with the real logic living unconditionally in
  `event_loop.c` (the transition table's safety properties are currently
  vacuous for those paths); documented the implicit, unenforced
  recursive-dispatch invariant in `action_tofu_accept`; noted
  `ST_CONNECTING` has no transition leading into it anywhere in the
  table; raised what is currently the single highest-priority open
  question — whether TOFU yes/no confirmation binds to the specific
  originating peer session or to "whichever slot is active," given peer
  slots are recycled within the 2-minute TOFU window.
- **2026-08-23 sync (this edit — keeps old format, adds stubs):**
  - Refreshed stale parts against current codebase: `architecture.md` already
    synced (line counts, `NOX_SUBKEY_ONION_SEED=4`, `src/linenoise.c`); here
    marked §4.2.1 trailing-ESC OOB as **RESOLVED** (guard now at
    `src/ui.c:353`), resolved §4.3.3 persistent-key-at-rest question via
    deterministic onion-key derivation (`src/crypto.c:277` + `src/network.c:1301`,
    `docs/onion-key-derived-plan.md`), split §6 TOFU row into prompt
    (implemented) vs. out-of-band verification (planned).
  - Added **draft stubs** to make the document a real TM without changing its
    structure: §1.1 Assumptions (A1-A6, PIN entropy guidance — per
    maintainer: weak PIN is user responsibility, 12+ char / diceware
    recommended), §3.1 Attack Surface / Entry Points (E1-E10), §4.7
    Post-TOFU malicious contact / file safety (Landlock write containment,
    content execution = user responsibility per maintainer), §4.8
    pre-hardening race window, §7.1 Top-5 Risk Prioritization (ordered list,
    maintainer-confirmed priority: silent MAC-failure #1, TOFU slot-recycling
    #2).
  - No source-code changes; all new sections are `[DRAFT STUB]` with
    `[TODO: maintainer — ...]` markers for your review.
- Still pending source review: `main.c` (full), `arena.c`, `stdin_handler.c`
  (now the top priority — TOFU binding, `ST_CONNECTING` entry, §7.1 #2),
  `file_transfer.c` (quota + chunk handling for §4.7/§7.1).
