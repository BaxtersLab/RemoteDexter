# RemoteDexter — Security Hardening Pass

**Date:** 2026-06-19
**Reviewer:** Claude (pre-audit pass ahead of the 2026-07-01 external review)
**Scope of this pass:** `host_app` — the Windows host runtime that terminates the mobile client's TCP connection, performs the Noise XX handshake, and dispatches Agent2 commands. This is the network-facing trust boundary, so it's reviewed first.

> Context: `host_app` is a **prototype**. Capture / input / file-transfer command handlers are currently ACK-only stubs, so several findings are "must-fix-before-enabling" rather than live-exploitable today. They are documented now so the real implementation is built on a sound boundary.

---

## Summary

The handshake design is mostly sound: a **persistent pinned host static key** (client refuses to connect unless the advertised pubkey matches), Noise XX for the encrypted channel, and single-use TTL session tokens. The previously-noted "session activates on plaintext token before handshake" issue is **resolved** — activation is now correctly deferred until after `into_transport_mode()` (`main.rs:319-327`).

Four issues remain.

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| RD-1 | Medium | Listener binds `0.0.0.0:8082` — exposed on every interface | **FIXED 2026-06-19** |
| RD-2 | High *(when un-stubbed)* | Command dispatch has no capability/window-scope enforcement | **PARTIAL 2026-06-20** — capture/input/file now deny by default (was ACK); real gate required at un-stub time |
| RD-3 | Medium | Session token sent in plaintext pre-handshake; not bound into Noise | **PARTIAL 2026-06-20** — opt-in Noise prologue (`RD_BIND_TOKEN_PROLOGUE=1`); off by default — enabling needs matching client change |
| RD-4 | Medium–High | Unbounded allocation on the initial handshake frame → pre-auth memory-exhaustion DoS | **FIXED 2026-06-19** |

> **Fixes applied (RD-1, RD-4):** `cargo check -p host_app` passes. RD-1 → bind now reads `RD_BIND`, defaults to `127.0.0.1:8082`. RD-4 → initial handshake frame bounded to `MAX_HANDSHAKE_FRAME` (64 KiB) before allocation.
> **Left open by design:** RD-2 (must be built when capture/input are un-stubbed) and RD-3 (handshake-protocol change — plan rather than rush before the audit).

---

## RD-4 — Unbounded allocation on the first frame (pre-auth DoS)

**Severity:** Medium–High (unauthenticated remote DoS) — **easiest high-value fix**
**Location:** `host_app/src/main.rs:266-271` (`handle_client_connection`)

### What
The very first read trusts a client-supplied 32-bit length and allocates that many bytes before any authentication:

```rust
let len = u32::from_be_bytes(len_buf) as usize;
let mut frame_buf = vec![0u8; len];   // len can be up to 4 GiB
socket.read_exact(&mut frame_buf).await?;
```

Every *later* read is bounded (`recv_noise_msg` rejects `len > 65535`, and the session loop checks `frame_len > 65535`), but this **first** frame is not. Any peer that can reach `0.0.0.0:8082` (see RD-1) can send `len = 0xFFFFFFFF` and force a 4 GiB allocation per connection — trivial unauthenticated memory-exhaustion DoS, repeatable across connections.

### Fix
Bound the handshake frame the same way the others are bounded:

```rust
const MAX_HANDSHAKE_FRAME: usize = 64 * 1024; // handshake JSON is tiny
let len = u32::from_be_bytes(len_buf) as usize;
if len == 0 || len > MAX_HANDSHAKE_FRAME {
    return Err(anyhow::anyhow!("handshake frame out of bounds: {len}"));
}
let mut frame_buf = vec![0u8; len];
```

---

## RD-1 — Listener binds `0.0.0.0:8082`

**Severity:** Medium (attack-surface exposure)
**Location:** `host_app/src/main.rs:194`

### What
`TcpListener::bind("0.0.0.0:8082")` listens on **every** interface. For a host that will grant screen capture + input injection, that's a wide surface: anyone on the LAN (or the internet, if the box is port-forwarded / on a public-IP VPS) can reach the listener and drive the pre-handshake path (RD-4, RD-3, token attempts). The Noise pin protects channel confidentiality/host-auth, but it doesn't reduce who can *knock*.

### Fix
- Make the bind address configurable (env `RD_BIND`, default `127.0.0.1:8082`), and for the LAN-pairing use case bind the specific LAN interface rather than `0.0.0.0`.
- Document a firewall rule scoping 8082 to the local subnet.
- Never expose this port publicly; pairing is a LAN/loopback transport.

```rust
let bind = std::env::var("RD_BIND").unwrap_or_else(|_| "127.0.0.1:8082".into());
let listener = TcpListener::bind(&bind).await?;
```

---

## RD-2 — No capability / window-scope enforcement in command dispatch

**Severity:** High once capture/input are real (architectural; not live today — handlers are stubs)
**Location:** `host_app/src/main.rs:387-426` (`dispatch_agent2_command`)

### What
`dispatch_agent2_command` routes `screenshot_request`, `input_event`, and `file_transfer` but currently only returns ACK stubs. There is **no integration with the VoDesktop security boundary** (`vodesktop-core`: `WindowScope` allow-list, `ControlLevel`, view-only default, instant revoke). When these handlers are implemented, a connected client would have unscoped screen/input/file access — exactly the "full desktop" outcome the VoDesktop model promises to prevent.

### Fix (before un-stubbing)
Route every capture/input/file command through `vodesktop-core` gates: enforce `WindowScope` (single permitted HWND, never full desktop), check `ControlLevel` (view-only unless input explicitly authorized for the session), and honor instant revoke. Reject any command that arrives outside an authorized `ShareSession`. Mark the stubs with `// STUB:` + a `ROADMAP.md` entry per Article VII of the constitution.

---

## RD-3 — Session token sent in plaintext before the handshake

**Severity:** Medium
**Location:** `host_app/src/main.rs:266-291`

### What
The client sends `session_token` in a **plaintext** JSON frame before the Noise handshake; the host validates (single-use, TTL) and only then runs Noise. Single-use consumption blocks passive replay, but an active on-path attacker on the LAN can observe/race the token (intercept, drop the real client, complete the handshake themselves). The token is the *only* client-side authenticator — Noise XX here authenticates the host to the client (pinned key) but the host accepts any client static key.

### Fix
Bind possession of the token into the encrypted handshake instead of sending it in cleartext:
- Use the token (or a hash of it) as the Noise **prologue** or a **PSK** (`Noise_XXpsk*`), so a peer that doesn't hold the token can't complete the handshake and the token never crosses the wire in clear; **or**
- Defer token presentation until the first message *inside* the encrypted transport.
Optionally pin/allow-list the client static key at first pairing for mutual authentication.

---

## Verified intact / good (no action)

- **Host key pinning** — persistent static keypair (`load_or_create_identity`, `main.rs:54`); public half advertised in invites and pinned by the client. Correct (a per-connection key would defeat pinning).
- **Activation ordering** — `SESSION_ACTIVE` is set only after `into_transport_mode()` (`main.rs:319-327`); the prior plaintext-token-activation bug is fixed.
- **Post-handshake framing** — bounded to 65535 (`recv_noise_msg`, session loop), decrypt errors are handled without tearing down on a single bad frame.

---

## Next (remaining `backup 10` sweep)

1. **VoDesktop** (`backup 10/VoDesktop`) — verify `vodesktop-core` gates (`WindowScope`/`ControlLevel`/`ShareSession`) and that `vodesktop-capture` only ever captures a single permitted HWND, never the desktop. This is the boundary RD-2 must call into.
2. **ThatLegalGuy / TheTaxGuy** — session/HMAC handling + sensitive tax-data boundary.
3. Quick secrets / bind / `.env` scan across the rest of `backup 10`.
