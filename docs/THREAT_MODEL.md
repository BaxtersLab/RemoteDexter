# Threat model — RemoteDexter

**Status:** written 2026-08-21 (Block 1) and re-audited against the tree at
release. It was built to describe **two** systems — the *target* design and the
*tree as it stands* — marking every divergence **GAP →** with the block that
would close it. Every one of those gaps has since been closed, and each is now
marked with the block that closed it and what to look at. A threat model that
describes only the intended product is a marketing document; one that still
lists gaps its own code has closed is no better, because a reader cannot tell
which warnings are live.

**Scope.** The standalone RemoteDexter host (Linux and Windows) and the Android
controller app. No VirtualOffice integration. Relay is second-tranche and
optional.

---

## 1. What RemoteDexter is, in one paragraph

One user-started host process and one user-started Android app. The owner starts
the host deliberately, picks a network interface, and shows a QR on the host
screen. The phone scans it, completes a pinned Noise handshake, and from then on
views the desktop and — separately and only if granted — controls it.
Installation alone starts nothing, listens on nothing, changes no group
membership, and grants no device access.

---

## 2. Assets

Ordered by what an attacker gains.

| # | asset | where it lives | loss means |
|---|---|---|---|
| A1 | **Host Noise static private key** | host identity store | an attacker can impersonate the host to every paired phone and defeat pinning |
| A2 | **Host signing private key** | host identity store | forged pairing invites that phones will trust |
| A3 | **Android device Noise static private key** | app-private storage on the phone | an attacker can authenticate to the host as that phone |
| A4 | **Live pairing token** | host memory, the QR on screen, inside the Noise channel | one-shot enrollment as a new trusted device |
| A5 | **Desktop pixels** | capture pipeline, wire, phone screen | everything on the owner's screen: documents, passwords being typed, other people's data |
| A6 | **Input authority** | uinput (Linux) / Windows input backend | arbitrary control of the workstation — this is the highest-consequence asset, and it is a *capability*, not a secret |
| A7 | **Paired-device list** | host store | who may connect; tampering re-authorises a revoked phone |
| A8 | **Known-host list and pinned host keys** | phone storage | tampering removes pinning and enables a substituted host |

**A6 is the asset that makes this product different from a file sync tool.** A
remote-desktop host that streams pixels is a confidentiality problem; one that
injects input is a full compromise of the machine. Every design decision that
looks over-strict — separate input grant, geometry fail-closed, release on
revoke — exists because of A6.

---

## 3. Trust boundaries

```
     phone app process  │  phone OS  │  LAN  │  host process  │  host OS  │  kernel/uinput
     ───────────────────┼────────────┼───────┼────────────────┼───────────┼───────────────
  B1 app-private store  │            │       │                │           │
  B2                    │            │  ⇅ Noise (the only trusted channel over the LAN)
  B3                    │            │       │  session_core authorization
  B4                    │            │       │                │  identity store file perms
  B5                    │            │       │                │           │  /dev/uinput ACL
```

* **B2 — the wire.** Everything crossing the LAN is inside a pinned
  `Noise_XX_25519_AESGCM_SHA256` session or it is not trusted. There is no
  plaintext fallback and no downgrade path.
* **B3 — authorization.** `session_core` is the only thing that may say yes to a
  frame or an input event. Three independent conditions must all hold for input:
  host capability, permitted surface, explicit input grant. **Viewing never
  grants control.**
* **B5 — the kernel boundary.** uinput publishes an evdev device *below* the
  display server. A nested compositor does not isolate it; only a VM does. This
  is why input testing happens in `BaxtersVMHarness` and never on this box's
  live seat (Article XIV).

---

## 4. Entry points

| # | entry point | reachable by | pre-auth work an attacker can force |
|---|---|---|---|
| E1 | the host's TCP listener | anyone who can route to the bound address | TCP accept, Noise handshake |
| E2 | the QR code on the host screen | anyone who can see the host screen for the invite's lifetime | full enrollment |
| E3 | the Android QR scanner | anything that can put an image in front of the camera | invite parse, signature verify |
| E4 | Android intents into `RDService` | other apps on the phone, if a component is exported | service start |
| E5 | the package/APK itself | whoever controls the distribution channel | arbitrary code as the user |
| E6 | `/dev/uinput` on the host | any local process running as the host user, once the opt-in rule is installed | input injection |
| E7 | the relay *(second tranche)* | anyone who can reach it | routing, rate-limit exhaustion |

**CLOSED IN BLOCK 3 (the listener half).** E1 no longer exists until the owner
presses Start. `host_controller` is the only thing that may create a listener;
`HostState::Stopped` means *no socket*, not a socket that refuses. Proven in
`BaxtersVMHarness` with `ss`: absent before launch, absent while the console is
open, absent after it exits, and present only between Start and Stop. Wildcard
binds (`0.0.0.0`, `::`, and `::ffff:0.0.0.0`) are refused before a socket is
created.

**CLOSED IN BLOCK 10.** Pre-auth work is bounded, and the bound refuses rather
than queues: `PreAuthLimit::MAX_PENDING` admits **4** connections in the
pre-authentication window and a fifth is dropped at accept, costing one accept
and one close instead of a task, a handshake buffer and a slot held for as long
as the peer likes. `PreAuthLimit::DEADLINE` drops any connection still
unauthenticated after **10 seconds**. Beyond authentication, `MAX_TOTAL` caps
concurrent sessions at **8** and `MAX_PER_DEVICE` at **3**.

**CLOSED. E4** — `RDService` is declared `android:exported="false"`, and it is
started from the connect and control-toggle click handlers, never on cold
launch. Nothing outside the app can start it and nothing starts it unasked.

---

## 5. Adversaries

### 5.1 The owner

Not an adversary, but the party every control must remain usable by. The owner
may start and stop the host, pair and revoke devices, and grant or withhold
input. The model's obligation to the owner is **truthfulness**: no state may be
displayed as safe when it is not, and no capability may be active without being
visible.

*Design consequence:* a fake UI that reports a placeholder as running
(`module25_windows_ui`) is a security defect against this adversary class, not
merely a usability one. **CLOSED IN BLOCK 3**: the module is deleted, and the
console now reports only what the controller told it. Where a capability is
unavailable it says so on screen — the pairing button is disabled and states
that the old implementation broadcast the token in plaintext, rather than
offering an action that would.

### 5.2 Malicious LAN peer

On the same network, can send to the bound port, observe broadcast and multicast
traffic, and attempt ARP/DNS interference.

**Target position.** Before authentication it learns only that a TCP port
accepts bounded Noise handshakes. No product version, paired-device list, screen
metadata, token, or authorization result is sent in plaintext. Global and
per-source limits make unauthenticated attempts finite.

**CLOSED IN BLOCK 4.** All four plaintext exposures are gone, and their absence
is proven by packet capture rather than by code review:

| was | evidence it is gone |
|---|---|
| `module23_wifi_beacon` sent `session_token` to `255.255.255.255` every 5 s | crate deleted; capture shows **0 packets to 255.255.255.255** |
| `module17` put `session_token` on a process-wide event bus | crate deleted; the token now exists only as a SHA-256 in `TokenStore` |
| `module17` probed `8.8.8.8:80` for the outbound address | crate deleted; capture shows **0 packets to 8.8.8.8**. The address is passed in from the already-bound listener |
| the QR was written to a temp file and opened with `xdg-open` | QR is returned as modules and drawn in-process; nothing touches the filesystem |

`scripts/vm-pairing-leak-proof.sh`, in `BaxtersVMHarness`, runs **both** hosts
under the same capture. The pre-Block-4 binary's capture contains **4
`session_token` matches in 20 s**; the current binary's contains **zero token
bytes**, with the host process asserted alive at both ends of the window and the
binary asserted newer than its sources. Without that control, a clean capture
would only prove tcpdump was pointed somewhere useless.

`crates/pairing` **cannot** reacquire these side effects: it has no dependency on
`tokio`, on `std::process`, on any socket type, or on any filesystem API.

**Second live defect, found in Block 1 — CLOSED IN BLOCK 4.**
`snow 0.9.3` carried **RUSTSEC-2024-0011, unauthenticated nonce increment**, in
the Noise implementation itself. Block 2 attempted the fix and could not land
it: the upgrade was blocked by `curve25519-dalek 3.2.1`'s `zeroize` ceiling,
reached through `ed25519-dalek 1.0.1` and `x25519-dalek 1.2.0`.

Block 4 cut the knot in the required order — delete the obsolete pairing crates,
migrate `ed25519-dalek` 1 → 2, then bump `snow` to **0.9.6**, which is the
version this release locks. `cargo audit` reported **zero vulnerabilities** when
it was run against that change.

That figure is dated on purpose. An advisory published tomorrow against a
dependency nobody touched would make an undated "reports zero vulnerabilities"
false without a single line changing, so treat it as a measurement with a date
rather than a standing property, and re-run `cargo audit` against the lockfile
in this release rather than trusting the sentence.

### 5.3 Stolen or compromised paired phone

Holds **A3** (its own device key) and **A8** (pinned host keys). It is a
legitimate device until the owner says otherwise.

**Position.** A stolen phone **remains authorized until the host revokes it.**
This is stated plainly rather than papered over: there is no remote wipe, no
heartbeat-based expiry, and no attempt to distinguish a thief holding an
unlocked phone from the owner. The local protection boundary is the Android OS
lock and full-disk encryption.

**What the design does provide:** host-side `Revoke` removes the device's public
key and is **tombstoned**, so an in-flight or replayed enrollment cannot
recreate the same identity without a fresh QR. `AuthMode::Paired` succeeds only
when Noise's remote static key matches a non-revoked record. Revocation is
therefore complete and immediate at the host, which is the only place that can
be trusted to enforce it. **CLOSED IN BLOCK 9.** Durable pairing and revocation
exist: device records persist, revocation tombstones the key, and
`AuthMode::Paired` succeeds only against a live record. Demonstrated on hardware
— revoking a device mid-session closed the session and released every held key.

*Deliberately not adopted:* a reusable password or public ID, which would let a
stolen phone's credential be extracted and replayed from elsewhere.

### 5.4 Compromised relay *(second tranche, Block 12)*

Runs the relay process; sees every byte that transits it.

**Can:** observe timing, sizes, and connection patterns; drop, delay, reorder,
or refuse traffic; deny service entirely.

**Cannot:** read or forge session content. It holds no session token, no Noise
static private key, and no device private key, and contains no parser for
decrypted messages. Endpoints complete the pinned Noise handshake end-to-end
*through* it; reordering breaks Noise and closes the session.

**Explicitly not claimed:** metadata privacy. Traffic timing and volume leak.
Padding and oblivious transport are not implemented and are not asserted.

### 5.5 Malicious local process on the host

Runs as the same user as the host process. This adversary is often ignored; it
should not be, because **E6** hands it the highest-consequence asset.

**Target position.** The opt-in grant is `uaccess` on `/dev/uinput` **only**, for
the active local seat. It does **not** grant read access to `/dev/input/event*`,
so a local process cannot read the owner's real keystrokes through it. There is
no root daemon, no setuid binary, no custom polkit rule, and `usermod` is never
called. Identity files are owner-only in the platform data directory and written
atomically.

**Honest limitation, stated rather than hidden:** once the rule is enabled, *any*
process running as that user can open `/dev/uinput` and inject input. That is
inherent to the mechanism. It is still strictly better than membership in
`input`, which additionally exposes every keyboard event device to every process
running as that user.

**Today's position — CLOSED IN BLOCK 7.** Operation does **not** depend on
`input` group membership. The optional grant is a single udev rule giving
`uaccess` on `/dev/uinput` to the active seat, and no part of the package adds a
group, an ACL or a setuid binary. This is enforced rather than intended: the
release gate fails the build if the package's maintainer scripts so much as
mention `usermod`, `gpasswd`, `setfacl` or `chmod`.

**Second exposure — CLOSED IN BLOCK 9.** `host_static_identity.key` and
`host_signing_identity.key` — **A1 and A2** — now live in an owner-only platform
data directory rather than beside the binary. The move is a migration that reads
the path and never a byte of the file, and it **fails startup** rather than
generate a fresh identity if it cannot complete: a host that silently re-keys
would present a new fingerprint to every paired client, which is the failure
this refusal exists to prevent.

### 5.6 Package-supply attacker

Controls, or can substitute, an artifact the user installs.

**Target position.** Native code updates go through signed APK and package
releases only. **There is no second native-code trust root.**

**Today's position — CLOSED IN BLOCK 13.** `UpdateManager.kt` shipped
`PUBLIC_KEY = "MIIBIjANBg…" // Placeholder` and used it to verify `.rdx` native
hot-update payloads — a placeholder verification key in a code-execution path,
which is not a weak lock but an unlocked door with a lock painted on. The answer
was **not a better key**: the `.rdx` path, its manager and its verification key
were deleted, so the second native-code trust root no longer exists. The target
position above is now the actual position.

A supply-chain fact recorded in Block 1 and since resolved: `core2 0.4.0` was in
the dependency graph, unmaintained, with **every version yanked** — meaning a
fresh builder could not re-fetch it. It is no longer a dependency: it appears in
no manifest and in no lockfile, and the published source export is checked by
building it from a clean directory before release.

---

### 5.7 An authorised peer typing into a locked screen

Holds a legitimate pairing and the input grant. The operator locks the screen and
walks away. Nothing about the pairing has changed, so nothing in the session
layer has any reason to refuse.

**The defect, characterised before it was fixed.** RemoteDexter injects input
through uinput, which publishes an evdev device *below* the compositor — the same
boundary B5 already describes. The lock screen is a client of that compositor, so
it receives injected key events exactly as it would receive a physical keyboard's.
Nothing above uinput declines on the session's behalf.

Proven in the VM harness on 2026-09-07, not argued from the diagram: five
synthetic keystrokes were written to uinput against a locked GNOME session and
five dots appeared in the lock screen's password field, with logind reporting
`LockedHint=yes` throughout. The injection also woke the blanked display. That
makes the lock screen a password oracle reachable by a paired phone, and the
session behind it reachable by anyone who guesses past it.

**Today's position — GUARDED, WITH A NAMED WINDOW.** The host reads logind's
`LockedHint` and refuses both input and clipboard while the screen is locked.
Three properties are worth stating because each one is a decision:

* The lock state is **polled on the five-second heartbeat the idle watchdog
  already runs**, not subscribed to. Subscribing would react immediately and is
  the intended follow-up; it would also stand a second D-Bus connection beside
  the portal's, which is the shape that has hung a capture session on this
  hardware before. So a peer that already holds the grant keeps it for **up to
  five seconds after the lock**. That is a large reduction, not a complete fix,
  and it is the residual risk this release ships with.
* The session is resolved through the user's **`Display` property**, not
  logind's `auto` selector. `auto` returns the caller's own session, so a host
  started over SSH — an ordinary way to run a headless host — would be asking
  about the SSH session, which is never locked, and the guard would silently
  never fire.
* A host where logind **never answers** is allowed to keep working: a machine
  without logind never had this protection, and refusing every keystroke there
  would break the product rather than protect anyone. A host where logind
  answered and then **stopped** is refused, because otherwise silencing the
  probe would itself be the way out of the guard.

**Not covered.** Windows. The lock screen there runs on the Winlogon desktop and
the OS already refuses cross-desktop `SendInput`, but this build has not tested
that and does not claim it — the probe reports the state as unobservable on any
non-Linux host, and the paragraph above says what that means.

---

### 5.8 Another app on the phone, and the phone's own successor

Not the network and not the host — the handset. Three ways pairing material left
the app without anyone attacking the protocol.

**A misread QR wrote a live token into a shareable log.** The scan path logged
the parse exception's message, and Android's `org.json` appends the *entire
input* to a tokenizer error. A QR read with one bit wrong — an ordinary event,
and the reason people re-scan — produced a message containing the whole invite,
which went into the `RdxLog` buffer that `DiagnosticsActivity` invites the user
to copy out and send to somebody, into a Toast, and into session state. The
second half was a 60-character prefix of any non-JSON payload, justified in a
comment by "not JSON, so it holds no token"; a truncated invite is not valid
JSON and holds the token in full. **Fixed:** all of it now goes through a pure,
tested redactor, and the throwable is not handed to the logger at all.

**A device-to-device transfer would have cloned an enrolled identity.** The
client's X25519 private key is a plain file in `filesDir`, and the code
justified that with `allowBackup="false"` — which governs cloud backup only.
From API 31, D2D transfer carries everything unless `dataExtractionRules`
excludes it. A phone-to-phone move would therefore have handed a second device
an identity the host never paired, and the host would have authenticated it,
because it presents the enrolled key. **Fixed:** both extraction paths exclude
every domain; `allowBackup="false"` remains for API < 31.

**Any app holding a MediaProjection could read the screen.** `FLAG_SECURE` was
set on nothing. It is now on the three windows that show host pixels or pairing
material — including the scanner, because the QR in front of the lens encodes a
live one-use token. That last one required subclassing zxing's capture activity:
a flag on our own scan activity would have protected a window that draws
nothing.

**What is not proven.** That the platform honours `FLAG_SECURE`, and that a real
D2D transfer carries nothing. Both need hardware — a second app recording, and a
second handset — and are text-level assertions plus platform documentation until
then. Neither is claimed as verified.

---

## 6. Revocation semantics

Stated explicitly, because "revoked" is a word products use loosely.

| action | who does it | effect | what it does **not** do |
|---|---|---|---|
| **Host: Stop** | owner, at the host | drops the listener, all sessions, capture, and input devices; the current invite dies | does not un-pair anything |
| **Host: new invite** | owner | invalidates the previous invite immediately | — |
| **Host: Revoke device** | owner | tombstones that device's public key; the live session is closed at its next command or within one 5s heartbeat, whichever comes first, and held input is released; future `AuthMode::Paired` fails closed | does not touch the phone's private key, and does not need to. **The in-flight half was NOT TRUE until 2026-09-07** — see P3 |
| **Phone: Forget host** | phone holder | deletes the stored host public keys and endpoint; a future connection requires a fresh signed QR | does not tell the host anything, and must not be relied on by the owner |
| **Phone: Unpair after identity mismatch** | phone holder, deliberately | clears the pin **only** after the user sees both fingerprints and confirms | never automatic — no silent TOFU re-pinning |
| **Process crash** | — | the OS closes the socket and destroys the uinput devices | does not revoke pairing |

**The asymmetry is deliberate.** Only the host can make an authorization
decision, so only host-side revocation is authoritative. Phone-side *Forget* is
hygiene for the phone's owner; it is not a security control the desktop's owner
may depend on.

**Input revocation is a live-session operation, not just a state flag.** Revoking
input mid-drag must release every pressed button *before* the denial takes
effect — after revocation an `Up` event is refused, and a host left button held
with no way to release it drag-selects everything the cursor crosses. The
Android client already orders it this way (`InputController.requestDisable()`);
the host side must match.

---

## 7. Out of scope

Named so that absence is a decision rather than an oversight.

1. **Physical compromise of the host.** An attacker with hands on the unlocked
   workstation already has everything RemoteDexter could grant. Disk encryption
   and screen lock are the OS's job.
2. **Physical compromise of an unlocked paired phone.** See §5.3. Android lock
   and encryption are the boundary; host-side revoke is the remedy.
3. **A compromised host OS or kernel.** Below every boundary in §3.
4. **Malicious owner.** RemoteDexter does not defend the desktop against the
   person who owns it.
5. **Metadata privacy over a relay.** §5.4.
6. **Multi-user hosts and headless servers without an active local seat.** The
   `uaccess` opt-in is defined for a seated local session on Ubuntu 26.04.
7. **Denial of service by resource exhaustion of the network itself.**
8. **NVIDIA-specific display behaviour.** The VM harness is virtio-gpu and
   llvmpipe; live-compositor experimentation is forbidden by Article XIV. Any
   NVIDIA claim stays **UNVERIFIED**.

---

## 8. Properties the release gate must prove

Block 14 gates these directly. Listed here so the threat model and the gate
cannot drift apart. **P4 and P5 became real in Block 2**: both are now executed
assertions in `session_core`, and both were shown to fail when the invariant
behind them was deliberately removed.

| # | property | proven by |
|---|---|---|
| P1 | No listener exists in Stopped state | **PROVEN (Block 3)** — `ss` in `BaxtersVMHarness`, plus 18 `host_controller` tests on real sockets; `scripts/vm-host-console-proof.sh` |
| P2 | Host pin continuity: a changed host key blocks | **PROVEN in suite** — `host_app::pinned_noise_rejects_wrong_host_pin_without_activation` and `host_app::pinned_noise_rejects_invalid_pin_before_connecting`, both executed every gate run. The real-device half is operator proof and was closed on 2026-08-23 |
| P3 | A revoked device key fails closed | **RECONNECT: PROVEN in suite** — `host_app::the_shipping_client_is_refused_once_revoked`, which drives the SHIPPING client rather than a test double, so a revocation that binds only in the store cannot pass it. **LIVE SESSION: implemented 2026-09-07, NOT YET PROVEN ON HARDWARE.** This row previously read "PROVEN" unqualified and the table above claimed the current session was disconnected in flight. IT WAS NOT. The named test proves only that a revoked device cannot RECONNECT; the device store was consulted once, at authentication, and nothing afterwards associated a running connection with the key that authorized it — so a revoked phone kept the session it already held. The UI text was accidentally honest about this ("a revoked device cannot reconnect"); this document was not. Found by an outside security review. Now the `live_session_verdict` decision in host_app is consulted before every command and on the existing 5s heartbeat, using `pairing`'s read-only `is_authorized` so the check cannot itself write the store — `authorize_paired` records `last_seen_at` and would have turned a security check into a continuous disk write. Unit-proven and red-proven by `host_app::revoking_a_device_terminates_the_session_it_already_has`, `host_app::a_forgotten_device_also_loses_its_live_session` and `host_app::revoking_one_device_does_not_disturb_another`. THOSE PROVE THE DECISION, NOT THE LOOP: only a phone can show a revoked device losing a live session with held input released, and that is asked as round 14 |
| P4 | Viewing never grants control | **PROVEN** — `session_core::authorize_input_requires_explicit_grant`; deleting the grant check turns 4 tests red |
| P5 | Unknown geometry denies absolute input | **PROVEN** — `session_core::unknown_geometry_denies_absolute_input`; making the clamp fail-open turns exactly that test red |
| P6 | No token in plaintext anywhere — UDP, logs, telemetry, filesystem, NFC, BLE | **PROVEN (Block 4)** — `scripts/vm-pairing-leak-proof.sh`: old host 4 `session_token` matches, new host 0 tokens / 0 broadcasts / 0 resolver probes |
| P7 | No private key bytes in any log | **PROVEN (Block 14)** — `pairing::nothing_the_pairing_service_emits_contains_the_private_key`. Was "log scan", which is a person reading output: it passes whenever nobody looks and cannot fail a build. Now a known secret is driven through every public method that produces a string and asserted absent as raw, hex and base64. Two `should_panic` tests prove the detector detects, and a third proves the surfaces are non-empty — an absence check that cannot tell "nothing leaked" from "nothing happened" is not a test |
| P8 | Pre-auth work is bounded | **PROVEN (Block 14, 2026-09-01)** — `host_controller::PreAuthLimit`: at most 4 connections in the pre-auth window and 10s before an unauthenticated one is dropped. Message size was already bounded (`wire::input_payloads_are_bounded_but_not_reinterpreted`, `host_app::an_oversized_chunk_is_refused_rather_than_truncated`, `host_app::an_oversized_payload_is_refused_whole`); connection COUNT and handshake DURATION were not, and this row claimed tests that had never been written. Now: `host_controller::a_stranger_cannot_hold_more_than_the_pre_auth_bound` drives the real accept loop on real sockets, and four unit tests cover the boundary and the deadline. An authenticated peer releases its slot, so a live session never consumes one |
| P9 | Clean shutdown releases every pressed button and closes the port | **PROVEN ON LINUX on hardware 2026-09-05** — Ubuntu 26.04 / GNOME 50.1 / Wayland, SM-G970U. `shutdown released input state: 0 key(s), 1 button(s)`, with a `button 0 Down` and no matching Up preceding it. **WAS NOT TRUE ON WINDOWS UNTIL 2026-09-06; PROVEN THERE 2026-09-07 (round 13)** — `0 key(s), 1 button(s)`, the held condition verified mechanically before the close (a watcher required the held set non-empty and stable for 1200 ms, then `PostMessage(hwnd, WM_CLOSE)`), and `GetAsyncKeyState` read back afterwards showing no button and no modifier stuck. THE BUTTON HALF IS HARDWARE-PROVEN ON BOTH PLATFORMS; THE `key(s)` HALF IS UNIT-TESTED ONLY and cannot be driven from the shipped client, which sends every key Down and Up together unconditionally — see the row below. the `shutdown` dispatch in `modules/module10/src/inject.rs` had ONE arm, for Linux, while `close_input` in host_app calls it on host Stop and window close from shared code — so on Windows a button held at that moment was never released. The Windows `release_input_state` existed and worked (round 4, 2026-08-31); shutdown simply never called it, and a stale doc comment still said Windows had no release path at all. Fixed by adding the arm and a Windows `shutdown` that reports in the same shape Linux does. Asked as round 13 and answered |
| P10 | Wayland capture survives a host restart via the portal restore token | **PROVEN on hardware 2026-09-05** — token deleted, first start prompted, second start silent with capture live |
| P11 | Install alone runs, listens, and changes nothing; purge reverses it | **PROVEN (Block 13, 2026-09-01)** — `scripts/test-deb-purge.sh` in `BaxtersVMHarness` from the pristine `clean-desktop` snapshot: sockets, groups, enabled units, udev rules, the `/dev/uinput` ACL, user data and host keys all unchanged by install; purge restored every one. Red proven with a deliberately-granting build — three independent assertions fired. `deb-inert` gates the package's contents on every run |
| P12 | APK permissions are exactly INTERNET, FOREGROUND_SERVICE, FOREGROUND_SERVICE_DATA_SYNC, WAKE_LOCK, CAMERA | **PROVEN** — the `android-permissions` row in `scripts/gate.sh` asserts the exact set on every run, so an added permission fails the gate rather than shipping |


### Where each proof lives, and what still has none

`scripts/check_threat_coverage.sh` asserts that every test named in this table
still exists, so a property cannot quietly lose its proof to a rename. It is the
`threat-coverage` row in `scripts/gate.manifest`.

**Machine-checked on every gate run:** P2, P3, P4, P5, P7, P8, P12.

**Proven once in a VM or on hardware, and recorded rather than re-run:** P1, P6,
P11. These need a disposable machine or a real seat; the gate names them and
does not pretend to re-prove them.

**Operator proof only, and BOTH NOW CLOSED (2026-09-05).** P9 and P10 needed a
person with a phone and a real seat, and got one. The evidence is recorded with
that date, including what each run could and could not distinguish.

They were the honest remaining gap in this release. P9 on Windows was open for
one day — the property held on Linux and the `shutdown` dispatch had a Linux arm
only — and was proven there on 2026-09-07. Closing a property on one platform and
writing "PROVEN" without naming the platform is how that stayed invisible; every
row now names its platform.

What remains needs hardware nobody here has: x86_64 native load, and
multi-monitor cursor origin.

Both were closed by running them, not by writing the procedure down. **Writing a
runbook does not close a property.** Neither row moved off "runbook" until a run
was recorded with its evidence — for P9 the release line and what was held, for
P10 whether the second start prompted and the token file's mtime. A row that says
"proven" with nothing behind it is worse than one that still says "runbook",
because the next person stops looking.

**P8 was the audit's finding and is now closed.** On 2026-09-01 this row was
asserting something untrue: it claimed connection-limit tests, and there were
none, because there were no limits. The bound was written the same day, red
proven both ways — with the policy removed, and with the policy left correct but
not consulted, which is how it would actually regress.

---

## 9. Operational advice for running a host

1. **Start the host deliberately, and choose the interface yourself.** Nothing
   listens until you do, and the console never preselects an interface or
   remembers the last one — that is a safety property, not an omission. Binding
   to a wide interface exposes the handshake port to everyone who can reach it;
   the handshake is bounded and rate-limited, but a port you did not mean to open
   is still a port you did not mean to open.

2. **Grant only the capability you need, per launch.** Viewing and control are
   separate. `run.sh` grants capture alone; control requires `RD_CAP_INPUT=1`
   explicitly, and clipboard is separate again. There is no persisted grant and
   no configuration file that can quietly widen one.

3. **Check the fingerprint when you pair.** The client pins the host identity, so
   the pairing moment is where trust is established. The host shows its
   fingerprint on screen; a relay cannot alter it without the client refusing the
   session, and that refusal is what makes an untrusted relay survivable.

4. **Protect the host identity keys.** `host_static_identity.key` and
   `host_signing_identity.key` under `target/release/` are the host's identity.
   Anyone holding them can present themselves as your host to a paired client.
   They are ignored by git, and they should never be copied, printed or shared —
   a public fingerprint is sufficient for every diagnostic purpose.

5. **The `/dev/uinput` grant is opt-in and reversible.** Installing the package
   grants nothing. If you enable it from the host UI, it adds exactly one udev
   rule; disabling revokes the access rather than merely removing the file.

---

## Known limits at release — peripherals

**A USB mouse plugged into the phone is not supported, and this is an absence of
code rather than an unproven claim.** The distinction matters: `multi-monitor`
and `x86-64-load` are properties of code that exists and has not been verified;
this is a feature that was never written, so "deferred" here must not be read as
"believed to work".

The client has no mouse handling at all — no `onGenericMotionEvent`, no
`onHoverEvent`, no `SOURCE_MOUSE`, no `getButtonState`, no `ACTION_SCROLL`. Its
only input path is the touch listener at `MainActivity.kt:309`.

Android delivers mouse input down two paths and the client implements one, so
the observed behaviour is:

| action | result |
|---|---|
| move the mouse | **nothing** — hover events are ignored; the phone's cursor moves, the host's does not |
| click | works, but the host pointer **teleports** to that point first |
| click and drag | works while the button is held |
| scroll wheel | **nothing** |
| right / middle button | not distinguished; most likely registers as a left click |

The teleporting is not a bug in itself: `SurfaceTouchRouter` treats every contact
as absolute positioning, which is right for a finger and wrong for a mouse.

Supporting it properly needs hover and scroll handling, button-state reading, and
relative-delta movement. That is a feature with its own hardware round. Nothing
depends on it, so it is deferred to a post-release update rather than rushed
before one.
