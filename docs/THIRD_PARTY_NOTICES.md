# Third-party notices — RemoteDexter

**RemoteDexter is licensed AGPL-3.0-only.** This file records every external
work RemoteDexter links against or absorbs, and what obligation each one
carries. RemoteDexter itself is independently implemented. It is maintained by hand and gated: a new
crate, Gradle dependency, or derived file that is absent from here is a gate
failure, not an oversight.

Established 2026-08-21 (Block 1). Amend it in the same change that introduces
the dependency — never afterwards.

---

## 1. VoDesktop — operator-owned code absorbed into RemoteDexter

`vodesktop-core` and `vodesktop-capture` were the operator's own crates,
declared `license = "MIT"` in their manifests. **Block 2 absorbed them** (done,
2026-08-21):

| was | is now | fate |
|---|---|---|
| `VoDesktop/core` (MIT, zero-dependency) | `crates/session_core/` | permanent — RemoteDexter's authorization authority |
| `VoDesktop/capture` (MIT) | ~~`crates/capture_windows_printwindow/`~~ | **DELETED in Block 8.** Its per-window `PrintWindow` policy was VoDesktop's, not RemoteDexter's; replaced by full-desktop `crates/capture_windows/`. Recoverable from git history at `f247471~`. |

* MIT is compatible with AGPL-3.0-only, and the operator owns the copyright in
  both works, so the combined work ships AGPL-3.0-only. Both absorbed crates now
  declare `license.workspace = true`.
* Both crates' `lib.rs` carries an origin paragraph naming `VoDesktop/core` or
  `VoDesktop/capture` and stating what the rename changed, so the history is
  recorded rather than erased.
* The vocabulary changed with the ownership: `WindowId` -> `SurfaceId`,
  `WindowScope` -> `SurfaceScope`, `permit_window` -> `permit_surface`,
  `contract_id` -> `peer_id`. VoDesktop scoped a *contractor* to *windows* on a
  client's machine; RemoteDexter scopes a *paired device* to *surfaces* on its
  owner's. Every authorization invariant survived the rename, and one that had
  been enforced loosely in the host binary — the absolute-move geometry clamp —
  moved *into* the core, where it is now tested.
* The two `../../../VoDesktop` path dependencies are **gone**. `Cargo.lock`
  contains zero `vodesktop` entries, and `host_app` has been built and tested in
  an isolated copy with no `VoDesktop/` directory anywhere in reach.
* **This is the operator's own code and must be attributed as such.**

---

## 2. Rust dependencies

Full table, with purpose, licence and transitive counts:
[`DEPENDENCIES.md`](DEPENDENCIES.md).

Summary at the Block 1 baseline: **34 distinct direct external crates**,
**367 packages** in the resolved graph. Every direct crate is MIT, Apache-2.0,
BSD-3-Clause, or a dual/tri licence including one of those. **No copyleft
dependency other than RemoteDexter's own AGPL-3.0-only licence.**

---

## 3. Android dependencies

Full table in [`DEPENDENCIES.md`](DEPENDENCIES.md). `debugRuntimeClasspath`
resolves to **67 distinct `group:artifact` coordinates** at the Block 1
baseline.

| dependency | licence | why it is present |
|---|---|---|
| `androidx.core:core-ktx`, `androidx.appcompat:appcompat`, `androidx.constraintlayout:constraintlayout`, `androidx.lifecycle:lifecycle-service`, `androidx.lifecycle:lifecycle-runtime-ktx` | Apache-2.0 | platform support library, activity/service lifecycle |
| `com.google.android.material:material` | Apache-2.0 | Material components in the host/session UI |
| `com.journeyapps:zxing-android-embedded` (pulls `com.google.zxing:core`) | Apache-2.0 | QR pairing scanner — the only use of `CAMERA` |
| `org.bouncycastle:bcprov-jdk18on` | Bouncy Castle Licence (MIT-style) | Ed25519 invite-signature verification. Android's `java.security.Signature` gained `"Ed25519"` only at API 33 and `minSdk` here is 26. |
| `org.jetbrains.kotlin:*`, `org.jetbrains.kotlinx:*` | Apache-2.0 | Kotlin stdlib and coroutines, pulled by AGP |
| `junit:junit` *(test only)* | **EPL-1.0** | JVM unit tests. Test-scope only; never shipped in the APK. |
| `org.json:json` *(test only)* | Public Domain | a real JVM JSON implementation for the wire-contract test — Android's own `org.json` is stubbed to throw under unit tests |
| `androidx.test.ext:junit`, `androidx.test:core`, `androidx.test:runner` *(test only)* | Apache-2.0 | instrumentation tests on `rd-test-34` |

## 3a. Host console GUI (Block 3)

| dependency | version | licence | why |
|---|---|---|---|
| `eframe` / `egui` | **=0.36.1**, pinned | MIT OR Apache-2.0 | one immediate-mode Rust UI for Linux and Windows. `default-features = false`; only `wayland`, `wgpu`, `default_fonts`. eframe's DEFAULT features include `x11`, which Article XIV.4 forbids on this box — `scripts/check_no_x11.sh` proves the resolved graph, package set and linked binary are all free of it. |
| `if-addrs` | 0.15 | MIT OR BSD-3-Clause | enumerate non-loopback interfaces for the "which network?" picker. Small and single-purpose. |

`x11rb` and `x11rb-protocol` appear in the resolved graph via `arboard`, the
clipboard backend `egui-winit` enables by default and `eframe` does not switch
off. They are **pure Rust** (their only dependencies are `rustix` and
`gethostname`) and link no X library; the host binary contains no X11 library
name at all. Clipboard is cut from v1 and the console never uses it. Recorded
rather than hidden — see `scripts/check_no_x11.sh` §2.

EPL-1.0 (`junit`) is the only licence here that would be awkward to ship. It is
**test scope**, is not packaged into the APK, and must stay that way; the
licence-inventory check in Block 13 asserts it.

---

## 3b. Pairing (Block 4)

`crates/pairing` is RemoteDexter's own code. It replaced five crates and, with
them, `btleplug` (146 transitive crates, for a Bluetooth transport that did not
exist), `qrcodegen` (a second QR encoder), and `x25519-dalek 1.2` (whose
`zeroize = "=1.3"` pin had blocked the `snow` security upgrade for two blocks).
`ed25519-dalek` moved 1.x → 2.x across six crates in the same change.

RemoteDexter's signed-invite contract is its own. A public-ID-plus-reusable-
password rendezvous model was considered and explicitly rejected: enrollment is
by signed QR with remembered device keys, and the relay is ciphertext-only.

## 4. Fonts, icons, media

None vendored as of Block 1. Material icons arrive with
`com.google.android.material` (Apache-2.0). Anything added later needs a row
here before it is committed.

## 5. Licence texts in the Linux package

This file records obligations; it does not carry licence texts. Since
3.1.0.2-2 the Linux package also ships
`/opt/baxters/remotedexter/THIRD_PARTY_LICENSES`, beside `host_app`: every
third-party crate the host links, each with its licence's full text,
generated from `Cargo.lock` by `scripts/third_party_notices.py` when the
package is built. 3.1.0.2-1 shipped
without it. `scripts/check_deb_notices.sh` (gate row `deb-notices`) fails a
package that lacks it.
