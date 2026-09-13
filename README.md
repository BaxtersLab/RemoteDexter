# RemoteDexter

View and control a Linux or Windows desktop from an Android phone, over a
pinned encrypted session that the owner starts deliberately.

**Licence: AGPL-3.0-only.** See [Licence](#licence) — the network clause matters
for this kind of program.

## What it is

One user-started host process and one user-started Android app. The owner starts
the host, picks a network interface, and shows a QR code on the host screen. The
phone scans it, completes a pinned Noise XX handshake, and from then on views the
desktop and — separately, and only if granted — controls it.

**Installing the host starts nothing.** No enabled unit, no autostart, no daemon,
no open port, no group change, no device access. The `.deb` ships the optional
`/dev/uinput` grant as inert data under `/usr/share`; it is installed only if you
ask for it from the host UI, and `postinst` deliberately does nothing at all.

Capabilities are deny-by-default and granted per launch:

| variable | grants |
|---|---|
| `RD_CAP_SCREENSHOT` | screen capture (the supported launcher sets this) |
| `RD_CAP_INPUT` | keyboard and mouse control |
| `RD_CAP_CLIPBOARD` | clipboard access |

## Status

This is the first public release. It is built and gated on Linux; the Windows
host builds and is exercised separately. Things this project does **not** claim
are recorded as such — see [`ROADMAP.md`](ROADMAP.md), which lists deliberate
refusals rather than a wishlist, and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
which describes both the target design and the tree as it stands, marking the
gaps between them. A threat model that describes only the intended product is a
marketing document.

## Building

**Host** (Rust, stable toolchain):

```bash
cargo build --release -p host_app
./run.sh
```

`run.sh` is the supported entry point. It scrubs the environment variables that
break GTK and GSettings under Snap-contaminated sessions, and it grants viewing
only. To grant control as well:

```bash
RD_CAP_INPUT=1 ./run.sh
```

The host opens a console and does nothing until you pick an interface and press
Start. There is no listener, no capture and no input path before that.

**Debian package:**

```bash
./scripts/build-deb.sh
```

No root, no fakeroot, no network. The build refuses to produce a package if
anything credential-shaped has been staged into it.

**Android client:** a standard Gradle project under `apk/`. The native library
is built by `scripts/build_android_so.sh` for `arm64-v8a`, `armeabi-v7a` and
`x86_64`. Signing reads four environment variables you hold; nothing key-shaped
is read from the tree, and an unsigned release build succeeds — so verify the
result with `apksigner verify` rather than trusting the build's exit status.

## Going off-LAN: run your own relay

The host can dial out to a relay instead of listening, so it works from behind
NAT without opening a port. **The relay splices ciphertext and nothing else** —
it terminates no session and holds no session key, because the client pins the
host's identity and the Noise handshake runs end to end through it.

You are not expected to use anyone else's relay. `relayd` is in this repository
and is meant to be self-hosted: see
[`docs/RUNNING_YOUR_OWN_RELAY.md`](docs/RUNNING_YOUR_OWN_RELAY.md) for how to
build and run it, both authentication methods, and an explicit account of what a
relay operator can and cannot observe.

## Security

* [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what is defended, what is not,
  and where the tree falls short of the design.
* [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md) — hardening decisions and
  their reasons.
* [`docs/RUNNING_YOUR_OWN_RELAY.md`](docs/RUNNING_YOUR_OWN_RELAY.md) — relay
  operator visibility.

If you find a security problem, please report it privately rather than opening a
public issue.

## Licence

Copyright (C) Baxter. Licensed under the **GNU Affero General Public License,
version 3 only** — see [`LICENSE`](LICENSE).

AGPL §13 is the clause that distinguishes this from the GPL: if you modify
RemoteDexter and let others interact with it over a network, you must offer those
users the corresponding source of *your* modified version. See
[`docs/SOURCE_OFFER.md`](docs/SOURCE_OFFER.md).
