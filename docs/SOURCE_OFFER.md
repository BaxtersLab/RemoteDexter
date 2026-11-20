# Written offer of Corresponding Source — RemoteDexter

**RemoteDexter is licensed AGPL-3.0-only.** That is a deliberate choice by its
author, not an inheritance: RemoteDexter is independently implemented and
contains no third-party copyleft code. The licence brings **two separate
obligations**, not one, and meeting §6 does not meet §13.

Status of each is stated plainly below. **One is unmet in code today.**

---

## 1. §6 — conveying the binary

Whenever a compiled RemoteDexter is conveyed — the `.deb`, the Windows
`host_app.exe`, the Android `.apk` — the Corresponding Source for **that exact
build** must be available to the recipient.

GPLv3 §6 offers several ways to satisfy this. The two that fit direct
distribution:

* **§6(a)** — accompany the binary with the source on the same medium.
* **§6(d)** — offer source **from the same place** as the binary, at no further
  charge. If the binary is a download, the source must be a download beside it.

**§6(b) — a written offer valid for three years — is the option to avoid.**
It is the one that outlives the project's attention: it obliges you to still be
able to produce the source for *that build* in three years, to anyone who asks,
whether or not the download page still exists. §6(d) discharges the duty the
moment the file sits next to the binary.

**Recommended: §6(d).** Ship `remotedexter-<version>-src.tar.gz` beside every
binary artifact, generated from the exact commit the binary was built from.

### What "Corresponding Source" has to include

More than the workspace. It is everything needed to **build, install and run**
the work:

* the full source tree at the build commit (`git archive` output is the right
  shape — tracked files, no `target/`, no `.git`);
* `Cargo.lock` and the Gradle lockfiles, so the dependency set is reproducible
  rather than "whatever crates.io serves today";
* the build scripts: `scripts/build_android_so.sh`, `scripts/build-deb.sh`,
  `scripts/third_party_notices.py` (the `.deb`'s licence texts),
  `apk/gradlew` and the wrapper properties;
* installation information for the `.deb` — the packaging directory.

It does **not** include the toolchain itself (rustc, the NDK, Gradle) — those
are System Libraries and general-purpose tools under §1.

### Where to get it

- **Distribution URL:** `https://github.com/BaxtersLab/RemoteDexter`
- **Contact for source requests**, should a download ever be unreachable:
  `baxtersbeats@outlook.com` — the same address carried in the `.deb`
  `Maintainer` field.

### To generate the source archive for a release

```sh
git archive --format=tar.gz --prefix=remotedexter-<version>/ \
    -o remotedexter-<version>-src.tar.gz <the exact commit>
sha256sum remotedexter-<version>-src.tar.gz
```

Publish it beside the binary, with the digest. **The commit must be the one the
binary was built from** — the APK's `versionName` carries it (`3.0.13+<sha>`),
which is exactly why the build stamps it.

---

## 2. §13 — the network clause, and the part that is UNMET

> If you modify the Program, your modified version must prominently offer all
> users interacting with it remotely through a computer network … an
> opportunity to receive the Corresponding Source.

This is the clause that distinguishes AGPL from GPL, and RemoteDexter is exactly
the shape of program it was written for: **a phone interacts with the host over a
network**. RemoteDexter is AGPL-3.0-only, so anyone who modifies it and lets
users reach it over a network owes them the Corresponding Source.

The author is the copyright holder and is not bound by their own grant, so the
notice below is not compliance with an obligation imposed from outside. It is
there because a licence that promises users source they cannot find is worth
nothing, and because every downstream fork **is** bound by §13 and should have a
working example to copy.

**CLOSED 2026-09-04.** Both artifacts now carry the notice: the host console
beside its fingerprint block, the Android client in its settings screen. Pinned
by two tests, one of which reads the Kotlin resources from the Rust suite so the
two addresses cannot drift apart.

*Before that date neither surfaced anything* — no occurrence of AGPL, "licence",
"license" or a source URL in `host_app/src/ui.rs`, `activity_main.xml`,
`activity_settings.xml`, or `strings.xml`.

That the operator and the phone user are usually the same person does **not**
discharge §13. The clause is about what the software offers, not about who
happens to be holding the phone.

### The smallest change that satisfies it

Two lines of text, one in each artifact:

1. **Host console** — beside the existing "This host's fingerprint" block, which
   is already the identity/provenance section:
   > RemoteDexter — AGPL-3.0-only. Source: `<url>`

2. **Android client** — in the settings screen, which already exists:
   > RemoteDexter — AGPL-3.0-only. Source: `<url>`

The host's notice is the load-bearing one: the phone user is the remote user
§13 is about, so the offer should be reachable **from the client**, which is why
it goes in the client's settings rather than only in the host.

**Done.** `SOURCE_URL` in `host_app/src/ui.rs` and `licence_source_url` in
`strings.xml`, surfaced in both UIs and asserted by tests that fail if either is
absent or becomes a placeholder. Red proven by renaming the Android view id.

---

## 3. Third-party obligations that travel with the binary

`scripts/licence_scan.py` checks compatibility mechanically and is a gate row.
Scope: the normal-dependency closure of the two distributed artifacts,
**453 external packages** as of 2026-09-04. Dev- and build-dependencies are
excluded because they are not conveyed.

Compatibility is not the same as attribution. These still require notices to
travel with the binary:

| licence | requirement |
|---|---|
| MIT, BSD-2/3-Clause, ISC | copyright notice and permission text retained |
| Apache-2.0 | notice retained; NOTICE file contents passed on where present |
| OFL-1.1 + Ubuntu-font-1.0 | `epaint_default_fonts` — an **embedded font**, attribution required |
| Unicode-3.0 | `unicode-ident` — data licence, attribution |
| BSL-1.0 | `clipboard-win`, `error-code` — no binary attribution required |

**One dual-licence choice must be recorded rather than assumed:**
`self_cell 1.3.0` is offered `Apache-2.0 OR GPL-2.0-only`. **GPL-2.0-only is
incompatible with the GPLv3 family**, so RemoteDexter takes the **Apache-2.0**
arm. Taking the other would make the work undistributable.

`docs/THIRD_PARTY_NOTICES.md` is the human record and is gated separately.

---

## 4. What changed on 2026-09-04, and why it matters here

The scan is scoped to what is *distributed*, and that scoping found a defect:

**`host_app` declared `module15_host_session` and never referenced it.** That one
unused line pulled in `rodio` and **seven MPL-2.0 `symphonia` crates** — an
MP3/ADPCM/WAV decoder — linked into a remote-desktop host that decodes no audio
files. Removing the line took the distributed closure from **500 to 453**
packages and removed every MPL-2.0 obligation.

MPL-2.0 is compatible (§3.3 names GPL and AGPL as Secondary Licences), so this
was never a licence *violation*. It is worth recording anyway: **an unused
dependency edge is still a conveyed work**, with notices to carry and source to
correspond to, and nobody would have looked for an audio decoder in this binary.

Twelve workspace crates also declared no licence at all — everything under
`modules/`, plus `governor` and `sil`. All nineteen now declare AGPL-3.0-only,
and the scan fails if one stops.
