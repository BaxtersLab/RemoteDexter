#!/usr/bin/python3 -I
"""third_party_notices — the THIRD_PARTY_LICENSES file a Baxters package ships beside its Rust binaries.

WHY. MIT, BSD, ISC, Zlib and Apache-2.0 are permissive, but each of them requires its copyright
and licence notice to accompany every copy of the software, binaries included. A statically
linked Rust binary contains every crate its normal dependency graph reaches, so the package must
carry exactly those notices. A hand-written list drifts: Stereo Mix's named FFmpeg, which that
port never used, for months. This one is generated from the lockfile when the package is built,
so it lists what links, no more and no less. On 2026-10-20 an audit of r10k found eight packages
shipping Rust binaries with no third-party notices at all.

WHAT COUNTS. `cargo metadata --locked --offline --filter-platform TARGET` resolves the graph the
release build uses. The crates listed are those reachable from the named packages through NORMAL
dependency edges. Excluded: the workspace's own members (the package's own licence covers them);
proc-macro crates, build-dependencies and dev-dependencies (they run in the compiler and never
reach the binary); and crates for other platforms. The Rust standard library, which every Rust
binary links statically and which cargo never lists, is always included.

TEXTS. Each crate's own licence files: any file under the crate whose name starts with LICENSE,
LICENCE, COPYING, COPYRIGHT, NOTICE, UNLICENSE, OFL or UFL. A crate that ships none gets the
standard text of a licence its expression offers: the system copy of Apache-2.0, MPL-2.0 or
CC0-1.0, or the embedded MIT, ISC, Zlib, BSD-2-Clause or BSD-3-Clause text with the crate's own
authors as the copyright holder. A crate this tool cannot cover is refused by name, because an
unlisted notice is the defect it exists to prevent. `--notice-file CRATE=PATH` supplies a text
by hand.

TERMS BEYOND A NOTICE. A licence can ask for more than its text. The Mozilla Public License
(file-level copyleft) requires everyone who receives the binary to be told where the source of
its MPL-covered files is; a crate under it, with no other licence on offer, is listed with its
crates.io archive and the SHA-256 Cargo.lock recorded, which names the exact source compiled.
Stronger copyleft (GPL, LGPL, EPL, ...) reaches the whole binary, so this tool refuses such a
crate, and one that declares no SPDX expression at all, until the package says how it meets the
terms: `--terms-met CRATE=HOW`, printed as given. Stereo Mix meets LAME's LGPL-3.0 that way, by
shipping its own source. Only crates.io releases are called unmodified; any other source is named.

Usage:
  third_party_notices.py --manifest-path DIR/Cargo.toml --package NAME [--package NAME ...]
                         [--target TRIPLE] [--title TEXT] [--notice-file CRATE=PATH ...]
                         [--terms-met CRATE=HOW ...]
Writes the notices to stdout. Exit: 0 written, 1 a crate is refused (named), 2 cannot run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
# Licence families whose terms go beyond keeping a notice. MPL is met by citing the source.
COPYLEFT = re.compile(r"(?i)^(a?gpl|lgpl|mpl|epl|cddl|eupl|osl|cpal|sspl|ms-rl)(-|\+|\s|$)")
LICENCE_FILE = re.compile(r"(?i)^(licen[cs]e|copying|copyright|notice|unlicense|ofl|ufl)([-._ ].*)?$")
SKIP_DIRS = {".git", "target"}
SYSTEM_TEXTS = {
    "Apache-2.0": "/usr/share/common-licenses/Apache-2.0",
    "MPL-2.0": "/usr/share/common-licenses/MPL-2.0",
    "CC0-1.0": "/usr/share/common-licenses/CC0-1.0",
}
# Preference when a crate that ships no licence file offers a choice (`MIT OR Apache-2.0`).
PREFERENCE = ["Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "MPL-2.0", "CC0-1.0"]

MIT = """Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
ISC = """Copyright (c) {holders}

Permission to use, copy, modify, and/or distribute this software for any purpose with or without
fee is hereby granted, provided that the above copyright notice and this permission notice appear
in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
OF THIS SOFTWARE.
"""
ZLIB = """Copyright (c) {holders}

This software is provided 'as-is', without any express or implied warranty. In no event will the
authors be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial
applications, and to alter it and redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim that you wrote the
   original software. If you use this software in a product, an acknowledgment in the product
   documentation would be appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be misrepresented as
   being the original software.
3. This notice may not be removed or altered from any source distribution.
"""
_BSD_HEAD = """Copyright (c) {holders}

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
   and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials provided
   with the distribution.
"""
_BSD_THIRD = """3. Neither the name of the copyright holder nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific prior written
   permission.
"""
_BSD_TAIL = """
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
EMBEDDED_TEXTS = {"MIT": MIT, "ISC": ISC, "Zlib": ZLIB,
                  "BSD-2-Clause": _BSD_HEAD + _BSD_TAIL, "BSD-3-Clause": _BSD_HEAD + _BSD_THIRD + _BSD_TAIL}


class CannotRun(Exception):
    pass


def metadata(manifest: Path, target: str) -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline",
           "--filter-platform", target, "--manifest-path", str(manifest)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise CannotRun(f"cargo metadata failed for {manifest}: {result.stderr.strip()[-600:]}")
    return json.loads(result.stdout)


def linked_crates(md: dict, roots: list[str]) -> list[dict]:
    """The third-party packages reachable from the named workspace members by normal edges."""
    packages = {p["id"]: p for p in md["packages"]}
    members = set(md["workspace_members"])
    nodes = {n["id"]: n for n in md["resolve"]["nodes"]}
    start = [i for i in members if packages[i]["name"] in roots]
    missing = sorted(set(roots) - {packages[i]["name"] for i in start})
    if missing:
        raise CannotRun(f"not workspace members of this manifest: {', '.join(missing)}")
    seen, todo = set(), list(start)
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):   # normal edge for this platform
                todo.append(dep["pkg"])
    return sorted((packages[i] for i in seen
                   if i not in members and not any("proc-macro" in t["kind"] for t in packages[i]["targets"])),
                  key=lambda p: (p["name"], p["version"], p["id"]))


def licence_files(crate_dir: Path) -> list[Path]:
    found = []
    for path in sorted(crate_dir.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(crate_dir).parts[:-1]):
            continue
        if path.is_file() and not path.is_symlink() and LICENCE_FILE.match(path.name) and path.suffix not in (".rs", ".toml"):
            found.append(path)
    return found


def _terms(expression: str) -> list[list[str]]:
    """An SPDX expression as AND-groups of OR-alternatives: `(A OR B) AND C` -> [[A, B], [C]]."""
    expr = expression.replace("/", " OR ").strip()
    groups = []
    for part in re.split(r"\s+AND\s+", expr):
        part = part.strip().strip("()").strip()
        groups.append([alt.strip().strip("()").strip() for alt in re.split(r"\s+OR\s+", part)])
    return groups


def standard_texts(crate: dict) -> list[tuple[str, str]] | None:
    """(label, text) for a crate that ships no licence file, or None when this tool has none."""
    expression = crate.get("license") or ""
    if not expression:
        return None
    holders = ", ".join(crate.get("authors") or []) or f"the {crate['name']} authors"
    chosen = []
    for alternatives in _terms(expression):
        options = [a for a in PREFERENCE if a in alternatives]
        if not options:
            return None
        spdx = options[0]
        if spdx in SYSTEM_TEXTS:
            text = Path(SYSTEM_TEXTS[spdx]).read_text(encoding="utf-8")
        else:
            text = EMBEDDED_TEXTS[spdx].format(holders=holders)
        chosen.append((f"{spdx} (standard text; the crate ships no licence file)", text))
    return chosen


def obligations(crate: dict) -> tuple[list[str], list[str]]:
    """(MPL terms, stronger terms) the crate's licence imposes on a binary containing it.

    An AND-group imposes a term only when it offers nothing outside the copyleft families:
    `MIT OR MPL-2.0` imposes nothing; `MPL-2.0` and `Apache-2.0 AND MPL-2.0` impose MPL-2.0. A
    group offering MPL beside a stronger licence imposes the MPL."""
    expression = crate.get("license") or ""
    if not expression:
        return [], ["no SPDX licence expression, so its terms cannot be checked"]
    mpl, strong = [], []
    for alternatives in _terms(expression):
        if not all(COPYLEFT.match(a) for a in alternatives):
            continue
        weak = [a for a in alternatives if a.upper().startswith("MPL-")]
        if weak:
            mpl.append(weak[0])
        else:
            strong.append(" OR ".join(alternatives))
    return mpl, strong


def lock_checksums(md: dict) -> dict[tuple, str]:
    """(name, version, source) -> the SHA-256 Cargo.lock records for that package's archive."""
    lock = tomllib.loads((Path(md["workspace_root"]) / "Cargo.lock").read_text(encoding="utf-8"))
    return {(p["name"], p["version"], p.get("source")): p["checksum"]
            for p in lock.get("package", []) if p.get("checksum")}


def _para(text: str) -> list[str]:
    return textwrap.wrap(text, width=100)


RUST_STD = {"name": "rust-std", "version": "(the Rust toolchain that built the binary)",
            "license": "MIT OR Apache-2.0", "authors": ["The Rust Project Developers"],
            "repository": "https://github.com/rust-lang/rust", "manifest_path": None, "id": "rust-std"}


def build(md: dict, roots: list[str], title: str, target: str, manual: dict[str, Path],
          terms_met: dict[str, str] | None = None) -> tuple[str, list[str]]:
    terms_met = terms_met or {}
    crates = linked_crates(md, roots) + [RUST_STD]
    checksums = lock_checksums(md)
    uncovered, texts, users = [], {}, {}
    rows, sources, met, outside, strong_names = [], [], [], [], set()
    for crate in crates:
        key = f"{crate['name']} {crate['version']}"
        licence = crate.get("license") or "none declared"
        mpl, strong = obligations(crate)
        if strong:
            strong_names.add(crate["name"])
        crate_dir = Path(crate["manifest_path"]).parent if crate["manifest_path"] else None
        entries = []
        for path in licence_files(crate_dir) if crate_dir else []:
            entries.append((path.relative_to(crate_dir).as_posix(), path.read_text(encoding="utf-8", errors="replace")))
        if not entries and crate["name"] in manual:
            entries.append((f"supplied by hand ({manual[crate['name']].name})", manual[crate["name"]].read_text(encoding="utf-8")))
        if not entries:
            entries = standard_texts(crate) or []
        if not entries:
            uncovered.append(f"{key} (licence: {licence}): no licence text; supply one with --notice-file {crate['name']}=PATH")
            continue
        from_crates_io = crate.get("source") == CRATES_IO
        if mpl:
            checksum = checksums.get((crate["name"], crate["version"], crate.get("source")))
            if not (from_crates_io and checksum):
                uncovered.append(f"{key} (licence: {licence}): {mpl[0]} requires its source to be cited, and only"
                                 " a crates.io release with a Cargo.lock checksum can be")
                continue
            sources.append(f"  {key}  [{', '.join(mpl)}]  https://crates.io/api/v1/crates/{crate['name']}/"
                           f"{crate['version']}/download  sha256 {checksum}")
        if strong:
            if crate["name"] not in terms_met:
                uncovered.append(f"{key} (licence: {licence}): terms beyond a notice ({'; '.join(strong)});"
                                 f" say how this package meets them with --terms-met {crate['name']}=HOW")
                continue
            met.append(f"  {key}  [{licence}]  {terms_met[crate['name']]}")
        if crate is not RUST_STD and not from_crates_io:
            outside.append(f"{key} ({crate.get('source') or 'path dependency'})")
        refs = []
        for label, text in entries:
            digest = hashlib.sha256(text.encode()).hexdigest()[:16]
            texts.setdefault(digest, text)
            users.setdefault(digest, []).append(f"{key}: {label}")
            refs.append(digest)
        source = crate.get("repository") or crate.get("source") or "path dependency"
        rows.append(f"  {crate['name']} {crate['version']}  [{crate.get('license') or 'see text'}]  {source}  texts: {', '.join(refs)}")
    stale = sorted(set(terms_met) - strong_names)
    if stale:
        raise CannotRun(f"--terms-met names crates that link with no such terms: {', '.join(stale)}")
    out = [f"THIRD-PARTY SOFTWARE NOTICES — {title}", "",
           f"{title} links the following {len(rows) - 1} third-party Rust crates, and the Rust standard library, into its binaries.",
           f"This list was generated from the Cargo lockfile for {target}: normal dependencies of",
           f"{', '.join(sorted(roots))}, excluding the workspace's own crates, build-time and test-only",
           "crates. Each crate's licence notice follows its entry, by text id."]
    out += _para("Every crate is the unmodified crates.io release whose checksum Cargo.lock records." if not outside
                 else "Every crate is the unmodified crates.io release whose checksum Cargo.lock records, except these,"
                      " which come from elsewhere and are not claimed to be unmodified: " + ", ".join(outside) + ".")
    out += ["", "CRATES", ""]
    out += rows
    if sources:
        out += ["", "SOURCE CODE OF THE MPL-LICENSED CRATES", ""]
        out += _para("The Mozilla Public License requires that everyone who receives this binary be told where the"
                     " source code of its MPL-covered files can be obtained. Each crate below is the unmodified"
                     " crates.io release: the archive at its address is that crate's complete source, and its"
                     " SHA-256 is the checksum Cargo.lock recorded for this build.")
        out += [""] + sources
    if met:
        out += ["", "LICENCE TERMS THIS PACKAGE MEETS SEPARATELY", ""]
        out += _para("These crates are under licences whose terms go beyond keeping a notice. The package that"
                     " ships this file meets them as stated:")
        out += [""] + met
    out += ["", "LICENCE TEXTS", ""]
    for digest in sorted(texts, key=lambda d: users[d][0]):
        out += [f"===== text {digest} — used by:"] + [f"  {u}" for u in users[digest]] + ["", texts[digest].rstrip("\n"), ""]
    return "\n".join(out) + "\n", uncovered


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest-path", required=True, type=Path)
    ap.add_argument("--package", action="append", required=True, dest="packages")
    ap.add_argument("--target", default="x86_64-unknown-linux-gnu")
    ap.add_argument("--title")
    ap.add_argument("--notice-file", action="append", default=[], metavar="CRATE=PATH")
    ap.add_argument("--terms-met", action="append", default=[], metavar="CRATE=HOW")
    args = ap.parse_args(argv)
    try:
        manual = {}
        for spec in args.notice_file:
            name, _, path = spec.partition("=")
            if not name or not path or not Path(path).is_file():
                raise CannotRun(f"--notice-file needs CRATE=PATH to an existing file: {spec!r}")
            manual[name] = Path(path)
        terms_met = {}
        for spec in args.terms_met:
            name, _, how = spec.partition("=")
            if not name or not how.strip():
                raise CannotRun(f"--terms-met needs CRATE=HOW, saying how the terms are met: {spec!r}")
            terms_met[name] = how.strip()
        md = metadata(args.manifest_path, args.target)
        text, uncovered = build(md, args.packages, args.title or ", ".join(args.packages), args.target, manual,
                                terms_met)
    except (CannotRun, OSError, ValueError, KeyError) as exc:
        print(f"third_party_notices: cannot run: {exc}", file=sys.stderr)
        return 2
    if uncovered:
        print("third_party_notices: refused —\n  " + "\n  ".join(uncovered), file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
