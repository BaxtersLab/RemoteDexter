#!/usr/bin/env bash
# Build the baxters-remotedexter .deb. No root, no fakeroot, no network.
#
# WHAT THE PACKAGE MUST BE, per Block 13
#
# Install alone runs nothing, listens on nothing and changes nothing: no enabled
# unit, no autostart, no daemon, no open port, no key, no ACL, no group change.
# The optional /dev/uinput grant ships as INERT DATA in the package directory and
# is installed only when the operator asks for it from the host UI. postinst does
# nothing at all, deliberately, and scripts/test-uinput-install.sh check 1 fails
# if it ever starts doing something.
#
# WHERE IT GOES, per the Baxters packaging contract (A1, 2026-08-18)
#
#   /opt/baxters/remotedexter/          all payload (A1 s1)
#       run.sh                          the only entry point (A1 s3)
#       host_app                        the host
#       remotedexter-enable-input       the one privileged operation, via pkexec
#       70-remotedexter-uinput.rules    inert data; copied out only by "Enable input"
#   /usr/bin/remotedexter               a symlink to run.sh, so the documented
#                                       `RD_CAP_INPUT=1 remotedexter` still works
#   /usr/share/applications/baxters-remotedexter.desktop
#   /usr/share/icons/hicolor/*/apps/baxters-remotedexter.png
#   /usr/share/doc/baxters-remotedexter/
#
# The rule is NOT put in /usr/lib/udev/rules.d, which A1 would allow: udev reads
# that directory, so the grant would be live from the moment of install -- a
# standing grant that "Disable input" could never take away.
#
# Every destination is written out in full rather than through a variable. The
# host's constants -- the helper it runs, the rule the helper reads, the binary
# the launcher execs -- are checked against THESE strings by host_app's tests
# (input_grant::tests::*_where_the_package_installs_it), so a layout change that
# forgets one of them fails in a second instead of on a user's machine.
#
# THE VERSION is the control file's, unchanged: 3.1.0.2-1. Until 3.0.13 it carried
# the commit (3.0.13+<sha>) so that two builds could never share a version. In
# the Baxters train that job belongs to the version ledger, where every version
# is used once, and to build-package.sh, which stamps the source commit INSIDE
# the .deb. A +<sha> suffix would also sort by hash rather than by time, so apt
# could not tell an upgrade from a downgrade.
#
# A build that is not the release sets RD_DEB_VERSION to a scratch version
# (3.1.0-0~vmscratch1, ...) and records it with version-ledger.sh as not for
# release. Without one, a tree with uncommitted changes is REFUSED: the package
# would claim the release version for bytes that no commit holds.
#
# `--root-owner-group` rather than fakeroot: everything in this package is
# root:root, so the one thing fakeroot would buy is already true by construction,
# and requiring it would put a build dependency in front of a package whose whole
# argument is that it asks for nothing.
set -euo pipefail
# The modes in the package are the package's, not the caller's. This box's
# shells run with umask 0002, and `install -D` would then create group-writable
# directories inside the package, which the estate audit rightly refuses.
umask 022
cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="${1:-$ROOT/target/deb}"
PKG=baxters-remotedexter

BASE=$(awk -F': ' '/^Version:/{print $2; exit}' packaging/linux/debian/control)
if [ -n "${RD_DEB_VERSION:-}" ]; then
    VERSION="$RD_DEB_VERSION"
else
    VERSION="$BASE"
    dirty="$(git status --porcelain 2>/dev/null || true)"
    if [ -n "$dirty" ]; then
        echo "REFUSING TO BUILD $PKG $VERSION: the tree has uncommitted changes," >&2
        echo "  so the package would claim the release version for bytes no commit holds." >&2
        echo "  Commit first, or set RD_DEB_VERSION to a scratch version recorded in the ledger." >&2
        exit 1
    fi
fi
PKGDIR="$OUT/${PKG}_${VERSION}_amd64"
DEB="$OUT/${PKG}_${VERSION}_amd64.deb"

echo "== building host_app (release) =="
cargo build --release --locked -p host_app

echo "== staging $PKGDIR =="
rm -rf "$PKGDIR"
install -d -m 0755 \
    "$PKGDIR/DEBIAN" \
    "$PKGDIR/opt/baxters/remotedexter" \
    "$PKGDIR/usr/bin" \
    "$PKGDIR/usr/share/applications" \
    "$PKGDIR/usr/share/doc/baxters-remotedexter"

install -m 0755 target/release/host_app                       "$PKGDIR/opt/baxters/remotedexter/host_app"
install -m 0755 packaging/linux/remotedexter-launcher          "$PKGDIR/opt/baxters/remotedexter/run.sh"
install -m 0755 packaging/linux/remotedexter-enable-input      "$PKGDIR/opt/baxters/remotedexter/remotedexter-enable-input"
# Inert data. NOT installed into /etc/udev/rules.d or /usr/lib/udev/rules.d by
# anything in this package.
install -m 0644 packaging/linux/70-remotedexter-uinput.rules   "$PKGDIR/opt/baxters/remotedexter/70-remotedexter-uinput.rules"
ln -s /opt/baxters/remotedexter/run.sh                          "$PKGDIR/usr/bin/remotedexter"
install -m 0644 packaging/linux/baxters-remotedexter.desktop    "$PKGDIR/usr/share/applications/baxters-remotedexter.desktop"
# The desktop entry names Icon=baxters-remotedexter. An empty glob would ship a
# launcher with a generic icon -- the defect A1 s5 exists to stop -- so a build
# that finds no icons fails rather than packing one.
shopt -s nullglob
icons=0
for png in packaging/linux/icons/hicolor/*/apps/baxters-remotedexter.png; do
    size="$(basename "$(dirname "$(dirname "$png")")")"
    install -D -m 0644 "$png" "$PKGDIR/usr/share/icons/hicolor/$size/apps/baxters-remotedexter.png"
    icons=$((icons + 1))
done
shopt -u nullglob
[ "$icons" -gt 0 ] || { echo "REFUSING TO BUILD: no icons under packaging/linux/icons/hicolor" >&2; exit 1; }
install -m 0644 LICENSE                                         "$PKGDIR/usr/share/doc/baxters-remotedexter/copyright"
install -m 0644 docs/THIRD_PARTY_NOTICES.md                     "$PKGDIR/usr/share/doc/baxters-remotedexter/"
install -m 0644 packaging/linux/README.md                       "$PKGDIR/usr/share/doc/baxters-remotedexter/README.uinput-grant.md"

sed "s/^Version: .*/Version: $VERSION/" packaging/linux/debian/control > "$PKGDIR/DEBIAN/control"
install -m 0755 packaging/linux/debian/postinst "$PKGDIR/DEBIAN/postinst"
install -m 0755 packaging/linux/debian/postrm   "$PKGDIR/DEBIAN/postrm"

echo "== refusing to ship anything credential-shaped =="
# The build reads target/release/, which is exactly where the host identity keys
# of an old development build live. A package that swept them up would publish
# them to every machine it is installed on. Checked by name and by extension,
# and the build FAILS rather than warns.
bad=$(find "$PKGDIR" -type f \( -name '*.key' -o -name '*.jks' -o -name '*.pem' \
        -o -name '*.p12' -o -name '*.keystore' -o -name 'id_*' \) 2>/dev/null || true)
if [ -n "$bad" ]; then
    echo "REFUSING TO BUILD — credential-shaped files staged:" >&2
    echo "$bad" >&2
    exit 1
fi
echo "   clean"

echo "== packing =="
dpkg-deb --root-owner-group --build "$PKGDIR" "$DEB" >/dev/null
# Hashed from inside $OUT so the checksum file names the package by its bare
# name: `sha256sum -c` then works in whatever folder it is downloaded to, and
# the file does not publish the build path. scripts/check_deb_checksum.sh.
( cd "$OUT" && sha256sum "$(basename "$DEB")" | tee "$(basename "$DEB").sha256" )

echo
echo "== what it installs =="
dpkg-deb -c "$DEB" | awk '{print "   "$1" "$2" "$6" "$7" "$8}'
echo
echo "== maintainer scripts =="
for s in postinst postrm; do
    printf "   %-9s %s lines\n" "$s" "$(wc -l < "$PKGDIR/DEBIAN/$s")"
done
echo
echo "built: $DEB"
