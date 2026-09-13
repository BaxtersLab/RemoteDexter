#!/usr/bin/env bash
# Build the RemoteDexter .deb. No root, no fakeroot, no network.
#
# WHAT THE PACKAGE MUST BE, per Block 13
#
# Install alone runs nothing, listens on nothing and changes nothing: no enabled
# unit, no autostart, no daemon, no open port, no key, no ACL, no group change.
# The optional /dev/uinput grant ships as INERT DATA under /usr/share and is
# installed only when the operator asks for it from the host UI. postinst does
# nothing at all, deliberately, and scripts/test-uinput-install.sh check 1 fails
# if it ever starts doing something.
#
# `--root-owner-group` rather than fakeroot: everything in this package is
# root:root, so the one thing fakeroot would buy is already true by construction,
# and requiring it would put a build dependency in front of a package whose whole
# argument is that it asks for nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="${1:-$ROOT/target/deb}"

# The version carries the commit, for the same reason the APK's does: five days
# of work once shipped as one version string, and a build that cannot say which
# build it is cannot be told apart from the one it replaced.
BASE=$(awk -F': ' '/^Version:/{print $2; exit}' packaging/linux/debian/control)
if SHA=$(git rev-parse --short=7 HEAD 2>/dev/null) && [ -n "$SHA" ]; then
    [ -z "$(git status --porcelain 2>/dev/null)" ] || SHA="$SHA-dirty"
    VERSION="$BASE+$SHA"
else
    VERSION="$BASE+nogit-$(date +%Y%m%d)"
fi
PKGDIR="$OUT/remotedexter_${VERSION}_amd64"
DEB="$OUT/remotedexter_${VERSION}_amd64.deb"

echo "== building host_app (release) =="
cargo build --release -p host_app

echo "== staging $PKGDIR =="
rm -rf "$PKGDIR"
install -d -m 0755 \
    "$PKGDIR/DEBIAN" \
    "$PKGDIR/usr/bin" \
    "$PKGDIR/usr/libexec/remotedexter" \
    "$PKGDIR/usr/share/remotedexter" \
    "$PKGDIR/usr/share/applications" \
    "$PKGDIR/usr/share/doc/remotedexter"

install -m 0755 target/release/host_app                        "$PKGDIR/usr/libexec/remotedexter/host_app"
install -m 0755 packaging/linux/remotedexter-launcher           "$PKGDIR/usr/bin/remotedexter"
install -m 0755 packaging/linux/remotedexter-enable-input       "$PKGDIR/usr/libexec/remotedexter/remotedexter-enable-input"
# Inert data. NOT installed into /etc/udev/rules.d by anything in this package.
install -m 0644 packaging/linux/70-remotedexter-uinput.rules    "$PKGDIR/usr/share/remotedexter/"
install -m 0644 packaging/linux/remotedexter.desktop            "$PKGDIR/usr/share/applications/"
install -m 0644 LICENSE                                         "$PKGDIR/usr/share/doc/remotedexter/copyright"
install -m 0644 docs/THIRD_PARTY_NOTICES.md                     "$PKGDIR/usr/share/doc/remotedexter/"
install -m 0644 packaging/linux/README.md                       "$PKGDIR/usr/share/doc/remotedexter/README.uinput-grant.md"

sed "s/^Version: .*/Version: $VERSION/" packaging/linux/debian/control > "$PKGDIR/DEBIAN/control"
install -m 0755 packaging/linux/debian/postinst "$PKGDIR/DEBIAN/postinst"
install -m 0755 packaging/linux/debian/postrm   "$PKGDIR/DEBIAN/postrm"

echo "== refusing to ship anything credential-shaped =="
# The build reads target/release/, which is exactly where the host identity keys
# live. A package that swept them up would publish them to every machine it is
# installed on. Checked by name and by extension, and the build FAILS rather
# than warns.
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
sha256sum "$DEB" | tee "$DEB.sha256"

echo
echo "== what it installs =="
dpkg-deb -c "$DEB" | awk '{print "   "$1" "$2" "$6}'
echo
echo "== maintainer scripts =="
for s in postinst postrm; do
    printf "   %-9s %s lines\n" "$s" "$(wc -l < "$PKGDIR/DEBIAN/$s")"
done
echo
echo "built: $DEB"
