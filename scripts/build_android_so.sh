#!/usr/bin/env bash
# Cross-compile libremotedexter.so for Android and stage it into the APK.
#
# The .so was previously built by hand, which meant the bytes in jniLibs/ could
# not be regenerated or matched to a commit. This script is the reproducible
# path: run it, and the three ABIs in apk/app/src/main/jniLibs/ are rebuilt from
# the current source.
#
#   ./scripts/build_android_so.sh              # release, all ABIs
#   ./scripts/build_android_so.sh --debug      # debug symbols, much slower JPEG
#   ./scripts/build_android_so.sh arm64-v8a    # one ABI (fastest iteration)

set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# shellcheck source=/dev/null
. "$REPO/scripts/android_env.sh"

PROFILE="release"
PROFILE_FLAG="--release"
ABIS=()

for arg in "$@"; do
    case "$arg" in
        --debug) PROFILE="debug"; PROFILE_FLAG="" ;;
        --release) PROFILE="release"; PROFILE_FLAG="--release" ;;
        arm64-v8a|armeabi-v7a|x86_64) ABIS+=("$arg") ;;
        *) echo "[build_so] unknown argument: $arg" >&2; exit 2 ;;
    esac
done
[ ${#ABIS[@]} -eq 0 ] && ABIS=(arm64-v8a armeabi-v7a x86_64)

if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "[build_so] ANDROID_NDK_HOME is not set or does not exist." >&2
    echo "[build_so] Install the NDK via Android Studio, or set it explicitly." >&2
    exit 1
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
API="${ANDROID_API_LEVEL:-26}"

# Rust target triple and NDK clang prefix per ABI. armeabi-v7a is the awkward
# one: its Rust target says "armv7" but the NDK clang is named "armv7a" and
# needs the "eabi" suffix — a mismatch here produces a linker-not-found error
# that reads as if the NDK is missing entirely.
triple_for() {
    case "$1" in
        arm64-v8a)   echo "aarch64-linux-android" ;;
        armeabi-v7a) echo "armv7-linux-androideabi" ;;
        x86_64)      echo "x86_64-linux-android" ;;
    esac
}
clang_for() {
    case "$1" in
        arm64-v8a)   echo "aarch64-linux-android${API}-clang" ;;
        armeabi-v7a) echo "armv7a-linux-androideabi${API}-clang" ;;
        x86_64)      echo "x86_64-linux-android${API}-clang" ;;
    esac
}

echo "[build_so] NDK      : $ANDROID_NDK_HOME"
echo "[build_so] API level: $API"
echo "[build_so] profile  : $PROFILE"
echo "[build_so] ABIs     : ${ABIS[*]}"
echo

for abi in "${ABIS[@]}"; do
    triple="$(triple_for "$abi")"
    clang="$TOOLCHAIN/$(clang_for "$abi")"

    if [ ! -x "$clang" ]; then
        echo "[build_so] missing NDK compiler: $clang" >&2
        exit 1
    fi

    # Cargo reads CARGO_TARGET_<TRIPLE>_LINKER from the environment, and the
    # environment wins over .cargo/config.toml. Setting it here keeps the
    # toolchain choice in this script rather than in committed config that would
    # break on a box with the NDK somewhere else.
    var="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
    flagvar="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"

    echo "[build_so] ── $abi ($triple)"
    # 16 KB PAGE SIZE. Android 15 runs on devices with 16 KB memory pages, and
    # this APK sets extractNativeLibs=false, so the loader mmaps the .so
    # straight out of the archive. A library whose LOAD segments are aligned to
    # 4 KB cannot be mapped there and the app fails to start -- on the user's
    # phone, not here. The NDK default was 4 KB until r27, so this is not
    # something the toolchain gives us for free.
    #
    # Windows round 7 measured the ZIP side of this (arm64-v8a and armeabi-v7a
    # were 4 KB but not 16 KB aligned in the archive). Checking the libraries
    # themselves showed all three were built with p_align 0x1000, which is the
    # half that no packaging flag can fix.
    #
    # Target-scoped rather than a global RUSTFLAGS so it cannot reach build
    # scripts or the host toolchain.
    env "$var=$clang" "$flagvar=-C link-arg=-Wl,-z,max-page-size=16384" \
        CC="$clang" AR="$TOOLCHAIN/llvm-ar" \
        cargo build $PROFILE_FLAG -p remotedexter --target "$triple"

    src="target/$triple/$PROFILE/libremotedexter.so"
    dst="apk/app/src/main/jniLibs/$abi/libremotedexter.so"
    if [ ! -f "$src" ]; then
        echo "[build_so] expected artifact missing: $src" >&2
        exit 1
    fi
    # Fail closed if the alignment did not take. Asserted on the artifact
    # rather than trusted from the flag: a typo in the flag name is silently
    # ignored by cargo, which would leave a 4 KB library staged and this script
    # reporting success.
    aligns=$(readelf -lW "$src" | awk '$1=="LOAD"{print $NF}' | sort -u)
    if [ "$aligns" != "0x4000" ]; then
        echo "[build_so] $abi: LOAD segments are aligned $aligns, need 0x4000." >&2
        echo "[build_so] A 4 KB-aligned library cannot be mapped from the APK on" >&2
        echo "[build_so] a 16 KB-page device (Android 15). Refusing to stage it." >&2
        exit 1
    fi

    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    echo "[build_so]    staged $(stat -c%s "$dst") bytes, LOAD align $aligns → $dst"
done

echo
echo "[build_so] done. Staged libraries:"
for abi in "${ABIS[@]}"; do
    f="apk/app/src/main/jniLibs/$abi/libremotedexter.so"
    printf '  %-13s %10s bytes  sha256 %s\n' \
        "$abi" "$(stat -c%s "$f")" "$(sha256sum "$f" | cut -c1-16)…"
done
echo
echo "[build_so] now rebuild the APK:  (cd apk && ./gradlew :app:assembleDebug)"
