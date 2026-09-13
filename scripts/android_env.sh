#!/usr/bin/env bash
# Source this before any Android build on the Linux box:
#
#     source scripts/android_env.sh
#     cargo build -p remotedexter --target aarch64-linux-android --release
#
# It does two jobs.
#
# ── 1. Scrub the snap environment ────────────────────────────────────────────
# A terminal launched from the VS Code snap injects ~18 vars pointing into the
# snap. LOCPATH kills processes outright (glibc mismatch), XDG_DATA_HOME shadows
# the system glib schemas and silently relocates app data. Java tools are not
# immune, so this runs before anything touches sdkmanager/gradle.
#
# Scrub by RULE, not by a hand-picked list:
#   unset every var whose value points into /snap/ OR $HOME/snap/
# with two exceptions:
#   PATH           left alone (/snap/bin sits after every system dir)
#   XDG_DATA_DIRS  filtered, never unset (it holds real system paths, and
#                  /var/lib/snapd/desktop is snapd, not /snap/)
#
# NOTE: the obvious rule is to scrub only "/snap/". Measured 2026-08-06,
# that is not enough — XDG_DATA_DIRS also carried $HOME/snap/code/<rev>/... .
# Both forms are handled here.
#
# ── 2. Point cargo at the NDK ────────────────────────────────────────────────
# .cargo/config.toml pins the Android linkers to Windows paths for the other
# box. Cargo gives environment variables precedence over config file entries, so
# exporting CARGO_TARGET_*_LINKER here cross-builds on Linux without editing a
# file the Windows box also builds from.
#
# Everything below can be overridden by exporting it before sourcing.

for _v in $(env | cut -d= -f1); do
    case "$_v" in
        PATH|XDG_DATA_DIRS) continue ;;
    esac
    _val="${!_v}"
    case "$_val" in
        */snap/*|"$HOME"/snap/*) unset "$_v" ;;
    esac
done
unset _v _val

if [ -n "${XDG_DATA_DIRS:-}" ]; then
    _kept=""
    IFS=':' read -ra _parts <<< "$XDG_DATA_DIRS"
    for _p in "${_parts[@]}"; do
        case "$_p" in
            */snap/*|"$HOME"/snap/*) ;;
            *) _kept="${_kept:+$_kept:}$_p" ;;
        esac
    done
    export XDG_DATA_DIRS="$_kept"
    unset _kept _parts _p
fi

# Gradle 8.5 can run on Java 17 through 21. Android Studio's rolling JBR may be
# newer, so select by compatibility rather than assuming its bundled JBR works.
_java_compatible() {
    local _version _major
    [ -x "$1/bin/java" ] || return 1
    _version="$("$1/bin/java" -version 2>&1 | sed -n '1s/.*version "\([^"]*\)".*/\1/p')"
    _major="${_version%%.*}"
    [ "$_major" = "1" ] && _major="$(printf '%s' "$_version" | cut -d. -f2)"
    [ "${_major:-0}" -ge 17 ] && [ "$_major" -le 21 ]
}

if [ -n "${JAVA_HOME:-}" ] && ! _java_compatible "$JAVA_HOME"; then
    echo "[android_env] WARNING: ignoring JAVA_HOME unsupported by Gradle 8.5: $JAVA_HOME" >&2
    unset JAVA_HOME
fi
if [ -z "${JAVA_HOME:-}" ]; then
    for _cand in /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-21-openjdk-* \
        /opt/android-studio/jbr /snap/android-studio/current/jbr; do
        _java_compatible "$_cand" && { export JAVA_HOME="$_cand"; break; }
    done
    unset _cand
fi
unset -f _java_compatible
[ -n "${JAVA_HOME:-}" ] && export PATH="$JAVA_HOME/bin:$PATH"

# Standalone Kotlin compiler (1.9.22, matching the version the Gradle plugin
# resolves in apk/build.gradle). Gradle does NOT need this — it downloads its own
# compiler — but it gives a fast syntax/type check on a single .kt file without
# paying for a full Gradle run. It shells out to `java`, so it only works once
# JAVA_HOME is on PATH above; there is no system JDK on this box.
if [ -d "$HOME/.local/kotlinc/bin" ]; then
    export KOTLIN_HOME="$HOME/.local/kotlinc"
    export PATH="$KOTLIN_HOME/bin:$PATH"
fi

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

# Highest installed NDK unless ANDROID_NDK_HOME is already set.
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    _ndk="$(ls -1 "$ANDROID_HOME/ndk" 2>/dev/null | sort -V | tail -1)"
    [ -n "$_ndk" ] && export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$_ndk"
    unset _ndk
fi

# Minimum supported API level; must match the Gradle module's minSdk.
export ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-26}"

if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    _bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
    if [ -d "$_bin" ]; then
        export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$_bin/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
        export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$_bin/armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
        export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$_bin/x86_64-linux-android${ANDROID_API_LEVEL}-clang"
        # For any dependency that compiles C.
        export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
        export CC_armv7_linux_androideabi="$CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"
        export CC_x86_64_linux_android="$CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
        export AR_aarch64_linux_android="$_bin/llvm-ar"
        export AR_armv7_linux_androideabi="$_bin/llvm-ar"
        export AR_x86_64_linux_android="$_bin/llvm-ar"
    else
        echo "[android_env] WARNING: no linux-x86_64 toolchain under $ANDROID_NDK_HOME" >&2
    fi
    unset _bin
else
    echo "[android_env] WARNING: no NDK found under $ANDROID_HOME/ndk" >&2
fi
