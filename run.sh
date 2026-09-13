#!/usr/bin/env bash
# RemoteDexter host — the supported entry point (Article XIV.6).
#
# WHAT CHANGED IN BLOCK 3, AND WHY THE OLD VERSION WAS DANGEROUS
# --------------------------------------------------------------
# The previous run.sh launched `target/release/host_app` directly, exported
# RD_BIND=<LAN address>, fed the host an 'I' on stdin to mint an invitation, and
# opened the resulting QR with xdg-open. Every one of those steps is now wrong:
#
#   * it launched whatever binary happened to be in target/release, which on
#     this box was two days stale;
#   * minting an invitation on startup ran `module17_bootstrap_invite::start()`,
#     which broadcasts the pairing session token IN PLAINTEXT to
#     255.255.255.255 every five seconds for as long as the host runs;
#   * it chose the network interface for the user, which is the one decision the
#     product now insists they make;
#   * it scrubbed no Snap variables, contrary to Article XIV.6.
#
# The host now opens a console and does NOTHING until the owner picks an
# interface and presses Start. There is no listener, no capture, no input
# device and no invitation before that.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

# ── Snap environment scrub (CLAUDE.md, Article XIV.6) ───────────────────────
# A terminal launched from the VS Code snap exports variables pointing into
# /snap and $HOME/snap. LOCPATH kills processes outright; XDG_DATA_HOME shadows
# the system glib schemas. Scrub by RULE — any variable whose VALUE points into
# a snap tree — with two exceptions: PATH is left alone, and XDG_DATA_DIRS is
# FILTERED rather than dropped, because it holds real system paths.
scrubbed=0
while IFS= read -r name; do
    case "$name" in PATH|XDG_DATA_DIRS) continue ;; esac
    value="${!name-}"
    case "$value" in
        /snap/*|"$HOME"/snap/*|*:/snap/*|*:"$HOME"/snap/*)
            unset "$name"; scrubbed=$((scrubbed + 1)) ;;
    esac
done < <(compgen -v)
if [ -n "${XDG_DATA_DIRS:-}" ]; then
    kept=""
    IFS=':' read -ra parts <<< "$XDG_DATA_DIRS"
    for p in "${parts[@]}"; do
        case "$p" in
            /snap/*|"$HOME"/snap/*|"") ;;
            *) kept="${kept:+$kept:}$p" ;;
        esac
    done
    export XDG_DATA_DIRS="$kept"
fi

# ── Wayland-only (Article XIV.4) ────────────────────────────────────────────
# The binary links no X11 library and contains no X11 library name at all
# (scripts/check_no_x11.sh proves it three ways), so it cannot select an X11
# backend. DISPLAY is unset anyway so nothing downstream is tempted to try.
unset DISPLAY
if [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "run.sh: WAYLAND_DISPLAY is not set — this host is Wayland-native." >&2
    echo "run.sh: refusing to start rather than silently failing to open a window." >&2
    exit 1
fi

# ── Build, so a stale binary can never be what launches ─────────────────────
PROFILE="${RD_PROFILE:-release}"
case "$PROFILE" in
    release) FLAG="--release" ;;
    debug)   FLAG="" ;;
    *) echo "run.sh: RD_PROFILE must be release or debug" >&2; exit 1 ;;
esac
echo "run.sh: building host_app ($PROFILE)…"
# shellcheck disable=SC2086
if ! cargo build $FLAG -p host_app; then
    echo "run.sh: build failed — not launching a previous binary." >&2
    exit 1
fi
BIN="./target/$PROFILE/host_app"
[ -x "$BIN" ] || { echo "run.sh: $BIN missing after a successful build" >&2; exit 1; }

# ── Capabilities are opt-in, per run ────────────────────────────────────────
# Viewing is the purpose of this supported launcher, so it grants capture for
# this process only. Input, clipboard and file access remain separate, explicit
# opt-ins; session_core refuses them independently unless the operator supplied
# them.
#
# RD_CAP_CLIPBOARD is its own grant and is NOT implied by RD_CAP_INPUT. A phone
# that may drive the mouse has not thereby been given this machine's clipboard,
# which holds things that were never on screen — a copied password among them.
export RD_CAP_SCREENSHOT=1
echo "run.sh: capture=${RD_CAP_SCREENSHOT:-off}  input=${RD_CAP_INPUT:-off}  clipboard=${RD_CAP_CLIPBOARD:-off}"

# Said in full, not left as one word in a status line. The operator launched
# with input off on 2026-08-30, tapped Enable Control, and got "Control
# unavailable" on the phone — a dead end unless you already know which variable
# it means. The host's own refusal names RD_CAP_INPUT, but it arrives as a
# toast on a device that is not the one you are typing on.
#
# The default stays OFF. Deny-by-default for input is deliberate and is not
# what needed fixing; being told how to turn it on is.
if [ "${RD_CAP_INPUT:-}" != "1" ]; then
    echo "run.sh:"
    echo "run.sh: INPUT IS OFF. The phone can view this desktop but not drive it —"
    echo "run.sh: Enable Control will be refused with"
    echo "run.sh:   \"capability not authorized (set RD_CAP_INPUT=1)\"."
    echo "run.sh: To allow control for THIS RUN only, stop the host and start it as:"
    echo "run.sh:   RD_CAP_INPUT=1 ./run.sh"
    echo "run.sh: The Ctrl+C / Ctrl+V clipboard buttons need their own grant as well:"
    echo "run.sh:   RD_CAP_INPUT=1 RD_CAP_CLIPBOARD=1 ./run.sh"
    echo "run.sh:"
fi
echo "run.sh: snap variables scrubbed: $scrubbed"
echo "run.sh: opening the host console — nothing listens until you press Start."
exec "$BIN"
