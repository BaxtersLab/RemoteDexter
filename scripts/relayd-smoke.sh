#!/usr/bin/env bash
# Build `relayd` and drive it from outside the process. See relayd_smoke.py for
# why this exists alongside the Rust tests.
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT" || exit 2
cargo build -p relay --bin relayd >/dev/null 2>&1 || {
  echo "relayd-smoke: could not build relayd — FAILING CLOSED" >&2; exit 2; }
exec python3 "$HERE/relayd_smoke.py"
