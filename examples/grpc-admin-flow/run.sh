#!/usr/bin/env bash
# One-command walkthrough of Hearth's gRPC management API.
#
#   ./run.sh
#
# What happens:
#   1. `cargo build` (release profile) — may take a while on first run.
#   2. Installs Node deps if `node_modules/` is missing.
#   3. Wipes any prior demo data under `./data/grpc-admin-flow/`.
#   4. Starts Hearth in the background (--dev, HTTP 8420 + gRPC 9420).
#   5. Runs `demo.mjs` which drives the full gRPC surface end-to-end.
#   6. Kills Hearth and exits with the demo's status code.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
DATA_DIR="$HERE/data/grpc-admin-flow"
HEARTH_LOG="$HERE/.hearth.log"
HEARTH_PID=""

cleanup() {
  if [[ -n "$HEARTH_PID" ]] && kill -0 "$HEARTH_PID" 2>/dev/null; then
    kill "$HEARTH_PID" 2>/dev/null || true
    wait "$HEARTH_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

wait_for() {
  local url="$1" attempts=60
  until curl -sfo /dev/null "$url"; do
    ((attempts--)) || {
      echo "✖ timed out waiting for $url"
      [[ -f "$HEARTH_LOG" ]] && tail -n 40 "$HEARTH_LOG"
      exit 1
    }
    sleep 0.5
  done
}

echo "▸ cargo build (hearth binary)"
(cd "$REPO_ROOT" && cargo build --release --quiet --bin hearth)

# Resolve the target directory — respects CARGO_TARGET_DIR if set.
TARGET_DIR="$(cd "$REPO_ROOT" && \
  cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' \
  2>/dev/null || echo "$REPO_ROOT/target")"
HEARTH_BIN="$TARGET_DIR/release/hearth"
if [[ ! -x "$HEARTH_BIN" ]]; then
  echo "✖ expected hearth binary at $HEARTH_BIN — did cargo build actually produce one?"
  exit 1
fi

echo "▸ npm ci (exact lockfile install)"
if [[ ! -d "$HERE/node_modules" ]]; then
  (cd "$HERE" && npm ci --silent)
fi

echo "▸ resetting demo data dir"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "▸ starting Hearth (HTTP 8420, gRPC 9420)"
(
  cd "$HERE"
  "$HEARTH_BIN" serve --dev --config "$HERE/hearth.yaml" \
    >"$HEARTH_LOG" 2>&1 &
  echo $! >"$HERE/.hearth.pid"
)
HEARTH_PID="$(cat "$HERE/.hearth.pid")"
rm -f "$HERE/.hearth.pid"
wait_for "http://127.0.0.1:8420/health"

echo "▸ running demo.mjs"
(cd "$HERE" && node demo.mjs)
