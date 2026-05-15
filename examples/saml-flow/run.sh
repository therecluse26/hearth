#!/usr/bin/env bash
# One-command end-to-end SAML demo.
#
#   ./run.sh
#
# What happens:
#   1. cargo build (release) the hearth binary.
#   2. npm install if needed.
#   3. Generate a throwaway RSA keypair + self-signed cert for the fake IdP.
#   4. Substitute the cert PEM into hearth.yaml (the rendered file lives
#      at hearth.yaml.rendered; the template is untouched).
#   5. Wipe prior demo data, start Hearth in the background.
#   6. Run demo.mjs (three acts: SP metadata, ACS roundtrip, IdP SSO roundtrip).
#   7. Tear Hearth down on exit regardless of demo outcome.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
DATA_DIR="$HERE/data/saml-flow"
HEARTH_LOG="$HERE/.hearth.log"
HEARTH_PID=""

cleanup() {
  if [[ -n "$HEARTH_PID" ]] && kill -0 "$HEARTH_PID" 2>/dev/null; then
    kill "$HEARTH_PID" 2>/dev/null || true
    wait "$HEARTH_PID" 2>/dev/null || true
  fi
  rm -f "$HERE/.hearth.pid" "$HERE/hearth.yaml.rendered"
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

TARGET_DIR="$(cd "$REPO_ROOT" && \
  cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' \
  2>/dev/null || echo "$REPO_ROOT/target")"
HEARTH_BIN="$TARGET_DIR/release/hearth"
if [[ ! -x "$HEARTH_BIN" ]]; then
  echo "✖ expected hearth binary at $HEARTH_BIN"
  exit 1
fi

echo "▸ npm ci (exact lockfile install)"
if [[ ! -d "$HERE/node_modules" ]]; then
  (cd "$HERE" && npm ci --silent)
fi

echo "▸ generating fake-IdP cert"
(cd "$HERE" && node gen-idp-cert.mjs)

echo "▸ rendering hearth.yaml with fake-IdP cert inlined"
# Indent the PEM to match the YAML literal block's leading whitespace (12 spaces).
INDENTED_PEM="$(sed 's/^/            /' "$HERE/.idp-cert.pem")"
# Use awk to avoid sed's pain with multi-line replacements.
awk -v pem="$INDENTED_PEM" '
  /__IDP_CERT_PEM__/ {
    print pem
    next
  }
  { print }
' "$HERE/hearth.yaml" > "$HERE/hearth.yaml.rendered"

echo "▸ resetting demo data dir"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "▸ starting Hearth (HTTP 8420)"
(
  cd "$HERE"
  "$HEARTH_BIN" serve --dev --config "$HERE/hearth.yaml.rendered" \
    >"$HEARTH_LOG" 2>&1 &
  echo $! >"$HERE/.hearth.pid"
)
HEARTH_PID="$(cat "$HERE/.hearth.pid")"
rm -f "$HERE/.hearth.pid"
wait_for "http://127.0.0.1:8420/health"

echo "▸ running demo.mjs"
(cd "$HERE" && node demo.mjs)
