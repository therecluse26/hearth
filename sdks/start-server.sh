#!/usr/bin/env bash
# Start a Hearth dev server for SDK integration tests.
#
# Usage:
#   ./start-server.sh [PORT]
#
# Builds the hearth binary, starts it in dev mode, waits for the health check,
# then prints the PID and port. Kill the server with: kill $PID
#
# Environment:
#   CARGO_TARGET_DIR — if set, the hearth binary is read from $CARGO_TARGET_DIR/debug/hearth

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolve binary path
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
HEARTH_BIN="$TARGET_DIR/debug/hearth"

# Build if needed
echo "Building hearth..." >&2
cargo build --bin hearth --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 >/dev/null

# Find a free port or use the provided one
PORT="${1:-0}"
if [ "$PORT" = "0" ]; then
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
fi

# Start the server
RUST_LOG=warn "$HEARTH_BIN" serve --dev --port "$PORT" &
SERVER_PID=$!

# Wait for health check
MAX_WAIT=15
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  if curl -sf "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then
    echo "port=$PORT"
    echo "pid=$SERVER_PID"
    echo "url=http://127.0.0.1:$PORT"
    exit 0
  fi
  sleep 0.1
  WAITED=$((WAITED + 1))
done

echo "ERROR: Hearth server did not start within ${MAX_WAIT}s" >&2
kill "$SERVER_PID" 2>/dev/null || true
exit 1
