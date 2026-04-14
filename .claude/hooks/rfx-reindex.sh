#!/usr/bin/env bash
# Hook: Reindex Reflex at end of turn (Stop hook, async)
# Runs `rfx index` incrementally to keep search results fresh.
# Incremental reindex with no changes completes in milliseconds.
# Fails silently — if rfx isn't installed or indexing fails, nothing breaks.
set -uo pipefail

PROJECT_ROOT="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || echo "")}"
[[ -z "$PROJECT_ROOT" ]] && exit 0

RFX="$PROJECT_ROOT/node_modules/.bin/rfx"
[[ -x "$RFX" ]] || exit 0

cd "$PROJECT_ROOT" || exit 0

"$RFX" index --quiet 2>/dev/null
exit 0
