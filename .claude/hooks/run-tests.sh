#!/usr/bin/env bash

set -uo pipefail

PROJECT_ROOT="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || echo "")}"
[[ -z "$PROJECT_ROOT" ]] && exit 0

cd "$PROJECT_ROOT" || exit 0

cargo nextest run 2>/dev/null
exit 0
