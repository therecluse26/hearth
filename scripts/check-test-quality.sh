#!/usr/bin/env bash
# scripts/check-test-quality.sh — CI guardrail for false-confidence test patterns.
#
# Tracks: HEA-571. Anti-pattern taxonomy: docs/specs/TESTING.md § "Test Quality
# Anti-Patterns". Audit baseline: docs/audit/test-suite-audit-2026-05-16.md.
#
# FAILS on:
#   A) assert!(<expr>.is_ok()) / .is_err()     in tests/ and simulation/
#   E) std::thread::sleep / tokio::time::sleep in tests/ and simulation/
#   I) #[ignore = "..."] without an HEA-####   anywhere in tests/, simulation/,
#                                              src/, or benches/
#
# WARNS (does not fail) on:
#   I) #[ignore] whose message contains "not yet implemented" — these tend to rot.
#
# Escape hatch (suppress per-line — place on the same line OR immediately
# preceding line, and include a non-empty reason after the colon):
#   // AUDIT: justified-weak-assert: <reason>     (suppresses an A finding)
#   // AUDIT: justified-sleep: <reason>           (suppresses an E finding)
#
# Scope note: src/ #[cfg(test)] inline modules are NOT yet scanned for A/E.
# They were outside the HEA-565 audit scope; broaden the lint after a follow-up
# audit, otherwise CI will fail on unaudited pre-existing patterns.
#
# Usage: scripts/check-test-quality.sh
# Exit:  0 if clean, 1 on any failure (warnings alone do not fail).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'
  BLD=$'\033[1m';    RST=$'\033[0m'
else
  RED=''; YEL=''; GRN=''; BLD=''; RST=''
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

VIOLATIONS=0
WARNINGS=0

# ---------------------------------------------------------------------------
# scan_with_escape_hatch <label> <kind> <regex> <root> [root ...]
#
# Scans the given Rust source roots for <regex>. A match is suppressed when
# either the matching line or its immediately preceding line contains
#   // AUDIT: justified-<kind>: <non-empty reason>
# ---------------------------------------------------------------------------
scan_with_escape_hatch() {
  local label="$1" kind="$2" regex="$3"
  shift 3

  local roots=()
  local r
  for r in "$@"; do
    [ -d "$r" ] && roots+=("$r")
  done
  [ ${#roots[@]} -eq 0 ] && return 0

  local out="$TMP/violations.$kind"
  : > "$out"

  while IFS= read -r f; do
    awk -v regex="$regex" -v kind="$kind" -v file="$f" '
      function has_marker(line,    pos, prefix, rest) {
        prefix = "// AUDIT: justified-" kind ":"
        pos = index(line, prefix)
        if (pos == 0) return 0
        rest = substr(line, pos + length(prefix))
        gsub(/^[[:space:]]+/, "", rest)
        return length(rest) > 0
      }
      {
        if ($0 ~ regex && !has_marker($0) && !has_marker(prev)) {
          line = $0
          sub(/^[ \t]+/, "", line)
          printf("%s:%d: %s\n", file, NR, line)
        }
        prev = $0
      }
    ' "$f" >> "$out"
  done < <(find "${roots[@]}" -type f -name '*.rs' 2>/dev/null | sort)

  if [ -s "$out" ]; then
    local count
    count=$(wc -l < "$out" | tr -d ' ')
    echo
    printf "%s%s✗ %s (%d):%s\n" "$RED" "$BLD" "$label" "$count" "$RST"
    sed 's/^/  /' "$out"
    printf "  %sfix:%s rewrite the test, or annotate the line with:\n" "$YEL" "$RST"
    printf "        %s// AUDIT: justified-%s: <one-line reason>%s\n" "$BLD" "$kind" "$RST"
    VIOLATIONS=$((VIOLATIONS + count))
  fi
}

# ---------------------------------------------------------------------------
# Check A — Weak Result assertions in tests/ + simulation/.
#
#   assert!(<expr>.is_ok())  // does not verify the Ok value
#   assert!(<expr>.is_err()) // does not pin the Err variant
#
# Replace with `assert!(matches!(x, Err(SpecificError::Variant)))` or
# `let v = x.expect(...); assert_eq!(v.field, ...);`.
# Audit cleanup: HEA-567 (commits 2c6f565, 0f7eed0).
# ---------------------------------------------------------------------------
scan_with_escape_hatch \
  "Weak Result assertions — use assert!(matches!(...)) to pin the variant" \
  "weak-assert" \
  'assert![(].*[.]is_(ok|err)[(][)]' \
  tests simulation

# ---------------------------------------------------------------------------
# Check E — Unconditional wall-clock sleep in tests/ + simulation/.
#
# Wall-clock sleeps cause flaky CI and slow down the suite. Use
# tokio::time::advance, event-based sync, or a bounded poll loop instead.
# Audit cleanup: HEA-569 (commit c8280dc).
# ---------------------------------------------------------------------------
scan_with_escape_hatch \
  "Unconditional sleep — prefer tokio::time::advance or condition polling" \
  "sleep" \
  '(std::thread::sleep|tokio::time::sleep)[(]' \
  tests simulation

# ---------------------------------------------------------------------------
# Check I — #[ignore] without an HEA-#### tracking issue (FAIL).
#                 stale "not yet implemented" reason (WARN).
#
# Ignored tests rot when nothing tracks why they're disabled. Every #[ignore]
# message must reference an HEA-#### issue describing the unblock work.
# Audit cleanup: HEA-568 (commit 69d9065).
# ---------------------------------------------------------------------------
ignore_out="$TMP/ignore.violations"
ignore_warn_out="$TMP/ignore.warnings"
: > "$ignore_out"
: > "$ignore_warn_out"

ignore_roots=()
for r in tests simulation src benches; do
  [ -d "$r" ] && ignore_roots+=("$r")
done

if [ ${#ignore_roots[@]} -gt 0 ]; then
  while IFS= read -r f; do
    awk -v file="$f" -v fail_out="$ignore_out" -v warn_out="$ignore_warn_out" '
      /#\[ignore/ {
        line = $0
        sub(/^[ \t]+/, "", line)
        if ($0 !~ /HEA-[0-9]+/) {
          print file ":" NR ": " line >> fail_out
        }
        if (tolower($0) ~ /not yet implemented/) {
          print file ":" NR ": " line >> warn_out
        }
      }
    ' "$f"
  done < <(find "${ignore_roots[@]}" -type f -name '*.rs' 2>/dev/null | sort)
fi

if [ -s "$ignore_out" ]; then
  count=$(wc -l < "$ignore_out" | tr -d ' ')
  echo
  printf "%s%s✗ #[ignore] without an HEA-#### tracking issue (%d):%s\n" \
    "$RED" "$BLD" "$count" "$RST"
  sed 's/^/  /' "$ignore_out"
  printf "  %sfix:%s reference the tracking issue in the ignore message:\n" "$YEL" "$RST"
  printf "        %s#[ignore = \"HEA-1234: <why this test is disabled>\"]%s\n" "$BLD" "$RST"
  VIOLATIONS=$((VIOLATIONS + count))
fi

if [ -s "$ignore_warn_out" ]; then
  count=$(wc -l < "$ignore_warn_out" | tr -d ' ')
  echo
  printf "%s%s⚠ stale #[ignore] reason — \"not yet implemented\" (%d):%s\n" \
    "$YEL" "$BLD" "$count" "$RST"
  sed 's/^/  /' "$ignore_warn_out"
  printf "  %sfix:%s update the message with the current blocker, or enable the test.\n" "$YEL" "$RST"
  WARNINGS=$((WARNINGS + count))
fi

# ---------------------------------------------------------------------------
# Final tally.
# ---------------------------------------------------------------------------
echo
if [ "$VIOLATIONS" -eq 0 ]; then
  printf "%s✓ test-quality lint: 0 violations" "$GRN"
  [ "$WARNINGS" -gt 0 ] && printf ", %d warning(s)" "$WARNINGS"
  printf "%s\n" "$RST"
  exit 0
else
  printf "%s%s✗ test-quality lint: %d violation(s)" "$RED" "$BLD" "$VIOLATIONS"
  [ "$WARNINGS" -gt 0 ] && printf ", %d warning(s)" "$WARNINGS"
  printf "%s\n" "$RST"
  printf "  See docs/specs/TESTING.md § \"Test Quality Anti-Patterns\" for context.\n"
  exit 1
fi
