#!/usr/bin/env bash
# check-bench-regression.sh — fail if any criterion benchmark mean regresses
# by more than THRESHOLD% vs the stored 'main' baseline.
#
# Usage: scripts/check-bench-regression.sh [threshold_pct]
#   threshold_pct  Regression limit as an integer percentage (default: 5)
#
# Reads:  target/criterion/<bench>/main/estimates.json  (baseline)
#         target/criterion/<bench>/new/estimates.json   (current run)
#
# The 'main' baseline is written by:
#   cargo bench --bench <name> -- --save-baseline main --noplot
#
# The 'new' snapshot is written automatically after every `cargo bench` run.
# Both must exist for a benchmark to be checked; missing pairs are skipped with
# a warning so that new benchmarks (no baseline yet) do not block PRs.
#
# Exit codes:
#   0  All checked benchmarks within threshold (or no baseline found).
#   1  One or more benchmarks regressed beyond threshold.

set -euo pipefail

THRESHOLD="${1:-5}"
CRITERION_DIR="target/criterion"
FAILED=0
CHECKED=0
SKIPPED=0

if [[ ! -d "$CRITERION_DIR" ]]; then
    echo "WARNING: $CRITERION_DIR not found; no benchmarks to check."
    exit 0
fi

while IFS= read -r -d '' baseline_file; do
    # Derive sibling 'new' snapshot from baseline path.
    # baseline: .../main/estimates.json  → new: .../new/estimates.json
    bench_dir="$(dirname "$(dirname "$baseline_file")")"
    current_file="$bench_dir/new/estimates.json"

    if [[ ! -f "$current_file" ]]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    baseline_mean=$(awk -F'"point_estimate":' 'NR==1{print $2}' "$baseline_file" \
        | awk -F'[,}]' '{print $1}' | tr -d ' ')
    current_mean=$(awk -F'"point_estimate":' 'NR==1{print $2}' "$current_file" \
        | awk -F'[,}]' '{print $1}' | tr -d ' ')

    # Skip if either value is empty or zero (malformed JSON guard).
    [[ -z "$baseline_mean" || -z "$current_mean" ]] && { SKIPPED=$((SKIPPED + 1)); continue; }
    awk "BEGIN { exit ($baseline_mean > 0) ? 0 : 1 }" || { SKIPPED=$((SKIPPED + 1)); continue; }

    # Derive a human-readable name from directory structure.
    bench_name=$(basename "$bench_dir")
    parent_dir=$(basename "$(dirname "$bench_dir")")
    if [[ "$parent_dir" == "criterion" ]]; then
        label="$bench_name"
    else
        label="$parent_dir/$bench_name"
    fi

    CHECKED=$((CHECKED + 1))

    # pct_change = (current - baseline) / baseline * 100
    result=$(awk "BEGIN {
        pct = ($current_mean - $baseline_mean) / $baseline_mean * 100
        if (pct > $THRESHOLD) {
            printf \"FAIL %.1f\", pct
        } else {
            printf \"OK   %.1f\", pct
        }
    }")

    status="${result%% *}"
    pct="${result##* }"

    if [[ "$status" == "OK" ]]; then
        echo "  OK   $label: ${pct}%"
    else
        echo "  FAIL $label: +${pct}% (threshold: ${THRESHOLD}%)"
        FAILED=$((FAILED + 1))
    fi
done < <(find "$CRITERION_DIR" -name "estimates.json" -path "*/main/estimates.json" -print0 2>/dev/null | sort -z)

echo ""
echo "Benchmarks checked: $CHECKED | Skipped (no baseline): $SKIPPED | Regressions: $FAILED"

if [[ $CHECKED -eq 0 && $SKIPPED -eq 0 ]]; then
    echo "WARNING: no main baseline found — run with --save-baseline main on main branch first."
    exit 0
fi

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo "ERROR: $FAILED benchmark(s) regressed by more than ${THRESHOLD}%." >&2
    echo "To investigate: PROTOC=protoc cargo bench -- --baseline main" >&2
    exit 1
fi
