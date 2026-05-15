#!/usr/bin/env bash
# check-sdk-conformance.sh — Verify each Hearth SDK conforms to docs/sdk-spec.md.
#
# Exits non-zero if any requirement is unmet. Designed to run in CI on every PR.
# Can also be run locally: ./scripts/check-sdk-conformance.sh [sdk_dir]
#
# If a single SDK directory is provided as $1 (e.g. sdks/typescript), only that
# SDK is checked. Otherwise all four SDKs are checked.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[0;33m%s\033[0m\n' "$*"; }

pass() { green "  ✓ $*"; }
fail() { red   "  ✗ $*"; FAIL=1; }

# ── Error type names required by spec §5 ─────────────────────────────────────
REQUIRED_ERRORS=(
  ConfigurationError
  DiscoveryError
  JWKSFetchError
  TokenExpiredError
  TokenNotYetValidError
  TokenInvalidError
  TokenIssuerError
  TokenAudienceError
  IntrospectionError
)

# ── Claims API method names required by spec §4 ───────────────────────────────
REQUIRED_CLAIMS=(
  subject
  issuer
  audiences
  expiry
  issuedAt
  jwtID
  scope
  scopes
  hasScope
  hasRole
  hasPermission
)

# ── README section keywords (case-insensitive) ────────────────────────────────
# Each entry is a pattern; any match in README.md satisfies that requirement.
README_SECTIONS=(
  "install"
  "quick.?start|quickstart|quick start"
  "troubleshoot"
)
README_SECTION_NAMES=(
  "Installation section"
  "Quickstart section"
  "Troubleshooting section"
)

check_sdk() {
  local sdk_dir="$1"
  local sdk_name
  sdk_name="$(basename "$sdk_dir")"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  SDK: $sdk_name ($sdk_dir)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # ── 1. Error types ──────────────────────────────────────────────────────────
  echo ""
  echo "  [§5] Error types"
  for err in "${REQUIRED_ERRORS[@]}"; do
    if grep -rq "$err" "$sdk_dir/src" "$sdk_dir"/*.go "$sdk_dir"/src/**/* 2>/dev/null \
        || grep -rql "$err" "$sdk_dir" --include="*.ts" --include="*.go" --include="*.py" --include="*.rs" 2>/dev/null; then
      pass "$err"
    else
      fail "$err — not found in $sdk_dir source; add this error type (spec §5)"
    fi
  done

  # ── 2. Claims API methods ───────────────────────────────────────────────────
  echo ""
  echo "  [§4] Claims API methods"
  for method in "${REQUIRED_CLAIMS[@]}"; do
    if grep -rql "\b${method}\b" "$sdk_dir" \
        --include="*.ts" --include="*.go" --include="*.py" --include="*.rs" 2>/dev/null; then
      pass "$method"
    else
      fail "$method — not found in $sdk_dir source; implement this Claims API method (spec §4)"
    fi
  done

  # ── 3. CHANGELOG.md ─────────────────────────────────────────────────────────
  echo ""
  echo "  [§8] Changelog"
  if [[ -f "$sdk_dir/CHANGELOG.md" ]]; then
    pass "CHANGELOG.md present"
  else
    fail "CHANGELOG.md missing — required by spec §8 (create it with an initial entry)"
  fi

  # ── 4. README sections ──────────────────────────────────────────────────────
  echo ""
  echo "  [§10] README sections"
  local readme="$sdk_dir/README.md"
  if [[ ! -f "$readme" ]]; then
    fail "README.md missing entirely — required by spec §10"
  else
    local i
    for (( i=0; i<${#README_SECTIONS[@]}; i++ )); do
      local pattern="${README_SECTIONS[$i]}"
      local label="${README_SECTION_NAMES[$i]}"
      if grep -iqE "$pattern" "$readme"; then
        pass "$label"
      else
        fail "$label — not found in $readme (spec §10)"
      fi
    done
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
if [[ "${1:-}" != "" ]]; then
  # Single SDK mode
  sdk_path="$REPO_ROOT/$1"
  if [[ ! -d "$sdk_path" ]]; then
    # Try as absolute path
    sdk_path="$1"
  fi
  check_sdk "$sdk_path"
else
  # All SDKs
  for sdk in typescript go python rust; do
    sdk_path="$REPO_ROOT/sdks/$sdk"
    if [[ -d "$sdk_path" ]]; then
      check_sdk "$sdk_path"
    else
      warn "SDK directory not found, skipping: $sdk_path"
    fi
  done
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
  green "All SDK conformance checks passed."
else
  red "One or more SDK conformance checks FAILED. See above for details."
  red "Reference: docs/sdk-spec.md"
  exit 1
fi
