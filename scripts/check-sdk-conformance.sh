#!/usr/bin/env bash
# Verifies that every SDK in sdks/ satisfies the Hearth SDK spec.
# Spec reference: docs/sdk-spec.md
# Run: bash scripts/check-sdk-conformance.sh
# Exit code: 0 = all checks passed, non-zero = one or more failures.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_ROOT="$REPO_ROOT/sdks"
PASS=0
FAIL=0
FAILURES=()

# ── helpers ──────────────────────────────────────────────────────────────────

ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*"; FAIL=$((FAIL+1)); FAILURES+=("$*"); }

# sdk_grep <sdk-dir> <pattern> <description>
# Returns 0 if pattern found anywhere under sdk-dir, 1 otherwise.
sdk_grep() {
    local dir="$1" pattern="$2" desc="$3"
    if grep -rq --include="*.go" --include="*.ts" --include="*.py" --include="*.rs" \
            --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=target \
            -e "$pattern" "$dir" 2>/dev/null; then
        ok "$desc"
    else
        fail "$desc"
    fi
}

# readme_contains <sdk-dir> <pattern> <description>
readme_contains() {
    local dir="$1" pattern="$2" desc="$3"
    local readme="$dir/README.md"
    if [[ -f "$readme" ]] && grep -qi "$pattern" "$readme"; then
        ok "$desc"
    else
        fail "$desc"
    fi
}

check_sdk() {
    local sdk_dir="$1"
    local sdk_name
    sdk_name="$(basename "$sdk_dir")"

    printf "\n\033[1m── %s ──\033[0m\n" "$sdk_name"

    # ── Section 5: Error taxonomy (9 required error type names) ──────────────
    local errors=(
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
    for err in "${errors[@]}"; do
        sdk_grep "$sdk_dir" "$err" "Section 5: $err defined"
    done

    # ── Section 4: Claims API public methods ──────────────────────────────────
    # Method names follow spec; language adapters (camelCase, snake_case) both accepted.
    local claims=(
        "subject\|Subject\|get_subject"
        "issuer\|Issuer\|get_issuer"
        "audiences\|Audiences\|get_audiences"
        "expiry\|Expiry\|get_expiry\|expires_at"
        "issuedAt\|IssuedAt\|issued_at\|get_issued_at"
        "jwtID\|JwtID\|JwtId\|jwt_id\|get_jwt_id"
        "hasScope\|HasScope\|has_scope"
        "hasRole\|HasRole\|has_role"
        "hasPermission\|HasPermission\|has_permission"
    )
    local claim_names=(
        "subject()" "issuer()" "audiences()" "expiry()" "issuedAt()"
        "jwtID()" "hasScope()" "hasRole()" "hasPermission()"
    )
    for i in "${!claims[@]}"; do
        sdk_grep "$sdk_dir" "${claims[$i]}" "Section 4: Claims API ${claim_names[$i]}"
    done

    # ── Section 8: CHANGELOG.md present ──────────────────────────────────────
    if [[ -f "$sdk_dir/CHANGELOG.md" ]]; then
        ok "Section 8: CHANGELOG.md present"
    else
        fail "Section 8: CHANGELOG.md missing in $sdk_name"
    fi

    # ── Section 10: README sections ───────────────────────────────────────────
    readme_contains "$sdk_dir" "install" "Section 10: README has installation section"
    readme_contains "$sdk_dir" "quick.start\|quickstart\|getting.started" "Section 10: README has quickstart section"
    readme_contains "$sdk_dir" "troubleshoot" "Section 10: README has troubleshooting section"
    readme_contains "$sdk_dir" "sdk-spec\.md\|sdk_spec\.md" "Section 10: README links to sdk-spec.md"

    # ── Section 11: No secrets in error messages (static check) ──────────────
    # Look for the most dangerous pattern: Go fmt.Errorf/Sprintf or TS template
    # literals that interpolate a variable explicitly named token/secret/password.
    # This is a heuristic; manual review is still required for complex cases.
    local go_pattern='fmt\.(Errorf|Sprintf)\([^)]*%(v|s|q)[^)]*,.*\b(token|secret|password|credential)\b'
    local ts_pattern='`[^`]*\$\{[^}]*(token|secret|password|credential)[^}]*\}[^`]*`'
    if grep -rqE --include="*.go" -e "$go_pattern" "$sdk_dir" 2>/dev/null || \
       grep -rqE --include="*.ts" --exclude-dir=node_modules -e "$ts_pattern" "$sdk_dir" 2>/dev/null; then
        fail "Section 11: Possible secret/token value interpolated into error/log string"
    else
        ok "Section 11: No obvious secret value interpolation in error messages"
    fi
}

# ── main ─────────────────────────────────────────────────────────────────────

printf "\033[1mHearth SDK conformance check\033[0m\n"
printf "Spec: docs/sdk-spec.md\n"

for sdk in "$SDK_ROOT"/*/; do
    [[ -d "$sdk" ]] || continue
    check_sdk "$sdk"
done

# ── summary ───────────────────────────────────────────────────────────────────

printf "\n\033[1mSummary:\033[0m %d passed, %d failed\n" "$PASS" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    printf "\n\033[31mFailed checks:\033[0m\n"
    for f in "${FAILURES[@]}"; do
        printf "  • %s\n" "$f"
    done
    printf "\nSee docs/sdk-spec.md for the full specification.\n"
    exit 1
fi

printf "\n\033[32mAll checks passed.\033[0m\n"
