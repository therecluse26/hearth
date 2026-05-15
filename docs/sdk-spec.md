# Hearth SDK Common Specification

> **Canonical reference.** This document is the board-approved specification for all Hearth client SDKs.  
> Generated from [HEA-332](https://github.com/therecluse26/hearth) — do not edit without board approval.

---

### 1. Configuration

Every SDK must accept a single primary entry point (a `HearthClient` class, struct, or equivalent) configured with:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `issuer_url` | string | Yes | Root URL of the Hearth instance (e.g. `https://auth.example.com`) |
| `client_id` | string | Conditional | Required for flows that need a client identity |
| `client_secret` | string | Conditional | Required for confidential client flows |
| `jwks_ttl` | duration | No | Override cache TTL for JWKS. Default: respect `Cache-Control`, fall back to 5 min |
| `introspection_endpoint` | string | No | Override discovered introspection URL |
| `http_timeout` | duration | No | Timeout for all outbound HTTP calls. Default: 10s |

SDKs **must** auto-discover all endpoint URLs from `{issuer_url}/.well-known/openid-configuration` on first use. Hard-coded endpoint paths are prohibited.

---

### 2. JWKS & Token Verification

**Required algorithms:** RS256, ES256. Both must be supported; others may be allowed if the server advertises them in `jwks_uri`.

**JWKS caching rules (mandatory):**
1. Cache keys by `kid`. Do not discard keys not present in the latest fetch.
2. Respect `Cache-Control: max-age` from the JWKS endpoint response.
3. On cache miss for a `kid`: re-fetch once before returning an error.
4. On HTTP 401 from a protected resource: re-fetch JWKS once, then retry the verification.
5. Maximum cache age: 24 hours regardless of Cache-Control.

**JWT validation steps (mandatory, in order):**
1. Verify signature against cached JWKS.
2. Verify `exp` claim (reject if expired).
3. Verify `iss` matches configured `issuer_url`.
4. Verify `aud` contains the configured `client_id` (server SDKs only; configurable).
5. Verify `iat` is not in the future (allow up to 5s clock skew).

**Rejected tokens must return a typed error** (see Section 5), not a bare string or generic exception.

---

### 3. Token Introspection

All SDKs must expose an introspection method (RFC 7662):

```
introspect(token: string) → IntrospectionResult
```

`IntrospectionResult` must include:

| Field | Type | Required |
|-------|------|----------|
| `active` | bool | Always |
| `sub` | string | When active |
| `exp` | timestamp/int | When active |
| `iat` | timestamp/int | When active |
| `iss` | string | When active |
| `aud` | string or string[] | When active |
| `scope` | string | When active and present |
| `client_id` | string | When active and present |
| `extra` | map/dict | All non-standard claims |

Introspection results **must not be cached** (RFC 7662 §2.1 — the token state can change at any time).

---

### 4. Claims API

Every SDK must provide typed access to standard JWT claims from a verified token, without requiring consumers to parse raw JSON:

| Method/Property | Returns |
|-----------------|---------|
| `subject()` | string |
| `issuer()` | string |
| `audiences()` | string[] |
| `expiry()` | native datetime/time type |
| `issuedAt()` | native datetime/time type |
| `jwtID()` | string (may be empty) |
| `scope()` | string (space-delimited) |
| `scopes()` | string[] (parsed) |
| `hasScope(s)` | bool |
| `hasRole(r)` | bool — reads Hearth `roles` claim |
| `hasPermission(p)` | bool — reads Hearth `permissions` claim |
| `get(claim)` | raw value (for custom claims) |

`hasRole` and `hasPermission` must read from Hearth's standard custom claims (`roles: string[]`, `permissions: string[]`). If the claim is absent, return `false` (never error).

---

### 5. Error Taxonomy

All SDKs must define and expose the following error/exception types. Language-native error handling patterns apply (Go: sentinel errors + types; Python: exceptions; TypeScript: typed Error subclasses; etc.):

| Error | When Thrown |
|-------|-------------|
| `ConfigurationError` | Missing required config, invalid issuer URL |
| `DiscoveryError` | OIDC discovery endpoint unreachable or returned invalid JSON |
| `JWKSFetchError` | JWKS endpoint unreachable or returned invalid response |
| `TokenExpiredError` | `exp` claim is in the past |
| `TokenNotYetValidError` | `nbf` claim is in the future (beyond clock skew) |
| `TokenInvalidError` | Signature invalid, malformed JWT, or algorithm mismatch |
| `TokenIssuerError` | `iss` does not match configured issuer |
| `TokenAudienceError` | `aud` does not contain expected audience |
| `IntrospectionError` | Introspection endpoint unreachable or returned error |

All errors must include a human-readable `message`. Errors that wrap an underlying network or parse error must expose the original cause (Go: `Unwrap()`; Python: `__cause__`; TypeScript: `cause` property).

**Tokens and secrets must never appear in error messages or log output.**

---

### 6. Middleware

All server-side SDKs (node, go, python) must provide HTTP middleware that:

1. Extracts the Bearer token from `Authorization: Bearer <token>`.
2. Verifies the token locally (JWKS path) by default. Introspection must be opt-in.
3. On success: injects verified claims into the request context using a well-known key.
4. On missing/invalid token: responds with `401 Unauthorized`, `WWW-Authenticate: Bearer realm="hearth"`.
5. On insufficient scope/role: responds with `403 Forbidden`.
6. Does not call `next` on auth failure.

The browser SDK (`@hearth/browser`) is exempt from the middleware requirement but must provide equivalent helpers for SPA route guards.

**Framework adapters** (Express, Fastify, Flask, FastAPI, net/http, chi, gin) are bundled with the SDK or in a companion package. The core SDK has no framework dependency.

---

### 7. PKCE & Browser Flows (browser SDK only)

The browser SDK must additionally implement:

- **PKCE authorization code flow** (RFC 7636): `login()` → redirect, `handleCallback()` → tokens
- **Silent refresh**: Attempt token renewal via hidden iframe before expiry. Configurable lead time (default: 60s before exp).
- **Logout**: Local session clear + RP-initiated logout redirect.
- **Storage abstraction**: Default `sessionStorage`; pluggable (localStorage, in-memory, custom). Storage key prefix must be configurable.
- **Cross-tab state sync**: Broadcast channel or storage events to sync login/logout across tabs (optional but recommended).

---

### 8. Versioning

- All SDKs use **SemVer** (MAJOR.MINOR.PATCH).
- Each SDK release declares a minimum compatible Hearth server version in its README and package metadata.
- A `CHANGELOG.md` is required and maintained per release.
- **During Phase 2–3 remediation:** major version bumps and breaking API changes are freely permitted with no deprecation period or migration guide required. The product is unreleased and has no external users to protect.

---

### 9. Testing Requirements

| Category | Requirement |
|----------|-------------|
| Unit tests | All public methods and error paths |
| Integration tests | Verified against a live Hearth instance (or Hearth test server in CI) |
| JWKS rotation test | Force a key rollover and verify transparent recovery |
| Clock skew test | Verify tolerance at boundaries |
| Coverage target | ≥ 80% line coverage |
| CI gate | Tests must pass on every PR; coverage check enforced |

---

### 10. Documentation Requirements

Every SDK repo must contain:

- `README.md` with installation + quickstart (< 5 min to first verified token)
- Full API reference (generated from source or hand-written)
- One runnable example per supported framework
- Troubleshooting section covering common errors from Section 5
- Link to Hearth server compatibility matrix

---

### 11. Security Requirements

- Tokens and secrets must **never** appear in logs, error messages, or stack traces.
- All HTTPS connections must validate TLS certificates (no `InsecureSkipVerify` or equivalent).
- Timing-safe comparison for any credential or secret comparison.
- Dependencies must be minimal and pinned/audited (e.g., `dependabot` enabled).
- No eval, exec, or dynamic code generation on token data.

---

## Conformance Checklist

For use in PR reviews and automated CI checks (see `.github/workflows/sdk-conformance.yml` and `scripts/check-sdk-conformance.sh`):

- [ ] Error types match the 9 names from Section 5 (`ConfigurationError`, `DiscoveryError`, `JWKSFetchError`, `TokenExpiredError`, `TokenNotYetValidError`, `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`, `IntrospectionError`)
- [ ] All public Claims API methods from Section 4 are present (`subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`, `scope`, `scopes`, `hasScope`, `hasRole`, `hasPermission`, `get`)
- [ ] No tokens or secrets can appear in error messages or logs (Section 11)
- [ ] JWKS caching follows the 5-rule contract (Section 2)
- [ ] Tests cover JWKS rotation and clock skew edge cases (Section 9)
- [ ] README includes quickstart, API reference, and troubleshooting (Section 10)
- [ ] CHANGELOG.md present and updated (Section 8)
