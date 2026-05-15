# Changelog

All notable changes to `hearth-sdk` (Python) are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-05-15

Full spec remediation (HEA-497): all open sections implemented.

### Added
- `HearthClient` now accepts spec-compliant constructor parameters:
  `issuer_url`, `client_id`, `client_secret`, `jwks_ttl`,
  `introspection_endpoint`, `http_timeout` (§1).
- Auto-discover all OIDC endpoints from
  `{issuer_url}/.well-known/openid-configuration` on first use (§1).
- `verify_token(token) -> VerifiedToken` with RS256 and ES256 support (§2).
- JWKS cache: respects `Cache-Control: max-age`, defaults to 5 min,
  hard cap 24 h, re-fetches on `kid` miss, accumulates keys without
  discard on rotation (§2 rules 1–5).
- `introspect(token) -> IntrospectionResult` per RFC 7662 (§3).
- `VerifiedToken` with typed snake_case accessors: `subject`, `issuer`,
  `audience`, `issued_at`, `expires_at`, `not_before`, `scope`,
  `scopes`, `get()`, `raw` (§4).
- `has_scope()`, `has_role()`, `has_permission()` helpers on
  `VerifiedToken` — all use `hmac.compare_digest` for timing safety
  (§4, §11).
- Complete error taxonomy — 9 exception types: `HearthError`,
  `ConfigurationError`, `DiscoveryError`, `JwksFetchError`,
  `TokenVerificationError`, `TokenExpiredError`, `TokenClaimsError`,
  `IntrospectionError`, `MiddlewareError`.  Granular sub-types
  (`TokenIssuerError`, `TokenAudienceError`, `TokenNotYetValidError`)
  kept as `TokenClaimsError` subclasses (§5).
- Flask `hearth_flask()` decorator: extracts Bearer token, verifies via
  JWKS, injects `VerifiedToken` into `flask.g.hearth_token`, returns
  `401` / `403` on failure (§6).
- FastAPI `hearth_fastapi()` dependency factory: async dependency,
  injects `VerifiedToken`, returns `401` / `403` on failure (§6).
- Both middleware adapters support introspection opt-in flag (§6).
- `IntrospectionResult` type with `active`, `sub`, `iss`, `aud`, `exp`,
  `iat`, `scope`, `extra` fields and `to_verified_token()` helper (§3).
- `JWKSFetchError` uppercase alias retained for spec conformance
  checklist (§5).
- pytest suite: unit tests for all public API surface, JWKS key-rotation
  integration test, clock-skew boundary tests (§9).
- `≥80%` line coverage gate enforced via `pytest-cov` (§9).
- GitHub Actions CI workflow: `sdks/python/` path-filtered,
  Python 3.10/3.11/3.12 matrix (§9).
- Dependabot `pip` entry for `sdks/python/` (§11).
- README: server compatibility matrix and expanded troubleshooting
  section covering all §5 error types (§8, §10).

### Changed
- Constructor parameters renamed from `base_url`/`realm_id`/`timeout`
  to `issuer_url`/`client_id`/`http_timeout` per spec §1.
- `HearthError` is now the single root exception class; all SDK errors
  inherit from it.  The old `HearthSdkError` base is removed.
- `Jwk` Pydantic model now uses `extra="allow"` and optional fields
  to correctly support both RSA and EC key types.
- `version` bumped to `0.2.0`.

## [0.1.0] — initial

- Initial SDK scaffold: `HearthClient`, `AdminClient`, basic OAuth flows,
  RBAC predicates, WebAuthn stubs.
