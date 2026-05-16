# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Hearth has not yet cut a versioned release; all shipped work appears under `[Unreleased]`.

## [Unreleased]

### Fixed

- **`onboarding.base_url` fallback is now an absolute URL** — when `onboarding.base_url` is not
  set, the setup URL logged at startup (and the `notification_email` delivery) now uses the bind
  address (`http://{bind_address}:{port}`) instead of a bare relative path (`/ui/setup?token=…`)
  that cannot be navigated to from a remote browser. A startup warning is also emitted advising
  operators to set `onboarding.base_url` for production deployments (HEA-547).
- **`onboarding.notification_email` without `onboarding.base_url` is now a startup error** —
  emailing a setup URL built from the bind address is likely unreachable by the recipient.
  Operators must now set `onboarding.base_url` explicitly when `notification_email` is configured
  (HEA-547).

- **`token.audience` now defaults to `oidc.issuer`** — the previous default `"hearth"` placeholder
  caused OIDC clients that validate `aud` against their `client_id` or resource server URL to
  silently reject all tokens. When `token.audience` is not explicitly set, the server now inherits
  `oidc.issuer` as the audience value. A startup warning is emitted if the audience is still
  `"hearth"` while `oidc.issuer` is configured to a real URL (HEA-551).
- **Global signing key now persists across restarts** — the server-wide fallback signing key was
  previously regenerated on every startup, silently invalidating all tokens that relied on it.
  The key is now stored in the WAL-backed system realm namespace on first startup and reloaded on
  subsequent startups, surviving `kill -9` and WAL replay (HEA-546).
- **`seed_realm` failures are now hard errors** — realm creation via gRPC, HTTP admin bootstrap,
  and web onboarding previously logged a warning and continued when RBAC seeding failed, leaving
  the realm permanently broken with no admin roles. All three paths now return an error to the
  caller. Startup reconciliation (`reconcile_rbac_seeds`) also runs on every `hearth serve` to
  repair any realms whose original seed was lost (HEA-545).

### Security

- **`validate_token` now rejects tokens from Suspended or Archived realms** — suspending or
  archiving a realm immediately blocks all token validation for that realm. Previously, tokens
  remained valid until natural expiry even after a realm was suspended or archived. As a
  belt-and-suspenders measure, `update_realm` also revokes all active sessions in the realm when
  transitioning to Suspended or Archived status (HEA-544).
- **PKCE mandatory for all clients** — confidential clients (those with a `client_secret`) are now
  required to supply `code_challenge`/`code_verifier` in the authorization code flow, matching the
  RFC 9700 §2.1.1 recommendation. Operators who need legacy-client compatibility can set
  `oidc.require_pkce_for_confidential_clients: false` in `hearth.yaml`; doing so emits a startup
  warning (HEA-550).
- **OIDC nonce replay protection** — `enforce_nonces` now defaults to `true`; new deployments reject replayed authorization responses for confidential clients out of the box. Operators who need legacy-client compatibility can set `oidc.enforce_nonces: false` in `hearth.yaml`; doing so emits a startup warning (HEA-548).
- **Go SDK** — minimum Go version bumped from 1.23 to 1.24, clearing `SNYK-GOLANG-STDNETHTTP-16535158` (infinite loop in `std/net/http`) (HEA-515).
- **Admin settings editor** — prototype-pollution guard strengthened in `setVal`: redundant point-of-use check on the final key segment added so static analysis can locally verify safety (HEA-515).
- **Kotlin SDK — nimbus-jose-jwt** upgraded from 9.40 to 9.41.2 (patches JWT library CVEs) (HEA-515).
- **SAML example — xmldom** replaced abandoned `xmldom ^0.6.0` (7 critical CVEs, no upstream fix) with maintained fork `@xmldom/xmldom ^0.9.10` (HEA-515).

### Added

- **Migration history page** — `/admin/migrations` lists all past cross-realm migration runs with
  source realm, destination realm, operation kind (move/copy), user counts, and status badge.
  Orphaned realms without a declared migration destination are shown in an inline recovery panel
  with an HTMX-powered YAML snippet generator to resolve or discard each orphan. The admin
  sidebar and dashboard orphan banner both link to this page (HEA-542).
- **Cross-realm user migration** — declare `migrate_from: <source-realm>` (move semantics) or
  `copy_from: <source-realm>` (copy semantics) on a destination realm's YAML block to atomically
  transfer users, credentials (Argon2id/PBKDF2/bcrypt, TOTP, WebAuthn), and RBAC role assignments
  at server startup. Role names are translated by name across realms; org memberships are matched
  by slug. A `migrate:` sub-block controls `users`, `orgs`, and `on_conflict` (`error` or `skip`).
  Migration is crash-safe: per-user progress markers in the system realm enable idempotent resume
  after an interrupted startup (HEA-541).
- **Signing key rotation** — `POST /admin/realms/{id}/rotate-signing-key` generates a new Ed25519
  key and serves both the new active key and the retiring key in JWKS for a configurable grace
  period (default 24 h), allowing clients to refresh their JWKS cache before the old key expires.
  Configure with `token.signing_key_rotation_grace_period: "24h"` (HEA-539).
- **Declarative rotation trigger** — set `rotate_signing_key: true` under a realm's YAML block to
  trigger rotation on the next server startup via config diff. The flag is auto-cleared from the
  stored snapshot so subsequent restarts do not re-rotate while the YAML still contains the flag
  (HEA-539).
- **Storage engine** — custom embedded WAL + memtable + SST storage engine with tiered hot/cold storage, crash-safe `fsync`-before-ack semantics, per-realm key prefix scoping, and background SST compaction via atomic rename.
- **Hot-path latency targets** — `benches/storage_gate.rs` CI gate enforces p50/p99 read latency; hot-tier auto-sizes from system memory / cgroup limits at startup.
- **Encryption at rest** — all stored realm data encrypted; configurable key material per deployment.
- **Identity layer** — users, hashed credentials (Argon2id), sessions, per-realm signing keys (Ed25519, PKCS#8 persisted), and full cascading delete across 11 key prefixes.
- **Multi-tenancy** — first-class `RealmId` newtype; each realm gets an isolated keyspace, its own signing key, and independent configuration. System realm (`RealmId::nil()`) stores realm metadata.
- **Per-realm branding and config** — stored email template config, locale variables, and web branding wired into login templates.
- **JWT issuance** — Ed25519-signed JWTs with `jti` claim for uniqueness, `iss`/`aud`/`exp` validation per RFC 7519.
- **OIDC Discovery** — `/.well-known/openid-configuration` document; `RS256 + ES256` keys published at `/certs`; document extended with `userinfo_endpoint`, `response_modes_supported`, `claims_supported`, `registration_endpoint`, `device_authorization_endpoint`, `revocation_endpoint`, `introspection_endpoint`, and `grant_types_supported`.
- **OAuth 2.0 complete** — authorization code flow, authorization code with PKCE, client credentials, device authorization (RFC 8628), refresh token rotation with theft detection via grant families, token revocation (RFC 7009), token introspection (RFC 7662). Introspection benchmark: ~1 µs.
- **RFC 8707 resource indicators** — threaded through token issuance and refresh.
- **Dynamic Client Registration** — RFC 7591 register + RFC 7592 read/update at `POST /register`.
- **OIDC Conformance** — Core 1.0 required claims, Discovery 1.0 metadata, UserInfo endpoint with scope-filtered claims, nonce round-trip (stored in auth code → echoed in ID token), and `iss` claim sourced from `config.oidc.issuer` to match discovery document.
- **OIDC RP-initiated logout** — with backchannel and front-channel fan-out to registered clients.
- **TOTP / MFA** — TOTP enrollment and validation (RFC 6238), time-window tolerance, recovery code generation and single-use redemption, brute-force lockout, replay protection. Per-realm `mfa_required` policy enforced at login.
- **WebAuthn / Passkeys** — full Level 2 ceremony: registration, authentication, multi-credential, resident keys, CBOR/authenticator-data parsing, counter-replay protection, RP ID mismatch rejection, and tampered `clientDataJSON` rejection.
- **Magic link / Passwordless** — single-use tokens with configurable TTL, rate limiting, enumeration resistance, and automatic account creation for unknown emails.
- **TLS termination** — PEM loading, live certificate hot-reload without restart, TLS 1.3 enforcement, weak cipher rejection, HTTP → HTTPS redirect, and mutual TLS (mTLS) support.
- **Claims-based RBAC** — replaced Zanzibar with an embedded RBAC engine: roles, groups, and permissions resolved at token issuance and embedded as `roles`/`groups`/`permissions` JWT claims. `GET /v1/me/permissions` effective-permissions endpoint. RBAC cycle detection, reserved namespace guards, and token-size cap. Admin HTTP (`/admin/roles`, `/admin/groups`) and gRPC (`RbacAdminService`) surfaces.
- **Organizations** — B2B customer groups within realms: full CRUD, membership lifecycle (invite → accept → remove), SHA-256 hashed invitation tokens with 7-day expiry, last-owner protection, cascading delete (memberships + invitations + indexes), and slug uniqueness validation.
- **Keycloak migration** — `hearth migrate keycloak --file <export.json>` CLI subcommand. Anti-corruption layer converts Keycloak's nested-JSON credential format to standard PHC strings. Native PBKDF2-SHA256 / PBKDF2-SHA512 verification; upgrades to Argon2id on next password change. `--dry-run` flag. Bypasses HTTP body limits for large exports.
- **Production email service** — five transports: Log (dev), SMTP, SendGrid, Postmark, Mailgun (with EU region). `EmailService` orchestration with per-realm branding override and Askama/Tera HTML + plaintext templates for verification and setup flows.
- **UI theming system** — six named themes: `ember` (dark default), `ocean`, `midnight`, `forest`, `cloud` (light), `slate` (light). Semantic `ht-*` Tailwind tokens backed by CSS custom properties. Global `branding.theme` / `branding.custom_css`; per-realm `web.{theme,custom_css}`. Routes: `GET /ui/static/theme.css` and `GET /ui/static/realm-theme/{id}`.
- **Admin web UI** — server-rendered Axum/Askama templates for users, realms, applications, organizations, groups, roles, permissions, scopes, identity providers, and audit log. Path-based realm scoping. Edit/delete disabled for YAML-managed applications.
- **Admin API** — CRUD endpoints for users, realms, and applications; pagination; bulk operations; full audit trail. `PUT → PATCH` on `/admin/users/{id}`; granular scope decisions; field filters.
- **SCIM provisioning** — user and group sync, service provider config endpoint, realm reconciliation, and per-handler auth enforcement.
- **Signed webhook subscriptions** — HMAC-signed delivery for auth and admin events; subscription management API.
- **Per-realm auth policy enforcement** — `allowed_auth_methods` checked at login; `AuthMethodNotAllowed` error returned when the method is disabled for the realm.
- **Configurable password-reset token TTL** — per-realm override for reset token lifetime.
- **Periodic cleanup** — background task evicts expired OAuth entities (device codes, grant families, revoked JTIs).
- **OpenTelemetry distributed tracing** — trace context propagated through identity and protocol layers.
- **Observability endpoints** — Prometheus `/metrics` (config-gated), `/healthz`, and `/readyz` with fault-injection test coverage.
- **TypeScript SDK** — `createHearth()` factory, `HearthProvider` React context, `useHasPermission` / `useHasRole` / `useInGroup` / `useInOrg` hooks, JWKS validation, and admin CRUD helpers.
- **Go SDK** — auth code flow client, admin CRUD, transparent token refresh, and `HasPermission` / `HasRole` / `InGroup` / `InOrg` / `Permissions` helpers.
- **Kotlin / JVM SDK** — `hearth-core` library for coroutine-based OIDC/JWT verification.
- **Node.js SDK** — unified `HearthClient` entry point (HEA-366).
- **SDK common specification** — `docs/sdk/SPEC.md` documents the cross-language contract; all SDK READMEs link it. CI spec-conformance checks added for TypeScript and Go.
- **Deployment artifacts** — Helm chart templates, `systemd` unit file, and `docker-compose` configuration.
- **Security Phase A** — PKCE mandatory for all public clients, redirect URI exact-match hardening, RFC 9207 `iss` parameter in all authorization responses; fuzz harnesses for token-exchange and redirect-URI validation paths (HEA-501 / HEA-503).
- **SECURITY.md** — vulnerability disclosure policy and reporting contacts.
- **OpenSSF Scorecard** — CI workflow scoring supply-chain hygiene; `CODEOWNERS` enforces review requirements.
- **Dependabot and Snyk** — automated dependency vulnerability scanning for GitHub Actions and Rust crates.
- **`cargo-audit` config** — integrated into `make check`; one known advisory (`RUSTSEC-2023-0071`, RSA, no active decrypt path) documented and ignored.
- **Rust CI quality-gate workflow** — `clippy --all-targets -D warnings`, `rustfmt --check`, `cargo nextest`, and CSS staleness check (`make css-check`) run on every PR.
- **Storage hot-path benchmark CI gate** — enforces `p50 < 50 µs` / `p99 < 200 µs` on `validate_token` / `lookup_session` / `lookup_user`.
- **`make setup`** — installs repo-managed git hooks (`.githooks/`) including pre-commit CSS and proto auto-regeneration.
- **User guides** — `docs/guides/` tree: getting-started, RBAC, SCIM provisioning, webhooks, organizations, and deployment.
- **Operator runbooks** — RBAC operator guide (client-scoped roles via `ClaimProfile`), SCIM provisioning guide, and webhooks guide.

### Changed

- **Authorization engine** — replaced Zanzibar/relationship-tuple engine with claims-based RBAC; permissions are now embedded in JWTs at issuance time rather than checked at request time.
- **License** — promoted to AGPL-3.0-only (`LICENSE`) for OpenSSF machine-detectability; commercial licensing available (see `docs/vision/VISION.md`).
- **Admin handler organization** — split `admin.rs` (~10 000 lines) into seven per-entity submodules for maintainability.
- **OIDC `iss` claim source** — now reads from `config.oidc.issuer` (not `config.token.issuer`) so the ID token issuer always matches the discovery document (OIDC Core §2 compliance).
- **Storage `put_batch` API** — all multi-record writes (user import, audit chain) go through a single WAL frame with CRC; a crash mid-batch leaves no partial state on replay.
- **Audit `append`** — refactored to use `put_batch` (primary record + actor index + action index in one WAL record), eliminating dangling index entries on crash.

### Fixed

- Double-slash 404s on Admin Users workspace links (HEA-306).
- `/jwks` endpoint cold-start timeout in CI OIDC HTTP flow test (HEA-276).
- `PUT → PATCH` on `/admin/users/{id}` to conform to RFC 7396 partial-update semantics.
- SCIM `ServiceProviderConfig` endpoint missing auth enforcement.
- Lettre CVE via cargo-audit remediation (HEA-304).
- Stale Tailwind `app.css` CI failure after template changes.
- CodeQL and Scorecard scanning alerts across protocol and identity layers (HEA-294).
- Various `clippy::pedantic` violations gating the new CI quality-gate workflow (HEA-276).

### Security

- **PKCE mandatory** — all public clients must supply a `code_challenge`; server rejects authorization requests without one (Security Phase A).
- **Redirect URI exact-match** — registered redirect URIs compared byte-for-byte; no prefix or wildcard matching (Security Phase A).
- **RFC 9207 `iss` parameter** — returned in every authorization response to prevent mix-up attacks (Security Phase A).
- **Fuzz harnesses** — `cargo-fuzz` targets for token exchange and redirect URI parsing added to `fuzz/` (HEA-503).
- **OIDC nonce replay protection** — TTL-based eviction on the in-memory nonce set prevents unbounded growth while preserving replay resistance.
- **Ed25519-only JWT signing** — `alg:none` and symmetric algorithms (HS256 etc.) rejected at decode time.
- **Argon2id password hashing** — OWASP-recommended parameters; off hot path via `spawn_blocking`.
- **Zeroize-on-drop for secrets** — passwords, tokens, and keys wrapped in `Zeroize`-on-drop types; `Debug`/`Display`/`Serialize` impls intentionally absent.
- **Constant-time comparisons** — all secret-equality checks use `subtle::ConstantTimeEq`.
- **Audience claim validation** — `aud` checked against configured allowed audiences per RFC 7519 §4.1.3 (HEA-239).
- **`exp` and `token_type` enforcement** — `validate_token` rejects expired and mis-typed tokens (HEA-129).
- **HTTP body size limits** — enforced at protocol layer to prevent memory-exhaustion attacks.
- **Error sanitization** — error messages scrubbed of sensitive data before crossing layer boundaries.

### Removed

- **Zanzibar authorization engine** — `src/authz/`, tuple storage, `AuthzCache` in TypeScript and Go SDKs, `POST /v1/authz/check`, `GET /v1/me/capabilities`, and `CapabilityPage` bundles. All authorization now goes through `src/rbac/`.
- **`lazy_static`** — replaced with `std::sync::OnceLock` / `LazyLock` throughout.
