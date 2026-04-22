# Feature Gaps & Roadmap Priorities

## Overview

Hearth has completed Phase 0 (18 steps, 148 scenarios), Phase 1 (13 steps, 135 scenarios), Phase 1.5 (production email), and Phase 2 (organizations). The system totals **941 Rust tests + 27 simulation + 6 SDK tests** across 8 testing layers.

**What works today:** Password authentication, TOTP/MFA, WebAuthn/Passkeys, magic links, public self-registration (per-realm policy: disabled/open/domain-restricted/invite-only, with email verification and IP+email rate limiting), password reset / account recovery, explicit realm routing in the web UI (`/ui/realms/<name>/...` path segments, optional `server.default_realm` for bare URLs, no cross-realm walk), OAuth 2.0 (authorization code, client credentials, device authorization, refresh rotation, revocation, introspection), OIDC (discovery, UserInfo, dynamic client registration, conformance), Zanzibar authorization (check, expand, write, watch, namespace config, conditional writes), multi-tenancy (realm isolation, per-realm signing keys, cascading deletes), organizations (membership, invitations), audit logging (SHA-256 hash chain, tamper detection), TLS termination (1.3, hot-reload, mTLS), admin API + web console, Keycloak migration, TypeScript + Go SDKs, and 5 email transports (SMTP, SendGrid, Postmark, Mailgun, Log).

This document inventories **features not yet implemented** that would block or hinder production adoption, compared against the commitments in `docs/vision/VISION.md`. Each gap cites the relevant Vision section for traceability.

## Priority Tiers

| Tier | Meaning |
|------|---------|
| **P0** | Blocks production deployment. Without these, an operator cannot safely run Hearth for real users. |
| **P1** | Expected for competitive parity. Enterprises and developers evaluating Hearth against Keycloak, Auth0, or Okta will expect these. |
| **P2** | Enhances operational maturity. Not blocking, but significantly improves operations, observability, and resilience. |
| **P3** | Post-release enhancements. Explicitly deferred in the Vision roadmap or listed as open questions. |

---

## P0 — Blocks Production Deployment

### 2. Self-Service Session Management

- **Vision ref:** §5.3 "Session management with revocation and device tracking."
- **Current State:** The identity engine has `list_sessions_by_user()` and session revocation. These are exposed only through the **admin** API and admin web UI (`/admin/users/{id}/sessions/{sid}/revoke`). No user-facing session visibility exists.
- **What's Missing:**
  - User-facing "My Sessions" page listing active sessions (device, IP, user-agent, last-active timestamp).
  - User-facing "Revoke" button per session ("log out my phone").
  - "Revoke all other sessions" action ("log out everywhere else").
  - Session metadata enrichment: user-agent parsing, approximate geolocation hint from IP.
  - API endpoints (`GET /account/sessions`, `DELETE /account/sessions/{id}`, `DELETE /account/sessions?all_others=true`).
- **Why It Matters:** Compromised sessions can only be revoked by administrators. Every modern auth provider (Auth0, Clerk, Google) gives users control over their own sessions. This is a baseline security expectation.
- **Priority Rationale:** P0 because session self-management is a fundamental user security control.

### 3. OAuth Consent Screen

- **Vision ref:** §5.3 "OIDC / OAuth 2.0" — implementing the full protocol implies consent per RFC 6749 §4.1.1.
- **Current State:** The authorization code flow (`src/identity/oidc.rs`) issues tokens after authentication. There is no consent prompt — users are never asked whether they approve sharing data with the requesting client. No consent is stored or revocable.
- **What's Missing:**
  - Consent prompt UI: display the requesting client name, logo, and requested scopes.
  - Scope selection: allow users to approve some scopes and deny others.
  - Consent persistence: store per-user, per-client, per-scope approvals to avoid re-prompting.
  - Consent revocation: user-facing page to review and revoke granted consents.
  - Admin visibility into consents granted per user.
  - First-party client bypass: skip consent for clients marked as trusted/first-party.
- **Why It Matters:** OAuth 2.0 best practices and GDPR require explicit user consent before sharing data with third-party clients. Without this, every OAuth client silently receives all requested scopes — a security and compliance gap.
- **Priority Rationale:** P0 for any deployment with third-party OAuth clients. Deferrable only for first-party-only setups.

---

## P1 — Expected for Competitive Parity

### 5. Social Login / External IdP Federation

- **Vision ref:** §5.3 "Multi-tenancy with per-realm identity provider configuration."
- **Current State:** Hearth functions exclusively as an identity **provider**. It issues OAuth 2.0/OIDC tokens but cannot **consume** tokens from external IdPs. There is no upstream OIDC RP flow, no social login, no account linking.
- **What's Missing:**
  - External IdP connector framework: register upstream OIDC providers (Google, GitHub, Microsoft, Apple, Okta, Azure AD) per realm.
  - OIDC RP flow: redirect → callback → token exchange → claim extraction.
  - Account linking: match external identity to existing Hearth user by email, or JIT-provision a new account.
  - Per-realm IdP configuration (realm A uses Google + GitHub, realm B uses corporate Okta).
  - UI: provider buttons on the login page, account linking in user settings.
  - Token mapping: translate external IdP claims into Hearth user attributes.
- **Why It Matters:** "Sign in with Google/GitHub" is Keycloak's most-used feature and the first thing developers evaluate. Without social login, Hearth cannot replace Keycloak for the majority of real-world deployments. Enterprise realms need OIDC federation with corporate IdPs as the modern alternative to SAML.
- **Priority Rationale:** P1 but arguably the single most impactful missing feature. This is the #1 blocker for Keycloak migration.

### 6. SAML 2.0 IdP / SP Support

- **Vision ref:** §5.3 explicitly lists "SAML 2.0 (SP-initiated and IdP-initiated)." §6.1 architecture diagram shows SAML as a protocol layer component.
- **Current State:** The protocol layer reserves a conceptual slot for SAML. No SAML code exists anywhere in the codebase.
- **What's Missing:**
  - SAML 2.0 IdP: issue SAML assertions for SP-initiated and IdP-initiated SSO.
  - SAML 2.0 SP: consume assertions from external IdPs (corporate AD FS, Okta, PingFederate).
  - Metadata exchange: XML descriptor generation (`/saml/metadata`) and parsing.
  - Assertion signing: RSA-SHA256 is the SAML standard (Ed25519 is not widely supported by SAML SPs). May need RSA key management alongside existing Ed25519.
  - Single Logout (SLO) support.
  - Attribute mapping between SAML assertions and Hearth user attributes.
- **Why It Matters:** Enterprise procurement gates on SAML. Corporate IT departments integrating with AD FS, Okta, or PingFederate require SAML. Without it, Hearth is excluded from enterprise evaluation shortlists.
- **Priority Rationale:** P1 because OIDC covers modern integrations, but enterprise deals require SAML.

### 7. SCIM 2.0 Provisioning

- **Vision ref:** §5.3 explicitly lists "SCIM 2.0 provisioning." §6.1 architecture diagram shows SCIM as a protocol layer component.
- **Current State:** SCIM is referenced in architecture and vision documents. No SCIM code exists.
- **What's Missing:**
  - SCIM 2.0 server endpoints: `/Users` and `/Groups` CRUD with filtering (`filter=userName eq "john"`), pagination, and PATCH.
  - Schema discovery endpoints (`/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig`).
  - SCIM User → Hearth User attribute mapping.
  - SCIM Group → Zanzibar relation / organization membership mapping.
  - Event hooks: audit when users are provisioned/deprovisioned via SCIM.
  - Bearer token or OAuth authentication for SCIM endpoints.
- **Why It Matters:** Enterprises sync HR directories (Workday, BambooHR) and IdPs (Okta, Azure AD) via SCIM. Without SCIM, user provisioning is manual or requires custom API integration.
- **Priority Rationale:** P1 because automated provisioning is a procurement requirement for mid-to-large enterprises.

### 8. gRPC Management API

- **Vision ref:** §6.1 "The protocol layer also exposes a gRPC and REST management API."
- **Current State:** Protobuf definitions exist in `proto/hearth/` (identity, oauth, authz, audit). Code generation via `buf` produces Rust, Go, and TypeScript types. REST/HTTP endpoints are fully implemented. **No gRPC server handlers exist** — the generated types are used only for serialization/deserialization in the REST layer.
- **What's Missing:**
  - `tonic`-based gRPC server with service implementations for all proto-defined RPCs.
  - gRPC reflection for tooling (grpcurl, Postman).
  - gRPC health checking protocol (for load balancer probes).
  - mTLS support on the gRPC listener (may share TLS config with HTTP).
  - Documentation: which operations are available via gRPC vs REST vs both.
- **Why It Matters:** The Vision promises gRPC alongside REST. Machine-to-machine integrations, SDKs, and infrastructure tools (Terraform providers, Kubernetes operators) prefer gRPC for type safety and code generation. The proto files are a promise without delivery.
- **Priority Rationale:** P1 because REST covers most use cases, but the Vision explicitly commits to gRPC.

### 9. Documentation Site

- **Vision ref:** Phase 1 exit criteria include "Documentation site" as a deliverable.
- **Current State:** Documentation exists as raw markdown files in `docs/` (specs, vision, gaps, theme). There is no built documentation site — no mdbook, docusaurus, or equivalent. No getting-started guide beyond code-level docs.
- **What's Missing:**
  - Static site generator setup (mdbook for Rust projects, or docusaurus for broader reach).
  - Getting started guide: install → configure → first login flow.
  - API reference: auto-generated from proto definitions and/or OpenAPI spec.
  - SDK documentation for TypeScript and Go.
  - Configuration reference (exists as markdown, needs to be in the site).
  - Migration guides (Keycloak, and eventually Auth0/Clerk).
  - Architecture overview for contributors.
  - Search functionality.
  - Deployment to a public URL (e.g., docs.hearth.dev via GitHub Pages or Vercel).
- **Why It Matters:** Developer adoption requires discoverable, navigable documentation. Raw markdown in a Git repository is not a documentation site. This is explicitly a Phase 1 deliverable that was not completed.
- **Priority Rationale:** P1 — Phase 1 exit criteria explicitly lists this. Open-source projects without documentation don't get adopted.

### 10. Additional Migration Tools

- **Vision ref:** §8.3 describes migration paths for Auth0, Clerk, Cognito, Firebase Auth, and generic SCIM/CSV/JSON import.
- **Current State:** Only Keycloak migration is implemented (`src/identity/migration/keycloak.rs`, `hearth migrate keycloak` CLI).
- **What's Missing:**
  - Auth0 migration: import users, connections, and applications via Auth0 Management API.
  - Clerk migration: import users and organizations via Clerk API.
  - Generic import: CSV/JSON bulk import for custom user databases.
  - SCIM-based bulk import for systems with SCIM export.
  - Shadow mode: run Hearth alongside existing auth, replaying traffic to validate correctness before cutover (Vision §5.5).
  - Export tools: full realm export to standard formats.
- **Why It Matters:** Migration friction is the #1 barrier to adoption. Keycloak is one source among many. Teams on Auth0, Clerk, or homegrown systems need a path in.
- **Priority Rationale:** P1 for Auth0/Clerk (large addressable market). P2 for Cognito/Firebase. Shadow mode is P2.

---

## P2 — Enhances Operational Maturity

### 11. Prometheus / OpenTelemetry Observability

- **Vision ref:** Phase 2 deliverable: "Prometheus metrics and OpenTelemetry tracing."
- **Current State:** Hearth uses `tracing` for structured logging throughout all layers. Benchmarks exist (`benches/`) but are dev-only. No metrics exporter, no trace exporter.
- **What's Missing:**
  - Prometheus metrics endpoint (`/metrics`) with counters, gauges, and histograms:
    - `hearth_auth_total{method,realm,status}` — authentication attempts.
    - `hearth_token_issued_total{grant_type,realm}` — tokens issued.
    - `hearth_authz_check_total{result,realm}` — authorization checks.
    - `hearth_session_active{realm}` — gauge of active sessions.
    - `hearth_request_duration_seconds{endpoint,method}` — request latency histograms.
    - `hearth_storage_wal_bytes`, `hearth_storage_memtable_entries`, `hearth_storage_sst_count`.
  - OpenTelemetry trace export (OTLP) via `tracing-opentelemetry`.
  - Grafana dashboard template.
- **Why It Matters:** Production operators need dashboards and alerting. Without metrics, detecting degradation, capacity planning, and incident response require log parsing. Every comparable system (Keycloak, Ory, Zitadel) exposes Prometheus metrics.
- **Priority Rationale:** P2 per Vision roadmap. Practically essential for any production deployment.

### 12. Backup / Restore / Snapshots

- **Vision ref:** §6.1 cluster layer mentions snapshot-based recovery. §3.1 mentions S3 for snapshots.
- **Current State:** WAL + SST provides crash recovery (survive `kill -9`). No user-facing backup, restore, or snapshot mechanism. No S3 integration.
- **What's Missing:**
  - Online snapshot: consistent point-in-time capture without stopping writes.
  - Snapshot export to local filesystem or S3-compatible object storage.
  - `hearth backup` and `hearth restore` CLI subcommands.
  - Incremental backup: ship WAL segments since last snapshot.
  - Per-realm export/import for migration between Hearth instances.
  - Restore validation: checksum verification on restore.
- **Why It Matters:** WAL provides crash safety, not disaster recovery. Operators need protection against DC failure, disk corruption, accidental deletion, and the ability to migrate data between environments.
- **Priority Rationale:** P2 because crash safety exists, but no production team deploys a database without backup/restore.

### 13. Webhook / Event Delivery

- **Vision ref:** §A Open Question #3: "Should Hearth provide a built-in event system?"
- **Current State:** Audit events are recorded internally with SHA-256 hash chain integrity. No external push notification mechanism exists.
- **What's Missing:**
  - Webhook subscription management: register per-realm HTTPS endpoints with event type filters.
  - Reliable delivery: at-least-once semantics with exponential backoff retry.
  - Payload signing (HMAC-SHA256) for recipient verification.
  - Delivery log: status tracking (pending, delivered, retrying, failed, disabled).
  - Event types: `user.created`, `user.deleted`, `session.created`, `session.revoked`, `permission.changed`, `realm.updated`, `org.member.added`.
  - Admin UI for managing webhook subscriptions and viewing delivery logs.
- **Why It Matters:** Downstream systems (billing, analytics, SIEM, Slack notifications) need real-time event feeds. Without webhooks, operators must poll the audit API.
- **Priority Rationale:** P2 — the audit log provides queryable history, but push-based integration is the modern standard.

### 14. Encryption at Rest

- **Vision ref:** §5.4 "Encryption at rest: credentials and sensitive fields are encrypted with per-realm keys. Compromising the storage layer does not compromise credentials."
- **Current State:** Credentials are hashed (Argon2id), sensitive fields use `Zeroize`-on-drop. The storage engine writes plaintext keys and values to WAL and SST files. There is **no encryption of data on disk** and no per-realm encryption key management.
- **What's Missing:**
  - Per-realm data encryption keys (DEKs) for encrypting stored values.
  - Key encryption key (KEK) hierarchy: master key wraps per-realm DEKs.
  - Transparent encryption/decryption in the storage engine write/read path.
  - Key rotation without re-encrypting all data (envelope encryption pattern).
  - Optional HSM/KMS integration for master key storage (Vision §A Open Question #6).
  - `hearth rotate-keys` CLI subcommand.
- **Why It Matters:** The Vision explicitly commits to this feature. Compliance-sensitive deployments (healthcare, finance, government) require encryption at rest. Password hashes alone don't satisfy this — user profiles, session data, audit logs, and relationship tuples are all stored in cleartext on disk.
- **Priority Rationale:** P2 for general use (hashed credentials are the primary defense). P1 for compliance-regulated environments.

### 15. CI/CD Pipelines

- **Current State:** No `.github/workflows/` directory. No automated testing, linting, or release pipeline. All testing is manual (`cargo nextest run`).
- **What's Missing:**
  - GitHub Actions workflow: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo nextest run` on every PR.
  - CI tiers matching TESTING.md: Fast (every commit), Standard (merge), Extended (nightly), Full (weekly).
  - Release pipeline: build binaries for Linux/macOS/Windows, publish Docker images, create GitHub releases.
  - Security scanning: `cargo audit`, `cargo deny check`.
  - Benchmark regression detection (compare against baseline).
- **Why It Matters:** Open-source credibility requires visible CI badges. Contributors need automated feedback. Release engineering requires automation.
- **Priority Rationale:** P2 per typical project lifecycle, but practically P0 for open-source project launch.

### 16. Global Configurable Rate Limiter

- **Current State:** Rate limiting exists per-feature: password auth (5 attempts/15min), admin API (100/min), TOTP (5 attempts/5min), magic link (per-email). No unified middleware.
- **What's Missing:**
  - Global rate limiter middleware: IP-based, configurable per endpoint and per realm.
  - Token bucket or sliding window algorithm with configurable parameters.
  - Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`).
  - Per-realm quota allocation (realm A: 1000 req/s, realm B: 100 req/s).
  - Connection-level limits (max concurrent connections per IP).
- **Why It Matters:** Per-feature limits protect specific abuse vectors. A unified system is needed for fair multi-tenant resource allocation and general API protection.
- **Priority Rationale:** P2 because critical paths are already protected.

### 17. Deployment Artifacts

- **Vision ref:** Phase 2: "Helm chart and systemd service file."
- **Current State:** Dockerfile and docker-compose.yaml exist. No Kubernetes or bare-metal deployment artifacts.
- **What's Missing:**
  - Helm chart: configurable values for single-node and future cluster mode.
  - systemd service file with proper sandboxing (`ProtectSystem=strict`, `PrivateTmp=true`).
  - Kubernetes manifests (StatefulSet for persistence, Service, ConfigMap, Secret).
  - Example Terraform module for cloud VM deployment.
- **Why It Matters:** Production teams deploy to Kubernetes or Linux VMs. Without official deployment artifacts, every team writes their own.
- **Priority Rationale:** P2 per Vision roadmap.

---

## P3 — Post-Release Enhancements

### 18. Authorization Schema Language

- **Vision ref:** §A Open Question #1: "How closely should Hearth follow SpiceDB's schema language vs. designing a bespoke DSL?"
- **Current State:** Namespace config is stored as raw JSON per realm. Relationship tuples are written via API with no schema validation beyond optional namespace config.
- **What's Missing:**
  - Schema definition language for permission models (types, relations, permissions).
  - Schema validation: reject tuples that don't match the schema.
  - IDE support: syntax highlighting, autocompletion for schema files.
  - Schema versioning and migration tooling.
- **Priority Rationale:** P3 — functional without it, but DX and correctness would benefit significantly.

### 19. Expression Language for Conditions (CEL)

- **Vision ref:** §A Open Question #2: "CEL is the obvious candidate."
- **Current State:** Conditional relationships (caveats) exist in the authorization engine, but no expression evaluator is integrated. Conditions are limited to what's hard-coded.
- **What's Missing:**
  - CEL (Common Expression Language) or equivalent evaluator.
  - Integration with caveat evaluation at permission check time.
  - Expression validation at write time (reject invalid expressions).
- **Priority Rationale:** P3 — current caveat system is functional for basic conditions.

### 20. Additional SDKs

- **Vision ref:** §8.2 lists priority order: TypeScript, Go, Python, Rust, PHP, Java, C#, Ruby, Elixir.
- **Current State:** TypeScript and Go SDKs exist with tests.
- **What's Missing:** Python, Rust, PHP, Java/Kotlin, C#, Ruby, Elixir SDKs.
- **Priority Rationale:** P3 for most. Python and Rust are Phase 2 deliverables per Vision roadmap.

### 21. Raft Clustering

- **Vision ref:** Phase 2 (v1.0): "Raft-based consensus and log replication."
- **Current State:** `src/cluster/mod.rs` is a 4-line stub. No Raft, no replication, no failover.
- **What's Missing:** Full Raft consensus (openraft), leader election, log replication, membership changes, snapshot recovery.
- **Priority Rationale:** P3 — explicitly Phase 2 / v1.0 scope. Single-node is the Phase 1 target.

### 22. Embedded Mode API Documentation

- **Vision ref:** §6.2 describes embedded mode as a key differentiator: "linked directly into the application process as a library."
- **Current State:** `src/lib.rs` exists as a library root. Trait-based APIs are used internally. No public documentation, no usage examples, no API stability guarantees.
- **What's Missing:**
  - Documented public API surface for embedded usage.
  - Example project showing embedded Hearth in a Rust application.
  - C ABI or language-specific bindings (Vision mentions "C ABI or language-specific bindings").
  - API stability policy for the library interface.
- **Priority Rationale:** P3 — server mode is the primary target. Embedded mode is a future differentiator.

---

## Completed Items (Previously Listed as Gaps)

### Production Email Provider Integration — COMPLETED ✅

Implemented in Phase 1.5. Five transports: Log (dev), SMTP, SendGrid, Postmark, Mailgun. Per-realm branding overrides, Askama + Tera templates, `ApiKey` zeroize-on-drop wrapper. Module: `src/identity/email/`.

**Remaining enhancements (not blocking):**
- AWS SES adapter (requires SigV4 signing).
- Delivery status tracking / bounce handling.
- Per-realm email provider configuration.

### User Self-Registration — COMPLETED ✅

Implemented as the public signup flow with per-realm `RegistrationPolicy` (disabled / open / domain-restricted / invite-only), per-email (3/hr) and per-IP (10/hr) rate limiting, and enumeration-resistant duplicate-email handling. Routes: `GET|POST /ui/register`, `GET /ui/register/sent`. Consumes the existing `issue_email_verification_token` + `verify_email_token` primitives, so registered users land in `PendingVerification` until they click the email link.

**Key files:**
- Engine: `src/identity/engine.rs` (`register_user`, `create_user_with_status`, `check_registration_rate_limit`)
- Types: `src/identity/types.rs` (`RegistrationPolicy`, `RegisterUserRequest`, `RegisterUserResponse`)
- Errors: `src/identity/error.rs` (`RegistrationDisabled`, `RegistrationDomainNotAllowed`, `RegistrationRequiresInvitation`)
- Validation: `src/identity/validation.rs` (`validate_password_against_policy`)
- Web: `src/protocol/web/handlers.rs` (`register_form`, `register_submit`, `register_sent`)
- Templates: `templates/ui/register.html`, `register_sent.html`
- YAML config: `src/config/types.rs` (`RegistrationPolicyYaml`, `RegistrationModeYaml`)
- Tests: `tests/self_registration.rs` (9 integration + adversarial tests)

**Remaining enhancements (not blocking):**
- CAPTCHA / proof-of-work (scope: pluggable anti-abuse). IP rate limit is the minimum viable defense today.
- Custom profile fields during registration.
- HTTP-layer handler tests (engine-layer tests cover the critical security paths).

### Password Reset / Account Recovery — COMPLETED ✅

Verified end-to-end functional: `request_password_reset` + `reset_password_with_token` in `src/identity/engine.rs:3400+`, UI handlers in `src/protocol/web/handlers.rs:1500+`, templates at `templates/ui/forgot_password*.html`, `templates/ui/reset_password*.html`, email template at `templates/email/password_reset.html`. Rate-limited (3/hr/email), SHA-256 token hash, 30-min expiry, single-use, enumeration-resistant (silent success for unknown emails).

**Remaining enhancements (not blocking):**
- Dedicated end-to-end integration test for the full forgot → email → reset flow (core methods covered indirectly).
- Optional notification to secondary verified channels on password change.

### Explicit Realm Routing in the Web UI — COMPLETED ✅

Discovered while testing self-registration: pre-auth `/ui/*` handlers had no explicit realm binding — they walked every realm until one matched. That leaked realm existence and prevented per-realm policy (like `RegistrationPolicy`) from applying correctly when the wrong realm was picked first.

The fix introduces explicit path-segment routes and a centralized resolver:

- **New route family:** `/ui/realms/<name>/login`, `/register`, `/forgot-password`, `/reset-password`, `/verify-email`, `/accept-invitation`, `/login/passkey-begin`, `/login/passkey-complete`, plus their `/sent` confirmation pages. Each scoped variant resolves the realm from the URL path.
- **Bare `/ui/*` resolution rules** (in [`src/protocol/web/realm_resolver.rs`](../../src/protocol/web/realm_resolver.rs)):
  1. Single-realm deployment → implicit use of the sole realm (no config needed).
  2. Multi-realm + `server.default_realm` set → the declared default is used.
  3. Multi-realm + `default_realm` unset → **terse 400 page** (`templates/ui/realm_required.html`) with no realm names. Hearth deliberately does not present an anonymous picker; enumerating tenants is a discovery leak.
- **Walk-all-realms fallback eliminated** from `login_submit`, `forgot_password_submit`, `reset_password_submit`, `verify_email`, `passkey_login_begin`, `passkey_login_complete`, `register_*`, and `accept_invitation_page`. All delegate to the shared `resolve_pre_auth_realm` helper in `src/protocol/web/handlers.rs`.
- **Startup validation:** if `server.default_realm` is set, the named realm MUST exist after reconciliation, else `main.rs` refuses to start.
- **Admin config editor:** new "Default Realm" field under the Server section of `/ui/admin/settings/editor`.

**Key files:**
- `src/config/types.rs` — `ServerConfig::default_realm: Option<String>`
- `src/protocol/web/realm_resolver.rs` — `resolve()` function returning `Resolved::Realm | NotFound | MustChoose | Storage`
- `src/protocol/web/handlers.rs` — `resolve_pre_auth_realm`, `PreAuthRealm`, `ChooseRealmTemplate`, plus `_impl` + `_scoped` variants of every pre-auth handler
- `src/protocol/web/mod.rs` — new `/ui/realms/{realm}/*` route family; `WebState::default_realm_name`, `with_default_realm`, `realm_theme_css_for`
- `templates/ui/choose_realm.html` (new), `templates/ui/admin/settings/_editor_sections.html` (default-realm input)
- `tests/web_ui_realm_routing.rs` — 10 integration tests covering single-realm, multi-realm with default, multi-realm picker, path-scoped routes, unknown realm, no-walk regression, and per-realm verify-email scoping.

**Remaining enhancements (not blocking):**
- Subdomain-per-realm routing (orthogonal; layer on top of path segments later if needed).
- Email-based home realm discovery (lookup email domain → realm) for enterprise SSO scenarios.
- Per-realm `primary: true` flag (YAGNI until a concrete use case appears).

---

## Gap Summary Matrix

| # | Gap | Priority | Vision Ref | Effort Estimate |
|---|-----|----------|------------|-----------------|
| 1 | ~~User self-registration~~ — **DONE** | P0 | §8.1 | Medium |
| 2 | Self-service session management | P0 | §5.3 | Small |
| 3 | OAuth consent screen | P0 | §5.3 | Medium |
| 4 | ~~Password reset~~ — **DONE** (verified) | P0 | §5.3 | — |
| 5 | Social login / external IdP | P1 | §5.3 | Large |
| 6 | SAML 2.0 | P1 | §5.3, §6.1 | Large |
| 7 | SCIM 2.0 | P1 | §5.3, §6.1 | Large |
| 8 | gRPC management API | P1 | §6.1 | Medium |
| 9 | Documentation site | P1 | Phase 1 exit | Medium |
| 10 | Additional migration tools | P1 | §8.3 | Medium per tool |
| 11 | Prometheus / OpenTelemetry | P2 | Phase 2 | Medium |
| 12 | Backup / restore / snapshots | P2 | §6.1 | Large |
| 13 | Webhook event delivery | P2 | §A Q#3 | Medium |
| 14 | Encryption at rest | P2 | §5.4 | Large |
| 15 | CI/CD pipelines | P2 | — | Small |
| 16 | Global rate limiter | P2 | — | Medium |
| 17 | Deployment artifacts | P2 | Phase 2 | Small |
| 18 | Authorization schema language | P3 | §A Q#1 | Large |
| 19 | Expression language (CEL) | P3 | §A Q#2 | Medium |
| 20 | Additional SDKs | P3 | §8.2 | Medium per SDK |
| 21 | Raft clustering | P3 | Phase 2 | Very Large |
| 22 | Embedded mode API docs | P3 | §6.2 | Small |

---

## Recommended Release Sequence

**Minimum viable public release (v0.1-alpha):**
Gaps 1 ✅ and 4 ✅ complete. Remaining: 2, 15 — session self-service, CI/CD.

**Production-ready single-node (v0.x per Phase 1 exit criteria):**
Add gaps 3, 5, 9, 11 — consent screen, social login, documentation site, Prometheus metrics.

**Enterprise-ready (v1.0 per Phase 2 exit criteria):**
Add gaps 6, 7, 8, 10, 12, 14, 17, 21 — SAML, SCIM, gRPC, migration tools, backup, encryption, deployment artifacts, Raft.

---

*Last updated: 2026-04-21. Generated by comparing VISION.md (§1–§12), ARCHITECTURE.md, IMPLEMENTATION_ORDER.md (steps 1–31), and codebase exploration against actual implementation. Revised 2026-04-21 to mark gaps #1 (self-registration) and #4 (password reset) as completed.*
