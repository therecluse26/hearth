# Feature Gaps & Roadmap Priorities

## Overview

Hearth has completed Phase 0 (148 scenarios, 351 tests) and Phase 1 (135 scenarios, 671+ Rust tests, 27 simulation tests, SDK tests). The system provides authentication (password, TOTP, WebAuthn, magic link), OAuth 2.0 / OIDC, Zanzibar authorization, multi-tenancy, audit logging, TLS termination, an admin API, and a Keycloak migration path.

This document inventories **features not yet implemented** that would block or hinder production adoption. Each gap is categorized by deployment impact.

## Priority Tiers

| Tier | Meaning |
|------|---------|
| **P0** | Blocks production deployment. Without these, an operator cannot safely run Hearth for real users. |
| **P1** | Expected for enterprise adoption. Enterprises will evaluate Hearth against incumbents (Keycloak, Auth0, Okta) and expect these capabilities. |
| **P2** | Enhances operational maturity. Not blocking, but significantly improves day-to-day operations, observability, and resilience. |

---

## P0 — Blocks Production Deployment

### Password Reset / Account Recovery

- **Current State:** Users can authenticate via password (`src/identity/engine.rs`), enroll TOTP recovery codes (`src/identity/totp.rs`), and use magic links for passwordless login (`src/identity/magic_link.rs`). There is no password reset flow.
- **What's Missing:**
  - Forgot-password endpoint that issues a time-limited, single-use reset token (similar to magic link token but bound to password change).
  - Token validation + new-password submission endpoint.
  - Rate limiting on reset requests per email (enumeration resistance).
  - Optional notification to the user's other verified channels when a password is changed.
- **Why It Matters:** Password reset is the single most common support request for any auth system. Without it, locked-out users have no self-service path — operators must manually intervene.
- **Priority Rationale:** P0 because every production deployment with password-based auth requires this flow.

### Production Email Provider Integration — COMPLETED

- **Status:** Implemented. The email subsystem (`src/identity/email/`) now supports five transports: Log (dev), SMTP, `SendGrid`, `Postmark`, and `Mailgun`.
- **What Was Delivered:**
  - HTTP-based provider adapters (`SendGrid` v3, `Postmark`, `Mailgun` with EU region) via injectable `HttpTransport` trait.
  - Branded email templates (Askama compiled into binary) with per-tenant branding overrides (`EmailBranding` on `TenantConfig`).
  - Optional disk-based template override via Tera (`email.templates_dir` config).
  - `EmailService` orchestration layer separating transport from content (branding + template rendering).
  - `ApiKey` zeroize-on-drop wrapper for provider credentials.
  - Config validation for all provider types.
- **What Remains (future enhancements):**
  - AWS SES adapter (requires Sig v4 signing).
  - Delivery status tracking / bounce handling.
  - Per-tenant email provider configuration (multi-tenant SaaS operators using different sender domains per tenant).

### Self-Service Session Management

- **Current State:** The identity engine supports `list_sessions_by_user()` (`src/identity/mod.rs`, `src/identity/engine.rs`) and session revocation. The admin API (`src/protocol/http.rs`) exposes session management for administrators.
- **What's Missing:**
  - User-facing endpoints to list their own active sessions (device, IP, last-active).
  - User-facing endpoint to revoke a specific session (e.g., "log out my phone").
  - User-facing endpoint to revoke all other sessions ("log out everywhere else").
  - Session metadata enrichment (user-agent parsing, geolocation hint).
- **Why It Matters:** Users expect to see and control their active sessions. This is a baseline security feature in every modern auth provider. Without it, a compromised session can only be revoked by an admin.
- **Priority Rationale:** P0 because session visibility is a fundamental security control for end users.

---

## P1 — Expected for Enterprise Adoption

### SAML 2.0 IdP / SP Support

- **Current State:** The protocol layer reserves a slot for SAML (`src/protocol/mod.rs`), and SAML is mentioned in the architecture (`docs/specs/ARCHITECTURE.md`) and vision (`docs/vision/VISION.md`). No SAML code exists.
- **What's Missing:**
  - SAML 2.0 IdP: issue SAML assertions for SP-initiated and IdP-initiated SSO.
  - SAML 2.0 SP: consume assertions from external IdPs (corporate AD FS, Okta, etc.).
  - Metadata exchange (XML descriptor generation and parsing).
  - Assertion signing (reuse existing Ed25519 infrastructure or add RSA-SHA256 for SAML compat).
  - Single Logout (SLO) support.
- **Why It Matters:** Large enterprises mandate SAML for SSO integration with legacy and compliance-driven systems. Without SAML, Hearth cannot replace incumbent IdPs in enterprise environments.
- **Priority Rationale:** P1 because OIDC covers most modern integrations, but enterprise procurement often gates on SAML.

### SCIM 2.0 Provisioning

- **Current State:** SCIM is referenced in the architecture and vision documents. The protocol layer lists it as a future wire adapter. No SCIM code exists.
- **What's Missing:**
  - SCIM 2.0 server endpoints: `/Users` and `/Groups` CRUD with filtering, pagination, and patch.
  - Schema discovery (`/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig`).
  - Mapping SCIM User attributes to Hearth's `User` type.
  - Mapping SCIM Groups to Zanzibar relations or Hearth roles.
  - Event hooks for provisioning lifecycle (user created/deprovisioned via SCIM).
- **Why It Matters:** Enterprises use SCIM to sync their HR directory (Workday, BambooHR) or IdP (Okta, Azure AD) into downstream systems. Without SCIM, user provisioning is manual or requires custom API integration.
- **Priority Rationale:** P1 because automated provisioning is a procurement requirement for mid-to-large enterprises.

### Social Login / External IdP Federation

- **Current State:** Hearth issues OAuth 2.0 / OIDC tokens as an IdP. The Keycloak migration module (`src/identity/migration/keycloak.rs`) handles imported users. There is no mechanism to *consume* tokens from external IdPs.
- **What's Missing:**
  - External IdP connector framework: register upstream OIDC providers (Google, GitHub, Microsoft, Apple) per tenant.
  - Authorization code flow as an OIDC RP (redirect → callback → token exchange → user linking).
  - Account linking: match external identity to existing Hearth user by email, or create a new account.
  - JIT (Just-In-Time) provisioning from external IdP claims.
  - Per-tenant IdP configuration (tenant A uses Google, tenant B uses Okta).
- **Why It Matters:** "Sign in with Google/GitHub" is expected by developers and consumers. Enterprise tenants need to federate with their corporate IdP (Okta, Azure AD) without SAML.
- **Priority Rationale:** P1 because social login drives conversion for consumer apps, and OIDC federation is the modern enterprise alternative to SAML.

### OAuth Consent Management

- **Current State:** OAuth authorization code flow is implemented (`src/identity/oidc.rs`, `src/identity/engine.rs`). Tokens are issued after authentication. There is no consent screen or consent persistence.
- **What's Missing:**
  - Consent prompt: display requested scopes to the user and collect explicit approval.
  - Consent storage: persist per-user, per-client scope approvals to avoid re-prompting.
  - Consent revocation: user-facing endpoint to revoke consent for a specific client.
  - Admin visibility into granted consents per user.
  - Granular scope selection (user can approve some scopes but deny others).
- **Why It Matters:** OAuth 2.0 best practices (and some regulatory frameworks like GDPR) require explicit user consent before sharing data with third-party clients. Without consent management, all authorized clients implicitly receive all requested scopes.
- **Priority Rationale:** P1 because first-party-only deployments can defer this, but any deployment exposing OAuth to third-party clients needs consent.

### User Self-Registration

- **Current State:** Magic link flow auto-creates accounts for unknown emails (`tests/magic_link.rs`). The admin API supports user creation. There is no public registration form or API endpoint.
- **What's Missing:**
  - Public signup endpoint (email + password, or email-only with magic link).
  - CAPTCHA or proof-of-work integration to prevent automated account creation.
  - Configurable registration policy per tenant (open, invite-only, domain-restricted).
  - Welcome email with verification link.
  - Custom fields / profile data collection during registration.
- **Why It Matters:** Applications need a self-service onboarding path for new users. Currently, users can only be created by admins or through the magic link side-effect.
- **Priority Rationale:** P1 because the magic link auto-create partially covers this, but a dedicated registration flow with policy controls is expected.

---

## P2 — Enhances Operational Maturity

### Prometheus / OpenTelemetry Metrics

- **Current State:** Hearth uses `tracing` for structured logging throughout all layers. There is no metrics exporter. Benchmarks exist for critical paths (`benches/`) but are dev-only.
- **What's Missing:**
  - Prometheus metrics endpoint (`/metrics`) with standard auth-system counters:
    - `hearth_auth_total{method,status}` — authentication attempts by method and outcome.
    - `hearth_token_issued_total{grant_type}` — tokens issued by grant type.
    - `hearth_authz_check_total{result}` — authorization checks by result.
    - `hearth_session_active` — gauge of active sessions.
    - `hearth_storage_*` — WAL size, memtable entries, SST count, compaction stats.
  - OpenTelemetry trace export (OTLP) for distributed tracing.
  - `tracing-opentelemetry` integration for automatic span export.
  - Request duration histograms on protocol endpoints.
- **Why It Matters:** Production operators need dashboards and alerting. Without metrics, detecting degradation, capacity planning, and incident response require log parsing.
- **Priority Rationale:** P2 because structured `tracing` logs provide a baseline, but metrics are the standard for production monitoring.

### Webhook Event Delivery

- **Current State:** Audit events are recorded internally (`src/audit/engine.rs`) with hash-chain integrity. There is no external notification mechanism. Webhooks are mentioned in the architecture (`docs/specs/ARCHITECTURE.md`) and vision (`docs/vision/VISION.md`).
- **What's Missing:**
  - Webhook subscription management: register per-tenant HTTPS endpoints with event filters.
  - Reliable delivery: at-least-once semantics with exponential backoff retry.
  - Payload signing (HMAC-SHA256) so recipients can verify authenticity.
  - Delivery log with status tracking (success, retry, failed, disabled).
  - Event types: user.created, user.deleted, session.created, session.revoked, permission.changed, tenant.updated.
- **Why It Matters:** Downstream systems (billing, analytics, compliance SIEM) need real-time event feeds. Without webhooks, operators must poll the audit API or build custom integrations.
- **Priority Rationale:** P2 because the audit log provides queryable history, but push-based integration is expected for operational workflows.

### Backup / Restore / Snapshots

- **Current State:** The storage engine writes a WAL (`src/storage/wal.rs`) and SSTables (`src/storage/tiered.rs`). The cluster layer mentions Raft snapshots (`src/cluster/mod.rs`). There is no user-facing backup/restore mechanism.
- **What's Missing:**
  - Online snapshot: consistent point-in-time capture without stopping writes.
  - Snapshot export to object storage (S3, GCS, local filesystem).
  - Restore from snapshot: cold start from a backup.
  - `hearth backup` / `hearth restore` CLI subcommands.
  - Incremental backup (ship WAL segments since last snapshot).
  - Per-tenant export/import for tenant migration between clusters.
- **Why It Matters:** Data durability is non-negotiable. While the WAL provides crash recovery, operators need disaster recovery (DC failure, corruption, accidental deletion) and migration capabilities.
- **Priority Rationale:** P2 because WAL + SST provides crash safety, but operational backup/restore is essential for production confidence.

### Cross-Cutting Configurable Rate Limiter

- **Current State:** Rate limiting exists in two places:
  - Password authentication: per-user lockout after 5 failed attempts, 15-minute window (`src/identity/engine.rs`, line 76–91).
  - Admin API: 100 requests/minute per admin user (`src/protocol/http.rs`, line 133).
  - TOTP: 5 attempts, 5-minute lockout (`src/identity/engine.rs`, line 185).
  - Magic link: per-email rate limiting (`tests/magic_link.rs`).
- **What's Missing:**
  - Global rate limiter middleware (IP-based, configurable per endpoint).
  - Configurable rate limit policies per tenant (e.g., tenant A gets 1000 req/s, tenant B gets 100 req/s).
  - Token bucket or sliding window algorithm with configurable parameters.
  - Rate limit headers in responses (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`).
  - DDoS mitigation: connection-level limits, request body size already enforced (Step 31).
- **Why It Matters:** The existing per-feature rate limits protect against specific abuse vectors, but a global configurable limiter is needed for fair multi-tenant resource allocation and general API protection.
- **Priority Rationale:** P2 because critical paths (password, TOTP, admin) are already protected. The gap is a unified, configurable system for all endpoints.
