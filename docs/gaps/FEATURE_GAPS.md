# Feature Gaps & Roadmap Priorities

## Overview

Hearth has completed Phase 0 (18 steps, 148 scenarios), Phase 1 (13 steps, 135 scenarios), Phase 1.5 (production email), and Phase 2 (organizations). The system totals **941 Rust tests + 27 simulation + 6 SDK tests** across 8 testing layers.

**What works today:** Password authentication, TOTP/MFA, WebAuthn/Passkeys, magic links, public self-registration (per-realm policy: disabled/open/domain-restricted/invite-only, with email verification and IP+email rate limiting), password reset / account recovery, self-service session management (list own sessions, revoke one, revoke all other devices), explicit realm routing in the web UI (`/ui/realms/<name>/...` path segments, optional `server.default_realm` for bare URLs, no cross-realm walk), an invisible system realm (`RealmId::nil()`) holding admins with a `TargetRealm` extractor, OAuth 2.0 (authorization code, client credentials, device authorization, refresh rotation, revocation, introspection) with a browser-facing consent screen (per-scope checkboxes, trusted-client bypass, self-service + admin consent management, `prompt=none|consent` semantics), OIDC (discovery, UserInfo, dynamic client registration, conformance), SAML 2.0 (SP + IdP sides, signed assertions, SLO wiring), SCIM 2.0 provisioning (Users + Groups CRUD + PATCH + filter + discovery, externalId idempotency, admin-scoped Bearer auth), social login / external IdP federation (generic OIDC + GitHub OAuth2, per-realm `LinkMode`, confirm-to-link, self-service unlink), claims-based RBAC authorization (roles, groups, permissions, JWT claim embedding, scope narrowing — see [`../specs/AUTHORIZATION.md`](../specs/AUTHORIZATION.md)), multi-tenancy (realm isolation, per-realm signing keys, cascading deletes), organizations (membership, invitations), audit logging (SHA-256 hash chain, tamper detection), TLS termination (1.3, hot-reload, mTLS), admin API + web console, gRPC management API (5 services + health + reflection, shared rate limiter with REST), Keycloak migration, Auth0 migration (Phase 1: bundle-file input via separate Node bundler), TypeScript + Go SDKs, and 5 email transports (SMTP, SendGrid, Postmark, Mailgun, Log).

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

*All P0 gaps are closed.*

---

## P1 — Expected for Competitive Parity

### 1. Documentation Site

- **Vision ref:** Phase 1 exit criteria include "Documentation site" as a deliverable.
- **Current State:** Documentation exists as raw markdown files in `docs/` (specs, vision, gaps, theme). There is no built documentation site — no mdbook, docusaurus, or equivalent. No getting-started guide beyond code-level docs.
- **What's Missing:**
  - Static site generator setup (mdbook for Rust projects, or docusaurus for broader reach).
  - Getting started guide: install → configure → first login flow.
  - API reference: auto-generated from proto definitions and/or OpenAPI spec.
  - SDK documentation for TypeScript and Go.
  - Configuration reference (exists as markdown, needs to be in the site).
  - Migration guides (Keycloak, Auth0, and eventually Clerk).
  - Architecture overview for contributors.
  - Search functionality.
  - Deployment to a public URL (e.g., docs.hearth.dev via GitHub Pages or Vercel).
- **Why It Matters:** Developer adoption requires discoverable, navigable documentation. Raw markdown in a Git repository is not a documentation site. This is explicitly a Phase 1 deliverable that was not completed.
- **Priority Rationale:** P1 — Phase 1 exit criteria explicitly lists this. Open-source projects without documentation don't get adopted.

### 2. Additional Migration Tools (Clerk / CSV / shadow mode)

- **Vision ref:** §8.3 describes migration paths for Auth0, Clerk, Cognito, Firebase Auth, and generic SCIM/CSV/JSON import.
- **Current State:** Keycloak and Auth0 (Phase 1) migrations are implemented.
- **Still Missing:**
  - **Auth0 live Management API client inside Hearth** (deferred — bundler is a separate Node process).
  - **Auth0 federated-identity connections** (Google / SAML / AD — orthogonal to Hearth's own federation module).
  - **Auth0 Rules / Actions / Hooks** (server-side logic has no Hearth equivalent).
  - Clerk migration: import users and organizations via Clerk API.
  - Generic import: CSV/JSON bulk import for custom user databases.
  - SCIM-based bulk import for systems with SCIM export.
  - Shadow mode: run Hearth alongside existing auth, replaying traffic to validate correctness before cutover (Vision §5.5).
  - Export tools: full realm export to standard formats.
- **Why It Matters:** Migration friction is the #1 barrier to adoption. Keycloak + Auth0 cover two large source systems; teams on Clerk, Cognito, or homegrown systems need a path in.
- **Priority Rationale:** P1 for Clerk (large addressable market). P2 for Cognito/Firebase. Shadow mode is P2.

### 3. SAML 2.0 Hardening (Phase 2)

Phase 1 SAML ships working SP + IdP, but several limitations are documented and should be closed before enterprise GA:

- **Exclusive C14N completeness:** current implementation handles the XML shapes Hearth produces and consumes in practice; not a general-purpose exc-c14n processor (no inclusive-namespace prefix lists, no processing instructions inside signed subtrees, no `#WithComments`).
- **X.509 path validation:** today's parser is a focused DER walker — cert extensions, path validation, and revocation are out of scope; we trust operator-supplied PEM verbatim.
- **SLO web fan-out:** library-level SLO is wired, but the web handler is not yet connected to session revocation. Enable before relying on SLO.
- **IdP-side SSO user identity:** currently uses a placeholder identity — needs integration with live `UiSession` / login redirect.
- **Outbound AuthnRequest signing:** not yet implemented; IdPs that require signed requests won't work.
- **Per-`<Assertion>` signing:** today only `<Response>` signing is supported when `sign_responses=true`.
- **Signature-wrapping defense depth:** narrow Reference URI check; doesn't deep-walk for secondary Signatures planted inside Extensions.
- **Independent security review:** XML-DSIG has a long CVE history. Recommend external review of `signature.rs` + `c14n.rs` + `xml.rs` before exposing to untrusted IdP traffic.
- **Priority Rationale:** P1 — required for enterprise GA but not blocking single-tenant or non-SAML deployments.

### 4. SCIM 2.0 Hardening (Phase 2)

Phase 1 SCIM covers the subset Okta + Azure AD exercise. Documented gaps to close:

- **Bracketed filter and PATCH paths** (`emails[type eq "work"].value`) — rejected today; RFC 7644 §3.4.2.2 allows them.
- **`/Bulk` endpoint** — not implemented.
- **Sorting / attribute projection / `excludedAttributes`** — list responses always return full representation.
- **Enterprise User schema extension** (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`) — manager / cost-center / division dropped if sent.
- **Engine-level pagination push-down** — pagination is in-memory; up to 1000 resources scanned per page.
- **`If-Match` enforcement** — emitted but not honored; concurrent PUTs both win-last.
- **Service-account / scope-limited SCIM tokens** — Phase 1 reuses admin Bearer tokens.
- **`displayName` uniqueness for Groups** — not enforced.
- **Non-primary emails** — accepted-and-dropped (single email persisted).
- **`userName` ≠ email** — Azure AD configurations using `userPrincipalName` as non-email are out of scope.
- **Credential provisioning** — Phase 1 clients cannot set passwords through the endpoint.
- **Priority Rationale:** P1 — enterprise GA requires the bracketed-path fix and per-tenant SCIM tokens at minimum.

---

## P2 — Enhances Operational Maturity

### 5. Prometheus / OpenTelemetry Observability

- **Vision ref:** Phase 2 deliverable: "Prometheus metrics and OpenTelemetry tracing."
- **Current State:** Hearth uses `tracing` for structured logging throughout all layers. Benchmarks exist (`benches/`) but are dev-only. No metrics exporter, no trace exporter.
- **What's Missing:**
  - Prometheus metrics endpoint (`/metrics`) with counters, gauges, and histograms:
    - `hearth_auth_total{method,realm,status}` — authentication attempts.
    - `hearth_token_issued_total{grant_type,realm}` — tokens issued.
    - `hearth_rbac_resolve_total{result,realm}` — permission resolutions at token-issue time.
    - `hearth_session_active{realm}` — gauge of active sessions.
    - `hearth_request_duration_seconds{endpoint,method}` — request latency histograms.
    - `hearth_storage_wal_bytes`, `hearth_storage_memtable_entries`, `hearth_storage_sst_count`.
  - OpenTelemetry trace export (OTLP) via `tracing-opentelemetry`.
  - Grafana dashboard template.
- **Why It Matters:** Production operators need dashboards and alerting. Without metrics, detecting degradation, capacity planning, and incident response require log parsing. Every comparable system (Keycloak, Ory, Zitadel) exposes Prometheus metrics.
- **Priority Rationale:** P2 per Vision roadmap. Practically essential for any production deployment.

### 6. Backup / Restore / Snapshots

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

### 7. Webhook / Event Delivery

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

### 8. Encryption at Rest

- **Vision ref:** §5.4 "Encryption at rest: credentials and sensitive fields are encrypted with per-realm keys. Compromising the storage layer does not compromise credentials."
- **Current State:** Credentials are hashed (Argon2id), sensitive fields use `Zeroize`-on-drop. The storage engine writes plaintext keys and values to WAL and SST files. There is **no encryption of data on disk** and no per-realm encryption key management.
- **What's Missing:**
  - Per-realm data encryption keys (DEKs) for encrypting stored values.
  - Key encryption key (KEK) hierarchy: master key wraps per-realm DEKs.
  - Transparent encryption/decryption in the storage engine write/read path.
  - Key rotation without re-encrypting all data (envelope encryption pattern).
  - Optional HSM/KMS integration for master key storage (Vision §A Open Question #6).
  - `hearth rotate-keys` CLI subcommand.
- **Why It Matters:** The Vision explicitly commits to this feature. Compliance-sensitive deployments (healthcare, finance, government) require encryption at rest. Password hashes alone don't satisfy this — user profiles, session data, audit logs, and RBAC state are all stored in cleartext on disk.
- **Priority Rationale:** P2 for general use (hashed credentials are the primary defense). P1 for compliance-regulated environments.

### 9. CI/CD Pipelines

- **Current State:** No `.github/workflows/` directory. No automated testing, linting, or release pipeline. All testing is manual (`cargo nextest run`).
- **What's Missing:**
  - GitHub Actions workflow: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo nextest run` on every PR.
  - CI tiers matching TESTING.md: Fast (every commit), Standard (merge), Extended (nightly), Full (weekly).
  - Release pipeline: build binaries for Linux/macOS/Windows, publish Docker images, create GitHub releases.
  - Security scanning: `cargo audit`, `cargo deny check`.
  - Benchmark regression detection (compare against baseline).
- **Why It Matters:** Open-source credibility requires visible CI badges. Contributors need automated feedback. Release engineering requires automation.
- **Priority Rationale:** P2 per typical project lifecycle, but practically P0 for open-source project launch.

### 10. Global Configurable Rate Limiter

- **Current State:** Rate limiting exists per-feature: password auth (5 attempts/15min), admin API (100/min, shared between REST + gRPC), TOTP (5 attempts/5min), magic link (per-email), self-registration (3/hr/email + 10/hr/IP). No unified middleware.
- **What's Missing:**
  - Global rate limiter middleware: IP-based, configurable per endpoint and per realm.
  - Token bucket or sliding window algorithm with configurable parameters.
  - Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`).
  - Per-realm quota allocation (realm A: 1000 req/s, realm B: 100 req/s).
  - Connection-level limits (max concurrent connections per IP).
- **Why It Matters:** Per-feature limits protect specific abuse vectors. A unified system is needed for fair multi-tenant resource allocation and general API protection.
- **Priority Rationale:** P2 because critical paths are already protected.

### 11. Deployment Artifacts

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

### 12. Policy-as-Code Integration (optional)

- **Vision ref:** §A Open Question #1.
- **Current State:** Hearth issues JWT claims carrying the user's resolved roles, groups, and permissions. Applications with policy-as-code needs (Cedar, OPA/Rego, Polar) consume those claims as inputs to their own policy engine.
- **What's Missing (optional, community-driven):**
  - Canonical integration example showing a Hearth-authenticated request feeding Cedar or OPA for resource-specific decisions.
  - Helper utilities in SDKs for extracting claims in formats commonly expected by policy engines.
- **Priority Rationale:** P3 — not required for any Hearth user; included because policy-as-code layers cleanly on top of the claim-based RBAC surface.

### 13. Dedicated Authorization-Service Integration (optional)

- **Vision ref:** §A Open Question #2.
- **Current State:** Teams that need graph-structured authorization (delegated sharing, Google-Drive-shaped ACLs) pair Hearth with a dedicated ReBAC service (SpiceDB, OpenFGA, Cerbos). Hearth's JWT claims provide the identity context these services need.
- **What's Missing (optional):**
  - Canonical integration example wiring a Hearth-authenticated request through to a SpiceDB / OpenFGA permission check.
  - SDK helper for threading the JWT `sub` / `tid` into external ReBAC API calls idiomatically.
- **Priority Rationale:** P3 — narrow audience; the integration pattern is standard across identity vendors.

### 14. Additional SDKs

- **Vision ref:** §8.2 lists priority order: TypeScript, Go, Python, Rust, PHP, Java, C#, Ruby, Elixir.
- **Current State:** TypeScript and Go SDKs exist with tests.
- **What's Missing:** Python, Rust, PHP, Java/Kotlin, C#, Ruby, Elixir SDKs.
- **Priority Rationale:** P3 for most. Python and Rust are Phase 2 deliverables per Vision roadmap.

### 15. Raft Clustering

- **Vision ref:** Phase 2 (v1.0): "Raft-based consensus and log replication."
- **Current State:** `src/cluster/mod.rs` is a 4-line stub. No Raft, no replication, no failover.
- **What's Missing:** Full Raft consensus (openraft), leader election, log replication, membership changes, snapshot recovery.
- **Priority Rationale:** P3 — explicitly Phase 2 / v1.0 scope. Single-node is the Phase 1 target.

### 16. Embedded Mode API Documentation

- **Vision ref:** §6.2 describes embedded mode as a key differentiator: "linked directly into the application process as a library."
- **Current State:** `src/lib.rs` exists as a library root. Trait-based APIs are used internally. No public documentation, no usage examples, no API stability guarantees.
- **What's Missing:**
  - Documented public API surface for embedded usage.
  - Example project showing embedded Hearth in a Rust application.
  - C ABI or language-specific bindings (Vision mentions "C ABI or language-specific bindings").
  - API stability policy for the library interface.
- **Priority Rationale:** P3 — server mode is the primary target. Embedded mode is a future differentiator.

---

## Gap Summary Matrix

| # | Gap | Priority | Vision Ref | Effort Estimate |
|---|-----|----------|------------|-----------------|
| 1 | Documentation site | P1 | Phase 1 exit | Medium |
| 2 | Additional migration tools (Clerk / CSV / shadow mode) | P1 | §8.3 | Medium per tool |
| 3 | SAML 2.0 hardening | P1 | §5.3, §6.1 | Medium |
| 4 | SCIM 2.0 hardening | P1 | §5.3, §6.1 | Medium |
| 5 | Prometheus / OpenTelemetry | P2 | Phase 2 | Medium |
| 6 | Backup / restore / snapshots | P2 | §6.1 | Large |
| 7 | Webhook event delivery | P2 | §A Q#3 | Medium |
| 8 | Encryption at rest | P2 | §5.4 | Large |
| 9 | CI/CD pipelines | P2 | — | Small |
| 10 | Global rate limiter | P2 | — | Medium |
| 11 | Deployment artifacts | P2 | Phase 2 | Small |
| 12 | Policy-as-code integration (optional) | P3 | §A Q#1 | Large |
| 13 | Dedicated authz-service integration (optional) | P3 | §A Q#2 | Medium |
| 14 | Additional SDKs | P3 | §8.2 | Medium per SDK |
| 15 | Raft clustering | P3 | Phase 2 | Very Large |
| 16 | Embedded mode API docs | P3 | §6.2 | Small |

---

## Recommended Release Sequence

**Production-ready single-node (v0.x per Phase 1 exit criteria):**
Gaps 1, 5, 9 — documentation site, Prometheus metrics, CI/CD.

**Enterprise-ready (v1.0 per Phase 2 exit criteria):**
Gaps 2, 3, 4, 6, 8, 11, 15 — remaining migration tools, SAML/SCIM hardening, backup, encryption, deployment artifacts, Raft.

---

*Last updated: 2026-05-01. Cleaned up to remove all completed gaps (P0 self-registration, password reset, OAuth consent, self-service sessions; P1 social login, SAML Phase 1, SCIM Phase 1, gRPC management API, Auth0 migration Phase 1; admin system realm; explicit realm routing; production email integration). Remaining work renumbered. Hardening pass added as explicit P1 entries for SAML and SCIM.*
