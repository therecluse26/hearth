# Hearth — Application Status

_Last updated: 2026-05-15 · Branch: feature/more-gap-fixes_

---

## 1. What is Hearth?

**Hearth is a purpose-built identity database** — a single-binary, memory-safe Rust server that handles authentication, session management, claims-based RBAC authorization, and multi-tenant identity federation without any external database dependency.

The core insight: every existing auth solution is an *application* built on top of a generic database (Postgres, MySQL). Hearth inverts this — it *is* the database, with protocol-native interfaces on top. The result is operational simplicity (one binary, one port, one config file, zero external dependencies) and performance that is physically unreachable when round-tripping to a general-purpose database: **sub-millisecond p99 for token validation and session lookup** — the same performance class as Redis `GET`, because the underlying operations are structurally similar.

**One-line pitch:** Auth0 or Keycloak as a database, not a SaaS or a JVM behemoth.

See [`docs/vision/VISION.md`](vision/VISION.md) for the full design rationale and competitive analysis.

---

## 2. Current Capabilities

| Feature | Status | Notes |
|---|---|---|
| **Storage engine** — WAL, memtable, SSTs, LRU tiering | ✅ Complete | fsync before ack; clock-based LRU; hot/cold tiering auto-sizes from cgroup/procfs |
| **Encryption at rest** | ✅ Complete | AES-256-GCM envelope encryption; per-file DEKs + per-realm KEKs; `HEARTH_MASTER_KEY` env var |
| **Background compaction & cleanup** | ✅ Complete | SST compaction (atomic rename, spawn_blocking); expired code/token sweep (configurable interval) |
| **User CRUD + credential management** | ✅ Complete | Argon2id default; bcrypt/PBKDF2/scrypt verify for migration; auto-upgrade-on-login |
| **Session management** | ✅ Complete | Create/lookup/revoke/TTL expiry; enumeration resistance |
| **Multi-tenancy (realms)** | ✅ Complete | Per-realm isolation; per-realm signing keys; cascading delete; 11-prefix key space |
| **Claims-based RBAC** | ✅ Complete | Roles, groups (transitive nesting), dot-namespaced permissions; seed roles out of the box; scope narrowing; JWT claims; cycle detection |
| **JWT issuance & validation** | ✅ Complete | Ed25519 only; JWKS endpoint; per-realm keys; JTI uniqueness |
| **OAuth 2.0** | ✅ Complete | Authorization code (+ PKCE mandatory), client credentials, device authorization, refresh token rotation with theft detection; RFC 9207 `iss` claim |
| **OIDC Core 1.0** | ✅ Complete | Discovery, UserInfo, Dynamic Client Registration (RFC 7591), nonce, ID token |
| **TOTP / MFA** | ✅ Complete | Provisioning URI, time-window validation, recovery codes, brute-force lockout, replay protection |
| **WebAuthn / Passkeys** | ✅ Complete | Registration & authentication ceremonies; multi-credential; counter replay protection; resident keys; attestation |
| **Magic link / Passwordless** | ✅ Complete | Token generation/validation/expiry; single-use; rate limiting; enumeration resistance |
| **SAML 2.0** | ✅ Complete | SP-initiated and IdP-initiated flows; federation |
| **Organizations (B2B tenancy)** | ✅ Complete | Org CRUD; membership lifecycle; invitation flow (hashed tokens, 7-day expiry); last-owner protection; cascading delete |
| **SCIM 2.0** | ✅ Complete | Provisioning protocol support (in codebase) |
| **Admin REST API** | ✅ Complete | Full CRUD for users, realms, applications, roles, groups, assignments, organizations; pagination; bulk ops; privilege escalation prevention |
| **Admin gRPC API** | ✅ Complete | RBAC admin services; all major admin operations over gRPC |
| **Admin web console** | ✅ Complete | ~70 Askama templates; full CRUD UI for all entities |
| **Audit logging** | ✅ Complete | SHA-256 append-only hash chain per realm; actor/action indexes; 47 mutation call sites wired; failure policy (FailOperation / LogOnly) |
| **TLS termination** | ✅ Complete | PEM loading; hot-reload; TLS 1.3 + cipher suites; mTLS; HTTP→HTTPS redirect |
| **Production email** | ✅ Complete | Log, SMTP, SendGrid, Postmark, Mailgun (+ EU region); per-realm branding; Askama/Tera templates |
| **UI theming** | ✅ Complete | 6 named themes (ember dark default, ocean, midnight, forest, cloud light, slate light); semantic `ht-*` Tailwind tokens; per-realm override |
| **TypeScript SDK** | ✅ Complete | Auth code flow; admin CRUD; JWKS validation; `createHearth()`, `HearthProvider`, hooks |
| **Go SDK** | ✅ Complete | Auth code flow; admin CRUD; transparent refresh; `Has{Permission,Role}`, `InGroup`, `InOrg` |
| **Keycloak import** | ✅ Complete | `hearth migrate keycloak`; imports realms, users, clients, roles; preserves credential hashes (PBKDF2→Argon2id upgrade-on-login) |
| **E2E flows** | ✅ Complete | MFA + password; passkey-only; multi-realm isolation; Keycloak migration round-trip |
| **Security hardening** | ✅ Complete (HEA-501–503) | PKCE mandatory; redirect URI hardening; RFC 9207; fuzz harnesses; CORS on /token |
| **Hot tier auto-sizing** | ✅ Complete | Reads `/proc/meminfo` + cgroup v1/v2; reserves `max(20%, 2 GiB)` margin |
| **Periodic cleanup** | ✅ Complete | Sweeps expired auth codes, device codes, pending auth tickets, grant families |
| **Token size cap enforcement** | ✅ Complete | permissions≤100, roles≤50, groups≤50, claim bytes≤8 KiB |
| **Effective-permissions endpoint** | ✅ Complete | `GET /admin/users/{id}/effective-permissions` with org_id + scope filtering |
| **Raft clustering** | 📋 Not started | `src/cluster/` is a stub; single-node only today |
| **Auth0 / Clerk / Cognito import** | 📋 Planned | Phase 2 feature; Keycloak import is the only working tool today |
| **Shadow mode** | 📋 Planned | Dual-run period for zero-downtime migration cutover |
| **Prometheus metrics / OpenTelemetry** | 📋 Planned | Phase 2 |
| **Python / Rust / Java SDKs** | 📋 Planned | Phase 2 priority order |
| **S3 audit log archival** | 📋 Planned | Phase 3 |
| **Hearth Cloud** | 📋 Planned | Managed hosted offering; Phase 3 |

---

## 3. Implementation Phases

### Phase 0 — Foundation ✅ Complete

148 / 148 test scenarios · 351 tests passing

Core storage engine (WAL, memtable, SSTs), user CRUD, session management, basic OIDC authorization code flow, JWT issuance and validation, single-node, CLI management tool, embedded mode, benchmark suite.

### Phase 1 — Production Single-Node ✅ Complete

135 / 135 test scenarios · 941 Rust tests + 27 simulation tests + 6 SDK tests passing

All production single-node features shipped:

| Step | Feature | Scenarios |
|---|---|---|
| 19 | Multi-tenancy (realms) | 16 / 16 ✅ |
| 20 | Audit logging | 12 / 12 ✅ |
| 21 | Zanzibar / watch (removed; replaced by RBAC) | 16 / 16 ✅ |
| 22 | OAuth 2.0 complete | 17 / 17 ✅ |
| 23 | TOTP / MFA | 11 / 11 ✅ |
| 24 | WebAuthn / Passkeys | 12 / 12 ✅ |
| 25 | Magic link / Passwordless | 8 / 8 ✅ |
| 26 | TLS termination | 8 / 8 ✅ |
| 27 | Admin API | 10 / 10 ✅ |
| 28 | OIDC conformance | 5 / 5 ✅ |
| 29 | SDK integration (TS + Go) | 6 / 6 ✅ |
| 30 | E2E flows (incl. Keycloak migration) | 4 / 4 ✅ |
| 31 | Cross-cutting concerns | 5 / 5 ✅ |

### Phase 1.5 — Production Email ✅ Complete

5 transports (Log, SMTP, SendGrid, Postmark, Mailgun + EU region); per-realm branding; Askama/Tera templates.

### Phase 1.5 — RBAC Migration ✅ Complete

Replaced Zanzibar authorization engine with claims-based RBAC (`src/rbac/`). Roles, groups, permissions embedded in JWT at token-issue time; synchronous checks from decoded claim — no network round trip per authorization decision.

### Phase 1.5 — UI Theming ✅ Complete

6 named themes; semantic `ht-*` Tailwind tokens; CSS custom properties; global + per-realm override.

### Phase 2 — Organizations ✅ Complete

16 / 16 scenarios: B2B organization model, membership lifecycle, invitation flow, last-owner protection, admin UI.

### Phase 2 — Clustering 📋 Not Started

`src/cluster/` exists as a stub. Raft consensus, leader election, auto-failover, online membership changes, and snapshot-based recovery are **not yet implemented**. Hearth runs single-node only.

**Phase 2 remaining work includes:** Raft clustering, SAML 2.0 (implemented; Phase 2 label was aspirational), Auth0 / Clerk import tools, shadow mode, Python / Rust / Java SDKs, Prometheus / OpenTelemetry, Helm chart, security audit by third-party firm.

### Phase 3 — Scale and Ecosystem 📋 Not Started

Hearth Cloud, multi-region replication, S3 audit log archival, compliance certifications (SOC 2, HIPAA), remaining SDKs (C#, Ruby, Elixir), remaining import tools (Cognito, Firebase Auth, Okta), plugin system for custom identity providers.

---

## 4. Performance Targets

These are design targets validated by the benchmark suite. They represent what a purpose-built identity database *should* achieve given the underlying operations and comparable systems. See [`docs/vision/VISION.md §7`](vision/VISION.md#7-performance-targets) for full detail.

### Latency (Single Node)

| Operation | Target p50 | Target p99 | Notes |
|---|---|---|---|
| Token validation (JWT verify + session lookup) | < 50 μs | < 500 μs | Hot path; in-memory, zero allocations |
| Session lookup by ID | < 10 μs | < 100 μs | Sessions always hot while active |
| Permission check (JWT claim lookup, in-process) | < 1 μs | < 5 μs | No network hop; pure memory read from decoded JWT |
| Permission resolution at token-issue time | < 100 μs | < 1 ms | RBAC graph traversal; runs once per token issuance |
| User lookup by email / ID | < 50 μs | < 500 μs | Hot tier; cold-path first access < 5 ms |
| Token issuance (full OAuth 2.0 flow) | < 1 ms | < 5 ms | Keycloak baseline: 5–50 ms p50 |
| User creation (with Argon2id hashing) | < 50 ms | < 100 ms | Dominated by intentional hashing cost |

### Throughput (Single Node, Modern Hardware)

| Workload | Target ops/sec/core | Target total (16-core) |
|---|---|---|
| Token validation (read-heavy) | 200,000+ | 3,000,000+ |
| Mixed read/write (95/5) | 100,000+ | 1,500,000+ |
| Permission checks (JWT claim lookup) | 1,000,000+ | 15,000,000+ |
| Session creation | 50,000+ | 500,000+ |

### Capacity (Single Node)

| Metric | Target |
|---|---|
| Total managed users per node | 100 M+ |
| Active sessions per node | 10 M+ |
| Memory (idle, 1 M hot users) | < 500 MB |
| Memory (idle, 10 M hot users) | < 8 GB |
| Binary size | < 50 MB |
| Cold start to serving requests | < 2 seconds |

---

## 5. Known Limitations / Not Yet Implemented

### Clustering (Critical)

Raft-based multi-node consensus is **not implemented**. `src/cluster/` is a code stub only. Hearth must run as a single node today. This means:

- No high availability (single point of failure)
- No horizontal scaling of the write path
- No automatic failover

**Target:** Phase 2 of the roadmap.

### Import Tools

Only the **Keycloak import** tool (`hearth migrate keycloak`) is implemented. Auth0, Clerk, Cognito, and Firebase Auth imports are planned but not started.

### Shadow Mode

The dual-running migration mode — replaying production traffic to Hearth alongside an existing system before cutover — is not yet implemented.

### Observability

Prometheus metrics export and OpenTelemetry tracing are not implemented. Structured `tracing`-based logging is in place throughout the codebase.

### Additional SDKs

Only TypeScript/JavaScript and Go SDKs are shipped. Python, Rust, Java/Kotlin, C#, Ruby, and Elixir SDKs are planned.

### Agent Authentication

Machine-to-machine and service-account authentication patterns (documented in [`docs/specs/AGENT_AUTH.md`](specs/AGENT_AUTH.md)) are a roadmap item; the [`AGENT_AUTH_ROADMAP.md`](specs/AGENT_AUTH_ROADMAP.md) tracks the plan.

### LDAP Server

Hearth does not act as an LDAP server. It provides migration tooling for importing from LDAP-backed systems, not ongoing LDAP protocol support.

### Custom Auth Flow Scripting

Hearth is deliberately opinionated about which authentication flows it supports. There is no plugin system for custom scripts (no equivalent of Keycloak's JavaScript providers or Auth0 Actions). This is a feature, not a gap — custom scripting adds attack surface and operational complexity.

---

## 6. Roadmap

### Now (Active)

- Security hardening: PKCE mandatory enforcement, redirect URI hardening, fuzz harnesses, CORS fixes (completed HEA-501–503)
- Gap analysis and P0/P1 fixes (`feature/more-gap-fixes` branch)

### Next (Phase 2)

- **Raft clustering** — multi-node HA; the largest remaining technical investment
- **Prometheus metrics + OpenTelemetry tracing** — observability primitives for production operators
- **Auth0 and Clerk import tools** — expanded migration coverage
- **Shadow mode** — zero-downtime cutover support
- **Python, Rust, and Java SDKs**
- **Helm chart and systemd service file** — operator packaging
- **Third-party security audit**
- **Client-scoped roles** (documented in [`docs/specs/client-scoped-roles.md`](specs/client-scoped-roles.md))

### Later (Phase 3)

- **Hearth Cloud** — managed hosted offering
- **Multi-region replication** — configurable consistency
- **S3-compatible audit log archival** — long-term retention
- **Compliance certifications** — SOC 2, HIPAA
- **Remaining SDKs** — C#, Ruby, Elixir
- **Remaining import tools** — Cognito, Firebase Auth, Okta
- **Edge deployment mode** — embedded Hearth at the CDN edge
- **Webhooks / event streaming** — user-created, session-revoked, role-assigned events for downstream consumers

---

## 7. Compatibility

### Protocol Compatibility

Hearth's OIDC, OAuth 2.0, SAML, and SCIM endpoints conform strictly to their respective RFCs. Any client library that speaks standard OIDC should work with Hearth without modification — just point the OIDC discovery URL at Hearth instead of Auth0 or Keycloak.

### Migration Guides

| Source system | Guide | Status |
|---|---|---|
| Keycloak | [`docs/specs/migrating-from-keycloak.md`](specs/migrating-from-keycloak.md) | ✅ Guide + working `hearth migrate keycloak` CLI |
| Auth0 | [`docs/specs/migrating-from-auth0.md`](specs/migrating-from-auth0.md) | 📋 Guide exists; import tool not yet implemented |
| Clerk | — | 📋 Planned |
| Cognito / Firebase Auth / Okta | — | 📋 Planned (Phase 3) |

### Credential Hash Compatibility

On Keycloak migration, Hearth reads the imported credential format (`PBKDF2-SHA256`, `PBKDF2-SHA512`) natively. Users log in with their existing passwords; Hearth verifies against the imported hash and **upgrades to Argon2id on the next successful login** automatically. No forced password reset is required.

---

## Test Coverage Summary

| Layer | Count | Notes |
|---|---|---|
| Rust unit + integration tests | 941 | All passing |
| Simulation tests (madsim) | 27 | Crash recovery, partition tolerance, concurrent ops |
| SDK tests (TypeScript + Go) | 6 | Auth code flow, admin CRUD, JWKS, transparent refresh |
| Fuzz targets | 7 | Token exchange, redirect URI, CBOR/authenticator-data parse, etc. |
| Benchmarks | 9 | Hot path ops, OAuth flows, RBAC checks, admin pagination |
| Property tests | 10+ | Proptest suites across storage, auth, org slugs, MFA |

---

_For architecture details see [`docs/specs/ARCHITECTURE.md`](specs/ARCHITECTURE.md). For the authorization model see [`docs/specs/AUTHORIZATION.md`](specs/AUTHORIZATION.md). For testing methodology see [`docs/specs/TESTING.md`](specs/TESTING.md)._
