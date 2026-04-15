# Implementation Order

Short implementation sequence mapping TEST_SCENARIOS.md sections to build order. Each step follows strict TDD: write failing test → make it pass → refactor.

Dependencies flow bottom-up (leaf → root), matching the layer architecture.

---

## Phase 0: Foundation (Steps 1–18) ✅

### Sequence

| # | What | TEST_SCENARIOS Section | Why this order |
|---|------|----------------------|----------------|
| 1 | **Project scaffold** | — | Cargo.toml, .gitignore, rustfmt.toml, clippy.toml, deny.toml, empty `src/` module tree, bacon.toml |
| 2 | **Core types** | — | `TenantId`, `UserId`, `SessionId`, `Timestamp`, `Clock` trait, error trait foundations. Everything depends on these. |
| 3 | **Storage: WAL** | Storage: WAL (12 scenarios) | Leaf dependency. All durability guarantees start here. Start with the 5 P0 unit tests. |
| 4 | **Storage: Memtable** | Storage: Memtable (7 scenarios) | Depends on WAL for crash recovery. 5 unit tests first. |
| 5 | **Storage: SST/Persistence** | Storage: Persistence (9 scenarios) | Depends on memtable flush. 4 unit tests first. |
| 6 | **Storage: Tiered Hot/Cold** | Storage: Tiered Hot/Cold (12 scenarios) | Depends on all storage components. Introduces hot path constraints. |
| 7 | **Storage: Public trait API** | (implicit) | `mod.rs` trait interface wrapping WAL+memtable+SST+tiered into clean `get/put/delete/scan` with `TenantId` enforcement. |
| 8 | **Configuration** | Configuration (5 scenarios) | Standalone, needed before wiring layers. YAML parsing, `--dev` flag, validation. |
| 9 | **Test infrastructure** | Test Infrastructure (4 scenarios) | `TestHarness` embedded mode. Server mode stays `#[ignore]` until HTTP exists. |
| 10 | **Authorization engine** | Authorization Engine (15 scenarios) | Standalone module. Identity depends on it (lateral), so build it first. |
| 11 | **Identity: User CRUD** | User CRUD (14 scenarios) | First domain logic. Depends on storage + core types. |
| 12 | **Identity: Credentials** | Credential Storage (12 scenarios) | Depends on users. Argon2id hashing, multi-algo verification. |
| 13 | **Identity: Sessions** | Session Management (17 scenarios) | Depends on users + credentials. Introduces hot path session lookup. |
| 14 | **Identity: JWT/Tokens** | JWT / Tokens (14 scenarios) | Depends on sessions. Ed25519 signing, JWKS endpoint shape. |
| 15 | **Protocol: OIDC** | OIDC (15 scenarios) | First wire protocol. Auth code flow, PKCE, discovery endpoint. |
| 16 | **CLI** | CLI Tool (3 scenarios) | `hearth serve --dev`, management commands. Wires layers together in `main.rs`. |
| 17 | **E2E flows** | End-to-End Flows (4 scenarios) | Integration tests spanning all layers. |
| 18 | **Cross-cutting** | Cross-Cutting Concerns (5 scenarios) | Adversarial tests applied globally (timing, leaks, zeroing). |

### Notes

- Within each step, tackle P0 `fast` scenarios first, then P0 `extended`, then P1.
- Property tests (`proptest`) and simulation tests (`madsim`) come after unit tests pass for each module.
- Benchmarks (`criterion`) added alongside steps 6, 11, 13, 14, 15 — not deferred to the end.
- Proto files created when step 15 (OIDC) demands wire format definitions, not before.

---

## Phase 1: Production Single-Node (Steps 19–31)

Phase 1 builds production features on top of the Phase 0 foundation. The dependency chain is: tenant isolation → observability → extended authorization → auth methods → transport security → management API → conformance → client SDKs → integration.

### Prerequisites

All 148 Phase 0 scenarios must be passing. Steps 1–18 are complete.

### Sequence

| # | What | TEST_SCENARIOS Section | Why this order |
|---|------|----------------------|----------------|
| 19 | **Multi-Tenancy** | Multi-Tenancy (16 scenarios) | Foundation for Phase 1. Per-tenant signing keys, cascading deletion, and tenant-scoped config underpin every subsequent module. Extends Phase 0 `TenantId` from key-prefix isolation to full tenant lifecycle. |
| 20 | **Audit Logging** | Audit Logging (12 scenarios) | Cross-cutting infrastructure. All subsequent modules must emit structured audit events. Append-only log with tamper detection. Build early so later steps can assert audit trail correctness. |
| 21 | **Zanzibar Authorization (Full)** | Zanzibar Authorization Full (16 scenarios) | Extends Phase 0 authz engine with Watch API, consistency tokens (zookies), permission caching, namespace config, and conditional writes. Admin API (step 27) depends on role enforcement from this. |
| 22 | **OAuth 2.0 Complete** | OAuth 2.0 Complete (17 scenarios) | Extends Phase 0 OIDC with client credentials grant, device authorization (RFC 8628), refresh token rotation with theft detection, revocation (RFC 7009), and introspection (RFC 7662). Depends on multi-tenancy for tenant-scoped clients. |
| 23 | **TOTP / MFA** | TOTP / MFA (11 scenarios) | First new credential type. TOTP secret generation, time-window validation, recovery codes, enrollment flow. Integrates with existing session issuance — authentication now requires optional second factor. |
| 24 | **WebAuthn / Passkeys** | WebAuthn / Passkeys (12 scenarios) | Second credential type. FIDO2 registration/authentication ceremonies, CBOR parsing, multi-credential support, resident keys. Heavier than TOTP (CBOR, attestation formats) but no dependency on it. |
| 25 | **Magic Link / Passwordless** | Magic Link / Passwordless (8 scenarios) | Third credential type. Simplest auth method — token generation, single-use validation, expiration. Depends on multi-tenancy (tenant-scoped tokens) and audit logging. |
| 26 | **TLS Termination** | TLS Termination (8 scenarios) | Transport security. Cert loading, hot-reload, TLS 1.3 negotiation, mTLS. Must be in place before Admin API exposes management endpoints over the network. |
| 27 | **Admin API** | Admin API (10 scenarios) | REST management endpoints for users, tenants, and applications. Depends on Zanzibar (role enforcement), audit logging (mutation trail), and all domain modules it manages. Heaviest integration surface. |
| 28 | **OIDC Conformance** | OIDC Conformance (5 scenarios) | Conformance testing against OpenID Connect Core/Discovery/Dynamic Registration specs. Requires stable OAuth 2.0 + OIDC surface (steps 22, Phase 0 step 15). |
| 29 | **SDK Integration (TS & Go)** | SDK Integration TS & Go (6 scenarios) | Client libraries for TypeScript and Go. Depends on stable API surface — auth code flow, admin CRUD, JWKS, token refresh must all be finalized. |
| 30 | **Phase 1 E2E Flows** | Phase 1 E2E Flows (4 scenarios) | Integration tests spanning Phase 1 features: Keycloak migration, MFA enrollment + login, passkey-only auth, multi-tenant isolation round-trip. |
| 31 | **Phase 1 Cross-Cutting** | Phase 1 Cross-Cutting (5 scenarios) | Global adversarial tests (error sanitization, Zeroize, input limits) and benchmarks (admin listing, audit queries) applied across all Phase 1 modules. |

### Notes

- Within each step, tackle P0 `fast` scenarios first, then P0 `extended`, then P1.
- Steps 23–25 (TOTP, WebAuthn, Magic Link) are peer credential types with no interdependency. They can be developed in any order, but the sequence above reflects decreasing complexity.
- Benchmarks (`criterion`) added alongside steps 21 (cached permission check, watch delivery), 22 (client credentials, introspection), and 31 (admin listing, audit queries).
- SDK work (step 29) requires the TypeScript and Go projects to be scaffolded. SDK test harness runs against a live Hearth instance.
- OIDC Conformance (step 28) may require running the official OpenID Connect certification test suite — plan for external tooling setup.

---

## Verification

After each step: `cargo nextest run` passes, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
