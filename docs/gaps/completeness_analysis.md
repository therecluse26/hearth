# Completeness Analysis — Hearth
_Generated: 2026-05-06 · Spec source: docs/specs/ + docs/vision/VISION.md · Code rev: a7c028d · Updated: 2026-05-07_

## Summary

- **Phase 0 (Foundation):** 148/148 test scenarios passing. Core engine is solid.
- **Phase 1 (Production Single-Node):** ~95% complete. P0 gaps closing.
- **Phase 2 (Clustering):** Not started. Entire `src/cluster/` is a stub.

### Top 5 Production Blockers

1. **~~Encryption at rest~~** — ✅ RESOLVED (2026-05-06).

2. **~~Audit logging is not wired~~** — ✅ RESOLVED (2026-05-07). `EmbeddedIdentityEngine` now holds `Arc<dyn AuditEngine>`. 47 mutation methods emit audit events (`src/identity/engine.rs`). Failure policy: `FailOperation` for destructive mutations (delete, credential change, session revoke, consent revoke), `LogOnly` for non-destructive. `AuditContext { actor: Actor, metadata }` type in `src/audit/context.rs`. 3 redundant protocol-layer audit calls removed (consent grant, consent revoke, session self-revoke). Follow-up: metadata-threading for remaining protocol-layer audit sites (4 federation + 1 SAML + registration IP).

3. **No periodic cleanup** — expired authorization codes, device codes, grant families, and pending authorization tickets accumulate indefinitely with no background reaper.

4. **Hot tier auto-sizing missing** — capacity hardcoded to `100_000` entries in `src/storage/tiered.rs:58`. Spec requires auto-detection from `/proc/meminfo` or cgroup limits.

5. **Token size cap enforcement missing** — `RbacError::TokenSizeExceeded` is defined (`src/rbac/error.rs:63`) but never constructed at runtime. The four caps (permissions≤100, roles≤50, groups≤50, claim bytes≤8KiB) are not enforced.

### What IS Working Well

- **Storage**: WAL with fsync, atomic batch writes, memtable with lock-free reads, SST format + compaction logic, clock-based LRU tiering — all passing unit/property/simulation tests.
- **RBAC**: Complete engine with roles, groups, assignments, transitive resolution, cycle detection, scope filtering, seed data, YAML reconciliation.
- **Identity**: User CRUD, Argon2id + multi-algo verification + upgrade-on-login, session management with enumeration resistance, JWT/Ed25519 + JWKS, realm management with cascading delete, full OAuth 2.0 (all grant types), WebAuthn/Passkeys, TOTP/MFA, magic links, organizations, SAML 2.0, federation.
- **Protocol**: OIDC, REST Admin API, comprehensive web UI (~70 templates), SCIM 2.0, gRPC admin services, SAML SP/IdP endpoints.
- **Tests**: All 148 Phase 0 scenarios pass. 55+ integration test files. 9 benchmarks. 7 fuzz targets. 10 simulation tests.

---

## Critical P0 Gaps (Must Fix Before Production)

| # | Gap | Spec | Evidence |
|---|-----|------|----------|
| 1 | **Encryption at rest** | ARCH §6.3 | ✅ RESOLVED. Envelope encryption (AES-256-GCM) implemented in `src/storage/`. Per-file DEKs wrapped by per-realm KEKs. Host key from `HEARTH_MASTER_KEY` env var or auto-generated. SST and WAL fully encrypted. |
| 2 | **Audit engine not wired** | ARCH §8.5 | `src/identity/engine.rs` has zero `audit::` references. `EmbeddedIdentityEngine` holds no `Arc<dyn AuditEngine>`. |
| 3 | **No periodic cleanup** | — | No background task for expired auth codes, device codes, grant families, pending tickets. |
| 4 | **Hot tier auto-sizing** | ARCH §6.2 | `TieredConfig::default()` hardcodes 100K capacity. No memory/cgroup detection. |
| 5 | **Background compaction** | — | `sst.rs:381` — `compact()` exists but never called automatically. SSTs accumulate. |
| 6 | **Token size cap enforcement** | AUTHZ §2.6, §5.4 | Error variant exists but no `validate_token_size()` function. |
| 7 | **`/admin/users/{id}/effective-permissions` REST endpoint** | AUTHZ §8.2 | No route in `src/protocol/http.rs`. Only available via gRPC/UI. |
| 8 | **Dynamic Client Registration (RFC 7591)** | AGENT_AUTH §2.7 | No `POST /register` endpoint. |
| 9 | **Resolve-time cycle detection** | AUTHZ §3 | `resolve.rs:505` treats DAG cycles as diamonds (silent skip), not errors. Only self-edges error. |

---

## Important P1 Gaps

| # | Gap | Detail |
|---|-----|--------|
| 10 | **Audience-scoped scope resolution** | `resolve_with_scopes` doesn't accept `resource: Option<Uri>`. Protected-resource scope precedence not implemented. |
| 11 | **User.attributes on create/import requests** | Field exists on `User` struct but `CreateUserRequest`/`ImportUserRequest` don't expose it. |
| 12 | **ArcSwap registry hot-swap not wired** | `PermissionRegistry` exists but SIGHUP reload in `main.rs` not wired. |
| 13 | **Missing OIDC default claim mappings** | `default_claim_profile()` only emits `email`/`name`. Missing `given_name`, `family_name`, `picture`, `locale`, `zoneinfo`, `phone_number`, `address`. |
| 14 | **Config structure: flat vs nested `rbac:`** | Spec says `realms.<id>.rbac.*`, implementation has flat fields on `RealmConfig`. |
| 15 | **No YAML-declared groups** | Groups are runtime-API only; no `groups` field in `RealmYamlConfig`. |
| 16 | **`list_groups`/`list_role_members` cursor unused** | Cursor parameter accepted but never used; `next_cursor` never set. |
| 17 | **`list_roles` cursor derivation flawed** | Captures last item's name from already-built list, not boundary entry. |
| 18 | **RESERVED_PREFIX: `system.` vs `hearth.`** | Code uses `"system."`, spec says `hearth.*`. |
| 19 | **No standalone WebAuthn REST API** | Passkey ceremonies browser-session only. |
| 20 | **Only 2 of 8 SDKs exist** | TypeScript and Go implemented. Python, Rust, Java, PHP, C#, Ruby, Elixir missing. |
| 21 | **Only 2 of 6 migration tools exist** | Keycloak and Auth0 implemented. Clerk, Cognito, Firebase Auth, Okta missing. |
| 22 | **No shadow mode** | Required for zero-downtime migration per VISION.md §5.5. |

---

## P2 Gaps (Polish)

| # | Gap | Detail |
|---|-----|--------|
| 23 | **Per-realm auth policies not enforced** | Password complexity, MFA required, allowed auth methods, rate limits, token TTLs populated from YAML into `RealmConfig` but never enforced in login/credential flows. |
| 24 | **No Prometheus `/metrics` endpoint** | ARCH §14.2 requires Prometheus-compatible metrics. |
| 25 | **No OpenTelemetry distributed tracing** | ARCH §14.3. No tracing integration exists. |
| 26 | **No Helm chart or systemd service file** | VISION §10 Phase 2. |
| 27 | **No comprehensive README** | THINGS_WE_NEED.md. |
| 28 | **No example sites** | THINGS_WE_NEED.md requires SPAs for every SDK. |
| 29 | **No comprehensive SDK READMEs** | THINGS_WE_NEED.md. |
| 30 | **UI audit P1 items unresolved** | P1-6 (silent realm redirect), P1-9 (admin-user route conflated), P1-10 (pagination unverified), P1-3 (invite form structure). |
| 31 | **UI audit P2 items unresolved** | Breadcrumb self-link, pagination breadcrumb, reset confirmation, syntax highlighting, RBAC autocomplete. |
| 32 | **Roles UI redesign not implemented** | ROLES_UI_REDESIGN.md — inline add member, dropdown-on-change, confirm-remove, resolver links. |
| 33 | **TEST_SCENARIOS.md RBAC checkboxes stale** | Phase 0 Authorization Engine (lines 258-291) and Phase 1 RBAC Authorization Full (lines 599-624) still show `[ ]` despite 15+ passing test files. |
| 34 | **TESTING.md §8 benchmark list outdated** | Missing `oidc_exchange`, `oauth`, `tiered_storage`, `admin`, `audit`; `permission_check` renamed to `rbac_check`; `token_issuance` merged into `token_validation`. |
| 35 | **Embedded mode support contradiction** | VISION.md §6.2 describes embedded mode as supported. ARCHITECTURE.md Appendix says "not supported — FFI tax unjustified". |
| 36 | **`email_verified` claim not computed** | Spec shows `email_verified` as supported. User struct has no `email_verified` bool — must be computed as `status != PendingVerification`. |

---

## Clustering: Entirely Unimplemented

Phase 2 (clustering) has not started. The `src/cluster/` directory is a stub. This means:
- No Raft consensus
- No log replication
- No leader election
- No automatic failover
- No online membership changes
- No snapshot-based recovery
- No multi-region replication

The system is single-node only. This is acceptable for Phase 1 but blocks v1.0 production-ready declaration.

---

## Spec/Code Divergences

| # | Issue | Spec Says | Code Does | Recommendation |
|---|-------|-----------|-----------|----------------|
| D1 | RBAC config nesting | `realms.<id>.rbac.{permissions,roles,scopes,groups}` | Flat fields on `RealmConfig` | Update spec to match code (simpler) or nest config |
| D2 | Reserved prefix | `hearth.*` | `system.` constant in `types.rs:21` | Align code to spec: change to `"hearth."` |
| D3 | Embedded mode support | VISION.md says supported; ARCHITECTURE.md appendix says not supported | Not implemented | Remove embedded-mode from VISION.md or update ARCHITECTURE.md |
| D4 | `email_verified` claim | Spec shows it as supported | `User.email_verified` not a field | Compute from `UserStatus` (`status != PendingVerification`) |

---

## Resolution Todo List

### P0 — Must fix before production deploy

- [x] **[P0][L]** Implement encryption at rest: envelope encryption (AES-256-GCM), DEK/KEK, SST header encryption fields, WAL per-segment encryption, per-realm keys — resolves gaps #1 · _depends on: none_
- [x] **[P0][M]** Wire `AuditEngine` into `EmbeddedIdentityEngine` — hold `Arc<dyn AuditEngine>`, call `audit.append()` for every security-critical mutation — resolves gaps #2 · _depends on: none_ ✅ DONE (2026-05-07)
- [ ] **[P0][S]** Add periodic cleanup background task: sweep expired authorization codes, device codes, grant families, pending authorization tickets — resolves gaps #3 · _depends on: none_
- [ ] **[P0][M]** Implement hot tier auto-sizing: read `/proc/meminfo` or cgroup `memory.limit_in_bytes`, reserve margin (20% or 2GB), allocate remainder; respect `storage.hot_tier_max_memory` override — resolves gaps #4 · _depends on: none_
- [ ] **[P0][M]** Add background compaction loop to `EmbeddedStorageEngine`: periodically merge accumulated SST files — resolves gaps #5 · _depends on: none_
- [ ] **[P0][S]** Implement `identity::validate_token_size()` — enforce permissions≤100, roles≤50, groups≤50, claim bytes≤8KiB; call from `issue_tokens_with_context` — resolves gaps #6 · _depends on: none_
- [ ] **[P0][S]** Add `GET /admin/users/{id}/effective-permissions` REST endpoint to `http.rs` — resolves gaps #7 · _depends on: none_
- [ ] **[P0][M]** Implement Dynamic Client Registration (RFC 7591) `POST /register` endpoint — resolves gaps #8 · _depends on: none_

### P1 — Should fix

- [ ] **[P1][M]** Add `resource: Option<Uri>` parameter to `resolve_with_scopes()` and implement audience-scoped scope resolution — resolves gaps #10 · _depends on: none_
- [ ] **[P1][S]** Add `attributes` field to `CreateUserRequest` and `ImportUserRequest` — resolves gaps #11 · _depends on: none_
- [ ] **[P1][S]** Wire `ArcSwap` hot-swap for `PermissionRegistry` in `main.rs` on SIGHUP — resolves gaps #12 · _depends on: none_
- [ ] **[P1][S]** Add missing OIDC default claim mappings to `default_claim_profile()` — resolves gaps #13 · _depends on: none_
- [ ] **[P1][S]** Fix `list_groups` and `list_role_members` cursor usage — resolves gaps #16 · _depends on: none_
- [ ] **[P1][S]** Fix `list_roles` cursor derivation — resolves gaps #17 · _depends on: none_
- [ ] **[P1][S]** Align `RESERVED_PREFIX` to `"hearth."` — resolves gaps #18 · _depends on: none_
- [ ] **[P1][S]** Decide: nest RBAC config under `realms.<id>.rbac.*` or update spec to flat structure — resolves gaps #14, D1 · _depends on: none_
- [ ] **[P1][S]** Add YAML-declared groups — resolves gaps #15 · _depends on: above_
- [ ] **[P1][M]** Add standalone REST WebAuthn/Passkey endpoint — resolves gaps #19 · _depends on: none_
- [ ] **[P1][M]** Add Python SDK — resolves gaps #20 (partial) · _depends on: stable API surface_
- [ ] **[P1][M]** Add Rust SDK — resolves gaps #20 (partial) · _depends on: stable API surface_
- [ ] **[P1][S]** Add resolve-time cycle detection for role DAGs — resolves gaps #9 · _depends on: none_

### P2 — Polish

- [ ] **[P2][M]** Enforce per-realm auth policies in login/credential flows — resolves gaps #23 · _depends on: none_
- [ ] **[P2][S]** Implement `/metrics` endpoint with Prometheus-compatible metrics — resolves gaps #24 · _depends on: none_
- [ ] **[P2][M]** Add OpenTelemetry-compatible distributed tracing — resolves gaps #25 · _depends on: none_
- [ ] **[P2][S]** Create systemd service file and Helm chart — resolves gaps #26 · _depends on: none_
- [ ] **[P2][S]** Write comprehensive README — resolves gaps #27 · _depends on: none_
- [ ] **[P2][M]** Create example sites — resolves gaps #28 · _depends on: SDKs_
- [ ] **[P2][S]** Write comprehensive README for each SDK — resolves gaps #29 · _depends on: none_
- [ ] **[P2][M]** Fix remaining UI audit items (P1-6, P1-9, P1-10, P2 items) — resolves gaps #30, #31 · _depends on: none_
- [ ] **[P2][M]** Implement Roles UI redesign — resolves gaps #32 · _depends on: P0 gap #7_
- [ ] **[P2][S]** Update TEST_SCENARIOS.md RBAC checkboxes — resolves gaps #33 · _depends on: none_
- [ ] **[P2][S]** Update TESTING.md §8 benchmark file list — resolves gaps #34 · _depends on: none_
- [ ] **[P2][S]** Resolve embedded-mode support contradiction — resolves gaps #35, D3 · _depends on: none_
- [ ] **[P2][S]** Compute `email_verified` from UserStatus — resolves gaps #36, D4 · _depends on: none_

### Future Phases (tracked, not started)

- [ ] **[P3][L]** Implement clustering: Raft consensus via `openraft`, leader election, log replication, snapshot recovery, online membership changes (Phase 2 per VISION.md)
- [ ] **[P3][L]** Implement agent authentication (Phase A-D per AGENT_AUTH.md): `AgentId` newtype, agent CRUD, credentials, DPoP, token exchange, OBO, consent, AATs, CAEP
- [ ] **[P3][M]** Add remaining SDKs: Java/Kotlin, PHP, C#/.NET, Ruby, Elixir
- [ ] **[P3][M]** Add remaining migration tools: Clerk, Cognito, Firebase Auth, Okta
- [ ] **[P3][L]** Implement shadow mode for zero-downtime migration
- [ ] **[P3][M]** S3-compatible object storage for cold data and audit logs
- [ ] **[P3][M]** Multi-region replication with configurable consistency

---

## Recommended Execution Order

1. **Encryption at rest** (L, 2-3 weeks) — envelope encryption in SST format first, then WAL, then per-realm keys with rotation
2. **Wire audit logging** (M, 3-5 days) — add `Arc<dyn AuditEngine>` to `EmbeddedIdentityEngine`, call at all mutation sites
3. **Periodic cleanup** (S, 1-2 days) — background task sweeping expired codes/tokens/tickets
4. **Hot tier auto-sizing + background compaction** (M, 3-5 days) — memory detection + compaction loop
5. **Token size cap enforcement** (S, <1 day) — add `validate_token_size()` and call in `issue_tokens_with_context`
6. **P1 fixes** (2-3 weeks total) — most are small (<1 day each); audience-scoped scope resolution and DCR are the largest
7. **P2 polish** (variable) — enforce per-realm policies, add metrics, fix UI issues, update docs
8. **Phase 2 (clustering)** — the largest remaining greenfield work; needs scoping and estimation
