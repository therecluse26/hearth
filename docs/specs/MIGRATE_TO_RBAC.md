# Migrate to RBAC

**Status:** one-time migration playbook. Delete or move to `docs/archive/` once the migration ships and the project is fully on the RBAC model.

**Reader:** the AI coding agent (or engineer) executing the migration. This doc is the complete mechanical playbook. Target-state design is defined in [`AUTHORIZATION.md`](./AUTHORIZATION.md) — do not duplicate design content here; link to it.

**Do NOT cite this document from permanent specs.** It is scaffolding.

---

## 1. Intent

Transform the current Zanzibar-based codebase into the RBAC system specified in `AUTHORIZATION.md`. The project is greenfield (pre-release, zero users, no deployed instances), so the migration may break the tree mid-branch and restore it; no backward compatibility is required; no data migration is needed.

Target: single merged branch, all tests green, every Zanzibar vocabulary reference gone from source and docs (except this file, which will be archived).

---

## 2. Preconditions

Before starting:

1. On a feature branch tracking `main`. The migration lands as one merge.
2. `cargo nextest run --workspace` passes on the starting branch.
3. You have read `AUTHORIZATION.md` in full. Every "see `AUTHORIZATION.md § N`" reference below assumes you know what's there.
4. You have read `CLAUDE.md` for development conventions (TDD, error handling, etc.).
5. `docs/specs/AUTHZ_HTTP.md` still exists at the start. Deletion is Step 1 of this migration.

---

## 3. Context

This migration removes the Zanzibar-style authorization engine (`src/authz/`) and replaces it with a claims-based RBAC engine (`src/rbac/`). The new engine resolves permissions at token-issue time and embeds them in access-token claims. Clients check permissions synchronously from the JWT. There is no tuple API, no consistency token, no watch stream.

See `AUTHORIZATION.md § 1` (conceptual overview) and `§ 2` (model) for the full target state.

Implementation style:

- **Single branch, merged when fully green.** Not a series of PRs. Step 1 intentionally leaves the tree non-compiling; subsequent steps restore compilation.
- **Test-first.** Per `CLAUDE.md § TDD Workflow`, every step writes failing tests first, then implements.

---

## 4. Demolition checklist

Delete these, in the order listed below. Use a single "authz removal" commit for all of Step 1; the tree will not compile after this commit.

### 4.1 Source code

```
src/authz/                                         # entire module
src/protocol/generated/hearth.authz.v1.rs
src/protocol/generated/hearth.authz.v1.serde.rs
src/protocol/convert/authz.rs
src/protocol/grpc/authz.rs
```

### 4.2 Proto

```
proto/hearth/authz/v1/authz.proto
proto/hearth/authz/                                # parent directory; empty after removal
```

Also: regenerate protobuf code (`buf generate`) after removal to purge the generated module.

### 4.3 Tests

```
tests/authz_http.rs
tests/authz_explain.rs
tests/authz_unions.rs
tests/authz_presets.rs
tests/authz_watch_property.rs
```

### 4.4 Benches

```
benches/zanzibar_watch.rs
benches/permission_check.rs            # rewrite as RBAC bench in Step 11; delete the Zanzibar version now
```

### 4.5 Simulation

```
simulation/src/tests/cache_stampede.rs
simulation/src/tests/watch_partition.rs
```

### 4.6 SDK surface

```
sdks/typescript/src/authz.ts
sdks/typescript/tests/authz-cache.test.ts
sdks/go/hearth/authz.go
sdks/go/hearth/authz_test.go
```

Also remove from `sdks/typescript/src/client.ts` / `types.ts` / `index.ts`:
- `check()` method and associated request/response types.
- `capabilities()` method and associated types.
- `AuthzCache` re-exports.

And from `sdks/go/hearth/client.go`:
- `Check()` method and its types.
- `Capabilities()` method.

### 4.7 Docs (this session)

```
docs/specs/AUTHZ_HTTP.md
```

Delete in the implementation session's first commit alongside the source removals. (This planning session does NOT delete it.)

### 4.8 Imports & wiring

After removing modules, grep for and delete:
- `use hearth::authz::*` / `crate::authz::*` anywhere.
- `AuthzConfig`, `EmbeddedAuthzEngine`, `AuthorizationEngine` trait references.
- `AppState::authz`, `GrpcState::authz`, `WebState::authz` field declarations and initializations.
- Any unused crate imports left behind.

---

## 5. Rewrite checklist

Each entry: path, current state, target state (linking to `AUTHORIZATION.md`), how to verify. Tackle after Step 4 scaffolds `src/rbac/` — you cannot rewrite consumers until the new engine exists.

### 5.1 Identity layer

| Path | Current | Target (`AUTHORIZATION.md` ref) | Verification |
|------|---------|---------------------------------|--------------|
| `src/identity/onboarding.rs` | Writes `authz.write_tuples` for first-admin (~line 451). | Call `rbac::assign_role(user, "realm.admin", Scope::Realm(tid))`. | First user in fresh realm can call admin endpoints. |
| `src/identity/reconcile.rs` | `install_preset_or_log` installs Zanzibar preset namespace. | Call `RbacEngine::seed_realm(realm_id)` (see `AUTHORIZATION.md § 9`). | Fresh realm has seed roles + permissions. |
| `src/identity/migration/keycloak.rs` | `emit_role_tuples` writes `realm:<tid>#<role>@user:<uid>` tuples. | `emit_role_assignments` calls `RbacEngine::assign_role` for each Keycloak realm role. Composite roles (if supported) map to role composition via `parent_roles`. | `tests/migration_keycloak.rs` fixtures produce expected role assignments. |
| `src/identity/migration/auth0.rs` | Same tuple pattern as Keycloak. | Same conversion as Keycloak. | Auth0 migration fixture test passes. |
| `src/identity/tokens.rs` | `TokenClaims` lacks `roles`/`groups`/`permissions`/`oid`. | Extend per `AUTHORIZATION.md § 5.1`. Add `oid: Option<String>`, `roles: Vec<String>`, `groups: Vec<String>`, `permissions: Vec<String>`. Update `IssueTokenRequest` per `§ 7.1`. | Round-trip test decodes populated claims. |
| `src/identity/engine.rs` | Admin check in some methods may call `authz.check("hearth#admin")`. | Use `rbac::resolve_permissions` + `permissions.contains("hearth.admin")` where needed, OR (preferred for in-process server calls) take a `TokenClaims` argument and inspect its `permissions` field. | Existing admin integration tests pass after auth wiring is updated. |
| `src/identity/mod.rs` | Doc comments reference Zanzibar tuples. | Remove tuple references; cross-reference `src/rbac/` for authz operations. | `rg 'tuple' src/identity/mod.rs` has no hits. |

### 5.2 Protocol layer — HTTP

Path: `src/protocol/http.rs`. This file has the largest rewrite surface.

**Remove:**
- `POST /v1/authz/check` route + `authz_check` handler + `AuthzCheckRequest`/`AuthzCheckItem`/`AuthzCheckResponse` types + `parse_object_pair` helper.
- `GET /v1/me/capabilities` route + `me_capabilities` handler + `MeCapabilitiesResponse` type + `resolve_template` helper.
- `AppState::capability_pages` field and `AppState::new`/`new_dev`/`with_shared_rate_limiter` capability-page init.
- `CapabilityPage`, `CapabilityPageEntry`, `CapabilityPages` type definitions.
- `use crate::authz::{...};` import line.

**Rewrite:**
- `extract_admin_auth` (line ~141): after validating the token, check `claims.permissions.contains("hearth.admin")` instead of calling `authz.check`. Return 403 with `{"error":"forbidden"}` if absent. Rate limit as before.
- `check_user_admin` (wherever it's called from web handlers): same — read `permissions` from the verified token.
- `grant_user_admin` / `revoke_user_admin`: call `rbac::assign_role` / `rbac::unassign_role` with `RoleId` for `realm.admin`.

**Add:**
- `GET /v1/me/permissions` — bearer auth, returns `{roles, groups, permissions, scope}`. Handler calls `rbac.resolve_permissions` afresh (does NOT just return cached JWT claims).
- Admin role/group/assignment endpoints per `AUTHORIZATION.md § 8.2`. Follow existing admin endpoint pattern (`admin_list_users`, `admin_create_user`, etc.).

**Verification:** integration tests per `TEST_SCENARIOS.md` Authorization section.

### 5.3 Protocol layer — gRPC

Path: `src/protocol/grpc/`.

**Remove:**
- `authz.rs` (already deleted in Step 4).
- `AuthorizationService` registration in `server.rs`.
- Any `proto_object_ref_to_domain` / `proto_subject_ref_to_domain` / `proto_tuple_write_to_domain` helpers in `convert/` (already deleted).

**Add:**
- `RbacAdminService` registration in `server.rs`.
- `rbac_admin.rs` implementing the service per `AUTHORIZATION.md § 8.4`. Mirror the HTTP admin surface. Auth via admin bearer metadata using the existing `authenticate_admin` helper.
- `proto/hearth/rbac/v1/rbac.proto` with message shapes matching the HTTP bodies. Generate via `buf generate`.

**Verification:** grpc-admin example at `examples/grpc-admin-flow/` updated to exercise role CRUD. Integration test under `tests/grpc_rbac_admin.rs`.

### 5.4 Protocol layer — Web UI

Paths: `src/protocol/web/admin.rs`, `src/protocol/web/handlers.rs`, `templates/ui/admin/**`.

Rewire every `authz.check` / `authz.write_tuples` call site to use `rbac`:
- `check_user_admin` reads `claims.permissions.contains("hearth.admin")`.
- Admin role grant/revoke in the UI calls `rbac::assign_role` / `rbac::unassign_role`.
- The authz-debugger page at `/ui/admin/authz/debug` becomes a permission-resolver page: input `(user, org?, scope?)` → display resolved permissions and contributing role assignments / group memberships. Repurpose the existing template; update terminology.
- Organization member UIs that currently mirror Zanzibar tuples for role changes now write a single `rbac::assign_role` call. See `ROLES_UI_REDESIGN.md` for the target UX.

**Verification:** `tests/web_ui_admin.rs`, `tests/admin_org_ui.rs`, `tests/web_ui_realm_routing.rs`.

### 5.5 Protocol layer — SCIM

Path: `src/protocol/scim/`.

Route `/scim/v2/Groups` to `RbacEngine::create_group` / `update_group` / `delete_group` / `add_group_member` / etc. SCIM Group members MAY be users OR other groups; map to `GroupMember::User` / `GroupMember::Group`.

**Verification:** `tests/scim.rs`.

### 5.6 Main wiring

Path: `src/main.rs`.

- Remove `use hearth::authz::*` imports.
- Remove `authz_engine` construction (around line 439-442).
- Add `rbac_engine: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(storage, config)?)`.
- Update `AppState::new`, `GrpcState::new`, `WebState::new` signatures to take `rbac_engine` instead of `authz_engine`.
- Update `build_engines` to return `(IdentityEngine, RbacEngine)`.
- Update `run_config_reconciliation` to pass the RBAC engine where Zanzibar preset installation previously happened.

### 5.7 SDKs

#### TypeScript (`sdks/typescript/`)

- `src/types.ts` — add `CheckResult` / `CapabilityBundle` types REMOVED; add new shape for `MePermissionsResponse` (roles/groups/permissions/scope).
- `src/client.ts` — remove `check`, `capabilities`; add `hearth.client.permissions()` as the escape-hatch live-introspection method.
- `src/hearth.ts` (new) — the user-facing facade `createHearth({ baseUrl, realmId, getToken })` exposing `hasPermission` / `hasRole` / `inGroup` / `inOrg`. Decodes the JWT locally via `jose` (already a dev dep; move to peer dep). Uses `getToken` synchronously on each check.
- `src/react.ts` (new) — `HearthProvider`, `useHasPermission`, `useHasRole`, `useInGroup`, `useInOrg`. React as optional peer dep (add to `peerDependencies`, leave out of `dependencies`).
- `src/index.ts` — re-export `createHearth`, `HearthClient` (for admin), `HearthError`. Drop `AuthzCache` re-export.
- `tests/` — delete `authz-cache.test.ts`; add `hasPermission.test.ts` covering JWT decoding + synchronous checks with mocked tokens.

#### Go (`sdks/go/`)

- `hearth/types.go` — remove `CheckRequestItem`, `CheckResultItem`, `CheckResponse`, `CapabilityBundle`. Add `MePermissions` response struct.
- `hearth/client.go` — remove `Check`, `Capabilities`. Add `client.HasPermission(token, perm) bool`, `HasRole`, `InGroup`, `InOrg`. Decode JWT via `github.com/golang-jwt/jwt/v5` (add to go.mod).
- `hearth/authz.go` — deleted in Step 4.
- `hearth/hearth_test.go` (or new `hearth/permissions_test.go`) — cover JWT decoding + checks with `httptest` for the introspection escape hatch.

### 5.8 Benches

Path: `benches/rbac_check.rs` (replaces `permission_check.rs`).

Benchmark the JWT-claim lookup (a hashset `contains` over typically <100 strings). Target: sub-microsecond p99.

### 5.9 Memory files

Paths: `memory/MEMORY.md`, `memory/phase1-step-details.md`.

After migration succeeds, update entries that describe Zanzibar state to reflect RBAC. Delete obsolete sections. Add a single summary entry documenting the migration (date, what changed). Done LAST — after verification passes.

---

## 6. Implementation order

Execute in this order. Each step includes preconditions, what to implement, what to test (test-first per `CLAUDE.md`), and what to commit.

### Step 1 — Demolition

**Pre:** branch clean, tests green.

**Do:** Apply the entire deletion list in `§ 4` (source, proto, tests, benches, simulation, SDK files, `docs/specs/AUTHZ_HTTP.md`). Commit once. Expected: tree does NOT compile.

**Test:** `cargo check` fails with expected errors (missing `authz` module references throughout). Treat this as the baseline.

**Commit message:** `remove zanzibar authorization engine (pre-rbac migration)`

### Step 2 — Scaffold `src/rbac/`

**Pre:** Step 1 committed.

**Do:** Create the module per `AUTHORIZATION.md § 6.1`. Define the `RbacEngine` trait, all types (`Role`, `Group`, `Permission`, `RoleAssignment`, `GroupMember`, `Scope`, `ResolvedPermissions`, `RbacError`). No method bodies yet — return `unimplemented!()` or a stub error. Add the module to `src/lib.rs` (or wherever).

**Test:** `cargo check` compiles (the new trait satisfies the old consumers only after Step 4; expect remaining consumer errors for now — fix those in Step 3+). Write unit tests for the `Permission` string validator (per `§ 2.5` grammar) and for `Role`/`Group` struct invariants. Test-first.

**Commit:** `scaffold src/rbac/ module (types, trait, error)`

### Step 3 — Implement `EmbeddedRbacEngine`

**Pre:** Step 2 committed.

**Do:** Implement all trait methods against `StorageEngine`. Storage keys per `AUTHORIZATION.md § 4.1`. Resolution per `§ 3`. Cycle detection and cap enforcement per `§ 2.6`.

**Test (all test-first):**
- Unit: `Permission` grammar rejects invalid strings; cycle detection for roles; cycle detection for groups; depth cap exceeded error; breadth cap exceeded error; transitive group BFS; role composition DAG expansion; realm-scoped vs org-scoped assignment resolution.
- Integration (in a new `tests/rbac_engine.rs`): create role → assign to user → resolve → permissions present; create role chain A→B→C → resolve → all permissions present; create group, add user, assign role to group → resolve → user gets role's permissions; add group-to-group membership, resolve, transitive membership works; scope filter intersects.

**Commit:** `implement EmbeddedRbacEngine with resolution, cycle detection, caps`

### Step 4 — Wire `RbacEngine` into `main.rs` and app state

**Pre:** Step 3 committed.

**Do:** Update `src/main.rs`, `AppState`, `GrpcState`, `WebState` to hold `Arc<dyn RbacEngine>`. Update test harness in `tests/common/mod.rs` to build both engines. At this point most consumers still reference authz — compile errors will cascade.

**Test:** Fix compile errors one consumer at a time by replacing `state.authz.*` calls with `state.rbac.*` equivalents OR placeholder `unimplemented!()` that will be replaced in later steps. Goal: the tree compiles and non-authz tests pass.

**Commit:** `wire RbacEngine through main, app state, test harness`

### Step 5 — Extend `TokenClaims` and issuance

**Pre:** Step 4 committed.

**Do:** Per `AUTHORIZATION.md § 5.1` and `§ 7`. Extend `TokenClaims` struct and `IssueTokenRequest`. Update `issue_token_pair` signature. Update `issue_tokens` in `IdentityEngine` to call `rbac::resolve_permissions` and populate the claim. Enforce size caps per `§ 5.4`.

**Test (test-first):** Integration: create user, assign role, issue token, decode, claim contains role and permissions. Adversarial: assign 101+ permissions, verify issuance fails with `token_too_large`. Property: round-trip serialize/deserialize preserves claim shape.

**Commit:** `extend TokenClaims with roles/groups/permissions; resolve at issue`

### Step 6 — Reimplement admin auth

**Pre:** Step 5 committed.

**Do:** Rewrite `extract_admin_auth` in `src/protocol/http.rs` per `§ 5.2`. Update `check_user_admin` and related web-layer helpers. Update gRPC `authenticate_admin` if it had a Zanzibar call path.

**Test (test-first):** Integration: user with `hearth.admin` can call admin endpoints; user without cannot (403); unauthenticated = 401.

**Commit:** `reimplement admin auth against permissions claim`

### Step 7 — Seed realm defaults on creation

**Pre:** Step 6 committed.

**Do:** Replace `install_preset_or_log` in `src/identity/reconcile.rs`. Call `RbacEngine::seed_realm(realm_id)` per `AUTHORIZATION.md § 9.1`/`§ 9.2`. Verify idempotency on re-run.

**Test:** Integration: create fresh realm, query roles, seed roles present with correct permissions.

**Commit:** `seed rbac defaults on realm creation`

### Step 8 — Migrate onboarding and importers

**Pre:** Step 7 committed.

**Do:** Update `src/identity/onboarding.rs` to call `rbac::assign_role(user, "realm.admin", Scope::Realm(tid))` for the first-created user. Update `src/identity/migration/keycloak.rs` and `auth0.rs` per `§ 5.1`.

**Test:** Integration: first user in realm auto-receives `realm.admin` role and can call admin endpoints. Keycloak import fixture produces expected role assignments. Auth0 import fixture likewise.

**Commit:** `migrate onboarding, keycloak, auth0 importers to rbac`

### Step 9 — Admin HTTP + gRPC endpoints

**Pre:** Step 8 committed.

**Do:** Implement all admin endpoints per `AUTHORIZATION.md § 8.2` and `§ 8.4`. Add `GET /v1/me/permissions`. Add proto messages under `proto/hearth/rbac/v1/rbac.proto`. Regenerate.

**Test (test-first):** For each endpoint: happy path, auth required (401/403), bad input (400), realm scoping enforced, cycle rejection on role composition, duplicate slug/name rejection, cascade semantics on delete.

**Commit:** `admin rbac endpoints (http + grpc) + /v1/me/permissions`

### Step 10 — SCIM Groups

**Pre:** Step 9 committed.

**Do:** Route `/scim/v2/Groups` to RBAC `Group` entity. Update existing SCIM tests.

**Test:** `tests/scim.rs` covers group create/read/update/delete and member CRUD.

**Commit:** `scim groups backed by rbac engine`

### Step 11 — TS SDK

**Pre:** Step 10 committed.

**Do:** Implement `sdks/typescript/src/hearth.ts` per `AUTHORIZATION.md § 11.1`/`§ 11.2`. Add `react.ts` per `§ 11.3`. Update exports. Add `jose` as direct dep (it was devDep).

**Test:** Vitest unit tests with mocked JWT; test hooks with `@testing-library/react`; one live-server integration test creating a realm, user, assignment, token and verifying `hasPermission` returns `true`.

**Commit:** `ts sdk: claim-based hasPermission + react hooks`

### Step 12 — Go SDK

**Pre:** Step 11 committed.

**Do:** Mirror TS shape in `sdks/go/hearth/`.

**Test:** Unit tests with `httptest` for the introspection escape hatch, JWT decoding covered by direct unit tests.

**Commit:** `go sdk: claim-based HasPermission`

### Step 13 — Docs reconciliation (post-code)

**Pre:** Step 12 committed.

**Do:** Re-read the docs updated in this planning session (`CLAUDE.md`, `ARCHITECTURE.md`, `IMPLEMENTATION_ORDER.md`, `TEST_SCENARIOS.md`, `TESTING.md`, `ROLES_UI_REDESIGN.md`, `AGENT_AUTH.md`, `CONFIGURATION.md`, `VISION.md`). If the implementation surface differs from what the docs describe, fix the docs — do NOT silently diverge the code. Delete `docs/specs/AUTHZ_HTTP.md` (already gone per Step 1, but confirm).

**Commit:** `docs: reconcile with shipped rbac implementation`

### Step 14 — Memory files + verification

**Pre:** Step 13 committed.

**Do:** Update `memory/MEMORY.md` and `memory/phase1-step-details.md` to reflect the shipped state. Run verification per `§ 8`. Open PR.

**Commit:** `memory: reflect rbac migration complete`

---

## 7. Test scenarios mapping

Each scenario in `AUTHORIZATION.md` (and `TEST_SCENARIOS.md`'s rewritten Authorization section) maps to a concrete test file. Use this as a checklist.

| Scenario | File | Notes |
|----------|------|-------|
| Permission grammar validation | `src/rbac/types.rs` (unit) | Property test with random strings. |
| Role composition — transitive | `tests/rbac_engine.rs::role_composition_transitive` | A→B→C expansion. |
| Role composition — cycle rejected | `tests/rbac_engine.rs::role_cycle_rejected` | A→B→A returns `CycleDetected`. |
| Role composition — depth cap | `tests/rbac_engine.rs::role_depth_cap` | 11-deep chain fails. |
| Group nesting — transitive | `tests/rbac_engine.rs::group_nesting_transitive` | User in G1⊂G2⊂G3. |
| Group nesting — cycle rejected | `tests/rbac_engine.rs::group_cycle_rejected` | G1⊂G2⊂G1. |
| Group depth/breadth caps | `tests/rbac_engine.rs::group_caps` | Exceed either bound. |
| Realm-scoped vs org-scoped assignment | `tests/rbac_engine.rs::scope_filtering` | Token without org excludes org-scoped. |
| Scope request narrows permissions | `tests/rbac_engine.rs::scope_intersection` | `scope=docs` filters to `docs.*`. |
| Token claim population | `tests/issue_token_rbac.rs::populates_roles_groups_permissions` | Integration. |
| Token size cap | `tests/issue_token_rbac.rs::size_cap_refuses_issuance` | Adversarial. |
| First user auto-admin | `tests/onboarding_rbac.rs::first_user_admin` | Integration. |
| Seed roles present on new realm | `tests/realm_rbac_seed.rs::fresh_realm_has_seed` | Integration. |
| Keycloak importer role mapping | `tests/migration_keycloak.rs::roles_to_assignments` | Updated existing test. |
| Auth0 importer role mapping | `tests/migration_auth0.rs::roles_to_assignments` | Updated existing test. |
| Admin auth via permission claim | `tests/admin_rbac_auth.rs::permission_gated` | Integration. |
| Admin role CRUD | `tests/admin_roles_rbac.rs::crud` | HTTP integration. |
| Admin group CRUD + members | `tests/admin_groups_rbac.rs::crud_and_members` | HTTP integration. |
| Role assignment CRUD | `tests/admin_assignments_rbac.rs::crud` | HTTP integration. |
| `GET /v1/me/permissions` | `tests/me_permissions.rs::returns_live_set` | Integration. |
| Cross-realm isolation | `tests/rbac_cross_realm.rs::no_leak` | Adversarial. |
| SCIM Groups | `tests/scim.rs::groups_backed_by_rbac` | Updated. |
| gRPC admin parity | `tests/grpc_rbac_admin.rs` | Integration. |
| TS SDK `hasPermission` | `sdks/typescript/tests/hasPermission.test.ts` | Vitest + mock. |
| TS SDK React hooks | `sdks/typescript/tests/react-useHasPermission.test.tsx` | `@testing-library/react`. |
| Go SDK `HasPermission` | `sdks/go/hearth/permissions_test.go` | httptest. |
| JWT claim lookup bench | `benches/rbac_check.rs` | Criterion; sub-μs target. |

---

## 8. Verification commands

Run these in order. Each MUST succeed before proceeding.

```bash
# From repo root:

# 1. All Rust tests pass.
cargo nextest run --workspace

# 2. No clippy violations in files we touched.
cargo clippy --all-targets -- -D warnings

# 3. Rust formatting clean.
cargo fmt --all -- --check

# 4. No surviving Zanzibar vocabulary in Rust source.
rg -i '(zanzibar|zookie|userset|relationship.tuple|consistency.token|write_tuples|ObjectRef|SubjectRef|authz::|AuthorizationEngine|TupleWrite|NamespaceConfig|CheckExplanation)' -t rust
# Expected: zero hits (or only tests/files documenting historical context).

# 5. No Zanzibar vocabulary in docs (except this file, which will be archived).
rg -i '(zanzibar|zookie|userset|consistency.token)' docs/ CLAUDE.md
# Expected: hits only in docs/specs/MIGRATE_TO_RBAC.md (this file).

# 6. TS SDK tests pass.
cd sdks/typescript && npm test

# 7. Go SDK tests pass.
cd sdks/go && go test ./...

# 8. Smoke test end-to-end.
cargo run -- --dev &
HEARTH_PID=$!
sleep 2

# Create realm + user + token; verify claims; verify admin access; revoke and re-verify.
# (Exact curl commands documented in examples/rbac-smoke-test/ — create this example as part of Step 13.)

kill $HEARTH_PID
```

**Exit criteria:** all 8 commands succeed. If any fail, do not merge.

---

## 9. Risks and recovery

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **Step 1 leaves tree non-compiling for multiple commits.** | Certain | Known; intentional. | Single branch; do not try to merge mid-migration. |
| **`TokenClaims` schema change invalidates any existing tokens.** | Certain | Greenfield; no deployed tokens exist. | Confirm with `git log` that no production deploys happened. |
| **Integration tests set up Zanzibar tuples as preconditions.** | High | Tests must be rewritten. | Step 5 and later steps include test updates; audit every `write_tuples` in `tests/` and convert to `assign_role`. |
| **`ROLES_UI_REDESIGN.md` may describe UI that assumed tuple mirroring.** | Medium | Doc drift. | Step 13 reconciles doc with shipped implementation; fix the doc, not the code. |
| **Keycloak composite roles are not supported by the new importer.** | Medium | Migration feature regression. | Accept as a follow-up or implement composite-role mapping via role `parent_roles`. Document in the PR which Keycloak features are supported. |
| **SCIM Group members are polymorphic (users + groups); existing SCIM code may assume users only.** | Medium | SCIM test failures. | Step 10 explicitly covers user and group members in `tests/scim.rs`. |
| **`jose` dependency becomes runtime for TS SDK.** | Low | Bundle size increase. | Acceptable; jose is ~30KB gzipped. |
| **Go JWT library choice.** | Low | One more dep to justify. | `github.com/golang-jwt/jwt/v5` is idiomatic; pass `cargo-audit`-equivalent. |
| **Missed consumer after demolition.** | Medium | Build failure; easy to fix. | Step 4 compiler output enumerates them; fix one at a time. |
| **Simulation test gap for concurrency.** | Medium | Less simulation coverage than before. | Add at least one property test for concurrent role-assignment writes in Step 3; simulation can come later. |

---

## 10. Post-migration cleanup

Once all verification passes and the PR merges:

1. Delete `docs/specs/AUTHZ_HTTP.md` (already done in Step 1).
2. Delete or archive this file (`docs/specs/MIGRATE_TO_RBAC.md`). Move to `docs/archive/MIGRATE_TO_RBAC.md` if a historical record is wanted; delete outright otherwise. The author's recommendation: archive once, keep for 6 months as history, then delete.
3. Mark the relevant step in `docs/specs/IMPLEMENTATION_ORDER.md` as complete.
4. Update `memory/MEMORY.md` with a one-paragraph summary of what changed (date, removed `src/authz/`, added `src/rbac/`, JWT shape changed, SDK surface reshaped).
5. Close any open issues referencing the old authorization model.
6. Update any external README or marketing that mentioned "Zanzibar" as a feature (if present).

The migration is complete when a reader of the docs tree plus source plus tests cannot tell that Zanzibar was ever in the project — except for the archived migration record, if kept.
