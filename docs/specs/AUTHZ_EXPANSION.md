# Authz Expansion: Custom Permissions, Scopes, and Configurable Claims

**Status:** Specification — architecture settled, not yet implemented.

## Context

Hearth's claims-based RBAC works end-to-end, but the administrative and developer surface around it is minimal. Today:

- `Permission` is a free-form `String` newtype (`src/rbac/types.rs:88`). No registry exists — admins can grant any string but cannot discover, document, or govern the permission vocabulary.
- Token claims (`roles`, `groups`, `permissions`) are hardcoded to always ship at `src/identity/engine.rs:2267-2309`. There is no way for a realm admin to configure what a token looks like — which claims emit, with what shape, or with what custom attributes.
- OAuth scopes exist as a pass-through string on the token but are not a first-class concept. Third-party OAuth flows cannot express "this client is allowed to request these capabilities" — every client effectively has full-trust access to the user's permission set.
- There is no UI for managing roles, permissions, groups, scopes, or user-level grants beyond the read-only `/ui/admin/rbac/debug` resolver. Org roles are hardcoded to three tiers (Member/Admin/Owner).
- There is no concept of user-level direct permission grants ("extras"). To give one user one extra capability, admins must invent a bespoke role.
- The SDKs (`sdks/typescript`, `sdks/go`) treat permission as free-form `string`.

The goal of this work is to turn authz from a code-and-config construct into a discoverable, governed, first-class admin surface — without sacrificing Hearth's performance (zero-alloc hot path), security (declarative mappers only, no scripting), or operational simplicity (one conceptual rule, no knobs with ambiguous semantics).

**Authoring model.** Permissions, roles, scope bundles, and token claim profiles are authored in `hearth.yaml` only. This matches Hearth's existing YAML-first pattern for realms, OAuth clients, and email configuration. The admin UI provides read-only browsing and discovery for YAML-defined entities, plus CRUD for runtime data (user role assignments, user extras, OAuth consents).

## Architectural Model

Five concepts, each answering exactly one question:

| Concept | Authored in | Answers |
|---|---|---|
| **Permission** | `hearth.yaml` (YAML registry) | What atomic capabilities exist in this realm? |
| **Role** | `hearth.yaml` (YAML registry) | What named bundles of permissions can be assigned? |
| **Scope bundle** *(optional)* | `hearth.yaml` (YAML registry) | What coarse-grained OAuth consent bundles should the consent screen present? |
| **User extra permission** | Runtime storage (`rba:user_perm:*`) | What direct grants does this specific user have outside their roles? |
| **Claim profile** | `hearth.yaml` per realm (`realms.<id>.claims`) | What does a token from this realm look like? |

### Naming convention (syntactic classification)

Permissions, scope bundles, and OIDC standard scopes occupy three disjoint namespaces distinguished by their separator. Classification is syntactic — a parser can identify what kind of string it has in constant time without consulting any registry.

- **Permission:** `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$` — MUST contain ≥1 dot, MUST NOT contain `:`. Minimum two non-empty segments. ≤128 chars.
- **Scope bundle:** `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$` — MUST contain ≥1 colon, MUST NOT contain `.`. Minimum two non-empty segments. ≤128 chars.
- **OIDC standard scope:** bare word from the closed set `{ openid, profile, email, address, phone, offline_access }`. No other bare-word names are permitted.

Single-word permission names like `admin` or `editor` are rejected at config load. Globally-scoped permissions use the conventional `system.*` namespace (`system.admin`, `system.readonly`). This forces resource-oriented naming and reserves the bare-word namespace for IETF-defined protocol scopes.

Hierarchical nesting is supported at arbitrary depth (`user.self.write` vs `user.write`, `docs.versions.read`) as a naming convention. There is **no implicit inheritance** — `docs.read` does not imply `docs.versions.read`. Each segmented name is an independent atomic permission. Admins group related permissions via roles or scope bundles.

### Resolution rule

Applied at every token issuance regardless of grant type:

```
effective =
    ∪ role.permissions for role in user.role_assignments WHERE role.scope matches token context
  ∪ extra.permission    for extra in user.permission_grants WHERE extra.scope matches token context

if requested_scopes non-empty:
    grantable = { s ∈ requested_scopes : scope_perms(s) ∩ effective ≠ ∅ OR s is OIDC-standard }
    effective = effective ∩ ∪ scope_perms(s) for s in grantable
    token.scope = grantable (space-delimited, RFC 6749)

    if grantable is empty: error(invalid_scope)

else:
    if client.trust_level == ThirdParty: error(invalid_scope)
    token.scope = ""

token.permissions = effective
token.roles       = user.roles (names only, informational)
token.groups      = user.groups (names only, informational)
token.<custom>    = output of each claim mapper in the realm profile
```

**Scope resolution for each requested string `s`:**
1. If `s` contains `:` → scope bundle; look up in YAML registry, `scope_perms(s) = bundle.permissions`.
2. If `s` contains `.` → permission; treat as synthetic single-permission scope, `scope_perms(s) = [s]`.
3. If `s` is a bare word → must be an OIDC standard scope; apply its claim-shape / refresh-token effect; contributes no permissions to the intersection.
4. Otherwise or if not in `client.declared_scopes` → `invalid_scope`.

**Scope-match rule for role assignments and user extras:**
- `Scope::Realm` matches any token context (always applies).
- `Scope::Org(X)` matches iff `token.oid == Some(X)` (only when the user is acting in the context of organization X).

**Consent requirements** remain per the spec's resolved `ClientTrustLevel` matrix:
- `FirstParty` — no consent required; empty `requested_scopes` yields full effective permissions.
- `ThirdParty` — consent required (first time per scope set, digest-validated afterwards); empty `requested_scopes` is `invalid_scope`.

### Field semantics (documented contract)

- `permissions` — authoritative for fine-grained authorization. Hearth SDKs check this. Always the flat effective set, server-resolved, post-intersection.
- `scope` — OAuth consent boundary per RFC 6749. RFC-compliant API gateways read this.
- `roles` / `groups` — informational. For UI personalization, federation, admin debugging. Never the authoritative check at an authz boundary, but nothing stops developers from using them for UI gating or persona checks.
- Custom claims — flattened into the top-level JWT payload, defined declaratively in the realm's claim profile.

### Consequences

- `permissions` and `scope` never disagree. Downstream code doesn't need to intersect them — the server already did. One source of truth per scenario (fine-grained → `permissions`, OAuth gateway → `scope`).
- User extras flow through the same code path as role grants. The SDK sees one flat permissions array regardless of grant source. The admin UI surfaces the distinction; the runtime does not.
- Scope is a pure filter. It can narrow but never widen. A client cannot request more than the user has, and cannot request a scope it didn't declare at registration.
- No expression language, no scripting, no dispatcher. Every mapping from server state to token claim is a data-driven declarative rule, writable in YAML, reviewable in a diff.

## Data Model

### YAML schema additions

```yaml
# hearth.yaml

permissions:
  - name: docs.read
    display_name: Read documents
    description: View documents and their metadata.
    category: Documents
  - name: docs.write
    display_name: Edit documents
    category: Documents
  - name: billing.read
    display_name: View billing
    category: Billing
  - name: system.admin
    display_name: System administrator
    category: System

roles:
  - name: editor
    scope_kind: realm              # realm | organization | any
    description: Create and edit documents
    permissions: [docs.read, docs.write]
  - name: org_owner
    scope_kind: organization
    permissions: [org.members.write, org.settings.write, org.billing.read]
  - name: auditor
    scope_kind: any
    permissions: [audit.read]

scopes:                             # OPTIONAL — only define when you want consent bundling
  - name: read:docs
    permissions: [docs.read, docs.list, docs.share]
    display_name: Read your documents
    description: View documents you own or have been shared with you.

oauth_clients:
  - id: first-party-app
    trust_level: first_party
    declared_scopes: [docs.read, docs.write, profile, email, openid]    # permissions + OIDC directly
  - id: third-party-partner
    trust_level: third_party
    declared_scopes: [read:docs, offline_access, openid]                # bundle + OIDC

realms:
  production:
    claims:                         # OPTIONAL — omit for default shape
      mappings:
        - { claim: groups,     source: omit }                           # drop native groups
        - { claim: roles,      source: role_subset, prefix: "realm." }  # override roles shape
        - { claim: department, source: user_attribute, attribute: dept }
```

### New types

```rust
// src/rbac/types.rs

/// Permissions are defined in YAML only; this type represents the definition
/// loaded into the in-memory registry at startup.
pub struct PermissionDefinition {
    pub name: Permission,            // must match the permission name grammar above
    pub display_name: String,
    pub description: Option<String>,
    pub category: Option<String>,
}

/// Scope bundles are optional coarse-grained consent units.
pub struct ScopeBundle {
    pub name: String,                // must match the scope bundle name grammar
    pub display_name: String,        // shown on consent screen
    pub description: Option<String>, // shown on consent screen
    pub permissions: Vec<Permission>,
}

pub enum RoleScopeKind {
    /// Role may only be assigned at realm scope.
    Realm,
    /// Role may only be assigned at organization scope.
    Organization,
    /// Role may be assigned at either scope.
    Any,
}

/// Existing `Role` gains `scope_kind` (see RoleScopeKind).
pub struct Role {
    pub id: RoleId,
    pub realm_id: RealmId,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<Permission>,
    pub scope_kind: RoleScopeKind,
    // ... existing fields ...
}

/// User-level direct permission grants (extras), outside any role.
pub struct UserPermissionGrant {
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub permission: Permission,
    pub scope: Scope,                // Realm or Org(id) — same enum as role assignments
    pub granted_at: Timestamp,
    pub granted_by: Option<UserId>,
}

// src/identity/types.rs — add attributes map to User

pub struct User {
    // ... existing fields ...
    pub attributes: BTreeMap<String, String>,
    //   key:   [a-z0-9_]{1,64}
    //   value: ≤ 1 KiB
    //   total map: ≤ 16 KiB
}

// src/identity/claims_config.rs (new file)

pub struct ClaimProfile {
    pub mappings: Vec<ClaimMapping>,
    pub updated_at: Timestamp,
}

pub struct ClaimMapping {
    pub claim: String,               // target JWT claim name
    pub source: ClaimSource,
    pub include_in_access_token: bool,
    pub include_in_id_token: bool,
}

#[serde(tag = "source", rename_all = "snake_case")]
pub enum ClaimSource {
    // Built-in sources (default profile uses these)
    RolesFromAssignments,
    GroupsFromMemberships,
    EffectivePermissions,
    OrgContext,

    // Custom sources
    UserAttribute { attribute: String },
    RoleSubset { prefix: String },
    Constant { value: serde_json::Value },

    // Suppression sentinel — emit nothing at this claim name
    Omit,
}
```

### Default claim profile

Realms with no `claims:` block emit tokens identically to today's hardcoded shape:

```rust
pub const DEFAULT_CLAIM_PROFILE: &[ClaimMapping] = &[
    ClaimMapping { claim: "roles",       source: RolesFromAssignments,  access: true, id: true  },
    ClaimMapping { claim: "groups",      source: GroupsFromMemberships, access: true, id: true  },
    ClaimMapping { claim: "permissions", source: EffectivePermissions,  access: true, id: false },
    ClaimMapping { claim: "oid",         source: OrgContext,            access: true, id: true  },
];
```

Realms that define `claims.mappings:` in YAML merge their list over defaults **by claim name, last-wins**. Admins write only the deltas.

### Claim name tiers

Mapper claim names are validated at config load against a three-tier policy:

**Tier 1 — Forbidden (config-load rejects):** JWT / OIDC integrity and authorization-critical claims that mappers MUST NOT touch.
- JWT: `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`
- Identity: `sub`, `tid`
- Authorization: `permissions`, `scope`, `sid`
- OIDC flow: `nonce`, `auth_time`, `acr`, `amr`

**Tier 2 — Overridable (mapper wins):** Informational and OIDC profile claims. Mapper output replaces default native emission.
- Hearth informational: `roles`, `groups`, `oid`
- OIDC profile: `email`, `email_verified`, `name`, `given_name`, `family_name`, `preferred_username`, `locale`, `zoneinfo`

**Tier 3 — Custom:** Any other name matching `^[a-z][a-z0-9_]*$`, ≤64 chars, no dots.

**Evaluation order:** mappings evaluated in YAML-declaration order; later mapping overrides earlier at same claim name. Tier 1 claims are written last by core issuance code as defense-in-depth — any mapping that slipped past Tier 1 validation would be clobbered.

### OAuth client additions

```rust
pub struct OauthClient {
    // ... existing fields ...
    pub trust_level: ClientTrustLevel,
    pub declared_scopes: Vec<String>,        // permission names, bundle names, or OIDC standard scopes
}

pub enum ClientTrustLevel { FirstParty, ThirdParty }
```

### Storage keys

YAML-authored entities do **not** get storage keys — they live in the in-memory registry. Only runtime data gets storage keys:

- `rba:user_perm:{realm}:{user}:{perm}` — user extras (primary)
- `rba:user_perm:by_perm:{realm}:{perm}:{user}` — reverse index (who has this extra)
- `oauth:consent:{realm}:{user}:{client}` — stored consent + scope digest

## Registry and Reload

The `PermissionRegistry` is loaded from YAML at startup into `Arc<PermissionRegistry>` and hot-swapped via `ArcSwap` on SIGHUP. It holds permissions, roles, scope bundles, and per-realm claim profiles.

### Dangling references

Runtime storage (user extras, role assignments, stored consents, active refresh tokens) may reference registry entries that a later YAML edit removes. Hearth handles this lazily:

- YAML reload is **non-destructive** at the storage layer — no forced cleanup, no startup abort.
- `resolve_effective` is the single enforcement point. References to missing registry entries are silently skipped — natural fail-closed behavior (a missing permission is simply not granted).
- Startup validator logs structured orphan summary at `warn` level.
- Audit event `OrphanedReferenceSkipped` is emitted once per (realm, reference) per hour to surface drift without log spam.
- Refresh tokens referencing removed scopes or bundles fail **lazily on next refresh** with `invalid_grant`. No eager sweep.
- Consent records for deleted scopes are dropped at the same lazy checkpoint.
- Claim-mapper removal does not invalidate outstanding JWTs (already signed); next issuance uses new shape. Short token lifetimes self-heal.

### Maintenance CLI (additive)

- `hearth config validate [file]` — pre-flight validation, including name grammar, tier enforcement, cross-references.
- `hearth config diff <new.yaml>` — terraform-style pre-flight impact diff against storage.
- `hearth rbac orphans list [--realm <id>]` — enumerate orphaned runtime data.
- `hearth rbac orphans purge --realm <id> [--dry-run]` — cascade-delete orphaned assignments/extras with audit events.

## Consent Storage

```
oauth:consent:{realm}:{user}:{client} → {
  scopes: Vec<String>,           // as requested by the client at consent time
  scope_digest: [u8; 32],        // sha256(sort(unique(resolved_permissions)))
  granted_at: Timestamp,
  granted_by: UserId,
}
```

### Invalidation (digest-based, lazy)

At grant time, Hearth computes `scope_digest = sha256(sort(unique(resolved_permissions(scopes))))` — resolving each scope string to its permission set via the classification rules above. OIDC standard scopes contribute a fixed sentinel so changes to OIDC handling invalidate correctly.

On every subsequent `/authorize` or `/token refresh_token`, Hearth re-resolves and re-hashes live. Mismatch → treat as no consent → trigger re-consent ceremony (or `invalid_grant error_description=consent_required` on refresh). Match → consent stands.

This is the SSH `known_hosts` pattern applied to OAuth consent: trust was granted to a specific artifact, not a name. Self-healing, precise, no eager sweep at YAML reload.

### Refresh token behavior under drift

| Scenario | Behavior |
|---|---|
| Scope bundle contents change in YAML | Digest mismatch → `invalid_grant consent_required`; client redirects to `/authorize`. |
| User loses a permission | Digest still matches (same scopes/bundles). Refresh succeeds with narrower effective set. Downstream apps see 403 when attempting actions the user no longer has — correct signal, no forced re-login. |
| Scope bundle deleted from YAML | Digest mismatch → `invalid_grant consent_required`. |

## Admin UI

All templates under `templates/ui/admin/rbac/` + `templates/ui/admin/realms/claims/`. Handlers in `src/protocol/web/admin.rs`. Theme tokens per `docs/specs/THEME.md`.

### New nav section "RBAC"

- Permissions — `/ui/admin/rbac/permissions` (**read-only**)
- Roles — `/ui/admin/rbac/roles` (**read-only**)
- Groups — `/ui/admin/rbac/groups`
- Scopes — `/ui/admin/rbac/scopes` (**read-only**; empty state when no bundles defined)
- Debug — `/ui/admin/rbac/debug` (enhanced)

### Pages

| Page | Key affordance |
|---|---|
| Permissions list | Name, display name, description, category. Usage count column ("used by N roles, N user extras"). Deep-link to `hearth.yaml` location. |
| Roles list/detail | YAML-defined. Read-only view of permissions, scope_kind. Groups currently assigned to this role shown as a helper panel. |
| Groups list/detail | Members tab + Roles tab. Typeahead user search. **CRUD** (groups and their memberships are runtime data). |
| Scopes list/detail | YAML-defined bundles. Side panel: "Roles that fully satisfy this bundle" + "Clients that declare this bundle." Empty state when no bundles defined. |
| Debug | Two tabs: **Resolver** (existing) + **Token preview** — inputs: user, client, requested scopes, org context; output: exact JSON token body after merge/resolution/mappers. Every role/permission/scope page deep-links into this tab prefilled. |

### Modified pages

- **User detail (`users/detail.html`)** — replace the single Admin checkbox with an Access card:
  - Roles: chip list with typeahead + remove-on-click (CRUD — runtime data)
  - Extra permissions: chip list with typeahead against the YAML registry (CRUD — runtime data)
  - Effective permissions: read-only flat list, updates live via HTMX as roles/extras change
  - Attributes: key/value editor for `User.attributes` (CRUD — runtime data)
  - "Preview claims" button → debug page prefilled
  - Connected applications list with Revoke button per row (admin-side revocation)
- **Org member row (`organizations/_member_row.html`)** — replace hardcoded Member/Admin/Owner dropdown with a role typeahead filtered to `scope_kind ∈ {Organization, Any}`. Seed the three hardcoded names as `scope_kind: organization` defaults in a `hearth-defaults.yaml` merged under user config, so existing org memberships keep working.
- **Application edit/detail** — read-only view of `trust_level` and `declared_scopes`. Effective permission union shown as a helper; scope picker is read-only (YAML-authored). The UI includes a "Copy YAML snippet" affordance for admins who want to extend the client in YAML.
- **Realm detail** — new "Claims" sub-page at `/ui/admin/realms/:id/claims`:
  - Read-only view of the realm's merged claim profile (defaults + YAML overrides)
  - Live "Example token" rendered against an admin-chosen sample user
  - Mapper list shown with source, target claim, access/id flags

### New account-settings surface (end-user self-service)

- **`/ui/account/applications`** — end-user-facing list of connected apps.
  - User can see display name, granted-at, granted scopes.
  - User can revoke a consent, which cascades: delete consent row + invalidate refresh tokens for that (user, client).
  - Requires only account-level auth; no admin privilege.
  - Emits `ClientConsentRevoked` audit event with `actor = user`.

## SDK Compatibility

The existing SDK surface remains correct under this design without code changes:

- **TypeScript** (`sdks/typescript/src/react.tsx:36-54`): `useHasPermission`, `useHasRole`, `useInGroup`, `useInOrg`
- **Go** (`sdks/go/hearth/client.go:137-166`): `HasPermission`, `HasRole`, `InGroup`, `InOrg`, `Permissions`

These methods read from the `permissions` / `roles` / `groups` claims, which retain their existing JSON shape under the new model (scope filtering and user extras merge server-side into the same flat arrays). Custom claims added by the realm's claim profile are orthogonal to the existing claim names and pass through the SDK's JWT decoder unchanged.

**New SDK methods (Phase 3):**
- TS: `hearth.revokeConsent(clientId: string): Promise<void>`
- Go: `client.RevokeConsent(ctx, clientID string) error`

These call `DELETE /v1/me/applications/{clientId}` for self-service revocation.

**Documentation updates** (in `sdks/*/README.md` and docstrings):
- Position `hasPermission` as the authorization primitive used in authz middleware/guard examples.
- Document `hasRole` as a legitimate tool for UI personalization and federation. No warning framing.

**Deferred to a later specification (not in scope here):** `hearth generate types` CLI for codegen of typed permission enums, `getClaims()` / `Claims()` helpers, and `createHearth({ debug: true })` mode.

## Engine Changes

- **File: `src/identity/engine.rs:2267-2309`** — `issue_tokens` becomes a thin wrapper around a new `issue_tokens_with_context` that takes a `TokenIssuanceContext { oid, client_id, requested_scopes, grant_type }`. The wrapper supplies an empty context so every existing caller is unchanged.
- **File: `src/rbac/registry.rs`** (new) — loads and validates the YAML registry; exposes `Arc<PermissionRegistry>` for hot-swap on SIGHUP via `ArcSwap`; provides `classify_scope_string(s: &str) -> ScopeKind` (the syntactic classifier); enforces Tier 1/2/3 claim-name rules; validates role permission references, scope bundle permission references, and claim profile tier enforcement.
- **File: `src/rbac/mod.rs`** — extend the `Rbac` trait:
  - `grant_user_permission` / `revoke_user_permission` / `list_user_permissions`
  - `resolve_effective(user_id, realm_id, oid, requested_scopes, client_id) -> ResolvedPermissions` — the one function that implements the resolution rule above.
  - Registry access methods (lookup/list) for admin UI read-only views.
- **File: `src/identity/tokens.rs:70-130`** — `TokenClaims` gains `#[serde(flatten)] custom: BTreeMap<String, serde_json::Value>`. Existing fields become `#[serde(skip_serializing_if = "...")]` so mappings with `Omit` source can suppress them without changing JSON shape for other tokens.
- **File: `src/identity/claims_config.rs`** (new) — `ClaimSource`, `ClaimMapping`, `ClaimProfile`, `DEFAULT_CLAIM_PROFILE`, `merge_mappings(defaults, overrides)`, mapper evaluation.

**Hot path unchanged.** `validate_token` reads `tid` / `sid` only, no new allocations, no new lookups. All of this is off-hot-path work at token issuance.

## Test Plan

Mapping to Hearth's eight layers (per `docs/specs/TESTING.md`):

1. **Unit** — type round-trips, naming grammar validator (boundary cases: single-word, mixed separators, whitespace, URL-reserved chars, hyphens, mixed case), tier enforcement (Tier 1 rejection, Tier 2 override, Tier 3 format), resolution math (union, atomic grant, empty cases, scope-match for realm/org), merge semantics for claim profile defaults.
2. **Integration** — storage CRUD for user extras, cascade behavior, user extras flowing through `resolve_effective`, scope filtering at each grant type (password, auth code, client credentials, refresh, device), YAML-reload swap via `ArcSwap`.
3. **Property** — `resolve_effective` idempotence, scope-match determinism, mapper output determinism, digest stability under permutation.
4. **Fuzz** — YAML deserialization, permission/scope name parser, claim profile JSON.
5. **Adversarial** — privilege escalation attempts (requesting undeclared scope, consenting to permission user lacks, Tier 1 claim override via mapper), scope-deletion-with-active-refresh-tokens, reserved-claim-name collision, name collision across namespaces.
6. **Simulation** — admin rewrites YAML while tokens are being issued (ArcSwap invalidation), scope definition deleted while refresh in flight, dangling-reference orphan skip.
7. **Conformance** — OAuth 2.0 RFC 6749 scope semantics (scope narrower on grant than request, refresh scope ⊆ original), OIDC Core scope claim shape, standard OIDC scope handling.
8. **Benchmarks** — `issue_tokens` with 40-permission user (target: same as baseline), `validate_token` (must be byte-identical perf since hot path is unchanged), registry lookup cached via `ArcSwap`.

## Critical Files

- `src/rbac/registry.rs` — **new** — YAML loader, `Arc<PermissionRegistry>`, `classify_scope_string`, validator.
- `src/rbac/types.rs` — `RoleScopeKind`, `UserPermissionGrant`, registry types (`PermissionDefinition`, `ScopeBundle`).
- `src/rbac/keys.rs` — add `rba:user_perm:*` storage keys; no `rba:permdef:*` or `rba:scope:*`.
- `src/rbac/mod.rs` — `resolve_effective`, user-extras trait methods, registry access.
- `src/rbac/engine.rs` — implementation.
- `src/identity/claims_config.rs` — **new** — `ClaimSource`, `ClaimMapping`, `DEFAULT_CLAIM_PROFILE`, merge logic.
- `src/identity/engine.rs:2267-2309` — `issue_tokens_with_context`, digest re-check on refresh.
- `src/identity/tokens.rs:70-130` — `TokenClaims` with `flatten custom` + optional fields.
- `src/identity/types.rs` — `User.attributes`, `OauthClient.trust_level` + `declared_scopes`.
- `src/protocol/web/admin.rs` — read-only handlers for permissions/roles/scopes, CRUD for user extras, groups, consent revocation.
- `src/protocol/web/account.rs` — **new** — user-facing account-settings handlers (connected applications).
- `templates/ui/admin/rbac/**` — read-only templates for YAML-managed entities; CRUD templates for groups and user extras.
- `templates/ui/admin/users/detail.html` — Access card replacement.
- `templates/ui/admin/realms/claims/view.html` — claim profile viewer.
- `templates/ui/admin/applications/{edit,detail}.html` — trust_level + declared_scopes (read-only).
- `templates/ui/account/applications.html` — **new** — user self-service connected-apps list.
- `templates/ui/_layout.html` — nav restructure (new RBAC section).
- `proto/hearth/rbac/v1/rbac.proto` — RPCs for user-extras CRUD and read-only lookups.
- `sdks/typescript/README.md`, `sdks/go/README.md` — documentation positioning of `hasPermission` vs `hasRole`; new `revokeConsent` method.

## Verification

End-to-end checks after each phase:

1. `cargo nextest run --workspace` — all tests pass, including new scenarios.
2. `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
3. `hearth config validate` on a sample YAML exercising all three namespaces catches: single-word permission names (with `system.*` suggestion), bundle containing `.` or permission containing `:`, Tier 1 claim name as mapper target, undeclared permission reference from a role.
4. Boot a realm that references a removed permission: startup logs orphan summary; resolver silently skips it; `OrphanedReferenceSkipped` audit event fires on first token issuance referencing the orphan.
5. Consent digest: grant consent to a bundled scope, edit the bundle's permission list in YAML, reload, confirm next refresh returns `invalid_grant consent_required`.
6. Self-service revocation: user revokes a client from `/ui/account/applications`, confirm refresh fails with `invalid_grant`, `ClientConsentRevoked` audit event fires with `actor = user`.
7. Manual admin UI walkthrough: define a permission + role + scope bundle in YAML, grant a user extra via admin UI, preview token in debug tab, confirm effective permissions match expectation.
8. SDK smoke test: compile TS and Go projects under `examples/rbac-smoke-test/` against a token from the new pipeline; confirm `hasPermission`, `hasRole`, and `revokeConsent` behave as expected.
9. Benchmark: `cargo bench --bench rbac_check` — `validate_token` p99 unchanged from baseline; `issue_tokens` p99 within 10% of baseline for a representative user.

---

## Resolved Decisions

All architectural forks have been settled. The decisions below are the final contract for this specification.

### Authoring model — YAML-only

Permissions, roles, scope bundles, and token claim profiles are authored in `hearth.yaml` only. This aligns with Hearth's existing pattern for realms, OAuth clients, and email configuration. The admin UI provides read-only discovery for these entities; runtime data (group memberships, user role assignments, user extras, OAuth consents) remains admin-UI-managed.

**Rationale:** Hearth is a self-hosted auth server. The team writing `hearth.yaml` is typically the same team writing the apps that integrate with it. Storage-backed CRUD for the permission vocabulary adds admin-UI complexity without a corresponding benefit over GitOps-style YAML review. Dangling references are handled lazily via `ArcSwap` swap and fail-closed resolution.

### Scope authoring — permission-as-scope default, bundles optional

Clients request scopes as either permission names (direct), OIDC standard scopes (closed set), or named bundles from the optional YAML `scopes:` block. Classification is syntactic (separator-based: `.` permission / `:` bundle / bare word OIDC). The spec's original `ScopeDefinition` becomes a purely optional bundling layer for consent UX.

**Rationale:** Most self-hosted deployments don't need the bundle layer. Making it opt-in removes ~40% of the admin-UI scope surface while preserving the capability for deployments that want coarse-grained consent bundling for third-party clients.

### Scope grant semantics — atomic, any-overlap

A scope is grantable if the user has ≥1 of its declared permissions (or if it's an OIDC standard scope). Grantable scopes are added to the token's `scope` claim; `permissions` is the intersection of user-effective with the union of grantable scope permissions. Empty `grantable` with non-empty `requested_scopes` → `invalid_scope`.

**Rationale:** Matches Auth0-with-RBAC semantics. Atomic grant at the scope level keeps consent UX coherent while still giving users exactly the permissions they have. Silent narrowing within a scope is explicitly avoided — partial overlap still yields full scope grant at label level but honors user's actual permission set in the `permissions` claim.

### Naming convention — separator-based disjoint namespaces

Permissions contain `.`, scope bundles contain `:`, OIDC standard scopes are bare words from a closed set. Enforced at config load by a syntactic validator. Single-word permissions are rejected; use the `system.*` namespace for legitimately global permissions.

**Rationale:** Syntactic classification eliminates name-collision bugs at the grammar level. Forces hierarchical resource-oriented naming (good RBAC hygiene). Reserves the bare-word namespace for protocol-defined scopes (preventing accidental shadowing of future OIDC scope additions).

### Claim profile — unified mapper model

All claim shaping is expressed as `ClaimMapping { claim, source }`. The `include_roles` / `include_groups` / `include_permissions` toggles from the original spec are collapsed into built-in `ClaimSource` variants (`RolesFromAssignments`, `GroupsFromMemberships`, `EffectivePermissions`, `OrgContext`). A default profile reproduces today's hardcoded emission. Realm YAML mappings merge over defaults by claim name, last-wins. An `Omit` source explicitly suppresses a default.

**Rationale:** Matches Keycloak/Auth0/Okta mental model (mappers are the only shaping mechanism). Collapses toggle-vs-mapper precedence questions. Keeps ergonomic parity for the common "disable one default claim" case.

### Claim name tiers

Three-tier classification enforced at config load: Tier 1 (forbidden — JWT/authz integrity), Tier 2 (overridable — informational and OIDC profile), Tier 3 (custom). Security-critical claims can never be targeted by a mapper; informational claims can be overridden; custom claims must match a conservative format.

**Rationale:** Allows flexible shaping while preventing privilege-escalation via `permissions` override or protocol-corruption via `exp`/`iss` override. Defense in depth: Tier 1 claims are written last by issuance code even if validation is bypassed.

### Role scoping — scope_kind per role

`Role` gains `scope_kind: RoleScopeKind { Realm, Organization, Any }`. Assignment-time validation refuses realm-kind roles at org scope and vice versa. `Any` accepts either. Admin UI typeahead filters by scope kind.

**Rationale:** Prevents semantic drift between "realm-level admin role" and "org-level member role." Matches how Hearth's existing org Member/Admin/Owner hardcoded tiers behave, now formalized. Seeds those three names as `scope_kind: organization` defaults for upgrade compatibility.

### User attributes

`User` gains `attributes: BTreeMap<String, String>` with validation (key `[a-z0-9_]{1,64}`, value ≤1 KiB, map total ≤16 KiB). Prerequisite for the `UserAttribute` claim mapper. Keycloak migration populates this from `UserRepresentation.attributes`.

**Rationale:** `UserAttribute` mapper variant cannot work without a flexible attribute store. `BTreeMap` chosen over `HashMap` for deterministic serialization (matters for Ed25519 deterministic signatures). Size caps prevent JWT / HTTP header bloat downstream.

### Client trust-level semantics

Unchanged from original spec.

| trust_level | Consent required | No-scope token shape | Scope request behavior |
|---|---|---|---|
| FirstParty | No | Full effective permissions | Narrows to scope ∩ effective; validates scope ∈ declared_scopes |
| ThirdParty | Yes (first time per scope set, digest-validated afterwards) | Rejected with `invalid_scope` | Narrows to scope ∩ effective; validates scope ∈ declared_scopes; consent ceremony if not cached |

### Consent invalidation — digest-based, lazy

Consent rows store `scope_digest = sha256(sort(unique(resolved_permissions)))`. On every `/authorize` or `/token refresh_token`, re-resolve and re-hash live; mismatch triggers re-consent. No eager sweep on YAML reload.

**Rationale:** SSH `known_hosts` pattern — trust was granted to a specific artifact, not a name. Self-healing, precise, no operational friction on YAML edits.

### User extras storage — first-class relation

Dedicated `rba:user_perm:{realm}:{user}:{perm}` storage, separate trait methods (`grant_user_permission`, `revoke_user_permission`, `list_user_permissions`), distinct UI affordance. Reuses existing `Scope { Realm | Org(id) }` enum. Matched against token context with the same rule as role assignments.

### User extras scope matching

| Grant scope | Token without oid | Token with oid=X | Token with oid=Y |
|---|---|---|---|
| `Realm` | applies | applies | applies |
| `Org(X)` | does not apply | applies | does not apply |

### Consent revocation — admin + self-service

Phase 3 ships both surfaces:
- Admin UI at `/ui/admin/users/{id}/applications`
- End-user UI at `/ui/account/applications`
- SDK methods: `hearth.revokeConsent(clientId)` (TS), `client.RevokeConsent(ctx, clientID)` (Go)
- Cascades: delete consent row + invalidate refresh tokens tied to `(user, client)`.

**Rationale:** End-user revocation is table-stakes for an auth product exposed to third-party apps. Deferring creates a user-trust gap. Shipping alongside admin surface amortizes implementation cost.

### SDK primitives

Ship `hasPermission` and `hasRole` as equal-citizen methods. Documentation leads with `hasPermission` for authz examples; `hasRole` is documented as a legitimate tool for UI personalization and federation without warning framing. No `can()` alias.

---

## Delivery Phasing

This specification commits to three phases. SDK DX improvements (codegen CLI, `getClaims()`/`Claims()` helpers, debug mode) are deferred to a follow-up specification.

### Phase 1 — Permissions registry + user extras (foundational)

Scope:
- New types: `RoleScopeKind`, `UserPermissionGrant`, `PermissionDefinition`, `ScopeBundle` (all in `src/rbac/types.rs` or `src/rbac/registry.rs`)
- User attributes: `BTreeMap<String, String>` field on `User` with validation
- YAML registry: new `src/rbac/registry.rs` with `ArcSwap<PermissionRegistry>`, `classify_scope_string`, grammar validator
- Storage keys: `rba:user_perm:*`, `rba:user_perm:by_perm:*`
- Trait methods: user-permission grant/revoke/list
- `resolve_effective` updated to union user extras and honor `scope_kind` / scope-match rule
- Admin UI: `/ui/admin/rbac/permissions` (read-only list), `/ui/admin/rbac/roles` (read-only), user detail page's Access card redesign (Roles + Extra permissions + Effective + Attributes), org member row upgrade to scope_kind-filtered typeahead
- Nav: new "RBAC" section in sidebar
- CLI: `hearth config validate`, `hearth rbac orphans list` / `purge`
- Audit events: `UserPermissionGranted/Revoked`
- Proto: new RPCs in `rbac.proto` for user extras
- Tests across all 8 layers per test plan section

Ships independently. Ends in a state where admins can define permissions and roles in YAML, grant direct user permissions without creating bespoke roles, and see effective permissions in the UI.

### Phase 2 — Configurable token claims

Scope:
- New file: `src/identity/claims_config.rs` with `ClaimProfile`, `ClaimMapping`, `ClaimSource`, `DEFAULT_CLAIM_PROFILE`, merge logic
- YAML schema: `realms.<id>.claims.mappings:` block; defaults apply if absent
- `TokenClaims` gains `#[serde(flatten)] custom: BTreeMap<String, Value>` and `skip_serializing_if` on existing claim fields
- `issue_tokens_with_context` implementation; existing `issue_tokens` becomes thin wrapper
- Tier 1/2/3 claim name validation at config load
- Admin UI: `/ui/admin/realms/:id/claims` read-only viewer; live token preview pane against a chosen sample user
- Debug page enhancement: new "Token preview" tab
- Audit events: none new (YAML reload is not an audit-worthy runtime event)

Depends on Phase 1 (mappers can reference registered permissions via `RoleSubset` and `EffectivePermissions` sources). Ends in a state where realm admins can shape token output declaratively.

### Phase 3 — OAuth scopes + client trust_level + consent

Scope:
- `ClientTrustLevel` enum; `OauthClient` gains `trust_level` and `declared_scopes`
- Optional `scopes:` YAML block for bundles
- Storage keys: `oauth:consent:*`
- `resolve_effective` gains the grantable-subset filter
- `/authorize` validation: requested scopes ⊆ `declared_scopes`; classify via separator rule; reject with `invalid_scope` on failure
- Consent ceremony for `ThirdParty` clients, rendered from `ScopeBundle` / `PermissionDefinition` / OIDC-standard display strings; digest cached per (user, client, scope-set)
- Digest re-check on refresh; `invalid_grant consent_required` on mismatch
- `FirstParty` empty-scope → full effective; `ThirdParty` empty-scope → `invalid_scope`
- Admin UI: `/ui/admin/rbac/scopes` list/detail (read-only with empty state), updated Applications pages with trust level + declared scopes (read-only)
- Admin UI: `/ui/admin/users/{id}/applications` — connected apps + revoke
- End-user UI: `/ui/account/applications` — self-service revoke
- SDK methods: `revokeConsent` in TS and Go
- Audit events: `ClientConsentGranted/Revoked`, `ConsentRequiredOnRefresh`
- Proto: no new CRUD RPCs for scopes (YAML-only); consent-revocation RPC

Depends on Phase 1 (scopes reference registered permissions) and Phase 2 (claim-profile toggles interact with scope filtering). Ends in a state where Hearth can serve as a full OAuth authorization server with consent-based third-party integrations and end-user consent management.
