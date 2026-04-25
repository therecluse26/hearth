# Authz Expansion: Custom Permissions, Scopes, and Configurable Claims

**Status:** Partially implemented — Phase 1 foundational types and storage complete; claim-profile structs skeletal; Phase 3 OAuth fields wired. See per-phase checkboxes in §Delivery Phasing and §Critical Files.

## Context

Hearth's claims-based RBAC works end-to-end, but the administrative and developer surface around it is minimal. Today:

- `Permission` is a free-form `String` newtype (`src/rbac/types.rs:88`). No registry exists — admins can grant any string but cannot discover, document, or govern the permission vocabulary.
- Token claims (`roles`, `groups`, `permissions`) are hardcoded to always ship at `src/identity/engine.rs:2267-2309`. There is no way for a realm admin to configure what a token looks like — which claims emit, with what shape, or with what custom attributes.
- OAuth scopes exist as a pass-through string on the token but are not a first-class concept. Third-party OAuth flows cannot express "this client is allowed to request these capabilities" — every client effectively has full-trust access to the user's permission set.
- There is no UI for managing roles, permissions, groups, scopes, or user-level grants beyond the read-only `/ui/admin/rbac/debug` resolver. Org roles are hardcoded to three tiers (Member/Admin/Owner).
- There is no concept of user-level direct permission grants ("extras"). To give one user one extra capability, admins must invent a bespoke role.
- The SDKs (`sdks/typescript`, `sdks/go`) treat permission as free-form `string`.

The goal of this work is to turn authz from a code-and-config construct into a discoverable, governed, first-class admin surface — without sacrificing Hearth's performance (zero-alloc hot path), security (declarative mappers only, no scripting), or operational simplicity (one conceptual rule, no knobs with ambiguous semantics).

**Authoring model.** Permissions, roles, scope bundles, claim profiles, and protected-resource registrations are authored in `hearth.yaml` only. This matches Hearth's existing YAML-first pattern for realms and email configuration. The admin UI provides read-only browsing and discovery for YAML-defined entities, plus CRUD for runtime data (user role assignments, user extras, OAuth consents, group memberships).

**Two-track OAuth client model.** Clients are NOT exclusively YAML-defined. Hearth supports two coexisting tracks:

- **Managed clients** — authored in `hearth.yaml` under `realms.<id>.oauth_clients`. Long-lived, configured by operators. Their `slug` is admin-supplied and stable across renames; the persisted record retains a UUID `ClientId` for runtime references.
- **Runtime-registered clients** — created via RFC 7591 Dynamic Client Registration at `POST /register` (per [AGENT_AUTH.md](./AGENT_AUTH.md) §2.7). Used by agents auto-registering against a Hearth instance and by ephemeral integrations. Storage-backed (`oauth:client:{realm}:{client_id}`); their `slug` is auto-generated from the client name plus a uniqueness suffix. NOT subject to YAML reload; modified via RFC 7592 `PUT /register/{client_id}`.

Both tracks produce records of the same `OauthClient` shape, and both participate in scope resolution and consent storage identically. They differ in **who is responsible for the client's identity**: managed-client slugs are admin-authored and stable; DCR slugs are auto-generated and treated as opaque.

**Policy references (`allowed_clients` mapper gates) accept managed-client slugs only.** Auto-generated DCR slugs are not a stable admin-authored reference and therefore not a sound input to a mapper allowlist. Config load rejects an `allowed_clients` entry whose slug resolves to a DCR-registered client. The slug↔`ClientId` index is materialized for both tracks (managed clients at registry load, DCR clients at registration time / on storage scan), but the index records each entry's track so the validator can enforce this asymmetry. To gate a claim on a runtime-registered client, an admin must first promote it to a managed client (by editing it into YAML, after which the slug is admin-authored and stable). A future spec MAY add `allowed_client_ids` for stable runtime references; this is deferred until a concrete use case appears.

Realm policy (configured separately) governs whether DCR is enabled, what trust level DCR-created clients receive (typically `ThirdParty`), and whether admins can promote a DCR client to a managed client by editing it into YAML.

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

**This is a Hearth-specific convention, not industry standard.** RFC 6749 §3.3 treats scope values as opaque tokens; OIDC Core allows arbitrary custom scope strings; Auth0/Keycloak/Ory accept any non-whitespace string. Hearth chooses syntactic classification to make name collisions impossible by construction and to allow constant-time parser dispatch — the trade-off is that integrators familiar with bare-word custom scopes (`read_user`, `manage_billing`) must learn Hearth's grammar. Realms that want the conventional opaque-string model can express any scope as a bundle (`:`-separated) trivially; the constraint is only on the bare-word namespace.

Permissions, scope bundles, and OIDC standard scopes occupy three disjoint namespaces distinguished by their separator. Classification is syntactic — a parser can identify what kind of string it has in constant time without consulting any registry.

- **Permission:** `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$` — MUST contain ≥1 dot, MUST NOT contain `:`. Minimum two non-empty segments. ≤128 chars.
- **Scope bundle:** `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$` — MUST contain ≥1 colon, MUST NOT contain `.`. Minimum two non-empty segments. ≤128 chars.
- **OIDC standard scope:** bare word from the closed set `{ openid, profile, email, address, phone, offline_access }`. No other bare-word names are permitted.

Single-word permission names like `admin` or `editor` are rejected at config load. Globally-scoped permissions use the conventional `system.*` namespace (`system.admin`, `system.readonly`). This forces resource-oriented naming and reserves the bare-word namespace for IETF-defined protocol scopes.

Hierarchical nesting is supported at arbitrary depth (`user.self.write` vs `user.write`, `docs.versions.read`) as a naming convention. There is **no implicit inheritance** — `docs.read` does not imply `docs.versions.read`. Each segmented name is an independent atomic permission. Admins group related permissions via roles or scope bundles.

### Resolution rule

Applied at every token issuance regardless of grant type:

```
# 1. User's full effective permission set, resolved transitively through role parents
#    and filtered by assignment scope matching the token context.
effective =
    ∪ transitive_permissions(role) for role in user.role_assignments
        WHERE assignment.scope matches token context
  ∪ extra.permission               for extra in user.permission_grants
        WHERE extra.scope matches token context

  where transitive_permissions(r) =
    r.permissions ∪ ∪(transitive_permissions(p) for p in r.parents)
    (cycle-detected, depth-bounded per AUTHORIZATION.md §2.6)

# 2. Scope grant (atomic, full-satisfiability; trust-level-aware partial-grant policy).
if requested_scopes non-empty:
    ungrantable_non_oidc = { s ∈ requested_scopes
                              : NOT (s is OIDC-standard)
                             AND NOT (scope_perms(s) ⊆ effective) }

    if client.trust_level == ThirdParty AND ungrantable_non_oidc is non-empty:
        error(invalid_scope)                                  # ← fail-closed for third-party

    grantable = { s ∈ requested_scopes
                    : s is OIDC-standard
                   OR scope_perms(s) ⊆ effective }            # full-subset
    if grantable is empty: error(invalid_scope)               # both trust levels

    effective_for_token = effective ∩ ∪ scope_perms(s) for s in grantable
    token.scope         = grantable (space-delimited, RFC 6749)
    # FirstParty may carry token.scope strictly smaller than requested_scopes (silent partial grant).
    # ThirdParty cannot — the early-exit above ensures grantable ⊇ non-oidc(requested_scopes).

else:
    if client.trust_level == ThirdParty: error(invalid_scope)
    effective_for_token = effective
    token.scope         = ""

token.permissions = effective_for_token
token.roles       = user.roles (names only, informational)
token.groups      = user.groups (names only, informational)
token.oid         = current organization context, if any (authoritative for tenant routing)
token.<custom>    = output of each claim mapper in the realm profile (Tier 2 / Tier 3 only)
```

**Scope resolution for each requested string `s`, given the issuance `resource: Option<Uri>`:**

1. If `s` is a bare word → must be an OIDC standard scope; apply its claim-shape / refresh-token effect; contributes no permissions to the grant check (always grantable at scope level if the client declared it). OIDC scopes are protocol-level and resource-independent — they are legal under any `resource`.
2. If `s` contains `.` → permission; **only legal when `resource = None`** (i.e., the token is bound to Hearth itself as audience). Treated as a synthetic single-permission scope, `scope_perms(s) = [s]`. A single permission is trivially fully-satisfied iff the user has it. **ThirdParty clients MUST NOT declare raw permission scopes** (config-load rejects); they exist only for first-party convenience. Third-party clients use bundles, which carry curated `display_name`/`description` for the consent screen instead of leaking internal RBAC vocabulary. When `resource = Some(uri)` and `s` is a `.`-permission → `invalid_scope` (raw permissions are realm-internal vocabulary; protected resources expose curated bundles).
3. If `s` contains `:` → scope bundle. Lookup is **audience-scoped**:
   - If `resource = None` → look up `s` in the realm's top-level `scopes:` registry only; `scope_perms(s) = bundle.permissions`. The protected-resource scope namespaces are NOT consulted.
   - If `resource = Some(uri)` → look up `s` in `protected_resources[uri].scopes` only; `scope_perms(s) = bundle.permissions`. The realm-level `scopes:` registry is NOT consulted, even if the same name exists there. A miss here is `invalid_scope`, never a fallback to realm bundles.
4. If `s` is not present in the registry selected by step 1–3, or if `s` is not in `client.declared_scopes` → `invalid_scope`.

**Audience precedence (normative).** When `resource` is present at issuance, the legal scope set for that token is exactly `OIDC_standard_scopes ∪ protected_resources[resource].scopes`. Realm-level bundles and raw `.`-permissions are not consulted under any condition. This keeps each protected resource's vocabulary self-contained and makes name overlap between a realm bundle and a resource bundle deterministic — they cannot be confused because they are looked up under different audiences.

**Legal requested scopes by context (quick reference).** Cross-product of the trust-level / resource / track dimensions:

| Context | OIDC standard (`openid`, `email`, …) | Raw `.`-permission | Realm `:`-bundle | Resource `:`-bundle |
|---|:-:|:-:|:-:|:-:|
| FirstParty client, `resource = None`                    | ✅ | ✅ (must be in `declared_scopes`) | ✅ (must be in `declared_scopes`) | ❌ |
| ThirdParty client, `resource = None`                    | ✅ | ❌ (config-load rejects in `declared_scopes`) | ✅ (must be in `declared_scopes`) | ❌ |
| Any client, `resource = Some(uri)`                      | ✅ | ❌ (always `invalid_scope` under a resource) | ❌ (not consulted under a resource) | ✅ (must be in both `declared_scopes` and `protected_resources[uri].scopes`) |
| DCR-registered client (any resource setting)            | per row above | per row above | per row above | per row above |

DCR-registered clients are not a separate row because their scope-grant rules are identical to managed clients of the same trust level. The only difference (Block D above) is that DCR slugs cannot appear in `allowed_clients` mapper gates.

**Partial-grant policy.**
- **FirstParty clients:** silent partial grant is allowed — `grantable` may be a strict subset of `requested_scopes` and the token issues with whatever was satisfiable. RFC 6749 §3.3 explicitly permits this and first-party clients are typically authored alongside the realm config, so the partial-grant signal can be surfaced via the response's `scope` parameter without confusion.
- **ThirdParty clients:** **fail-closed** — if any non-OIDC requested scope is ungrantable, the entire request fails with `invalid_scope`. This avoids the "authorized but not really" UX trap where a third-party app silently receives a narrower set than it asked for. OIDC standard scopes are exempt from the fail-closed rule (they have well-defined fallback semantics per OIDC Core).

**Full-satisfiability rationale.** A bundle `read:docs = [docs.read, docs.list, docs.share]` is grantable only if the user has **all three** permissions. Partial-satisfaction would cause the `scope` claim to say "read:docs granted" while `permissions` carries only a subset — an API gateway reading `scope` would see full bundle approval when the user has only 1 of 3 capabilities. Full-satisfiability preserves the invariant that `scope` and `permissions` never disagree. Bundles should be defined as coherent capability sets that roles naturally align with; misalignment surfaces as the bundle simply not being granted (user falls back to direct permission scopes).

**Scope-match rule for role assignments and user extras:**
- `Scope::Realm` matches any token context (always applies).
- `Scope::Org(X)` matches iff `token.oid == Some(X)` (only when the user is acting in the context of organization X).

**Consent requirements** remain per the spec's resolved `ClientTrustLevel` matrix:
- `FirstParty` — no consent required; empty `requested_scopes` yields full effective permissions.
- `ThirdParty` — consent required (first time per scope set, digest-validated afterwards); empty `requested_scopes` is `invalid_scope`.

### Field semantics (documented contract)

- `permissions` — authoritative for fine-grained authorization. Hearth SDKs check this. Always the flat effective set, server-resolved, post-intersection.
- `scope` — OAuth consent boundary per RFC 6749. RFC-compliant API gateways read this.
- `oid` — authoritative for **tenant routing and data partitioning**. Never overridable by a custom mapper (Tier 1). Downstream apps trust that `oid` reflects the current organization context exactly as Hearth resolved it.
- `roles` / `groups` — informational by default. For UI personalization, federation, admin debugging. Overridable by mapper (Tier 2) — see SDK caveat below. Never the authoritative check at an authz boundary.
- Custom claims — flattened into the top-level JWT payload, defined declaratively in the realm's claim profile.

**SDK helper caveat.** The stock SDK helpers `hasRole(name)`, `useHasRole()`, `InGroup(name)`, etc. read `roles` / `groups` claims directly. These helpers are **only guaranteed correct under the default claim profile or profiles that keep `roles` / `groups` as their respective `RolesFromAssignments` / `GroupsFromMemberships` built-in sources.** Realms that override these claims (e.g., via `RoleSubset` or a custom mapper) should document that SDK helpers operate on the overridden shape — which is often the desired behavior (e.g., "only show federation-prefixed roles to the client") but is the operator's responsibility to confirm.

### Consequences

- `permissions` and `scope` never disagree. Downstream code doesn't need to intersect them — the server already did. One source of truth per scenario (fine-grained → `permissions`, OAuth gateway → `scope`).
- User extras flow through the same code path as role grants. The SDK sees one flat permissions array regardless of grant source. The admin UI surfaces the distinction; the runtime does not.
- Scope is a pure filter. It can narrow but never widen. A client cannot request more than the user has, and cannot request a scope it didn't declare at registration.
- No expression language, no scripting, no dispatcher. Every mapping from server state to token claim is a data-driven declarative rule, writable in YAML, reviewable in a diff.

### Worked example: token bound to a protected resource

This example walks the full pipeline for a token bound to an MCP tool server, exercising audience-scoped scope lookup, resource-keyed consent, and the disclosure-surface digest.

**Setup.** A realm `production` declares:

```yaml
realms:
  production:
    permissions:
      - { name: mcp.tools.invoke,    display_name: "Invoke MCP tools",    category: MCP }
      - { name: mcp.resources.read,  display_name: "Read MCP resources",  category: MCP }
    roles:
      - { name: mcp_user, scope_kind: realm, permissions: [mcp.tools.invoke, mcp.resources.read] }
    scopes:
      - { name: read:docs, permissions: [docs.read], display_name: "Read your documents" }
    protected_resources:
      - resource_uri: "https://mcp.acme.com"
        display_name: "Acme MCP tool server"
        scopes:
          - { name: mcp:tools:invoke,    permissions: [mcp.tools.invoke],   display_name: "Invoke tools on Acme MCP" }
          - { name: mcp:resources:read,  permissions: [mcp.resources.read], display_name: "Read MCP resources" }
    oauth_clients:
      - slug: agent-client
        trust_level: third_party
        declared_scopes: [mcp:tools:invoke, mcp:resources:read, openid, offline_access]
```

User `alice` has the `mcp_user` role at realm scope. Acting in no organization context (`oid = None`), her agent makes:

```
POST /authorize?
  client_id=...&
  resource=https://mcp.acme.com&
  scope=openid mcp:tools:invoke&
  ...
```

**Resolution walk-through.**

1. **Scope dispatch (per "Scope resolution" §):** `resource = Some("https://mcp.acme.com")`.
   - `openid` → bare-word OIDC scope, resource-independent. Grantable.
   - `mcp:tools:invoke` → contains `:`, `resource` is `Some(...)` → look up in `protected_resources["https://mcp.acme.com"].scopes` only. Found. `scope_perms = [mcp.tools.invoke]`.
   - The realm-level `scopes:` block (`read:docs`) is **not consulted** even though it shares the `:`-bundle namespace.
2. **Effective set:** `alice.effective = {mcp.tools.invoke, mcp.resources.read}` (from `mcp_user` role, realm-scoped, matches `oid = None`).
3. **Grantability:** `mcp.tools.invoke ⊆ effective` → `mcp:tools:invoke` fully satisfied. ThirdParty fail-closed check passes (no ungrantable non-OIDC scopes). `grantable = {openid, mcp:tools:invoke}`.
4. **Consent key:** `org_key = "_realm"`, `resource_key = sha256("https://mcp.acme.com")[..16]`. The consent storage key is `oauth:consent:{realm}:{alice}:{agent-client}:_realm:<resource_key>`. A pre-existing consent under the same client but `resource_key = "_default"` (Hearth itself as audience) does NOT match — distinct rows. First call triggers consent ceremony.
5. **Disclosure surface:** the realm's claim profile is evaluated against `(client = agent-client, granted_scopes = {openid, mcp:tools:invoke}, resource = Some(...))`. Default mapper for `permissions` has `first_party_only: true`, so it does NOT emit (agent-client is third-party). `roles` and `groups` likewise gated out. The ID token carries only OIDC standard claims under `openid` (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`).
6. **Digest:** `scope_digest = sha256("https://mcp.acme.com" || sort({mcp.tools.invoke}) || sort({}))` — empty disclosure tuple set because the third-party gates suppress all Hearth-proprietary claims; only OIDC-standard claims emit. Digest stored on the consent row.
7. **Token issuance:**
   - `aud = "https://mcp.acme.com"` (per RFC 8707; resource indicator becomes audience).
   - `scope = "openid mcp:tools:invoke"`.
   - `permissions` claim: omitted (third-party gate fails).
   - `azp = agent-client_id` (authorized party).

**Refresh case.** A subsequent refresh for the same `(user, client, resource)` re-runs steps 1–6 against the current registry. If the operator later edits `protected_resources["https://mcp.acme.com"].scopes` to redefine `mcp:tools:invoke = [mcp.tools.invoke, mcp.tools.list]`, the digest changes (step 6) and refresh returns `invalid_grant consent_required` — the agent re-consents to the broadened bundle. If the operator simply removes alice's `mcp_user` role, the digest still matches (same scope/bundle definitions) and refresh succeeds with a narrower effective set; downstream MCP server returns 403 the next time the agent calls a removed tool.

## Data Model

### YAML schema additions

All authz YAML lives **under each realm**. Cross-realm bleed is impossible by construction — different realms own independent permission, role, scope-bundle, claim-profile, and OAuth-client vocabularies. This matches the existing per-realm scoping in [`AUTHORIZATION.md`](./AUTHORIZATION.md) §2.1.

```yaml
# hearth.yaml

realms:
  production:
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
      - name: viewer
        scope_kind: realm
        permissions: [docs.read]
      - name: editor
        scope_kind: realm              # realm | organization | any
        description: Create and edit documents
        permissions: [docs.write]
        parents: [viewer]              # inherits docs.read transitively
      - name: org_owner
        scope_kind: organization
        permissions: [org.members.write, org.settings.write, org.billing.read]
      - name: auditor
        scope_kind: any
        permissions: [audit.read]

    scopes:                            # OPTIONAL — realm-level consent bundles
      - name: read:docs
        permissions: [docs.read, docs.list, docs.share]
        display_name: Read your documents
        description: View documents you own or have been shared with you.

    # Protected resources (per AGENT_AUTH.md §2.5) own their own scope namespaces.
    # MCP tool servers and other RFC 8707 protected resources register here; their
    # scopes are NOT realm-global — they apply only when a token is being issued
    # with `aud` set to this resource's URI. A realm-level scope and a resource-level
    # scope MAY share a name; they are distinct because they are looked up under
    # different audiences.
    #
    # Precedence rule (normative): when a token request includes
    # `resource = Some(uri)`, ONLY OIDC standard scopes plus the scopes declared
    # under that resource's `scopes:` block are legal. The realm-level top-level
    # `scopes:` block is NOT consulted — neither as a primary source nor as a
    # fallback. Raw `.`-permission scopes are also illegal under a resource.
    # See "Scope resolution" above for the full dispatch rule.
    protected_resources:
      - resource_uri: "https://mcp.acme.com"
        display_name: "Acme MCP tool server"
        scopes:
          - name: mcp:tools:invoke
            permissions: [mcp.tools.invoke]    # realm-level permissions backing the resource scope
            display_name: "Invoke tools on Acme MCP"
            description: "Allows the agent to execute tools on the Acme MCP server."
          - name: mcp:resources:read
            permissions: [mcp.resources.read]
            display_name: "Read MCP resources"

    oauth_clients:
      - slug: first-party-app          # YAML reference (human-readable). Persisted record retains UUID ClientId.
        trust_level: first_party
        declared_scopes: [docs.read, docs.write, profile, email, openid]    # permissions + OIDC directly
      - slug: third-party-partner
        trust_level: third_party
        declared_scopes: [read:docs, offline_access, openid]                # bundle + OIDC (third-party MUST use bundles, not raw permissions)

    claims:                            # OPTIONAL — omit for default shape
      mappings:
        - { claim: groups,     source: omit }                           # drop native groups
        - { claim: roles,      source: role_subset, prefix: "realm." }  # override roles shape
        - { claim: department, source: user_attribute, attribute: dept }

  staging:
    permissions: [...]                 # entirely independent vocabulary
    roles: [...]
```

**Client references in YAML.** OAuth clients are persisted by UUID `ClientId` per the existing identity model. To make YAML readable and `allowed_clients` mapper gates ergonomic, every `oauth_clients` entry MUST include a `slug` (unique within the realm). The registry materializes a slug↔ClientId index at load time. `allowed_clients` mapper gates accept slugs; the engine resolves them to ClientIds before evaluation. This adds a one-line schema change to the existing `OauthClient` record (`slug: String`).

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

/// Existing `Role` gains `scope_kind` (see RoleScopeKind). `parents` is
/// retained from the AUTHORIZATION.md base model — role composition via
/// parent chains is cycle-detected and depth-bounded per §2.6 of that doc.
pub struct Role {
    pub id: RoleId,
    pub realm_id: RealmId,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<Permission>,
    pub parents: Vec<String>,        // parent role names (transitive, capped at 10 hops)
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

/// Existing organization membership row (`src/identity/types.rs`) gains an
/// `additional_roles` field. The canonical tier remains `OrganizationRole`
/// (Member|Admin|Owner) for shipped-API compatibility; `additional_roles` is
/// the layered RBAC extension introduced by this spec.
pub struct OrganizationMembership {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub role: OrganizationRole,                  // existing — canonical tier (maps to seeded RBAC role)
    pub additional_roles: Vec<RoleName>,         // NEW — extra org-scoped RBAC roles layered on
    pub joined_at: Timestamp,
    // ... other existing fields ...
}

// Additional-role constraints (validated at API call time, not config load):
//   - each name in additional_roles must resolve to a Role in the realm registry
//   - each resolved Role must have scope_kind ∈ {Organization, Any}
//   - additional_roles cannot include the names of the seeded canonical bridge roles
//     (org_member / org_admin / org_owner); the canonical tier owns those exclusively
//   - duplicates are rejected at the API surface
//   - cap: ≤ 32 additional_roles per membership (operational guardrail; bumpable)
//
// Storage: additional_roles travels inline with the membership record — no new
// storage key. Existing org-membership read/write paths in src/identity/engine.rs
// (memory: orgm:user:{uid}:org:{oid} + reverse index) carry the new field.

/// API surface additions (in the Rbac trait):
//   - add_additional_role(org_id, user_id, role_name) -> Result<(), RbacError>
//   - remove_additional_role(org_id, user_id, role_name) -> Result<(), RbacError>
//   - list_additional_roles(org_id, user_id) -> Vec<RoleName>
//
// gRPC additions in proto/hearth/rbac/v1/rbac.proto: AddOrgMemberRole,
// RemoveOrgMemberRole, ListOrgMemberAdditionalRoles RPCs.

// Audit events (new):
//   - OrgMemberAdditionalRoleAdded   { actor, org_id, user_id, role_name }
//   - OrgMemberAdditionalRoleRemoved { actor, org_id, user_id, role_name }

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
    pub claim: String,                             // target JWT claim name
    pub source: ClaimSource,
    pub include_in_access_token: bool,
    pub include_in_id_token: bool,
    pub include_in_userinfo: bool,                 // UserInfo endpoint emits the mapper output too

    // --- Release gates (all AND-combined; all must pass for the claim to emit) ---
    pub first_party_only: bool,                    // emit only when client.trust_level == FirstParty
    pub required_scopes: Option<Vec<String>>,      // if Some, the final GRANTED scope set must include ≥1 of these (post-resolution, not raw request)
    pub allowed_clients: Option<Vec<String>>,      // if Some, client.slug must be in this list. Each slug MUST resolve to a managed (YAML-authored) client at registry-load time; DCR-registered slugs are rejected by the validator. Resolved to ClientId via the slug↔ClientId index; comparison at evaluation time uses ClientId.
}

#[serde(tag = "source", rename_all = "snake_case")]
pub enum ClaimSource {
    // Built-in sources (default profile uses these)
    RolesFromAssignments,
    GroupsFromMemberships,
    EffectivePermissions,
    OrgContext,

    // Canonical user state — closed enum of OIDC-defined and Hearth-canonical
    // user fields. Reads `User` struct fields directly; format-validated at
    // config load (e.g., `Locale` requires the mapped claim to match BCP 47).
    CanonicalUserField { field: CanonicalUserField },

    // Free-form attribute-map lookup. Reads `User.attributes[attribute]` only;
    // never falls back to canonical fields. Returns no value if the key is
    // missing (the claim is omitted from output, not emitted as null).
    UserAttribute { attribute: String },

    // Other custom sources
    RoleSubset { prefix: String },
    Constant { value: serde_json::Value },

    // Suppression sentinel — emit nothing at this claim name
    Omit,
}

/// Canonical user state fields that mappers can read. Closed set; matches the
/// OIDC Core §5.1 standard claim names (plus Hearth's `display_name`). Realms
/// CANNOT extend this enum from YAML — to expose additional structured user
/// state, use `User.attributes` and the `UserAttribute { attribute }` variant.
#[serde(rename_all = "snake_case")]
pub enum CanonicalUserField {
    Email,
    DisplayName,
    FirstName,           // → `given_name` in OIDC
    LastName,            // → `family_name` in OIDC
    PreferredUsername,
    Nickname,
    Picture,
    Website,
    Gender,
    Birthdate,
    Locale,
    Zoneinfo,
    PhoneNumber,
    Address,
    UpdatedAt,
}
```

### Default claim profile

Realms with no `claims:` block use the built-in default profile below. For first-party clients it emits tokens identically to today's hardcoded shape (`roles`, `groups`, `permissions`, plus `oid` from core issuance). For third-party clients the default is tighter: `roles`, `groups`, AND `permissions` are all withheld by default (`first_party_only: true`), and none of these Hearth-proprietary claims appears in `/userinfo` for any client. Admins who want to release any of them to third-party clients override the default with explicit release gates (see "Evaluation and merge model" below) — the `permissions` override should typically pair with `allowed_clients` or `required_scopes` to keep the surface narrow, since `permissions` exposes internal RBAC vocabulary.

```rust
// Note: oid is emitted by core issuance as a Tier 1 claim and is NOT a mapping
// (not overridable). Included here as a reminder of what tokens carry by default.
//
// Defaults tighten for third-party clients: roles, groups, AND permissions are
// first_party_only=true by default. First-party clients (the only kind that existed
// before this spec) are unaffected; new third-party clients must be explicitly opted
// in to receive these Hearth-proprietary claims. permissions is gated for the same
// reason as the prohibition on raw-permission scopes for ThirdParty clients (see
// "Scope resolution" §): internal RBAC vocabulary should not leak via either the
// scope channel OR the permissions claim by default. Realms whose third-party
// clients legitimately need a fine-grained permissions claim override this mapping
// in YAML with first_party_only: false (and should pair with allowed_clients or
// required_scopes).
pub const DEFAULT_CLAIM_PROFILE: &[ClaimMapping] = &[
    ClaimMapping {
        claim: "roles", source: RolesFromAssignments,
        access: true, id: true, userinfo: false,
        first_party_only: true, required_scopes: None, allowed_clients: None,
    },
    ClaimMapping {
        claim: "groups", source: GroupsFromMemberships,
        access: true, id: true, userinfo: false,
        first_party_only: true, required_scopes: None, allowed_clients: None,
    },
    ClaimMapping {
        claim: "permissions", source: EffectivePermissions,
        access: true, id: false, userinfo: false,
        // first_party_only mirrors the prohibition on raw-permission scopes for ThirdParty clients
        // declared in §"Scope resolution". Internal RBAC vocabulary should not leak to third-party
        // clients via either the scope channel OR the permissions claim by default. Admins who
        // need third-party clients to receive the permissions claim override this mapping in YAML
        // with first_party_only: false (and should pair with allowed_clients or required_scopes).
        first_party_only: true, required_scopes: None, allowed_clients: None,
    },

    // OIDC profile / contact claims — default scope-gated emission from canonical user state
    // via the `CanonicalUserField` source (NOT `UserAttribute`, which is map-only).
    // These don't conflict with Tier 1 verification claims (email_verified / phone_number_verified),
    // which are emitted by core issuance, not by mapper.
    ClaimMapping {
        claim: "email", source: CanonicalUserField { field: Email },
        access: false, id: true, userinfo: true,
        first_party_only: false, required_scopes: Some(vec!["email"]), allowed_clients: None,
    },
    ClaimMapping {
        claim: "name", source: CanonicalUserField { field: DisplayName },
        access: false, id: true, userinfo: true,
        first_party_only: false, required_scopes: Some(vec!["profile"]), allowed_clients: None,
    },
    ClaimMapping {
        claim: "given_name", source: CanonicalUserField { field: FirstName },
        access: false, id: true, userinfo: true,
        first_party_only: false, required_scopes: Some(vec!["profile"]), allowed_clients: None,
    },
    ClaimMapping {
        claim: "family_name", source: CanonicalUserField { field: LastName },
        access: false, id: true, userinfo: true,
        first_party_only: false, required_scopes: Some(vec!["profile"]), allowed_clients: None,
    },
    // ... `preferred_username`, `locale`, `zoneinfo`, `picture`, etc. follow the same shape under the `profile` scope,
    //     using `CanonicalUserField { field: PreferredUsername | Locale | Zoneinfo | Picture | ... }`
    // ... `phone_number` under `phone` scope (`CanonicalUserField { field: PhoneNumber }`);
    //     `address` under `address` scope (`CanonicalUserField { field: Address }`) ...
    //
    // `CanonicalUserField` and `UserAttribute` are disjoint: `CanonicalUserField` reads strongly-typed
    // fields off the `User` struct; `UserAttribute` reads `User.attributes` only. There is no fallback
    // between them — operators choose explicitly. Realms wanting to override an OIDC profile claim
    // with attribute-map data write `{ source: user_attribute, attribute: <key> }` in YAML and accept
    // responsibility for format-conformance (the validator's BCP 47 / email-format / IANA-tz checks
    // only run against `CanonicalUserField` sources, since the attribute-map content is operator-supplied).
];
```

Realms that define `claims.mappings:` in YAML append their list after the built-in defaults and then evaluate per-claim under the **layered gate-aware model** defined in "Evaluation and merge model" below. This is not simple last-wins replacement — when a YAML override's release gates fail for a given context, evaluation falls back to the default profile's mapping for the same claim rather than suppressing the claim entirely. Admins write only the deltas; the defaults are always present as a fallback layer.

### Claim name tiers

Mapper claim names are validated at config load against a three-tier policy:

**Tier 1 — Forbidden (config-load rejects):** JWT / OIDC integrity, authorization-critical, tenant-routing, delegation-attestation, and verification-attestation claims that mappers MUST NOT touch.
- **JWT registered (RFC 7519):** `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`
- **Identity:** `sub`, `tid`
- **Authorization:** `permissions`, `scope`, `sid`
- **Tenant routing:** `oid` — downstream apps use `oid` to partition data per organization.
- **OIDC flow:** `nonce`, `auth_time`, `acr`, `amr`, `azp` (authorized party — RFC OIDC Core §2)
- **OIDC token-binding hashes:** `at_hash`, `c_hash`, `s_hash` — set by the issuer to bind ID tokens to access tokens / authorization codes / state; mapper-writable would let admins forge bindings.
- **OAuth client identity:** `client_id` — the requesting client's identifier; mapping would let one client impersonate another in audit/inspection.
- **Proof-of-possession (RFC 7800):** `cnf` — confirmation method binding the token to a key; mapper-writable would let admins fabricate sender-constrained tokens.
- **Delegation attestation (RFC 8693, [AGENT_AUTH.md](./AGENT_AUTH.md) §3):** `act`, `actor` — the actor claim documents delegation chains for agent-on-behalf-of-user tokens. Resource servers rely on `act` for accountability and authorization. Mapper-writable would let admins fabricate delegation history. Always sourced from the actual delegation flow.
- **Verification attestation:** `email_verified`, `phone_number_verified` — these claims attest something the auth server has verified about the user; allowing realms to remap them to constants or arbitrary attributes would let admins fabricate verification status, which has real downstream consequences (email-confirmed UIs, password-reset eligibility, MFA fallback). Always sourced from canonical user state.

**Tier 2 — Overridable with semantic constraints (mapper wins):** Informational and OIDC profile claims. Mapper output replaces default native emission. The validator enforces type/format constraints to keep OIDC conformance intact (e.g., a mapper writing to `email` must produce a string matching email-address format; `locale` must match BCP 47; `zoneinfo` must match IANA tz names). Constraint violations are config-load errors. See "SDK helper caveat" above — overriding `roles` / `groups` means SDK helpers operate on the overridden shape.
- Hearth informational: `roles`, `groups`
- OIDC profile: `email`, `name`, `given_name`, `family_name`, `preferred_username`, `nickname`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `updated_at`
- OIDC contact: `phone_number`, `address`

**Tier 3 — Custom:** Names that are neither Tier 1 nor Tier 2. Two forms permitted:
- **Short form:** `^[a-z][a-z0-9_]*$`, ≤64 chars. Used for simple custom claims (`department`, `employee_id`).
- **HTTPS-namespaced form:** `^https://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$` — collision-free namespacing for custom claims, e.g., `https://acme.com/department`. ≤256 chars. Matches Auth0/Okta convention. HTTP is rejected (security: namespace should be an owned HTTPS origin). URN-form (`urn:example:…`) is not supported in this phase — admins who need it can request it via a future spec; until then, use an HTTPS URL under a domain they control.

**Evaluation order:** see "Evaluation and merge model (layered with fallback)" below for the authoritative rule. Tier 1 claims are additionally written last by core issuance code as defense-in-depth — any mapping that slipped past Tier 1 validation would be clobbered regardless of how mapper evaluation resolved.

### Claim release gates

Each mapping carries three optional release gates that AND-combine — **all** must pass for the claim to appear in a given token, ID token, or UserInfo response. This prevents realm-wide custom claims from leaking indiscriminately to every client, closing the default-over-disclosure gap present in purely realm-global mapper systems.

- **`first_party_only: bool`** — if `true`, only emit when the client's `trust_level == FirstParty`. Third-party clients never receive this claim regardless of scope request.
- **`required_scopes: Option<Vec<String>>`** — if `Some(list)`, the final **granted** scope set for this token (post-resolution — see note below) must include at least one scope from the list. Matches OIDC profile-claim-per-scope semantics and Keycloak's scope-attached mappers.
- **`allowed_clients: Option<Vec<String>>`** — if `Some(list)`, the requesting client's slug must appear in the list. Each entry MUST be a **managed-client slug** (authored in `realms.<id>.oauth_clients` in `hearth.yaml`); DCR-registered slugs are rejected at config load with a clear error pointing the admin at the slug's track. Rationale: auto-generated DCR slugs are ephemeral and not a stable admin-authored reference — using them in a policy gate creates silent breakage when the registration churns. The registry materializes a slug↔`ClientId` index at YAML load; gate evaluation compares the resolved `ClientId`. Slugs are realm-unique. Hard allowlist for sensitive claims.

**`required_scopes` evaluates against granted scopes, not requested scopes.** After `/authorize` or `/token` scope resolution produces the final `token.scope` set (the `grantable` set from the Resolution rule above), release gates are evaluated against that set. A claim gated on `required_scopes: [admin:bundle]` does NOT emit if the client requested `admin:bundle` but the user couldn't fully satisfy it and the scope was dropped. This closes a real information-leak vector that request-time gating would have exposed.

### Evaluation and merge model (layered with fallback, per-target)

Claim mappings evaluate per-(claim-name, token-target) tuple with gate-aware fallback — NOT per claim name. This matters because a YAML override might win for ID-token output but not for access-token output, in which case the access-token output should fall back to the default rather than being suppressed. For each target claim name `C` and each token target `T ∈ {access_token, id_token, userinfo}`:

1. Collect all mappings that target `C` AND have `include_in_<T>: true`, in declaration order: defaults first (from `DEFAULT_CLAIM_PROFILE`), then realm YAML mappings.
2. Walk the collected list in reverse order (most-recently-declared first).
3. The first mapping whose release gates **all** pass for the current `(client, granted_scopes)` context wins — its source is evaluated and written to claim `C` in token-target `T`.
4. If no mapping's gates pass for this `(C, T)` pair, claim `C` is omitted from `T` (but may still appear in other targets via different winning mappings).

**Why per-target.** Consider a YAML override that filters `roles` for a customer-portal client and disables `include_in_userinfo`. Under per-claim-name evaluation, the override wins for `roles` and suppresses it from UserInfo entirely — but the operator's intent was usually "filter for the access token, leave UserInfo alone." Per-(claim, target) evaluation treats UserInfo's `roles` independently, allowing the default profile to fill in if the override doesn't include UserInfo. This is also the granularity at which the consent digest tracks disclosure surface, so evaluation and digest computation use the same model.

This gives admins the "per-client variant with fallback to default" pattern that plain last-wins replacement can't express. The example below shows the intended behavior:

```yaml
claims:
  mappings:
    - { claim: department, source: user_attribute, attribute: dept,
        first_party_only: false, required_scopes: [profile] }
    - { claim: "https://acme.com/internal_id", source: user_attribute, attribute: employee_id,
        first_party_only: true }                             # first-party tooling only, never leaks
    - { claim: roles, source: role_subset, prefix: "customer.",
        allowed_clients: [customer-portal] }                 # customer-portal gets filtered roles
```

Under the layered model, the third entry means: for the client whose `slug` resolves to the same `ClientId` as the YAML entry `slug: customer-portal`, the `roles` claim uses `RoleSubset { prefix: "customer." }`; for every other first-party client, the `allowed_clients` gate fails and evaluation falls back to the `DEFAULT_CLAIM_PROFILE` entry for `roles` (`first_party_only: true`, `RolesFromAssignments`), which still emits because the requesting client is first-party. Third-party clients fail both mappings' gates and receive no `roles` claim. No first-party client ends up with `roles` unintentionally suppressed.

**Safe defaults for Tier 3 custom claims.** When a custom mapper (Tier 3 claim name) is declared in YAML without specifying release gates, the validator injects `first_party_only: true` as the default. Admins who want to release custom claims to third-party clients must set `first_party_only: false` explicitly (and should gate with `required_scopes` or `allowed_clients`). Over-disclosure is opt-in, not default.

**Tier 2 defaults in the built-in profile** tighten from "today's shape" to prevent third-party over-disclosure. See the `DEFAULT_CLAIM_PROFILE` constant above — `roles`, `groups`, AND `permissions` all default to `first_party_only: true`, so existing first-party clients (the only kind that existed before this spec) continue to see them, but any new third-party client must be explicitly allowed to receive them by overriding the mapping with `first_party_only: false` in YAML. The `permissions` claim is gated alongside the prohibition on raw-permission scope declarations for ThirdParty clients: internal RBAC vocabulary should not leak via either channel by default. Realms whose third-party clients legitimately need a fine-grained permissions claim (e.g., a customer-portal API gateway) override this mapping in YAML with `first_party_only: false` and SHOULD pair with `allowed_clients` or `required_scopes` to keep the surface narrow.

Admins who explicitly override `roles` or `groups` in YAML control their own gate values; defaults only apply to the built-in mappings, not to overrides.

### OAuth client additions

```rust
pub struct OauthClient {
    pub id: ClientId,                        // existing — UUID, persisted, stable across renames
    pub slug: String,                        // NEW — realm-unique human-readable handle used by YAML refs and `allowed_clients` gates
    // ... other existing fields ...
    pub trust_level: ClientTrustLevel,
    pub declared_scopes: Vec<String>,        // permission names, bundle names, or OIDC standard scopes
    pub consent_spans_orgs: bool,            // opt-in: realm-level consent row covers all org contexts
}

pub enum ClientTrustLevel { FirstParty, ThirdParty }
```

`slug` is unique per realm; the registry maintains an `Arc<HashMap<(RealmId, String), ClientId>>` for slug→ClientId resolution at YAML load and gate evaluation. ThirdParty clients additionally validate at config load that `declared_scopes` contains no permission-form (`.`-separated) strings — third-party scope declarations must be bundle names or OIDC standards only.

`consent_spans_orgs` is a client capability flag, **not** a scope. Default: `false` (strict per-org consent). When `true`, a realm-level consent row (`org_key = "_realm"`) authorizes the client in any of the user's org contexts. Intended for first-party dashboards or utilities that legitimately operate across all of a user's organizations. Realms may constrain which clients are allowed to set this via admin-policy tooling.

### Storage keys

YAML-authored entities do **not** get storage keys — they live in the in-memory registry. Only runtime data gets storage keys:

- `rba:user_perm:{realm}:{user}:{scope_key}:{perm}` — user extras (primary). `scope_key` = `_realm` for realm-scoped grants, or `org_id` for org-scoped grants. The same permission CAN be granted realm-wide AND in N specific orgs without overwriting; each scope-distinct grant is its own row.
- `rba:user_perm:by_perm:{realm}:{perm}:{scope_key}:{user}` — reverse index (who has this extra at this scope)
- `oauth:consent:{realm}:{user}:{client}:{org_key}:{resource_key}` — stored consent + scope digest, keyed by organization context AND RFC 8707 resource indicator. `org_key` = org id or `"_realm"`; `resource_key` = 16-byte hex of `sha256(resource_uri)` or `"_default"` for tokens bound to Hearth itself. Per-resource keying composes with the MCP / protected-resource model in [AGENT_AUTH.md](./AGENT_AUTH.md). See Consent Storage section.

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

Hearth organizations are B2B customer boundaries within a realm. Different orgs represent different customers' data. A consent granted while Alice is acting in Acme Corp should **not** implicitly authorize the same client to access her data in Globex Inc. Consent is therefore keyed on the organization context in which it was granted.

```
oauth:consent:{realm}:{user}:{client}:{org_key}:{resource_key} → {
  scopes: Vec<String>,                  // as requested by the client at consent time
  scope_digest: [u8; 32],               // see Invalidation section
  context_oid: Option<OrganizationId>,  // the org the user was in at consent time
  resource: Option<Uri>,                // RFC 8707 resource indicator at consent time, or None for default audience
  granted_at: Timestamp,
  granted_by: UserId,
}

where org_key =
  "_realm"         if context_oid = None    (consent granted at realm level)
  org_id.to_string() if context_oid = Some(id)

where resource_key =
  "_default"       if resource = None       (token bound to Hearth itself, default audience per AGENT_AUTH §2.4)
  sha256(resource_uri)[..16] hex            (16-byte hex of the canonical resource URI; truncation OK because realm/client scope already isolates)
```

**Why resource is part of the key.** Per [AGENT_AUTH.md](./AGENT_AUTH.md) §2.4, MCP and other protected-resource clients pass an RFC 8707 `resource` parameter at `/authorize` and `/token`, producing access tokens with `aud` set to that resource URI. Each protected resource is a distinct security boundary — consent to call MCP tool server A is not consent to call MCP tool server B, even from the same client. Keying consent on `resource_key` keeps the boundary intact. Clients that don't pass a `resource` parameter use `_default`, which corresponds to Hearth itself as audience.

**FirstParty clients bypass consent storage entirely.** No consent row is materialized, no digest is computed, no digest validation runs at `/authorize` or `/token refresh_token`. Refresh tokens for FirstParty clients re-resolve effective permissions live against the registry without comparing to a stored digest — drift in the YAML registry is reflected immediately on next refresh (matching the "first-party apps share the realm config lifecycle" trust model). Refresh failure for a FirstParty token never returns `consent_required`; if the user lost a permission, the token still issues with the narrower set (per the "User loses a permission" row in the Refresh-token-drift table below).

**Consent lookup rule at `/authorize` and `/token refresh_token` for ThirdParty clients:**
1. Look up consent at `(realm, user, client, org_key, resource_key)` where both keys derive from the current request context (`oid` and RFC 8707 `resource` parameter).
2. If the user is in an org context (`oid = Some(X)`) and no matching row exists at that `org_key`, fall back to the realm-level consent row (`org_key = "_realm"`) **only if** the client's YAML declares `consent_spans_orgs: true`. Default behavior is strict per-org.
3. `resource_key` does NOT have a fallback: each protected resource is its own consent boundary. If `resource_key` doesn't match, trigger consent ceremony for the new resource.
4. On miss, trigger the consent ceremony (interactive).

**Rationale:** Keeping consent strict-per-org preserves the org-as-data-boundary invariant. A client that legitimately spans orgs (e.g., a user-wide dashboard) opts in via `consent_spans_orgs` on its YAML definition, which the admin surface must explicitly allow per realm policy. Without opt-in, Alice must re-consent when switching orgs — the safer default for B2B tenants. This is a client capability flag, not a scope — it does not appear in `declared_scopes` and does not participate in scope resolution.

### Invalidation (digest-based, lazy)

Consent is about **disclosure surface**, not just authorization. Two artifacts can change without the requested-scope strings changing: bundle permission contents (covered by the permission set) AND the set of claims that will actually be released to this client given the realm's mappers + release gates. Both must contribute to the digest.

At grant time, Hearth computes:

```
scope_digest = sha256(
    canonicalize(resource),                         // audience boundary
    "||",
    sort(unique(resolved_permissions(scopes))),     // authorization surface
    "||",
    sort(effective_emitted_claim_targets(client, scopes, resource))  // disclosure surface, per token target
)

where canonicalize(resource) =
  "_default"           if resource = None
  resource_uri (lower-cased scheme/host, normalized path)  if resource = Some(uri)
```

`effective_emitted_claim_targets(client, scopes, resource)` is the set of `(claim_name, token_target)` tuples — where `token_target ∈ {access_token, id_token, userinfo}` — that the realm's claim profile would emit to *this client* given its `trust_level`, *these granted scopes*, and *this resource*, evaluated under the layered gate-aware model. Each (claim, target) pair is a distinct disclosure surface element: a claim that moves from ID-token-only to access-token-and-userinfo widens the disclosure surface even if the claim name set is unchanged, and the digest catches it.

**Why resource is a digest input.** The same scope name can resolve to a different permission set under different resources (a `:`-bundle's contents come from whichever registry the resource selects), and mappers gated on `required_scopes` may emit different claim sets when the granted scope set differs. Binding the digest to `resource` ensures consent to call resource A is not silently reusable when the same client later requests resource B with the same scope strings — even though the consent storage key already enforces this at the storage layer, the digest enforces it at the validation layer too. Defense in depth across the two consent invariants.

Example representation: `{("email", "id_token"), ("email", "userinfo"), ("roles", "access_token"), ("department", "id_token")}` serialized as sorted `claim@target` strings before hashing.

The digest covers claim *names and targets*, not their values or the mapper internals — what the user consented to is "this client will receive these claims via these surfaces." OIDC standard scopes contribute fixed sentinels so OIDC-handling changes invalidate correctly.

On every subsequent `/authorize` or `/token refresh_token`, Hearth re-resolves both surfaces live against the current registry and re-hashes. Mismatch → treat as no consent → trigger re-consent ceremony (or `invalid_grant error_description=consent_required` on refresh). Match → consent stands.

**Why claim-name set, not values?** Values change every token (timestamps, dynamic attrs); we'd thrash. Names are the stable disclosure-surface contract: "this app will receive your `email`, `department`, and `roles`." Adding a new mapper that emits `salary` to this client changes the name set; the digest catches it; user re-consents. Removing a mapper also invalidates — safer than silently shrinking what the user thought they agreed to.

This is the SSH `known_hosts` pattern extended to disclosure: trust was granted to a specific authorization-and-disclosure artifact, not just a permission name. Self-healing, precise, no eager sweep at YAML reload.

### Refresh token behavior under drift

| Scenario | Behavior |
|---|---|
| Scope bundle contents change in YAML | Digest mismatch → `invalid_grant consent_required`; client redirects to `/authorize`. |
| User loses a permission | Digest still matches (same scopes/bundles). Refresh succeeds with narrower effective set. Downstream apps see 403 when attempting actions the user no longer has — correct signal, no forced re-login. |
| Scope bundle deleted from YAML | Digest mismatch → `invalid_grant consent_required`. |
| Client requests a different `resource` on refresh than the one captured in the consent row | A refresh request MUST NOT switch `resource` from the value captured in the original consent. Mismatch → `invalid_grant consent_required`. The agent must re-run `/authorize` with the new `resource`, which produces a distinct consent row (per the per-resource key) and a fresh grant family. This is enforced at the consent lookup layer (the `resource_key` in the storage key wouldn't match) and at the digest layer (`resource` is a digest input). |

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
- **Org member row (`organizations/_member_row.html`)** — replace hardcoded Member/Admin/Owner dropdown with a role typeahead filtered to `scope_kind ∈ {Organization, Any}`. See "Reconciliation with `OrganizationRole`" below for how the existing enum maps into the new model.

### Reconciliation with `OrganizationRole`

The current identity layer has a first-class `OrganizationRole { Member, Admin, Owner }` enum (`src/identity/types.rs:704`) attached to organization memberships. This spec does NOT delete that enum — doing so would invalidate every existing org membership row in shipped Hearth. Instead, the enum becomes the **canonical membership-tier shortcut** and maps deterministically to seeded RBAC roles:

- A `hearth-defaults.yaml` ships three `scope_kind: organization` RBAC roles named `org_member`, `org_admin`, `org_owner` with empty permission lists by default. Realms can extend these in their own YAML by adding permissions to the same names.
- An organization membership row continues to carry an `OrganizationRole` enum value as its primary tier marker. At token-issue time, the enum value is mapped 1:1 to the seeded RBAC role of the corresponding name, and the role's permissions flow into the resolution rule like any other org-scoped role assignment.
- The admin UI's org-member row presents the typeahead with the three seeded names pre-listed (so the membership UX is unchanged for the common case), but admins can also assign additional org-scoped RBAC roles to a member alongside the canonical tier.
- `OrganizationRole` enum values are NOT renameable (they're shipped Rust types); the seeded RBAC role names matching them are NOT renameable in `hearth-defaults.yaml` (they're the bridge); but realm YAML can add MORE org-scoped roles freely.
- API surface: existing membership APIs keep their `OrganizationRole` parameter; new APIs accepting arbitrary RBAC role names operate on the same membership row's `additional_roles: Vec<RoleName>` field.

This keeps shipped contracts intact while letting admins extend org authz with full RBAC. Phase 1 implements the bridge; the enum stays in place indefinitely as a stable shortcut.
- **Application edit/detail** — read-only view of `trust_level` and `declared_scopes`. Effective permission union shown as a helper; scope picker is read-only (YAML-authored). The UI includes a "Copy YAML snippet" affordance for admins who want to extend the client in YAML.
- **Realm detail** — new "Claims" sub-page at `/ui/admin/realms/:id/claims`:
  - Read-only view of the realm's merged claim profile (defaults + YAML overrides)
  - Live "Example token" rendered against an admin-chosen sample user (with client trust-level and granted-scope inputs so admins can preview gate behavior for first-party vs third-party clients)
  - Mapper list showing source, target claim, include-in access-token / ID-token / UserInfo flags, and release gates (`first_party_only`, `required_scopes`, `allowed_clients`)

### New account-settings surface (end-user self-service)

- **`/ui/account/applications`** — end-user-facing list of connected apps.
  - User can see display name, granted-at, granted scopes. When an app has multiple consent rows, they are grouped hierarchically: **per-org breakdown at the outer level, per-resource breakdown nested under each org**. Example: under "AcmeNotes" → "Acme Corp" → two entries: "Hearth (default audience)" and "https://mcp.acme.com" — each with its own granted-at timestamp and scope list. The realm-level row (when the client has `consent_spans_orgs: true`) appears as its own outer-level group labeled "All organizations."
  - **First-party clients may not appear in this list at all**, because they bypass consent storage entirely (see "Consent Storage" §). Realms whose first-party clients never store consent rows will see only third-party clients here. This is intentional — first-party access is part of the realm trust contract, not user-grantable.
  - User can revoke a consent. **Revocation scope is all-or-nothing per client** (see below) — the user cannot selectively revoke one resource while keeping another.
  - Requires only account-level auth; no admin privilege.
  - Emits one `ClientConsentRevoked` audit event per consent row deleted (with `actor = user`, `context_oid` = the org the row was keyed under, `resource_uri` = the resource the row was keyed under or `null` for default-audience rows).

**Revocation semantics (normative):**

Clicking "Revoke" for an app removes every consent row matching `(realm, user, client)` — the realm-level row (if any), every org-scoped row, **and every per-resource row under each of those**. All refresh tokens tied to `(user, client)` across every grant family and every resource are invalidated.

This is the "revoke this app" meaning that matches Auth0, GitHub, and Google's consent UIs. A user who wants finer control (e.g., "only stop letting AcmeNotes into Acme Corp, keep it working in Globex") or per-resource granularity ("stop letting the agent talk to MCP server A, keep MCP server B") must re-consent from scratch afterwards in the (org, resource) combination they want to keep active. Per-org and per-resource granular revocation UI is deferred to a future spec; it is not a Phase 3 deliverable.

**Admin revocation uses the same scope.** `DELETE /v1/admin/users/{uid}/applications/{clientId}` wipes all consent rows for that (user, client) across all orgs and all resources. Audit events emit one per deleted row.

## SDK Compatibility

The existing SDK method signatures remain unchanged under this design — no breaking API changes. Behavioral guarantees, however, depend on the realm's claim profile:

- **TypeScript** (`sdks/typescript/src/react.tsx:36-54`): `useHasPermission`, `useHasRole`, `useInGroup`, `useInOrg`
- **Go** (`sdks/go/hearth/client.go:137-166`): `HasPermission`, `HasRole`, `InGroup`, `InOrg`, `Permissions`

**Guaranteed correct regardless of profile:**
- `hasPermission` / `HasPermission` — reads the `permissions` claim, which is Tier 1 (authoritative, never overridable). Always reflects the server-resolved effective set.
- `inOrg` / `InOrg` — reads the `oid` claim, which is Tier 1 (tenant-routing, never overridable).

**Correct under default or default-shaped profiles only:**
- `hasRole` / `HasRole` — reads the `roles` claim. Default profile emits the `RolesFromAssignments` shape (flat array of role names), but **first-party clients only** under the tightened greenfield defaults. Third-party clients see no `roles` claim unless an admin explicitly overrides the default mapping with `first_party_only: false` (and optionally adds `allowed_clients` or `required_scopes` gating). Realms that remap `roles` via `RoleSubset` / `Constant` / etc. produce different shapes; SDK helpers operate on whatever is in the claim.
- `inGroup` / `InGroup` — same caveat for the `groups` claim: first-party by default, no third-party emission without explicit opt-in.

Custom claims added by the realm's claim profile are orthogonal to the existing claim names and pass through the SDK's JWT decoder unchanged (the decoder ignores unknown fields).

**New SDK methods (Phase 3):**
- TS: `hearth.revokeConsent(clientId: string): Promise<void>`
- Go: `client.RevokeConsent(ctx, clientID string) error`

These call `DELETE /v1/me/applications/{clientId}` for self-service revocation.

**Documentation updates** (in `sdks/*/README.md` and docstrings):
- Position `hasPermission` as the authorization primitive used in authz middleware/guard examples.
- Document `hasRole` as a legitimate tool for UI personalization and federation. No warning framing.

**Deferred to a later specification (not in scope here):** `hearth generate types` CLI for codegen of typed permission enums, `getClaims()` / `Claims()` helpers, and `createHearth({ debug: true })` mode.

## Engine Changes

- **File: `src/identity/engine.rs:2267-2309`** — `issue_tokens` becomes a thin wrapper around a new `issue_tokens_with_context` that takes a `TokenIssuanceContext { oid, client_id, requested_scopes, grant_type, resource: Option<Uri> }`. The `resource` field carries the RFC 8707 resource indicator from `/authorize` and `/token` (or `None` when the token is bound to Hearth itself as audience). The wrapper supplies an empty context so every existing caller is unchanged.
- **File: `src/rbac/registry.rs`** (new) — loads and validates the YAML registry; exposes `Arc<PermissionRegistry>` for hot-swap on SIGHUP via `ArcSwap`; provides `classify_scope_string(s: &str) -> ScopeKind` (the syntactic classifier); enforces Tier 1/2/3 claim-name rules; validates role permission references, scope bundle permission references, and claim profile tier enforcement.
- **File: `src/rbac/mod.rs`** — extend the `Rbac` trait:
  - `grant_user_permission` / `revoke_user_permission` / `list_user_permissions`
  - `resolve_effective(user_id, realm_id, oid, requested_scopes, client_id, resource: Option<Uri>) -> ResolvedPermissions` — the one function that implements the resolution rule above. `resource` selects which scope registry the `:`-bundles are looked up in (realm-level when `None`, `protected_resources[resource]` when `Some`) and gates whether `.`-permission scopes are legal at all.
  - Registry access methods (lookup/list) for admin UI read-only views.
- **File: `src/identity/tokens.rs:70-130`** — `TokenClaims` gains `#[serde(flatten)] custom: BTreeMap<String, serde_json::Value>`. Existing fields become `#[serde(skip_serializing_if = "...")]` so mappings with `Omit` source can suppress them without changing JSON shape for other tokens.
- **File: `src/identity/claims_config.rs`** (new) — `ClaimSource`, `ClaimMapping`, `ClaimProfile`, `DEFAULT_CLAIM_PROFILE`, `merge_mappings(defaults, overrides)`, mapper evaluation.
- **File: `src/identity/engine.rs` UserInfo endpoint (`src/identity/engine.rs:4260` per current impl)** — `/userinfo` response is produced by evaluating the realm's claim profile with `include_in_userinfo: true` filter, rather than hardcoded scope-to-field projection. This prevents drift between ID-token claims and `/userinfo` claims when a realm overrides `email` / `name` / etc. OIDC scope filtering (`scope=profile` includes profile claims, `scope=email` includes email claims) is applied on top of the mapper output. Unmapped OIDC profile claims (not overridden in the realm's profile) fall back to canonical user fields exactly as they do today.

**Hot path unchanged.** `validate_token` reads `tid` / `sid` only, no new allocations, no new lookups. All of this is off-hot-path work at token issuance.

## Test Plan

Mapping to Hearth's eight layers (per `docs/specs/TESTING.md`):

1. **Unit** — type round-trips, naming grammar validator (boundary cases: single-word, mixed separators, whitespace, URL-reserved chars, hyphens, mixed case), tier enforcement (Tier 1 rejection, Tier 2 override, Tier 3 short-form and HTTPS-namespaced), resolution math (union, atomic full-satisfiability grant, empty cases, scope-match for realm/org), merge/layered-fallback semantics for claim profile (YAML-override gate failure falls back to default; default also failing → claim omitted), release-gate matrix (each of `first_party_only` / `required_scopes` / `allowed_clients` individually and AND-combined, across access-token / ID-token / UserInfo outputs), `required_scopes` evaluated against granted-not-requested.
2. **Integration** — storage CRUD for user extras, cascade behavior, user extras flowing through `resolve_effective`, scope filtering at each grant type (password, auth code, client credentials, refresh, device), YAML-reload swap via `ArcSwap`, org-keyed consent lookup with and without `consent_spans_orgs` fallback, org-context switch forces re-consent by default.
3. **Property** — `resolve_effective` idempotence, scope-match determinism, mapper output determinism, digest stability under permutation, layered-fallback determinism under mapping reordering.
4. **Fuzz** — YAML deserialization, permission/scope name parser, claim profile JSON, HTTPS-namespaced claim name parser.
5. **Adversarial** — privilege escalation attempts (requesting undeclared scope, consenting to permission user lacks, Tier 1 claim override via mapper), scope-deletion-with-active-refresh-tokens, reserved-claim-name collision, name collision across namespaces, **raw-request scope leak** (gate a sensitive claim on `required_scopes: [admin:bundle]`, have the client request it but lack permissions — verify the claim does NOT emit), **cross-org consent reuse** (consent in org A must not authorize in org B without `consent_spans_orgs`), third-party client receiving `roles`/`groups` via default profile (must NOT emit).
6. **Simulation** — admin rewrites YAML while tokens are being issued (ArcSwap invalidation), scope definition deleted while refresh in flight, dangling-reference orphan skip, claim profile toggled to tighten gates mid-flight (in-flight tokens unaffected, next issuance honors tightening).
7. **Conformance** — OAuth 2.0 RFC 6749 scope semantics (scope narrower on grant than request, refresh scope ⊆ original), OIDC Core scope claim shape, standard OIDC scope handling, UserInfo endpoint claim shape matches ID token shape under mapper overrides.
8. **Benchmarks** — `issue_tokens` with 40-permission user (target: same as baseline), `validate_token` (must be byte-identical perf since hot path is unchanged), registry lookup cached via `ArcSwap`, layered-fallback evaluation cost (target: <1µs per claim for realistic mapping counts).

## Critical Files

- [x] `src/rbac/registry.rs` — `RealmPermissionRegistry`, `PermissionRegistry`, `RegistryError`, grammar validator, `TIER1_CLAIMS`. **ArcSwap hot-swap not yet wired.**
- [x] `src/rbac/types.rs` — `RoleScopeKind`, `UserPermissionGrant`, `PermissionDefinition`, `ScopeBundle`.
- [x] `src/rbac/keys.rs` — `rba:user_perm:*` storage keys added.
- [x] `src/rbac/mod.rs` — user-extras trait methods (`grant`/`revoke`/`list`). **`add_additional_role` / `remove_additional_role` / `list_additional_roles` not yet added.**
- [x] `src/rbac/engine.rs` — user-extras implementation, tracing events. **Additional-roles implementation not yet done.**
- [x] `src/identity/claims_config.rs` — `ClaimSource`, `ClaimMapping`, `ClaimProfile`, `CanonicalUserField`, `evaluate()`. **`DEFAULT_CLAIM_PROFILE`, layered fallback, `required_scopes`-vs-granted, `allowed_clients` slug resolution not yet done.**
- [ ] `src/identity/engine.rs` — `issue_tokens_with_context`, digest re-check on refresh, `User.attributes` runtime validation at create/update/import.
- [x] `src/identity/tokens.rs` — `TokenClaims` with `#[serde(flatten)] custom: BTreeMap<String, Value>` + `skip_serializing_if` on existing fields.
- [x] `src/identity/types.rs` — `User.attributes` field, `OauthClient.trust_level` + `declared_scopes` + `consent_spans_orgs` + `slug`, `OrganizationMembership.additional_roles`, `scope_digest` on consent, `ProtectedResource`, `RealmConfig.protected_resources` + `scopes`.
- [ ] `src/protocol/web/admin.rs` — read-only handlers for permissions/roles/scopes, CRUD for user extras, consent revocation admin surface.
- [x] `src/protocol/web/account.rs` — account self-service handlers (password, MFA). **Connected-applications page not yet done.**
- [ ] `templates/ui/admin/rbac/**` — read-only templates for YAML-managed entities; CRUD templates for groups and user extras.
- [ ] `templates/ui/admin/users/detail.html` — Access card replacement.
- [ ] `templates/ui/admin/realms/claims/view.html` — claim profile viewer.
- [ ] `templates/ui/admin/applications/{edit,detail}.html` — trust_level + declared_scopes (read-only).
- [ ] `templates/ui/account/applications.html` — user self-service connected-apps list.
- [ ] `templates/ui/_layout.html` — nav restructure (new RBAC section).
- [ ] `proto/hearth/rbac/v1/rbac.proto` — RPCs for user-extras CRUD, additional-roles, read-only lookups.
- [ ] `sdks/typescript/README.md`, `sdks/go/README.md` — documentation positioning; new `revokeConsent` method.
- [ ] `hearth-defaults.yaml` — canonical `org_member` / `org_admin` / `org_owner` bridge roles.

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

### Scope grant semantics — atomic, full-satisfiability

A scope is grantable if the user has **all** of its declared permissions (or if it's an OIDC standard scope). Grantable scopes are added to the token's `scope` claim; `permissions` is the intersection of user-effective with the union of grantable scope permissions. Empty `grantable` with non-empty `requested_scopes` → `invalid_scope`.

**Rationale:** Full-satisfiability preserves the invariant that `scope` and `permissions` never disagree. Any-overlap grants would cause API gateways reading `scope=read:docs` to assume full bundle approval while `permissions` carries only a subset — a real security gap. Bundles should be defined as coherent capability sets that roles naturally align with; misalignment surfaces as the bundle simply not being granted, and the client falls back to requesting direct permission scopes.

### Naming convention — separator-based disjoint namespaces

Permissions contain `.`, scope bundles contain `:`, OIDC standard scopes are bare words from a closed set. Enforced at config load by a syntactic validator. Single-word permissions are rejected; use the `system.*` namespace for legitimately global permissions.

**Rationale:** Syntactic classification eliminates name-collision bugs at the grammar level. Forces hierarchical resource-oriented naming (good RBAC hygiene). Reserves the bare-word namespace for protocol-defined scopes (preventing accidental shadowing of future OIDC scope additions).

### Claim profile — unified mapper model

All claim shaping is expressed as `ClaimMapping { claim, source }`. The `include_roles` / `include_groups` / `include_permissions` toggles from the original spec are collapsed into built-in `ClaimSource` variants (`RolesFromAssignments`, `GroupsFromMemberships`, `EffectivePermissions`, `OrgContext`). The default profile preserves today's emission for first-party clients while tightening third-party exposure by default (see `DEFAULT_CLAIM_PROFILE`). Realm YAML mappings append after built-in defaults and evaluate under a **layered gate-aware model** — for each claim name, mappings walk in reverse declaration order and the first whose release gates pass wins; if none pass, the claim is omitted. This is not plain last-wins replacement: a YAML override whose gates fail falls back to the default rather than suppressing the claim. An `Omit` source explicitly suppresses a default when the admin wants no emission at all.

**Rationale:** Matches Keycloak/Auth0/Okta mental model (mappers are the only shaping mechanism). Collapses toggle-vs-mapper precedence questions. Keeps ergonomic parity for the common "disable one default claim" case.

### Claim name tiers

Three-tier classification enforced at config load: Tier 1 (forbidden — JWT/authz/tenant-routing integrity including `oid`), Tier 2 (overridable — `roles`, `groups`, OIDC profile claims), Tier 3 (custom — short `snake_case` OR HTTPS-namespaced). Security-critical and tenant-routing claims can never be targeted by a mapper; informational claims can be overridden (with the SDK caveat that helpers operate on overridden shape); custom claims support both flat and HTTPS-URL forms for collision-free extension. URN namespacing is not supported in this phase.

**Rationale:** Allows flexible shaping while preventing privilege-escalation via `permissions` override, cross-tenant data leaks via `oid` override, or protocol-corruption via `exp`/`iss` override. Defense in depth: Tier 1 claims are written last by issuance code even if validation is bypassed.

**Release gates.** Each mapping has `first_party_only`, `required_scopes` (evaluated against **granted** scopes, not the raw request), and `allowed_clients` gates — all AND-combined. Built-in defaults tighten for third-party safety: `roles` and `groups` default to `first_party_only: true` and omit from `/userinfo`; `permissions` keeps open gates because it's the authoritative authz primitive. Tier 3 custom mappers default to `first_party_only: true` at config-load time. Tier 2 overrides in YAML use whatever gates the admin sets; the admin owns their own exposure decisions when they override a default.

**Consent keyed with org context.** Consent rows include the organization id (`oid`) they were granted under. A consent granted while in org A does not implicitly authorize the client in org B. Clients that intend to span orgs opt in via `consent_spans_orgs: true` on their OAuth client definition — a first-class client capability flag, not a scope.

### Role scoping — scope_kind per role

`Role` gains `scope_kind: RoleScopeKind { Realm, Organization, Any }`. Assignment-time validation refuses realm-kind roles at org scope and vice versa. `Any` accepts either. Admin UI typeahead filters by scope kind.

**Rationale:** Prevents semantic drift between "realm-level admin role" and "org-level member role." The existing `OrganizationRole { Member, Admin, Owner }` enum stays as the canonical membership-tier shortcut and maps to seeded `org_member` / `org_admin` / `org_owner` RBAC roles in `hearth-defaults.yaml`. Existing memberships continue to work without migration; admins can layer additional org-scoped RBAC roles on top via the new `additional_roles` field. See "Reconciliation with `OrganizationRole`" in the Admin UI section for the full bridge.

### User attributes

`User` gains `attributes: BTreeMap<String, String>` with validation (key `[a-z0-9_]{1,64}`, value ≤1 KiB, map total ≤16 KiB). Prerequisite for the `UserAttribute` claim mapper. Keycloak migration populates this from `UserRepresentation.attributes`.

**Rationale:** `UserAttribute` mapper variant cannot work without a flexible attribute store. `BTreeMap` chosen over `HashMap` for deterministic serialization (matters for Ed25519 deterministic signatures). Size caps prevent JWT / HTTP header bloat downstream.

### Client trust-level semantics

Unchanged from original spec.

| trust_level | Consent required | No-scope token shape | Scope request behavior |
|---|---|---|---|
| FirstParty | No | Full effective permissions | Atomic full-satisfiability grant per Resolution rule. **Silent partial grant permitted** — `token.scope` may be a strict subset of `requested_scopes` (RFC 6749 §3.3). Validates requested ⊆ `declared_scopes`; `invalid_scope` if `grantable` empty. |
| ThirdParty | Yes (first time per scope set, digest-validated afterwards) | Rejected with `invalid_scope` | Atomic full-satisfiability grant per Resolution rule. **Fail-closed:** if any non-OIDC requested scope is ungrantable, the entire request fails with `invalid_scope` (no partial grant). OIDC standard scopes exempt. Consent ceremony runs if no cached consent matches. |

### Consent invalidation — digest-based, lazy, disclosure-aware

Consent rows store `scope_digest` computed over BOTH the authorization surface (resolved permissions for the consented scopes) AND the disclosure surface (the set of `(claim_name, token_target)` pairs the realm's claim profile would emit to this client given its trust level and granted scopes). See "Invalidation" subsection of Consent Storage for the exact formula. On every `/authorize` or `/token refresh_token`, re-resolve both surfaces and re-hash live; mismatch triggers re-consent. No eager sweep on YAML reload.

**Rationale:** SSH `known_hosts` pattern extended to disclosure — trust was granted to a specific (authorization, disclosure) artifact, not just a permission name. Self-healing, precise, no operational friction on YAML edits. Adding a new mapper that emits to this client invalidates consent automatically; moving a claim from ID-token-only to access-token-and-userinfo also invalidates.

### User extras storage — first-class relation

Dedicated `rba:user_perm:{realm}:{user}:{scope_key}:{perm}` storage where `scope_key` is `_realm` for realm-scoped grants or the org id for org-scoped grants. Reverse index `rba:user_perm:by_perm:{realm}:{perm}:{scope_key}:{user}`. Separate trait methods (`grant_user_permission`, `revoke_user_permission`, `list_user_permissions`), distinct UI affordance. Reuses existing `Scope { Realm | Org(id) }` enum. Matched against token context with the same rule as role assignments. The same permission CAN be granted realm-wide AND in N specific orgs simultaneously without overwriting; each scope-distinct grant is its own row.

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
- Cascades are **all-or-nothing per client**: delete every consent row matching `(realm, user, client)` across all org contexts + invalidate every refresh token tied to `(user, client)`. Matches Auth0/GitHub/Google "revoke app" semantics. Per-org granular revocation deferred to a future spec.

**Rationale:** End-user revocation is table-stakes for an auth product exposed to third-party apps. Deferring creates a user-trust gap. Shipping alongside admin surface amortizes implementation cost.

### SDK primitives

Ship `hasPermission` and `hasRole` as equal-citizen methods. Documentation leads with `hasPermission` for authz examples; `hasRole` is documented as a legitimate tool for UI personalization and federation without warning framing. No `can()` alias.

---

## Delivery Phasing

This specification commits to three phases. SDK DX improvements (codegen CLI, `getClaims()`/`Claims()` helpers, debug mode) are deferred to a follow-up specification.

### Phase 1 — Permissions registry + user extras (foundational)

Scope:
- [x] New types: `RoleScopeKind`, `UserPermissionGrant`, `PermissionDefinition`, `ScopeBundle` (all in `src/rbac/types.rs` or `src/rbac/registry.rs`)
- [x] `User.attributes` field (`BTreeMap<String, String>`) on `User` struct — **runtime validation not yet done** (key grammar, value ≤1 KiB, map total ≤16 KiB)
- [x] `src/rbac/registry.rs`: `RealmPermissionRegistry`, `PermissionRegistry`, `RegistryError`, grammar validator, `TIER1_CLAIMS` — **`ArcSwap` hot-swap not yet wired in `main.rs`**
- [x] Storage keys: `rba:user_perm:*`, `rba:user_perm:by_perm:*`
- [x] Trait methods: `grant_user_permission`, `revoke_user_permission`, `list_user_permissions`
- [x] `resolve_permissions` updated to union user extras and honor `scope_kind` / scope-match rule
- [x] `OrganizationMembership.additional_roles: Vec<String>` field + getter/setter — **`add_additional_role` / `remove_additional_role` / `list_additional_roles` RbacEngine API not yet done**
- [ ] `User.attributes` runtime validation at `create_user`, `update_user`, `import_user` call sites
- [ ] `add_additional_role` / `remove_additional_role` / `list_additional_roles` on `RbacEngine` trait + `EmbeddedRbacEngine` + RBAC-owned storage key + `resolve_permissions` integration
- [ ] `PermissionRegistry` hot-swap via `ArcSwap` on SIGHUP wired in `main.rs`
- [ ] Admin UI: `/ui/admin/rbac/permissions` (read-only list), `/ui/admin/rbac/roles` (read-only), user detail page Access card redesign (Roles + Extra permissions + Effective + Attributes), org member row upgrade to scope_kind-filtered typeahead
- [ ] Nav: new "RBAC" section in sidebar
- [ ] CLI: `hearth config validate`, `hearth rbac orphans list` / `purge`
- [x] Audit events: `UserPermissionGranted`, `UserPermissionRevoked`, `OrphanedReferenceSkipped`
- [ ] Audit events: `OrgMemberAdditionalRoleAdded`, `OrgMemberAdditionalRoleRemoved`
- [ ] Proto: new RPCs in `rbac.proto` for user extras and additional-roles
- [ ] `hearth-defaults.yaml` + extend `seed_realm` to idempotently create `org_member` / `org_admin` / `org_owner` as `scope_kind: Organization` roles
- [ ] Tests across all 8 layers per test plan section

Ships independently. Ends in a state where admins can define permissions and roles in YAML, grant direct user permissions without creating bespoke roles, and see effective permissions in the UI.

### Phase 2 — Configurable token claims

Scope:
- [x] `src/identity/claims_config.rs`: `ClaimProfile`, `ClaimMapping`, `ClaimSource`, `CanonicalUserField`, `evaluate()` — **`DEFAULT_CLAIM_PROFILE` constant, layered fallback model, `required_scopes`-vs-granted semantics, `allowed_clients` slug resolution not yet done**
- [x] `TokenClaims` gains `#[serde(flatten)] custom: BTreeMap<String, Value>` and `skip_serializing_if` on existing claim fields
- [x] Tier 1 claim name validation (`TIER1_CLAIMS`) in registry validator
- [ ] `DEFAULT_CLAIM_PROFILE` constant in `claims_config.rs`
- [ ] Layered per-`(claim, target)` gate-aware evaluation (fallback to default when YAML override gates fail)
- [ ] `required_scopes` gate evaluated against **granted** scope set (not requested)
- [ ] `allowed_clients` gate with slug→`ClientId` index resolution; DCR slugs rejected at config load
- [ ] Tier 2/3 claim name validation in registry validator
- [ ] YAML schema: `realms.<id>.claims.mappings:` block wired through `to_realm_config`
- [ ] `issue_tokens_with_context` implementation; existing `issue_tokens` becomes thin wrapper
- [ ] Admin UI: `/ui/admin/realms/:id/claims` read-only viewer; live token preview pane
- [ ] Debug page enhancement: new "Token preview" tab
- Audit events: none new (YAML reload is not an audit-worthy runtime event)

Depends on Phase 1 (mappers can reference registered permissions via `RoleSubset` and `EffectivePermissions` sources). The release-gate framework (`first_party_only`, `required_scopes`, `allowed_clients`) and layered-fallback evaluation model land in this phase too, even though `required_scopes` only becomes meaningful once Phase 3 produces granted scope sets. Ends in a state where realm admins can shape token output declaratively with safe-by-default exposure for any future third-party clients.

### Phase 3 — OAuth scopes + client trust_level + consent

Scope:
- [x] `ClientTrustLevel` enum; `OauthClient` gains `trust_level`, `declared_scopes`, `consent_spans_orgs`, `slug`
- [x] Optional `scopes:` YAML block (`RealmConfig.scopes: Vec<ScopeBundle>`) wired
- [x] `ProtectedResource` type + `RealmConfig.protected_resources` wired
- [x] `scope_digest` field on consent row struct
- [ ] `resolve_effective` with full scope-resolution pipeline: separator-based dispatch, resource-scoped bundle lookup, full-satisfiability check, ThirdParty fail-closed, `.`-permission prohibition for ThirdParty clients
- [ ] `/authorize` validation: requested scopes ⊆ `declared_scopes`; `invalid_scope` on failure
- [ ] Consent ceremony for `ThirdParty` clients rendered from `ScopeBundle` / `PermissionDefinition` / OIDC strings; consent rows keyed by `(realm, user, client, org_key, resource_key)` per Consent Storage section; `consent_spans_orgs` fallback
- [ ] Digest re-check on every `/authorize` and `refresh_token`; `invalid_grant consent_required` on mismatch
- [ ] `FirstParty` empty-scope → full effective; `ThirdParty` empty-scope → `invalid_scope`
- [ ] Admin UI: `/ui/admin/rbac/scopes` list/detail (read-only with empty state), updated Applications pages with trust level + declared scopes (read-only)
- [ ] Admin UI: `/ui/admin/users/{id}/applications` — connected apps + revoke
- [ ] End-user UI: `/ui/account/applications` — self-service revoke
- [ ] SDK methods: `revokeConsent` in TS and Go
- [ ] Audit events: `ClientConsentGranted`, `ClientConsentRevoked`, `ConsentRequiredOnRefresh`
- [ ] Proto: consent-revocation RPC

Depends on Phase 1 (scopes reference registered permissions) and Phase 2 (the claim-profile mapper model supplies the `required_scopes` release gate that Phase 3's scope-resolution output feeds into). Ends in a state where Hearth can serve as a full OAuth authorization server with consent-based third-party integrations and end-user consent management.
