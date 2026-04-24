# Authorization

This is the normative specification for Hearth's authorization model. It defines how users, groups, roles, and permissions work; how permissions are resolved at token issue time; how they are carried in JWTs; how the admin surface manages them; and how SDKs consume them.

Terminology follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** carry their standard meaning.

Related documents:
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — layer placement, module conventions, lateral-dependency rules.
- [`CONFIGURATION.md`](./CONFIGURATION.md) — realm YAML for declarative role, permission, and scope setup.
- [`IMPLEMENTATION_ORDER.md`](./IMPLEMENTATION_ORDER.md) — where RBAC falls in the build sequence.
- [`TEST_SCENARIOS.md`](./TEST_SCENARIOS.md) — enumerated test coverage for this spec.
- [`AGENT_AUTH.md`](./AGENT_AUTH.md) — how AI-agent authorization layers on top of this model.

---

## 1. Conceptual overview

Hearth uses **claims-based role-based access control (RBAC)**. A user accumulates *permissions* — named strings like `docs.edit` or `hearth.admin` — by being assigned *roles* directly or by belonging to *groups* that are assigned roles. Permissions are resolved when an access token is issued and embedded in the token as a claim. Clients read permissions synchronously from the token; servers verify tokens and authorize requests against the same claim.

Three intentional boundaries:

1. **Hearth answers "what roles, groups, and permissions does this user have."** Apps answer "can this user do this action on this specific resource, given its state." Resource-specific authorization (ownership checks, quota enforcement, business rules) lives in the application layer with Hearth claims as one input.
2. **No graph-structured ACLs, no delegated sharing, no per-object grants.** Teams that need those semantics pair Hearth with a dedicated ReBAC service (SpiceDB, OpenFGA). Hearth does not attempt to own that problem.
3. **Short-lived tokens, eventually-consistent revocation.** Permission changes take effect on next access-token refresh. For emergency revocation, session revocation invalidates all tokens immediately. Operators choose access-token TTL per security posture.

This matches the authorization pattern used by Auth0, Clerk, Keycloak, Okta, and Firebase Auth.

---

## 2. Conceptual model

### 2.1 Entities

| Entity | Description | Scope |
|--------|-------------|-------|
| **Realm** | Top-level tenant boundary. Every entity below lives in exactly one realm. | Global |
| **Organization** | B2B customer grouping within a realm. Has memberships with `owner` / `admin` / `member` role assignment shortcuts. | Realm |
| **User** | A human or machine principal. | Realm |
| **Group** | Named collection of users and/or other groups. Resolves transitively. | Realm |
| **Role** | Named set of permissions, plus optional parent roles. Composes through parent chains. | Realm |
| **Permission** | Dot-delimited string identifier (`docs.edit`, `org.billing.view`). Not a first-class entity; a validated string. | Realm (implicit via `tid`) |
| **RoleAssignment** | Binds `(user or group, role, scope)`. Scope is realm-level or org-level. | Realm, with org narrowing |
| **GroupMembership** | Edge from a group to a user or another group. | Realm |

### 2.2 Relationship diagram

```text
                    ┌────────┐
                    │  User  │
                    └───┬────┘
                        │ (member of)
                        ▼
                   ┌─────────┐            ┌──────────┐
                   │  Group  │ ◀───────▶  │  Group   │  (groups may nest)
                   └────┬────┘            └──────────┘
                        │ (member of)
                        ▼
              ┌─────────────────────┐
              │   RoleAssignment    │  ← users and groups are assigned roles
              │   (role, scope)     │
              └──────────┬──────────┘
                         │ (resolves to)
                         ▼
                    ┌─────────┐
                    │  Role   │ ◀─────┐
                    └────┬────┘       │ (role includes other roles)
                         │            │
                         └────────────┘
                         │
                         │ (grants)
                         ▼
                    ┌─────────────┐
                    │ Permission  │  (string identifier)
                    └─────────────┘
```

### 2.3 Composition rules

- **Roles compose.** A role MAY include one or more parent roles; its effective permission set is the union of its own permissions and its parents' effective permission sets. Parent-role chains are cycle-detected and bounded in depth.
- **Groups nest.** A group MAY contain users, other groups, or both. Membership resolves transitively — if user U is a member of group A, and group A is a member of group B, then U is a member of B for resolution purposes. Group graphs are cycle-detected and bounded in depth and breadth.
- **Permission strings are flat.** A permission is a validated string, not a hierarchy. The dotted notation (`docs.edit`) is a readability convention, not a prefix-matching semantic. `docs.edit` does not grant `docs.edit.comments`.

### 2.4 Scope

Role assignments carry a scope:

- **Realm-scoped.** The assignment applies whenever the user acts in the realm. Permissions granted by realm-scoped assignments appear in all access tokens for that user in that realm.
- **Org-scoped.** The assignment applies only when the user acts in the context of the specified organization. Permissions granted by org-scoped assignments appear ONLY when the token is issued with an `oid` (organization context) matching the scope's org.

Resolution NEVER crosses realm boundaries. A role in realm A cannot be resolved in realm B, even for the same user.

### 2.5 Permission string grammar

Permissions MUST match: `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`

- Dot-delimited lowercase segments.
- Each segment starts with a letter, continues with letters/digits/underscores.
- Maximum total length: 128 characters.
- Reserved namespace: `hearth.*` is engine-level and only grantable by Hearth itself or by roles seeded at realm bootstrap. Operator-defined roles MUST NOT include `hearth.*` permissions.
- Convention: `realm.*` for realm administration, `org.*` for organization-scoped permissions, everything else app-defined.

### 2.6 Caps and bounds

| Bound | Value | Rationale |
|-------|-------|-----------|
| Role composition depth | 10 hops | Bounds resolution cost; catches pathological configs. |
| Group membership depth | 10 hops | Same. |
| Group membership breadth | 1000 groups per user | Per-user transitive membership count. |
| Permissions per token | 100 | JWT size control; hard cap. |
| Role names per token | 50 | JWT size control. |
| Group names per token | 50 | JWT size control. |
| Serialized JWT claim bytes (`roles + groups + permissions`) | 8 KiB | JWT size control; tighter of the three limits wins. |
| Permission string length | 128 chars | Engine-level validation. |

Exceeding any bound at token-issue time causes issuance to fail with a structured error naming the violating entity. See [§ 5.4](#54-size-overflow).

---

## 3. Resolution algorithm

Given a user, realm, optional organization, and optional requested OAuth scope, resolve the effective permission set:

```text
resolve_permissions(user_id, realm_id, maybe_org_id, requested_scope) -> Set<Permission>:
    # 1. Transitive group membership (BFS, cycle-detected).
    user_groups := bfs_groups(user_id, realm_id, max_depth=10, max_breadth=1000)

    # 2. Collect all reachable role assignments.
    assignments := []
    for subject in {user_id} ∪ user_groups:
        for ra in get_role_assignments(subject, realm_id):
            if ra.scope is Realm:
                assignments.push(ra)
            elif ra.scope is Org(oid) and maybe_org_id == oid:
                assignments.push(ra)

    # 3. Expand role composition (DFS with visited set; depth ≤ 10).
    roles := set()
    for ra in assignments:
        expand_role(ra.role, roles, max_depth=10)

    # 4. Flatten to permission set.
    perms := set()
    for role in roles:
        perms ∪= role.permissions

    # 5. Scope down if requested.
    if requested_scope is Some(scope):
        scope_perms := scope_to_permissions(scope, realm_id)
        perms := perms ∩ scope_perms

    return perms
```

Cycle detection tracks visited groups and roles separately. Exceeding any bound returns a structured error identifying the specific entity and limit.

### 3.1 Worked example

**Setup in realm `acme`:**
- User `alice`
- Group `engineers`, group `leads` (where `leads` is a member of `engineers`)
- `alice` is a direct member of `leads`
- Role `docs.editor` grants permissions `{docs.view, docs.edit}`
- Role `docs.admin` includes parent role `docs.editor` and additionally grants `{docs.delete}`
- Role assignments: `engineers → docs.editor` (realm-scoped), `leads → docs.admin` (realm-scoped)

**Resolution:**
1. Transitive groups for alice: `{leads, engineers}` (via `leads ∈ engineers`).
2. Role assignments reachable: `engineers→docs.editor`, `leads→docs.admin`.
3. Role expansion: `{docs.admin, docs.editor}` (docs.admin pulls in docs.editor).
4. Permission union: `{docs.view, docs.edit, docs.delete}`.
5. No requested scope narrowing.

Final permission set: `{docs.view, docs.edit, docs.delete}`.

### 3.2 Complexity

- Group BFS: O(G) where G is the number of groups reachable from the user.
- Role DAG expansion: O(R) where R is the number of roles reachable from any assignment.
- Permission union: O(P) where P is the total permissions across resolved roles.
- Overall: O(G + R + P), bounded by the caps above. In practice, dominated by small constants; resolution runs on the token-issue path, NOT the hot read path.

---

## 4. Storage model

### 4.1 Keys

All RBAC state lives under the `rba:` storage-key prefix. Keys are realm-scoped by embedding `RealmId` in the key wherever resolution must be realm-bounded.

| Key pattern | Purpose |
|-------------|---------|
| `rba:role:{role_id}` | Role primary record |
| `rba:role:name:{realm_id}:{name}` | Name-lookup index for roles within a realm |
| `rba:group:{group_id}` | Group primary record |
| `rba:group:slug:{realm_id}:{slug}` | Slug-lookup index for groups within a realm |
| `rba:assign:user:{user_id}:{assignment_id}` | Role assignments indexed by subject user |
| `rba:assign:group:{group_id}:{assignment_id}` | Role assignments indexed by subject group |
| `rba:assign:role:{role_id}:{assignment_id}` | Reverse index for "who has this role" queries |
| `rba:gm:group:{group_id}:member:{member_type}:{member_id}` | Forward index: group → members |
| `rba:gm:member:{member_type}:{member_id}:group:{group_id}` | Reverse index: member → containing groups |
| `rba:perm:{realm_id}:{permission}` | Permission-name registry (for admin listings and validation) |
| `rba:scope:{realm_id}:{scope_name}` | Scope → permission set mapping |

### 4.2 Realm-scope guarantees

Every key either contains `{realm_id}` directly or is reachable only through a record that carries a realm ID. Scans are bounded to a single realm's key space per [ARCHITECTURE.md § 7](./ARCHITECTURE.md). Cross-realm resolution is impossible through the `RbacEngine` trait.

### 4.3 Seed data

On realm creation, the engine writes a minimal starter set (see [§ 9](#9-bootstrap-and-seed-data) for exact contents). First-user auto-assignment of `realm.admin` is part of realm onboarding, not RBAC engine scope.

---

## 5. JWT claim schema

### 5.1 TokenClaims shape

Access tokens (and refresh tokens where applicable) carry these claims:

```json
{
  "sub":         "user_<uuid>",
  "iss":         "https://hearth.example.com",
  "aud":         "hearth",
  "exp":         1700000900,
  "iat":         1700000840,
  "sid":         "<session_uuid>",
  "tid":         "<realm_uuid>",
  "oid":         "<org_uuid>",
  "token_type":  "access",
  "jti":         "<token_uuid>",
  "scope":       "read write docs",
  "roles":       ["realm.admin", "org.member"],
  "groups":      ["leads", "engineering"],
  "permissions": ["docs.view", "docs.edit", "docs.delete", "hearth.admin"]
}
```

**Field notes:**

- `tid` (realm ID) is mandatory and implicit in every permission check.
- `oid` (organization ID) is present ONLY when the token was issued in an organization context. Its presence MAY enable org-scoped role assignments (see [§ 2.4](#24-scope)).
- `roles` and `groups` carry **names** (not IDs) for legibility in SDKs and debugging. They are informational; the authoritative source for client-side authorization is `permissions`.
- `permissions` is the resolved flat set. Client SDK checks read exclusively from this field.
- Tokens MUST be signed with Ed25519 per [ARCHITECTURE.md § 8.1](./ARCHITECTURE.md).

### 5.2 Example: typical user token

User `alice` in realm `acme`, org `acme-corp`, with the role resolution from § 3.1:

```json
{
  "sub": "user_01HXYZ...",
  "tid": "realm_01HABC...",
  "oid": "org_01HDEF...",
  "token_type": "access",
  "exp": 1700000900,
  "iat": 1700000840,
  "sid": "sess_01HGHI...",
  "jti": "tok_01HJKL...",
  "scope": "openid profile docs",
  "roles": ["docs.admin"],
  "groups": ["leads", "engineers"],
  "permissions": ["docs.view", "docs.edit", "docs.delete"]
}
```

### 5.3 Example: scope-narrowed client credentials token

Machine client with client credentials grant, requesting `scope=docs`:

```json
{
  "sub": "client_01HMNO...",
  "tid": "realm_01HABC...",
  "token_type": "access",
  "exp": 1700003600,
  "iat": 1700000000,
  "jti": "tok_01HPQR...",
  "scope": "docs",
  "roles": ["docs.editor"],
  "groups": [],
  "permissions": ["docs.view", "docs.edit"]
}
```

(`hearth.admin` is filtered out because the requested scope `docs` narrowed the token to `docs.*` permissions only.)

### 5.4 Size overflow

If the resolved claim set exceeds any bound from [§ 2.6](#26-caps-and-bounds), token issuance fails with:

```
HTTP 400 Bad Request
{
  "error": "token_too_large",
  "error_description": "resolved permission set exceeds size limit",
  "limit": "permissions_per_token",
  "limit_value": 100,
  "actual_value": 127,
  "remediation": "narrow the request via OAuth scope, or split the user's role assignments across scoped tokens"
}
```

Clients handle this by requesting narrower scopes (`scope=docs` rather than `scope=all`). Operators addressing it persistently should audit the user's role assignments for over-broad roles.

---

## 6. Engine API — `src/rbac/`

### 6.1 Module layout

```
src/rbac/
├── mod.rs       # Public trait RbacEngine + re-exports. No implementation.
├── types.rs     # Role, Group, Permission, RoleAssignment, GroupMembership, Scope.
├── error.rs     # RbacError enum.
├── engine.rs    # EmbeddedRbacEngine (storage-backed implementation).
├── resolve.rs   # resolve_permissions + BFS/DFS + cycle detection.
├── keys.rs      # Storage-key encoding (pub(crate)).
└── seed.rs      # Bootstrap role/permission installer.
```

Per [ARCHITECTURE.md § 13](./ARCHITECTURE.md), `mod.rs` contains ONLY the trait, re-exports, and module declarations.

### 6.2 Trait

```rust
pub trait RbacEngine: Send + Sync {
    // --- Permission resolution ---

    /// Resolves the effective permission set for a user at token-issue time.
    /// Honors realm and optional org scope; if `requested_scope` is Some,
    /// intersects with the scope's declared permission set.
    fn resolve_permissions(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scope: Option<&str>,
    ) -> Result<ResolvedPermissions, RbacError>;

    // --- Roles ---

    fn create_role(&self, realm_id: &RealmId, req: &CreateRoleRequest)
        -> Result<Role, RbacError>;
    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId)
        -> Result<Option<Role>, RbacError>;
    fn get_role_by_name(&self, realm_id: &RealmId, name: &str)
        -> Result<Option<Role>, RbacError>;
    fn update_role(&self, realm_id: &RealmId, role_id: &RoleId, req: &UpdateRoleRequest)
        -> Result<Role, RbacError>;
    fn delete_role(&self, realm_id: &RealmId, role_id: &RoleId)
        -> Result<(), RbacError>;
    fn list_roles(&self, realm_id: &RealmId, cursor: Option<&str>, limit: usize)
        -> Result<Page<Role>, RbacError>;

    // --- Groups ---

    fn create_group(&self, realm_id: &RealmId, req: &CreateGroupRequest)
        -> Result<Group, RbacError>;
    fn get_group(&self, realm_id: &RealmId, group_id: &GroupId)
        -> Result<Option<Group>, RbacError>;
    fn update_group(&self, realm_id: &RealmId, group_id: &GroupId, req: &UpdateGroupRequest)
        -> Result<Group, RbacError>;
    fn delete_group(&self, realm_id: &RealmId, group_id: &GroupId)
        -> Result<(), RbacError>;
    fn list_groups(&self, realm_id: &RealmId, cursor: Option<&str>, limit: usize)
        -> Result<Page<Group>, RbacError>;

    fn add_group_member(&self, realm_id: &RealmId, group_id: &GroupId, member: &GroupMember)
        -> Result<GroupMembership, RbacError>;
    fn remove_group_member(&self, realm_id: &RealmId, group_id: &GroupId, member: &GroupMember)
        -> Result<(), RbacError>;
    fn list_group_members(&self, realm_id: &RealmId, group_id: &GroupId, cursor: Option<&str>, limit: usize)
        -> Result<Page<GroupMember>, RbacError>;

    // --- Assignments ---

    fn assign_role(&self, realm_id: &RealmId, req: &AssignRoleRequest)
        -> Result<RoleAssignment, RbacError>;
    fn unassign_role(&self, realm_id: &RealmId, assignment_id: &AssignmentId)
        -> Result<(), RbacError>;
    fn list_user_assignments(&self, realm_id: &RealmId, user_id: &UserId)
        -> Result<Vec<RoleAssignment>, RbacError>;
    fn list_group_assignments(&self, realm_id: &RealmId, group_id: &GroupId)
        -> Result<Vec<RoleAssignment>, RbacError>;
    fn list_role_members(&self, realm_id: &RealmId, role_id: &RoleId, cursor: Option<&str>, limit: usize)
        -> Result<Page<RoleSubject>, RbacError>;

    // --- Bootstrap ---

    /// Installs the default role/permission/scope seed for a new realm.
    /// Idempotent: re-running on a realm with existing seed state is a no-op.
    fn seed_realm(&self, realm_id: &RealmId) -> Result<(), RbacError>;
}
```

### 6.3 Types

```rust
pub struct Role {
    pub id: RoleId,
    pub realm_id: RealmId,
    pub name: String,              // unique per realm, e.g. "docs.admin"
    pub description: Option<String>,
    pub permissions: Vec<Permission>,
    pub parent_roles: Vec<RoleId>, // composition edges
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub struct Group {
    pub id: GroupId,
    pub realm_id: RealmId,
    pub name: String,
    pub slug: String,              // URL-safe, unique per realm
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub enum GroupMember {
    User(UserId),
    Group(GroupId),
}

pub struct GroupMembership {
    pub group_id: GroupId,
    pub member: GroupMember,
    pub added_at: Timestamp,
    pub added_by: Option<UserId>,
}

pub enum Subject {
    User(UserId),
    Group(GroupId),
}

pub enum Scope {
    Realm,                      // applies realm-wide
    Org(OrganizationId),        // applies only in this org context
}

pub struct RoleAssignment {
    pub id: AssignmentId,
    pub realm_id: RealmId,
    pub subject: Subject,
    pub role_id: RoleId,
    pub scope: Scope,
    pub assigned_at: Timestamp,
    pub assigned_by: Option<UserId>,
}

pub struct Permission(String);  // validated via § 2.5 grammar

pub struct ResolvedPermissions {
    pub roles: Vec<String>,       // role names, de-duplicated
    pub groups: Vec<String>,      // group slugs, de-duplicated
    pub permissions: Vec<Permission>, // sorted, de-duplicated
}
```

### 6.4 Errors

```rust
#[non_exhaustive]
pub enum RbacError {
    RoleNotFound,
    GroupNotFound,
    AssignmentNotFound,
    DuplicateRoleName,
    DuplicateGroupSlug,
    InvalidPermission { reason: String },
    InvalidRoleName { reason: String },
    InvalidGroupSlug { reason: String },
    CycleDetected { kind: CycleKind, entity: String },
    DepthExceeded { kind: TraversalKind, limit: usize },
    BreadthExceeded { kind: TraversalKind, limit: usize },
    TokenSizeExceeded { limit: String, limit_value: usize, actual: usize },
    ReservedNamespace { permission: String },
    Storage(Box<dyn std::error::Error + Send + Sync>),
    // ...
}
```

Per [ARCHITECTURE.md § 5](./ARCHITECTURE.md), `RbacError` does not cross layer boundaries as a concrete type; upper layers (protocol, identity) convert via `From` into their own error types.

### 6.5 Storage dependency

The embedded engine uses the same `StorageEngine` trait as the identity layer. No new storage dependency. No dedicated WAL segment; batch writes work through the existing `put_batch` API.

### 6.6 Cache strategy

The engine does NOT maintain an internal permission cache. `resolve_permissions` is called at token issuance (off the hot path) and its result is embedded in the JWT. The JWT itself is the cache, valid for the token's lifetime. This avoids the cache-invalidation class of bugs while still delivering synchronous authorization on the client.

---

## 7. Token issuance integration

### 7.1 Where permissions populate

In `src/identity/tokens.rs`, `IssueTokenRequest` gains fields populated by the identity engine before calling `SigningKey::issue_token_pair`:

```rust
pub struct IssueTokenRequest<'a> {
    // existing: sub, iss, aud, sid, tid, scope, nonce, ...
    pub oid: Option<&'a str>,
    pub roles: &'a [String],
    pub groups: &'a [String],
    pub permissions: &'a [String],
}
```

### 7.2 Call path

```
POST /token  (or any grant flow)
    ↓
identity::issue_tokens(realm, user, session, org, requested_scope)
    ↓
rbac::resolve_permissions(user, realm, org, requested_scope)  ← NEW
    ↓ returns ResolvedPermissions
identity::validate_token_size(resolved)  ← enforces caps § 2.6
    ↓
identity::build_claims(user, session, realm, org, resolved)
    ↓
SigningKey::issue_token_pair(claims)
```

### 7.3 OAuth scope handling

`POST /token` accepts the standard OAuth 2.0 `scope` parameter. The identity engine passes it to `resolve_permissions` as `requested_scope`. Scope-to-permission mapping is realm config (see [CONFIGURATION.md](./CONFIGURATION.md) and [§ 9.3](#93-scope-to-permission-mapping)).

A scope value NOT mapped in realm config results in an empty intersection — the token is issued with zero permissions. A missing `scope` parameter means "no narrowing"; the full resolved set is embedded.

---

## 8. HTTP and gRPC API

### 8.1 Bearer-authenticated user endpoints

#### `GET /v1/me/permissions`

Returns the freshly-resolved permission set for the bearer-token user. Used by backends that want to confirm current permissions during long-running operations rather than trusting a possibly-stale JWT.

**Headers:**
- `Authorization: Bearer <access_token>` — required.
- `X-Realm-ID: <realm_uuid>` — required.

**Response 200:**
```json
{
  "roles": ["docs.admin"],
  "groups": ["leads", "engineers"],
  "permissions": ["docs.view", "docs.edit", "docs.delete"],
  "scope": "docs openid profile"
}
```

**Errors:**
- `401` — missing / invalid / expired token.
- `400` — missing `X-Realm-ID` or token-realm mismatch.

### 8.2 Admin endpoints

All admin endpoints require the `hearth.admin` permission in the caller's access token.

#### Roles

- `GET /admin/roles?cursor=...&limit=...` — list realm roles.
- `POST /admin/roles` — create a role.
  ```json
  { "name": "docs.editor", "description": "Edit docs.",
    "permissions": ["docs.view", "docs.edit"],
    "parent_roles": ["docs.viewer"] }
  ```
- `GET /admin/roles/{id}` — fetch a role.
- `PATCH /admin/roles/{id}` — update name/description/permissions/parents.
- `DELETE /admin/roles/{id}` — delete a role (fails if it is assigned or is a parent of another role; use `?cascade=true` to remove assignments and parent links in the same transaction).

#### Groups

- `GET /admin/groups?cursor=...&limit=...` — list realm groups.
- `POST /admin/groups` — create a group.
  ```json
  { "name": "Engineering Leads", "slug": "leads", "description": "..." }
  ```
- `GET /admin/groups/{id}` — fetch a group.
- `PATCH /admin/groups/{id}` — update fields.
- `DELETE /admin/groups/{id}` — delete a group (cascades memberships and assignments).
- `GET /admin/groups/{id}/members?cursor=...&limit=...` — list members (users + nested groups).
- `POST /admin/groups/{id}/members` — add a member. Body: `{"type": "user", "id": "user_..."}` or `{"type": "group", "id": "group_..."}`.
- `DELETE /admin/groups/{id}/members/{member_type}/{member_id}` — remove.

#### Role assignments

- `POST /admin/users/{user_id}/roles` — assign a role to a user.
  ```json
  { "role_id": "role_...", "scope": { "type": "realm" } }
  ```
  or
  ```json
  { "role_id": "role_...", "scope": { "type": "org", "org_id": "org_..." } }
  ```
- `DELETE /admin/users/{user_id}/roles/{assignment_id}` — remove an assignment.
- `GET /admin/users/{user_id}/roles` — list the user's assignments.
- `GET /admin/users/{user_id}/effective-permissions?org_id=...&scope=...` — resolve and return what the user WOULD receive in a token with those parameters. Support/debug aid.
- `POST /admin/groups/{group_id}/roles` — assign a role to a group. Same body shape as the user variant.
- `DELETE /admin/groups/{group_id}/roles/{assignment_id}` — remove.
- `GET /admin/roles/{role_id}/members?cursor=...&limit=...` — list subjects (users + groups) assigned this role.

### 8.3 Error envelope

All endpoints return errors in the shared envelope:
```json
{ "error": "<code>", "error_description": "<human message>", ...extra }
```
Extra fields MAY include `limit`, `limit_value`, `actual_value`, `remediation` for size errors, and `entity` / `path` for cycle errors.

### 8.4 gRPC

The gRPC admin surface exposes RPCs matching the HTTP endpoints one-to-one under a service named `RbacAdminService`. Message shapes mirror the HTTP JSON bodies, generated from `proto/hearth/rbac/v1/rbac.proto`. Auth is bearer metadata, same as existing gRPC admin services. There is NO service-to-service `Check` RPC — callers decode the JWT's `permissions` claim locally.

### 8.5 Multi-tenancy

Every endpoint requires a realm context (bearer-token `tid` for user endpoints, `X-Realm-ID` header for admin endpoints where the caller's realm does not match the target). Cross-realm admin operations require per-request explicit targeting and a corresponding `hearth.admin` grant in the admin's token; see [§ 10](#10-multi-tenancy-invariants).

---

## 9. Bootstrap and seed data

### 9.1 Seed permissions

Every fresh realm has these permissions registered:

- `hearth.admin` — realm-level admin authority. Reserved; only granted via seed roles.
- `realm.read`, `realm.write`, `realm.admin` — realm configuration read/write.
- `org.read`, `org.write`, `org.admin`, `org.billing` — organization-scoped administration.
- `user.read`, `user.write`, `user.impersonate` — user administration.

Operator-added realms, groups, and user roles extend this set via config or admin API.

### 9.2 Seed roles

| Role name | Permissions | Notes |
|-----------|-------------|-------|
| `realm.admin` | `hearth.admin`, `realm.*`, `org.*`, `user.*` | Full realm admin. |
| `realm.member` | — (empty by default) | Default role for authenticated users; app-customizable. |
| `org.owner` | `org.read`, `org.write`, `org.admin`, `org.billing` | Scoped to one org per assignment. |
| `org.admin` | `org.read`, `org.write`, `org.admin` | Scoped to one org per assignment. |
| `org.member` | `org.read` | Scoped to one org per assignment. |

`org.owner` includes `org.admin` as a parent, which includes `org.member`. Composition is explicit in seed data so operators can see the full chain.

### 9.3 Scope-to-permission mapping (default)

| OAuth scope value | Permission glob |
|-------------------|-----------------|
| `openid` | (no permission filter; identifier only) |
| `profile` | (no permission filter) |
| `email` | (no permission filter) |
| `admin` | `hearth.*`, `realm.*`, `user.*` |
| `org` | `org.*` |
| (any custom value) | (operator-defined in realm config) |

"Glob" here is literal string prefix-plus-dot or exact-match; no regex. `admin` → matches `realm.admin`, `realm.read`, etc.

### 9.4 First-user assignment

When the first user is created in a fresh realm (via onboarding, admin bootstrap, or migration importer), the identity engine creates a realm-scoped `realm.admin` assignment for that user via `RbacEngine::assign_role`. Subsequent users have no default assignment; app-level flows (invitation acceptance, self-registration) decide what role they receive.

### 9.5 Declarative config

Operators MAY declaratively specify roles, permissions, groups, and scope mappings in realm YAML. See [CONFIGURATION.md § RBAC](./CONFIGURATION.md) for the full shape. Example:

```yaml
realms:
  acme:
    rbac:
      permissions:
        - docs.view
        - docs.edit
        - docs.delete
      roles:
        - name: docs.viewer
          permissions: [docs.view]
        - name: docs.editor
          permissions: [docs.view, docs.edit]
          parents: [docs.viewer]
        - name: docs.admin
          permissions: [docs.delete]
          parents: [docs.editor]
      groups:
        - name: Engineering
          slug: engineering
      scopes:
        docs: [docs.*]
```

Declarative config is reconciled at startup: roles/groups declared in YAML are created if missing, updated if drifted. YAML-managed entities MUST NOT be edited via admin API; the admin API refuses mutations on them with a clear error referencing the YAML source of truth.

---

## 10. Multi-tenancy invariants

The following MUST hold:

1. **Every RBAC operation requires a `RealmId`.** The `RbacEngine` trait does not expose any method that can be called without a realm parameter.
2. **All RBAC storage keys embed or are reachable only via a `RealmId`.** No cross-realm scans are possible through the engine.
3. **Resolution never crosses realms.** A role in realm A is invisible during resolution in realm B, even for the same user principal. Realm boundaries are enforced by the resolver, verified by property tests, and backed by debug-mode runtime assertions.
4. **A token issued in realm A MUST NOT grant any permission in realm B.** Callers verifying tokens MUST validate the `tid` claim against the expected realm.
5. **Cross-realm admin operations are explicit.** An admin acting across realms MUST hold `hearth.admin` in a token targeted at the appropriate realm; the admin service MUST NOT perform implicit cross-realm writes.

These mirror the isolation invariants in [ARCHITECTURE.md § 7](./ARCHITECTURE.md).

---

## 11. SDK contract

This section is normative for every Hearth SDK. "The SDK" refers to any language binding (TypeScript, Go, Python, Ruby, etc.) that apps use to consume Hearth tokens and admin APIs.

### 11.1 Required primary surface

Every SDK MUST expose these synchronous methods on the main client object:

```ts
hearth.hasPermission(permission: string): boolean
hearth.hasRole(role: string): boolean
hearth.inGroup(group: string): boolean
hearth.inOrg(org: string): boolean
```

- All return a boolean, synchronously, with zero network calls.
- All read exclusively from the decoded JWT claims.
- `hasPermission` matches an exact permission string (no glob, no prefix).
- `hasRole` matches an exact role name.
- `inGroup` matches an exact group slug.
- `inOrg` matches the `oid` claim exactly.
- When no token is present (unauthenticated), ALL four return `false`.

### 11.2 Client construction

```ts
const hearth = createHearth({
  baseUrl: "https://auth.example.com",
  realmId: "<realm_uuid>",
  getToken: () => currentAccessToken,
});
```

- `getToken` is called synchronously on every check; SDKs MUST NOT cache the token internally. Tokens change via the app's auth flow; the getter is the contract.
- `baseUrl` and `realmId` are used only for the server-side introspection escape hatch (§ 11.5) and admin client construction (§ 11.6).

### 11.3 Reactive framework bindings

Every reactive SDK (React, Vue, Svelte, SwiftUI, etc.) MUST expose hook/composable/property-wrapper equivalents of the four primary methods:

```tsx
// React
const canEdit = useHasPermission("docs.edit");
const isAdmin = useHasRole("realm.admin");
const inLeads = useInGroup("leads");
const inAcme = useInOrg("acme-corp");
```

- Return the same boolean as the imperative method.
- NO loading state, NO tri-state (`true | false | undefined`). The JWT is in memory already; there is nothing to load.
- Re-render when the underlying token changes (caller swaps `getToken` or calls `hearth.refresh()`).

### 11.4 Permission decoding

SDKs MUST decode JWTs locally using a small JOSE / JWT library (`jose` for TS, `golang-jwt` for Go, etc.). SDKs MUST verify the JWT signature against the realm's JWKS on token ingestion and reject unsigned or tampered tokens. SDKs MUST NOT call `/v1/me/permissions` for routine `hasPermission` checks — that endpoint is the escape hatch, not the primary path.

### 11.5 Escape hatch: live introspection

For cases where the app wants the live permission set (e.g. long-running background job double-checking before a sensitive action):

```ts
const { permissions, roles, groups } = await hearth.client.permissions();
```

Wraps `GET /v1/me/permissions`. Returns the same shape as `hasPermission`/`hasRole`/etc. read from, but freshly resolved by the server. This is rarely needed; document as "use when you can't trust the cached JWT."

### 11.6 Admin client (separate)

Admin operations (role/group/assignment CRUD) live on a distinct `AdminClient`:

```ts
const admin = hearth.admin(adminAccessToken);
await admin.createRole({ name: "docs.editor", permissions: [...] });
```

The user-facing `hearth` client MUST NOT expose admin mutation methods. This is a separation of concerns boundary: regular app code should not accidentally hold an admin surface.

### 11.7 Error shape

All SDK errors MUST be a typed `HearthError` with:

```ts
interface HearthError {
  status: number;           // HTTP status (or 0 for network errors)
  code: string;             // machine-readable: "invalid_token", "forbidden", etc.
  message: string;          // human-readable
  details?: Record<string, unknown>;  // MAY include limit/entity/etc.
}
```

Network errors surface as `HearthError` with `status: 0`, not as the host language's raw network exception.

### 11.8 Prohibitions

SDKs MUST NOT:

- Poll any endpoint for permission changes.
- Hold persistent connections (SSE, WebSocket, gRPC streams) for cache coherence.
- Accept a `subject` parameter in any check method — the subject is always the bearer-token user, enforced by the token itself.
- Expose vocabulary from prior tuple-based authorization models. Those concepts are not part of Hearth's authorization surface.
- Persist decoded permissions to disk or across process restarts. Tokens are short-lived; persistence is the app's responsibility if required.

### 11.9 Testing requirements

Every SDK MUST ship:

- A unit-test suite using an HTTP mock (not a live server), covering: JWT decoding, `hasPermission`/`hasRole`/`inGroup`/`inOrg` returning correct booleans for given tokens, tokens missing claims defaulting to `false`, invalid JWT signature rejected, admin client CRUD against mocked responses.
- At least one live-server integration test covering: create realm → create user → assign role → issue token → verify `hasPermission` returns `true` → unassign role → refresh → verify `hasPermission` returns `false`.
- Reactive binding tests (where applicable) using the framework's test harness, covering: hook returns the correct boolean, re-renders on token change.

---

## 12. Non-goals and escape hatches

**Non-goals (Hearth does NOT do these):**

- Resource-specific authorization ("can Alice edit *this* doc given its state"). Apps do this using claims plus their own data.
- Graph-structured ACLs with delegated sharing (the Google Drive pattern). Use a dedicated authorization service (SpiceDB, OpenFGA, Cerbos) alongside Hearth.
- Policy-as-code (Cedar, Rego, Polar). Apps MAY layer these on top of claims; Hearth does not ship a policy engine.
- Real-time permission change propagation to connected clients. Change-on-refresh is the mechanism.
- Cross-realm permission inheritance. Realms are hard isolation boundaries.

**Escape hatches (supported but advanced):**

- `GET /v1/me/permissions` for backends that want live resolution.
- Admin `GET /admin/users/{id}/effective-permissions` for support/debug introspection.
- YAML-declarative role/permission setup for GitOps-managed realms.
- Org-scoped role assignments for B2B multi-tenant shapes where a user belongs to multiple orgs with different roles in each.

---

## 13. Cross-references

- [`ARCHITECTURE.md § 1`](./ARCHITECTURE.md) — module placement (`src/rbac/` as a peer of `src/identity/`).
- [`ARCHITECTURE.md § 3`](./ARCHITECTURE.md) — hot path rules (RBAC resolution is OFF the hot path; token claim reads are on it).
- [`ARCHITECTURE.md § 4.2`](./ARCHITECTURE.md) — wire protocol rules.
- [`ARCHITECTURE.md § 5`](./ARCHITECTURE.md) — error policy; `RbacError` follows the standard pattern.
- [`ARCHITECTURE.md § 7`](./ARCHITECTURE.md) — multi-tenancy invariants.
- [`CONFIGURATION.md`](./CONFIGURATION.md) — declarative YAML for realms, roles, permissions, groups, scopes.
- [`TEST_SCENARIOS.md`](./TEST_SCENARIOS.md) — enumerated test checklist.
- [`AGENT_AUTH.md`](./AGENT_AUTH.md) — how agent-specific authorization layers on top.
- [`IMPLEMENTATION_ORDER.md`](./IMPLEMENTATION_ORDER.md) — where RBAC work falls in the build sequence.
