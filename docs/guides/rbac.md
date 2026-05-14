# RBAC Guide

**Audience:** developers and operators who need to create roles, assign permissions, manage groups, and understand how authorization claims appear in Hearth JWTs.

Hearth uses **claims-based RBAC**: permissions are resolved at token-issue time and embedded in the JWT. Downstream services read permissions synchronously from the verified token — no network call to Hearth at authorization time.

## Concepts

### The four entities

| Entity | Description |
|--------|-------------|
| **Permission** | A dot-delimited string (`docs.edit`, `org.billing.view`). Not a first-class DB row; validated at write time and stored inside roles. |
| **Role** | A named set of permissions. Roles can include parent roles for composition. |
| **Group** | A named collection of users and/or other groups. Membership is transitive. |
| **RoleAssignment** | Binds a subject (user or group) to a role within a scope (realm-level or org-level). |

Hearth answers *"what roles, groups, and permissions does this user have."* Resource-specific authorization (ownership, quotas, business rules) lives in your application, using Hearth claims as input.

### Permission string grammar

Permissions must match `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$`:

- At least one dot (two or more non-empty segments).
- Segments contain ASCII alphanumerics, `_`, and `-`. No spaces, `/`, `:`, or `?`.
- Maximum 128 characters.
- Reserved namespace: `hearth.*` is engine-level only; operator roles must not include it.
- Dotted notation is a **readability convention, not a hierarchy**. `docs.edit` does not grant `docs.edit.comments`.

```
✔ docs.edit
✔ org.billing.view
✔ user.self.write
✘ admin           (single segment — use system.admin)
✘ docs:edit       (colon forbidden)
✘ hearth.admin    (reserved namespace)
```

### JWT claims

After resolving permissions, Hearth embeds three claims in the issued JWT:

```json
{
  "roles":       ["editor", "billing-viewer"],
  "groups":      ["engineers", "leads"],
  "permissions": ["docs.edit", "docs.view", "org.billing.view"]
}
```

`roles` and `groups` carry **names/slugs** (not IDs) for SDK legibility. `permissions` is the authoritative authorization surface. All three arrays are sorted and de-duplicated.

### Scope

Role assignments carry a scope:

- **Realm-scoped** — assignment applies in all tokens for that user in that realm.
- **Org-scoped** — assignment applies only when the token is issued with a matching `org_id` parameter (see [Organizations guide](organizations.md)).

Resolution never crosses realm boundaries.

### Limits

| Bound | Value |
|-------|-------|
| Role composition depth | 10 hops |
| Group membership depth | 10 hops |
| Group membership breadth | 1 000 groups per user |
| Permissions per token | 100 |
| Role names per token | 50 |
| Group names per token | 50 |

Exceeding any limit causes token issuance to fail with a structured error naming the violating entity.

---

## Setting up RBAC

All examples require an admin token. In dev mode, bootstrap one with:

```bash
curl -X POST http://127.0.0.1:8420/admin/bootstrap
# Returns: { "token": "<admin-token>", "realm_id": "<realm-uuid>", ... }
```

Set environment variables for the examples:

```bash
HEARTH_ADMIN="Authorization: Bearer <admin-token>"
REALM="X-Realm-ID: <realm-uuid>"
```

### 1. Create permissions (via roles)

Permissions are not created independently; define them inside a role:

```bash
curl -X POST http://127.0.0.1:8420/admin/roles \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "docs-editor",
    "description": "Can view and edit documents",
    "permissions": ["docs.view", "docs.edit"],
    "parent_roles": [],
    "scope_kind": "realm"
  }'
```

`scope_kind` values: `"realm"` (default), `"organization"`, or `"any"`.

### 2. Compose roles via parent roles

```bash
curl -X POST http://127.0.0.1:8420/admin/roles \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "docs-admin",
    "description": "Full document control",
    "permissions": ["docs.delete"],
    "parent_roles": ["<docs-editor-role-id>"]
  }'
```

`docs-admin` effective permissions = `{docs.delete}` ∪ `{docs.view, docs.edit}` = `{docs.view, docs.edit, docs.delete}`.

### 3. Create a group

```bash
curl -X POST http://127.0.0.1:8420/admin/groups \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Documentation Team",
    "slug": "docs-team",
    "description": "Writers and editors"
  }'
```

### 4. Add a user to a group

```bash
curl -X POST http://127.0.0.1:8420/admin/groups/<group-id>/members \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{"type": "user", "id": "<user-id>"}'
```

Add a nested group:

```bash
-d '{"type": "group", "id": "<child-group-id>"}'
```

### 5. Assign a role to a user or group

**Realm-scoped assignment to a user:**

```bash
curl -X POST http://127.0.0.1:8420/admin/users/<user-id>/roles \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "<role-id>",
    "scope": {"type": "realm"}
  }'
```

**Org-scoped assignment to a group:**

```bash
curl -X POST http://127.0.0.1:8420/admin/users/<user-id>/roles \
  -H "$HEARTH_ADMIN" -H "$REALM" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "<role-id>",
    "scope": {"type": "org", "org_id": "<org-uuid>"}
  }'
```

Org-scoped permissions appear in the JWT only when the token is issued with a matching `org_id` query parameter.

### 6. Remove an assignment

```bash
curl -X DELETE http://127.0.0.1:8420/admin/assignments/<assignment-id> \
  -H "$HEARTH_ADMIN" -H "$REALM"
```

---

## Checking effective permissions

### Via the token itself

Decode the `permissions` claim from any valid access token. All standard JWT libraries work with Hearth's Ed25519-signed tokens.

```bash
# Fetch JWKS for signature verification
curl http://127.0.0.1:8420/jwks

# Decode and inspect claims (requires a JWT library)
```

### Admin API (resolve without issuing a token)

```bash
curl "http://127.0.0.1:8420/admin/users/<user-id>/effective-permissions" \
  -H "$HEARTH_ADMIN" -H "$REALM"
```

Response:

```json
{
  "roles": ["docs-admin", "docs-editor"],
  "groups": ["docs-team"],
  "permissions": ["docs.delete", "docs.edit", "docs.view"]
}
```

### Token endpoint (with scope narrowing)

Request a token with only the permissions mapped by a declared scope bundle:

```bash
curl -X POST http://127.0.0.1:8420/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&scope=docs"
```

If `docs` scope is configured to map to `{docs.view, docs.edit}`, the issued token's `permissions` claim is intersected with that set regardless of what the user was assigned.

---

## Admin console

Roles, groups, and assignments can also be managed through the Admin UI at `/ui/admin/`. The console supports bulk assignment and visualizes transitive group membership.

---

## Reference

- `docs/specs/AUTHORIZATION.md` — normative specification, algorithm, and all caps.
- `GET /admin/roles` — list roles (paginated, cursor-based).
- `GET /admin/groups` — list groups.
- `GET /admin/users/{id}/roles` — list a user's direct role assignments.
