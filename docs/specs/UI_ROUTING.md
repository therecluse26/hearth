# UI Routing — Admin Surfaces

**Status:** Normative. This document defines how realm context is bound to admin URLs.
**Owner:** Web UI module (`src/protocol/web/`).
**Test surface:** `tests/web_ui_admin.rs` and the `tests/admin_*.rs` family.

## Why this spec exists

Hearth is multi-tenant. Every admin operation is scoped to exactly one realm (or the system realm for cross-tenant operator pages). A long-standing source of bugs was that realm context was carried as a `?realm=<name>` query parameter that templates had to thread through every form action manually. HTMX form submissions do not inherit query strings from the page URL, so any form whose author forgot to append `?realm=` would silently route to the wrong realm — with no error surfaced to the operator.

This spec eliminates that bug class by making realm context part of the URL identity itself.

## Normative rules

### R-1: Realm is in the path, not the query string

Every realm-scoped admin URL MUST be of the form:

```
/ui/admin/realms/{realm_name}/{sub-resource}/...
```

Where `{realm_name}` is the realm's slug. The `TargetRealm` extractor recovers the realm from this path segment and from no other source (except R-3 below).

Realm-scoped surfaces are: users, groups, organizations, applications, sessions, audit, rbac, permission resolver, claims, realm-admin grants, realm deletion.

### R-2: System-scoped admin URLs

Admin pages that operate on system-wide state, or that span all realms, MUST live under `/ui/admin/...` with no realm in the path:

- `/ui/admin` — dashboard
- `/ui/admin/realms` — list of all realms
- `/ui/admin/admin-users` — system realm operators (this surface is itself a system-realm view; see R-3)
- `/ui/admin/admin-users/new` — create a system-realm operator
- `/ui/admin/settings/...` — global config editor
- `/ui/admin/api/config/reload` — config reload
- `/ui/admin/api/nav/realms` — sidebar realm tree
- `/ui/admin/test-email` — email transport test

### R-3: System realm sentinel

A system-realm view (operating on the realm whose UUID is `RealmId::nil()`) MUST be requested via the explicit query sentinel `?admin_target=system`. This is the only query-based realm signal that survives this refactor; it exists because the system realm has no path slug — it is a special-cased operator workspace.

The `admin-users` admin pages reuse the generic user-management handlers but with this sentinel; that is the only surface where this matters.

### R-4: Forbidden as realm names

A realm name MUST NOT collide with any first-segment sub-resource keyword used under `/ui/admin/realms/{name}/...`. The reserved set is:

```
admins
api
applications
audit
claims
delete
groups
new
organizations
permissions
rbac
sessions
settings
status
test-email
users
```

This set is enforced in `validate_realm_name` and rejected at realm-create time. It is a closed set: adding a new sub-resource keyword to the route map MUST also add it here.

### R-5: TargetRealm extractor — sources of truth

The extractor (`src/protocol/web/auth.rs::TargetRealm`) MUST resolve in exactly this order:

1. `?admin_target=system` query → system realm (R-3)
2. Path segment `/ui/admin/realms/{name}/...` → that realm (R-1)
3. **No further fallback.** If neither (1) nor (2) matched, the extractor returns `404 Not Found` for GETs and `400 Bad Request` for non-GET methods.

Specifically deleted from the prior implementation:
- `?realm=<name>` query parser
- `hearth_ui_admin_target` cookie read
- "first non-system realm" silent default

### R-6: Realm switching

Switching realms is a navigation, not a state change. The realm switcher MUST be a `<select>` (or a list of `<a>` links) whose targets are URLs of the form `/ui/admin/realms/{newname}{rest_of_current_subpath}`. There is no `POST /admin/switch-realm` handler and no `hearth_ui_admin_target` cookie. An admin who wants to operate in realm B navigates directly to a URL that names realm B.

The system-realm switch (the "Admin users" tab in the sidebar) is a hard-coded link to `/ui/admin/admin-users` (which already targets the system realm).

### R-7: Realm meta-management

Operations that act on a realm itself — viewing detail/status, granting realm-admin to a user, viewing claims config, deleting the realm — also live under `/ui/admin/realms/{name}/...`:

- `/ui/admin/realms/{name}` — workspace landing
- `/ui/admin/realms/{name}/admins` — realm admin grants list (HTML page is part of the workspace's settings tab)
- `/ui/admin/realms/{name}/admins/picker` — HTMX picker
- `/ui/admin/realms/{name}/admins/grant`
- `/ui/admin/realms/{name}/admins/{uid}/revoke`
- `/ui/admin/realms/{name}/claims` — claims config view
- `/ui/admin/realms/{name}/delete` — delete realm

Previously, realm meta routes used `{id}` (UUID). Switching them to `{name}` makes URLs consistent across the entire realm-scoped surface and eliminates a second URL shape that callers had to remember.

### R-8: Templates

No admin template MAY emit a URL that matches the regex `/ui/admin/(users|groups|organizations|applications|sessions|audit|rbac|permissions)(\/|$)` — those URLs are forbidden because they lack realm context. Every realm-scoped link MUST be of the form `/ui/admin/realms/{{ realm_name }}/...`.

Templates MUST receive `realm_name: String` (or `realm_name: &str`) directly. The previous optional `target_realm_name: Option<String>` and the `target_query: String` field are deleted from every template struct. The Askama match-blocks `{% match target_realm_name %}{% when Some with (name) %}?realm={{ name }}{% when None %}{% endmatch %}` are deleted.

### R-9: Tests

Every web-UI integration test MUST request realm-scoped pages at `/ui/admin/realms/{name}/...`. Tests that previously exercised `?realm=...` or set the `hearth_ui_admin_target` cookie are rewritten or deleted.

A new negative test asserts: `GET /ui/admin/users` (no realm) returns 404; `POST /ui/admin/users/{id}/delete` (no realm) returns 400.

## Compatibility note

Hearth has zero customers and is pre-release. There is no migration path, no redirect from old URLs, and no deprecation window. Old URLs simply stop existing.
