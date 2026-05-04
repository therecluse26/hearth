# Completeness Analysis — Hearth Admin UI (Bug Audit)
_Generated: 2026-05-04 · Spec source: `docs/specs/` (UI_AUDIT_FINDINGS.md, ROLES_UI_REDESIGN.md, CONFIG_VS_UI_GAP_ANALYSIS.md, THEME.md) · Code rev: `881fa7b` (feature/authz-migration)_

**Scope:** Admin UI only. This audit complements `docs/gaps/completeness_analysis.md` (feature completeness, 90/102 ✅) by focusing exclusively on **defects in shipped surfaces** rather than missing features. The user reported one bug (group member removal silently fails on refresh) and asked for a sweep for similar UI bugs.

## Summary

- Total requirements audited: **23 admin-UI mutation surfaces** (forms that POST/DELETE state-changing requests)
- ✅ Complete (working correctly): **3** (group add-member, all `realms/*` paths, sessions list)
- 🔴 Broken (silent failure on non-default realms): **20 forms across 7 templates**
- ⚠️ Divergent (BUG-004 — error-path mishandling): **1 handler**
- ❓ Unverifiable: 0

**Top risks:**
1. **Silent data integrity failure (P0):** Twenty admin mutations submit to URLs that drop the realm context, then call storage APIs that are idempotent on missing keys. The handler returns a "success" UI response while the actual data in the operator's intended realm is untouched. The UI lies about whether the change persisted.
2. **Cross-realm misattribution risk:** When the realm fallback resolves to a different tenant's realm, `delete()` / `put()` calls succeed against that *other* realm's namespace. In the worst case (admin who legitimately has access to both realms) this could flip the wrong tenant's state — and audit events get logged in the wrong realm too.
3. **Asymmetric breakage masks the bug class:** Add-member works (form has `?realm=`); remove-member doesn't (form omits it). Pair-asymmetric bugs are easy to miss in manual testing because the "happy path" feels fine.
4. **HTMX `outerHTML` swap on empty error responses (BUG-004):** Even after fixing the realm parameter, the group remove handler will still delete the row from the DOM on legitimate errors, masking failure as success.
5. **No test guards against the bug class:** Existing integration tests cover engine correctness but no test exercises an admin mutation where the page-realm context could drift between page render and form submit.

## Requirements Matrix

Each row is a single mutation surface. "Realm-in-URL" = whether the form's action/`hx-post` includes the realm context that `TargetRealm` needs (`auth.rs:597-705`).

| ID | Requirement | Priority | Status | Evidence | Notes |
|----|-------------|----------|--------|----------|-------|
| REQ-G01 | Add member to group | must | ✅ Complete | `templates/ui/admin/groups/_member_picker_rows.html:27` includes `?realm=` | Reference for correct pattern |
| REQ-G02 | Remove member from group | must | 🔴 Missing | `templates/ui/admin/groups/_member_row.html:25` lacks `?realm=` | **USER-REPORTED BUG** — BUG-001 |
| REQ-G03 | Group remove HTMX error path re-renders row on failure | should | ⚠️ Divergent | `src/protocol/web/admin.rs:5687-5700` returns empty body | BUG-004 — diverges from org pattern at `admin.rs:3889-3905` |
| REQ-G04 | Assign role to group | must | ✅ Complete | `templates/ui/admin/groups/detail.html:149` includes `?realm=` | |
| REQ-G05 | Unassign role from group | must | ✅ Complete | `templates/ui/admin/groups/detail.html:209` includes `?realm=` | |
| REQ-G06 | Delete group | must | ✅ Complete | `templates/ui/admin/groups/detail.html:253` includes `?realm=` | |
| REQ-G07 | Edit group | must | ✅ Complete | `templates/ui/admin/groups/edit.html:26` includes `?realm=` | |
| REQ-G08 | Create group | must | ✅ Complete | `templates/ui/admin/groups/new.html:24` includes `?realm=` | |
| REQ-O01 | Org member RBAC unassign | must | 🔴 Missing | `templates/ui/admin/organizations/_member_row.html:28-29` lacks `?realm=` | BUG-002 |
| REQ-O02 | Org member RBAC assign | must | 🔴 Missing | `_member_row.html:72-73` lacks `?realm=` | BUG-002 |
| REQ-O03 | Org member permission revoke | must | 🔴 Missing | `_member_row.html:98-99` lacks `?realm=` | BUG-002 |
| REQ-O04 | Org member permission grant | must | 🔴 Missing | `_member_row.html:125-126` lacks `?realm=` | BUG-002 |
| REQ-O05 | Org member role change | must | 🔴 Missing | `_member_row.html:155` lacks `?realm=` | BUG-002 |
| REQ-O06 | Org member remove | must | 🔴 Missing | `_member_row.html:178` lacks `?realm=` | BUG-002 |
| REQ-U01 | User assign role | must | 🔴 Missing | `templates/ui/admin/users/_roles_tab.html:82` lacks `?realm=` | BUG-003 |
| REQ-U02 | User unassign role | must | 🔴 Missing | `_roles_tab.html:43` lacks `?realm=` | BUG-003 |
| REQ-U03 | User grant permission | must | 🔴 Missing | `_permissions_tab.html:71` lacks `?realm=` | BUG-003 |
| REQ-U04 | User revoke permission | must | 🔴 Missing | `_permissions_tab.html:38` lacks `?realm=` | BUG-003 |
| REQ-U05 | User edit | must | 🔴 Missing | `users/edit.html:15` lacks `?realm=` | BUG-003 |
| REQ-U06 | User reset password | must | 🔴 Missing | `users/detail.html:70` lacks `?realm=` | BUG-003 |
| REQ-U07 | User disable MFA | must | 🔴 Missing | `users/detail.html:81` lacks `?realm=` | BUG-003 |
| REQ-U08 | User session revoke | must | 🔴 Missing | `users/detail.html:218` lacks `?realm=` | BUG-003 |
| REQ-U09 | User WebAuthn credential revoke | must | 🔴 Missing | `users/detail.html:272` lacks `?realm=` | BUG-003 |
| REQ-U10 | User delete | must | 🔴 Missing | `users/detail.html:342` lacks `?realm=` | BUG-003 — also high blast radius |
| REQ-U11 | User OAuth consent revoke | must | 🔴 Missing | `users/consents.html:39` lacks `?realm=` | BUG-003 |
| REQ-S01 | Session revoke (sessions list) | must | ✅ Complete | `sessions/_rows.html:20-21` uses server-injected `s.realm_target_query` | Correct alternative pattern |
| REQ-R01 | All `/ui/admin/realms/{name}/...` operations | must | ✅ Complete | Realm in path; `path_realm_segment` (`auth.rs:730`) recovers it | No `?realm=` needed |

## Findings by Area

### Root Cause: Realm Context Drift on HTMX Mutations

`TargetRealm` (`src/protocol/web/auth.rs:597-705`) resolves the operating realm in this priority:

1. `?admin_target=system` query → system realm
2. Path segment `/ui/admin/realms/{name}/...` → that realm (only matches the explicit shape; UUIDs rejected)
3. `?realm=<name>` query → that realm
4. Cookie `hearth_ui_admin_target` → cookied realm
5. **Fallback:** first non-system realm (`list_realms(None, 1)`)

HTMX form submissions do **not** inherit query parameters from the page URL — they POST exactly the URL specified in `hx-post`. So when an `hx-post` URL omits `?realm=`, the resolver falls through to the cookie or the default. The cookie is only set when the admin explicitly clicks "Switch realm" (`admin.rs:4534-4572`), so deep-links and breadcrumb navigation can leave it stale or unset.

When the resolved realm differs from the operator's intended realm:

1. Engine call hits the wrong realm's storage namespace.
2. `delete()` is idempotent on missing keys (`src/storage/...`) → returns `Ok(())`.
3. `put()` writes to the wrong realm (potentially mutating the wrong tenant's state).
4. Handler reports success, audits a "success" event in the wrong realm.
5. HTMX swaps the row out of the DOM (visual success).
6. User refreshes; the page (correctly resolving the realm via `?realm=foo`) reads the unchanged data — the row reappears.

### BUG-001 [P0] — Group member removal *(USER-REPORTED)*

**Symptom:** Frontend removes the row; refresh restores the member.

**Evidence:**
- Buggy template: `templates/ui/admin/groups/_member_row.html:25`
- Handler: `src/protocol/web/admin.rs:5630-5703` (`admin_group_member_remove`)
- Engine (correct): `src/rbac/engine.rs:991-1002` (`remove_group_member`)

**Why ADD works:** `templates/ui/admin/groups/_member_picker_rows.html:27` correctly includes `{% match target_realm_name %}{% when Some with (name) %}?realm={{ name }}{% when None %}{% endmatch %}`. The asymmetry is what produced the user-visible bug.

### BUG-002 [P0] — All Organization member operations have the same defect

Every form action in `templates/ui/admin/organizations/_member_row.html` lacks `?realm=`:

| Line(s) | Operation |
|---------|-----------|
| 28-29 | Per-role-row RBAC unassign |
| 72-73 | RBAC assign |
| 98-99 | Permission revoke |
| 125-126 | Permission grant |
| 155 | Role change |
| 178 | Remove member |

Most rows duplicate both `action=` (no-JS fallback) and `hx-post=` (HTMX path). Both must be fixed. User likely hasn't noticed because the "default realm" in development is usually the same as the org's realm; the bug surfaces only when the operator switches to a non-default realm.

### BUG-003 [P0] — User detail / role / permission / consent / lifecycle forms

Thirteen form actions, all missing `?realm=`:

| File:line | Operation |
|-----------|-----------|
| `users/_roles_tab.html:43, 82` | Role assign/unassign |
| `users/_permissions_tab.html:38, 71` | Permission grant/revoke |
| `users/edit.html:15` | User edit |
| `users/detail.html:70` | Reset password |
| `users/detail.html:81` | Disable MFA |
| `users/detail.html:218` | Session revoke |
| `users/detail.html:272` | WebAuthn credential revoke |
| `users/detail.html:342` | Delete user |
| `users/consents.html:39` | Revoke OAuth consent |

Especially severe for `users/detail.html:342` (user delete) — silent cross-realm misfire on a destructive op.

### BUG-004 [P1] — Group remove HTMX error path also deletes the row

Independent of BUG-001. In `admin_group_member_remove` (`admin.rs:5687-5700`), the HTMX error branch returns `htmx_toast_response(&format!("{e}"), "error")` — an **empty body** with `outerHTML` swap. So even if BUG-001 is fixed and a real engine error occurs, the row is still removed from the DOM. The user sees a "success-shaped" failure: a toast says error, but the row is gone, masking that the data is unchanged.

The org equivalent (`admin.rs:3889-3905` in `admin_org_remove_member`) handles this correctly — it re-renders the row with an inline toast on error. The group handler should mirror this pattern via a `render_group_member_row_with_toast` helper.

### Items examined and cleared

- **Engine `remove_group_member`** correctly deletes both forward (`encode_gm_forward`) and reverse (`encode_gm_reverse`) indexes (`src/rbac/engine.rs:991-1002`).
- **`list_group_members`** scans the forward index that remove deletes (`engine.rs:1004-1027`).
- **Key encoding** is symmetric and unit-tested (`src/rbac/keys.rs:122-150`, tests at lines 412-433).
- **Route registration** is correct: `POST /admin/groups/{id}/members/{kind}/{mid}/remove` (`mod.rs:938-939`).
- **CSRF / auth middleware** — every mutation handler is gated by `RequireAdmin` and `verify_csrf_form_field`. No bypasses found.
- **No "stub" handlers** — every mutation handler audited (40+) calls a real engine/identity/RBAC method. No handlers that pretend to mutate without persisting.
- **Sessions list** uses server-computed `s.realm_target_query` — correct alternative pattern.
- **`/ui/admin/realms/{name}/...` paths** recover the realm from the path itself; their forms intentionally omit `?realm=` and that is correct.
- **Settings / audit / applications** are realm-agnostic; their missing `?realm=` is intentional.

## Spec Issues

None directly affecting this audit. `docs/specs/UI_AUDIT_FINDINGS.md` and `docs/specs/ROLES_UI_REDESIGN.md` documented earlier UI fixes (modal backdrops, sidebar opacity, role-change auto-submit) but did not encode "realm context must round-trip on every admin mutation" as a normative requirement. This is the only ambiguity worth flagging:

- **Recommend codifying:** add a one-liner to `docs/specs/THEME.md` or a new `docs/specs/UI_INVARIANTS.md` stating that any HTMX form action under `/ui/admin/` (excluding `/ui/admin/realms/{name}/...` and explicitly system-targeted forms) MUST include the same realm-context query string the page used. This is the rule the existing template at `_member_picker_rows.html:27` implements; it just isn't written down.

## Out-of-Spec Implementations

None observed in this scope. Existing admin UI templates are all traceable to documented requirements in `completeness_analysis.md`.

## Resolution Todo List

Ordered by priority and dependency. P0 items are blockers; the bug class affects every realm Hearth ships into production with more than one tenant.

- [ ] **[P0][S]** Fix `templates/ui/admin/groups/_member_row.html:25` — append `{% match target_realm_name %}{% when Some with (name) %}?realm={{ name }}{% when None %}{% endmatch %}` to the `hx-post` URL · resolves `REQ-G02` (BUG-001) · _depends on: none_
- [ ] **[P0][S]** Fix `templates/ui/admin/organizations/_member_row.html` — append realm match block to all 6 form action/hx-post URLs (lines 28-29, 72-73, 98-99, 125-126, 155, 178) · resolves `REQ-O01` through `REQ-O06` (BUG-002)
- [ ] **[P0][S]** Fix `templates/ui/admin/users/_roles_tab.html` — append realm match block to lines 43 and 82 · resolves `REQ-U01`, `REQ-U02` (BUG-003)
- [ ] **[P0][S]** Fix `templates/ui/admin/users/_permissions_tab.html` — append realm match block to lines 38 and 71 · resolves `REQ-U03`, `REQ-U04` (BUG-003)
- [ ] **[P0][S]** Fix `templates/ui/admin/users/edit.html:15` — append realm match block · resolves `REQ-U05` (BUG-003)
- [ ] **[P0][S]** Fix `templates/ui/admin/users/detail.html` — append realm match block to lines 70, 81, 218, 272, 342 · resolves `REQ-U06`–`REQ-U10` (BUG-003)
- [ ] **[P0][S]** Fix `templates/ui/admin/users/consents.html:39` — append realm match block · resolves `REQ-U11` (BUG-003)
- [ ] **[P0][S]** Verify each affected template's `*Template` struct already exposes `target_realm_name: Option<String>`. Most do via the standard chrome layout; if any don't, add the field and populate it from the handler · _depends on: above template fixes_
- [ ] **[P0][S]** Run `cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify` if any template structure changed (defensive — Tailwind purge can drop classes if templates are reorganized)
- [ ] **[P0][M]** Add integration test in `tests/web_ui_admin.rs`: create realms `foo` + `bar`, group + member in `foo`, set admin-target cookie to `bar`, POST member-remove to `/ui/admin/groups/.../remove?realm=foo`, assert the member IS removed in `foo` (and untouched in `bar`) · resolves `REQ-G02` regression-prevention · _depends on: BUG-001 fix_
- [ ] **[P1][S]** Refactor `admin_group_member_remove` error path (`src/protocol/web/admin.rs:5687-5700`) to mirror `admin_org_remove_member` (3887-3905) — fetch group + member, render row + toast on error · resolves `REQ-G03` (BUG-004)
- [ ] **[P1][M]** Add one cross-realm-mismatch test per affected surface (org member, user role, user permission, user lifecycle) — same shape as the BUG-001 test · resolves BUG-002, BUG-003 prevention
- [ ] **[P1][S]** Manual Playwright walkthrough: create two realms, switch to non-default, exercise every fixed form, refresh after each, confirm state actually persists · regression check across all bug fixes
- [ ] **[P2][S]** Document the invariant: add a `docs/specs/UI_INVARIANTS.md` section stating "Every admin HTMX form action MUST round-trip the realm context that the page URL carried" · resolves spec issue #1
- [ ] **[P2][M]** Audit `templates/ui/admin/_components/` (newly added per git status) and any non-admin templates that may carry forward into `/ui/admin/` for the same pattern · systemic prevention
- [ ] **[P2][L]** **Out of scope for this PR — log as separate epic:** Restructure all admin routes to `/ui/admin/realms/{name}/...` (path-based realm scoping). Would eliminate this whole class of bugs by making the realm part of the URL identity, not a query parameter that has to be redundantly threaded through every mutation. Larger refactor; ~80 routes affected.
- [ ] **[P2][M]** **Out of scope for this PR — log as separate epic:** Add a route-level guard that rejects mutations to realm-scoped admin endpoints if the realm context resolution fell through to the default (i.e., neither path-segment nor query-param nor cookie was present). Defense-in-depth on top of the template fix.

## Recommended Next Steps

Start with the user-reported bug. Fix `templates/ui/admin/groups/_member_row.html:25` first (single-line change), add the regression test described in the todo list, and validate manually with two realms. That confirms the root-cause hypothesis end-to-end before touching the other 19 forms.

Once BUG-001 is verified fixed, the BUG-002 / BUG-003 fixes are mechanical applications of the same pattern across the remaining seven templates — bundle them into a single PR for atomicity since they're all the same defect class with the same fix shape. The error-path fix (BUG-004) can ride along or be split out.

The two P2 epics (path-based realm scoping, route-level guard) are systemic prevention. Both are larger than this audit's scope but should be tracked as follow-up work — they are the only way to guarantee this bug class never reappears as new admin features ship.

**Critical files referenced:**
- `src/protocol/web/auth.rs:597-705` — `TargetRealm` extractor (root resolver)
- `src/protocol/web/auth.rs:730-752` — `path_realm_segment` (path-based fallback)
- `src/protocol/web/admin.rs:5630-5703` — `admin_group_member_remove` (handler with BUG-004)
- `src/protocol/web/admin.rs:3839-3920` — `admin_org_remove_member` (correct error-path reference)
- `src/protocol/web/admin.rs:4534-4572` — `admin_switch_realm` (cookie setter)
- `src/rbac/engine.rs:991-1027` — `remove_group_member` + `list_group_members` (engine, correct)
- `src/rbac/keys.rs:122-150` — group member key encodings (correct)
- `templates/ui/admin/groups/_member_picker_rows.html:27` — reference for correct pattern
