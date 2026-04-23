# Roles & Permissions UI Redesign

**Status:** proposed, not implemented
**Target branch:** feature/saml (or a follow-up branch off `main`)
**Primary files:** `src/protocol/web/admin.rs`, `templates/ui/admin/organizations/*`, `templates/ui/admin/realms/detail.html`

## Context

Phases 1–6 of the Roles & Permissions work (see `/home/brad/.claude/plans/cool-now-relating-to-mossy-map.md`) shipped:

1. The Zanzibar engine primitives (relation unions, preset namespace, `check_explain`, reverse lookup).
2. An opt-in realm admin surface, Zanzibar mirroring for org memberships, a user Access panel, and an authz debugger.

What landed works end-to-end — tests are green, every role change writes both the legacy `OrganizationMembership` record and a matching Zanzibar tuple, audit events are paired, and the debugger can trace any check — but **the product UX for managing organization members is still bad**. This spec is the punch-list for a proper redesign and an explicit list of the bugs behind the current pain.

The immediate trigger was a production bug: a bulk-add submission with exactly one checkbox ticked returned

```
Failed to deserialize form body: user_ids: invalid type: string "…uuid…", expected a sequence
```

That bug is already fixed (`deserialize_string_list` helper on `BulkAddMembersForm` in `src/protocol/web/admin.rs`, plus regression test `bulk_add_members_form_accepts_single_user_id` in `tests/admin_roles.rs`). The fix revealed that the whole Members flow has accumulated UX debt that a patch will not absolve.

## The problems to solve

Each item below is a discrete pain point observed on the current `templates/ui/admin/organizations/detail.html` + its handlers. Numbered so commits can reference them individually.

### P1. Two overlapping "add member" flows

The Members section currently exposes:

- **"Invite by email" form** (inline, directly above the members table) — posts to `POST /ui/admin/organizations/{id}/invite`, creates an `OrganizationInvitation`, emails a signed link.
- **"Add Members" button** (opens an HTMX modal) — posts to `POST /ui/admin/organizations/{id}/members/bulk`, adds one or more existing realm users with a chosen role.

Nothing on the page explains which to use. New operators frequently try to "invite" an existing user via the email form, which works but creates a pending invitation they then have to manually accept. The modal also has no zero-state guidance — its "Add selected" button is disabled until a checkbox is ticked, so a user who opens it, skims, and clicks looks like nothing happened.

### P2. Role change requires a second click

Every member row has `<select><option>Member</option>…</select>` followed by an `<button>Update</button>` link. Changing the dropdown does nothing until Update is clicked. Every modern admin panel I've seen (Auth0, Keycloak, Google Workspace) applies role changes on select, with an undoable toast. The current design makes a two-step action feel like a one-step one — users change the dropdown, walk away, and are surprised the role didn't change.

### P3. "Remove" is a naked text link

A bare `Remove` link directly commits `POST /members/{uid}/remove`. The engine refuses to remove the last owner, but any other misclick permanently severs the membership. Adjacent to the `Update` text link of the same visual weight, it's a misclick magnet.

### P4. Bulk-add forces a single role for the whole batch

The modal has one role dropdown in the footer that applies to every checked user. Realistically, the most common "bulk" is "add these three people: Alice and Bob as Admin, Carol as Member." That forces three separate passes through the modal. For the **very common** one-person case, opening a modal at all is overkill.

### P5. No "did my change take effect?" loop

When an operator changes a role, the Zanzibar mirror writes the matching tuple and emits paired `RoleRevoked` + `RoleAssigned` audit events. None of that is visible in the Members UI. If an operator is debugging "why can Bob still view this doc?" they have to:

1. Open the Members tab and eyeball Bob's role.
2. Open the authz debugger in a different tab.
3. Type the organization UUID + relation + user UUID by hand.
4. Compare traces.

The debugger exists; the Members page should link into it with the fields pre-filled.

### P6. Invite-by-email and member-list coexist as co-equal forms

The "Invite by email" form is visually heavier than the members table. Invites happen occasionally; managing existing members is the 90% flow. The hierarchy is upside down.

### P7. The single-vs-many form bug may exist elsewhere

The `deserialize_string_list` helper was added to `BulkAddMembersForm` only. Every other handler that accepts multi-valued checkbox input (audit CSV export filters, SCIM batch ops, anything with `Vec<String>` from an HTML form) has the same latent bug. A cleanup pass should apply the helper — or replace `Vec<String>` with a newtype that owns the deserializer — everywhere it applies.

## Proposed redesign

### New single-member add flow (replaces P1, P4)

At the top of the Members section, inline (no modal):

```
┌───────────────────────────────────────────────────┐
│ Add member                                        │
│ ┌───────────────┐ ┌──────────┐ ┌──────┐           │
│ │ search users…│ │ Member ▾ │ │ Add  │           │
│ └───────────────┘ └──────────┘ └──────┘           │
│ [ live-updating results list as operator types ]  │
└───────────────────────────────────────────────────┘
```

- One search input with `hx-trigger="input changed delay:200ms"` → hits `GET /ui/admin/organizations/{id}/members/picker?q=…` (existing endpoint) rendering the existing `_member_picker_rows.html` partial **inline** (not in a modal).
- Each row in the results has its own form: user_id hidden, role select, Add button. Clicking Add commits that one user. No batch state, no disabled buttons, no Alpine.
- Result: the common case (add one person) is two clicks; the rare case (add five) is five clicks — not worse than the modal, and no JS state to get wrong.
- The bulk modal + `admin_org_bulk_add_members` handler can be **deleted** once this ships. The `_member_modal.html` + `_member_picker_rows.html` templates stay — the rows partial just gets a different wrapper.

### Row-level role change applies on select (fixes P2)

Each member row replaces the Update button with an `hx-post`-driven dropdown:

```html
<select name="role"
        hx-post="/ui/admin/organizations/{id}/members/{uid}/role"
        hx-trigger="change"
        hx-target="closest tr"
        hx-swap="outerHTML"
        hx-include="[name=_csrf]">
  …options…
</select>
```

- Handler (`admin_org_update_role`) returns **a refreshed row fragment** instead of a full-page redirect, so HTMX can swap it in place.
- Add a brief success toast via the existing toast system (`_layout.html` defines `x-data="{ toasts: [] }"`). `admin_org_update_role` already fires audit events; we add an HTMX response header `HX-Trigger: {"toast": {"message": "Role updated", "kind": "success"}}` so the template's existing Alpine handler shows the toast.
- Optimistic rollback: if the server returns an error the swap includes the old role selected; the toast kind flips to `error`.

### Two-click confirm for Remove (fixes P3)

No modal, no JS library. Alpine state on each row:

```html
<div x-data="{ confirm: false }">
  <form method="post" action="/ui/admin/organizations/{id}/members/{uid}/remove">
    <input type="hidden" name="_csrf" value="{{ token }}">
    <button type="button" x-show="!confirm" @click="confirm = true" class="text-xs text-danger-fg">Remove</button>
    <button type="submit"  x-show="confirm"  class="btn-danger rounded px-2 py-1 text-xs">Confirm remove</button>
    <button type="button" x-show="confirm" @click="confirm = false" class="text-xs text-ht-content-muted">Cancel</button>
  </form>
</div>
```

Matches the existing pattern used on `templates/ui/admin/users/detail.html` for "Disable MFA." No new UI primitive required.

### "Check access" link per row (fixes P5)

Add a small `<a>` at the end of each member row pointing at:

```
/ui/admin/authz/debug?object_type=organization
                    &object_id={{ org.id().as_uuid() }}
                    &relation=viewer
                    &subject_type=user
                    &subject_id={{ m.user_id.as_uuid() }}
```

The debugger handler (`admin_authz_debug`) already accepts those query params and auto-runs the check. Zero new backend work — just a link.

Similarly, the realm Admins section gets a Check access link next to each admin using `object_type=hearth&object_id=admin&relation=admin`.

### Invite-by-email demoted (fixes P6)

Move the invite form to a collapsible `<details>` at the bottom of the Members section:

```html
<details class="mt-6">
  <summary class="cursor-pointer text-sm text-ht-content-secondary">Invite someone who isn't in this realm yet</summary>
  <!-- existing invite form -->
</details>
```

Invites are rare, always targeting non-users. They shouldn't visually compete with member management.

### `deserialize_string_list` helper cleanup (fixes P7)

Move the helper out of `admin.rs` (where it's currently hidden beside `BulkAddMembersForm`) to a shared location — proposal: `src/protocol/web/forms.rs` (new module) or inline in a reusable newtype `MultiValue(Vec<String>)` with a `Deserialize` impl. Then grep for every `Vec<String>` in a form struct under `src/protocol/` and either apply the helper or replace with the newtype. Start with:

- `admin.rs::BulkAddMembersForm` (already done, leave as reference)
- Any admin filter / search forms that take multi-select checkboxes
- SCIM bulk endpoints under `src/protocol/scim/` (these may use JSON not form-encoding, so low priority)

The ideal end state: no `Vec<String>` form field in the codebase is allowed to use the default `serde_urlencoded` deserializer.

## Concrete file plan

| File | Change |
|---|---|
| `templates/ui/admin/organizations/detail.html` | Rewrite Members section: new inline add-member, role-dropdown-on-change, confirm-remove, Check access links, invite demoted to `<details>`. |
| `templates/ui/admin/organizations/_member_row.html` | **NEW** — extracted single-row partial. Returned by `admin_org_update_role` for in-place swap. |
| `templates/ui/admin/organizations/_member_modal.html` | **DELETE** after new flow lands. |
| `src/protocol/web/admin.rs` | `admin_org_update_role` returns row partial + `HX-Trigger` header. `admin_org_member_picker` renders rows inline (drops `is_rows_only` branching). `admin_org_bulk_add_members` deleted. Helper `render_member_row` extracted. `deserialize_string_list` moved out. |
| `src/protocol/web/mod.rs` | Remove `/organizations/{id}/members/bulk` route. |
| `src/protocol/web/forms.rs` | **NEW** (optional) — reusable multi-value form helpers. |
| `templates/ui/admin/realms/detail.html` | Add Check access link per admin row. |
| `tests/admin_roles.rs` | Extend tests for in-place row swap + toast trigger header. |

## Non-goals / out of scope

- Redesigning the **invite accept** flow (`/ui/invitations/accept?token=…`). It's fine as-is.
- Changing the Zanzibar mirror semantics (still fires `RoleAssigned` + `RoleRevoked` per role change).
- The realm admin picker (shipped in Phase 6c, keep it — the inline add flow is isomorphic anyway).
- Refactoring `OrganizationMembership` away. The mirror stays.
- Schema editor UI — still deferred until a customer asks.

## Verification

1. `cargo nextest run --workspace` — all existing tests (1,375+) remain green, plus new tests:
   - Row-partial swap: POSTing to `/members/{uid}/role` returns HTML containing the new role selected.
   - HTMX toast header: response includes `HX-Trigger` with the right JSON shape.
   - Inline add: submitting `user_id=<uuid>&role=Member` via the per-row Add form creates a membership and writes a matching tuple.
   - Remove confirm: a bare GET/POST without the confirm flow does nothing surprising (the form itself gates it in markup, so this is really a template snapshot test if anything).
2. `cargo fmt --check && cargo clippy --all-targets -- -D warnings` — clean (modulo the pre-existing SCIM lints).
3. Tailwind rebuild after template changes: `cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify`.
4. Manual smoke (`cargo run -- serve --dev`):
   - Create an org, add one user via inline form → single click works, toast appears.
   - Change the user's role from Member → Admin via the dropdown → no Update button, toast appears, audit log shows `RoleRevoked(member) + RoleAssigned(admin)`.
   - Click Remove → button flips to "Confirm remove" → click again → member gone, toast appears.
   - Click Check access → debugger opens pre-filled and auto-runs the check.
   - Expand "Invite someone who isn't in this realm yet" → existing invite form works.
5. Regression: verify the single-checkbox bulk-add path is simply gone; the handler and template should no longer exist.

## Risks / open questions

- **`admin_org_update_role` signature change.** Today it returns a `Redirect::to(…)` with a flash query param. Switching to a partial-returning handler means callers that weren't HTMX (e.g. a curl script someone wrote) will now get HTML fragments instead of redirects. Mitigation: check the `HX-Request` header; fall back to the old redirect path if absent. Keeps the API contract but adds one branch.
- **Dropdown-on-change and accidental changes.** An operator scrolling past a row with focus on its dropdown + arrow keys could silently demote someone. Two mitigations: (a) only fire `hx-trigger="change"` when the value actually differs from the server-rendered selected value (HTMX has `[value changed]` trigger modifier); (b) add an Alpine-level "unsaved" indicator if we keep the explicit commit. Prefer (a).
- **Deleting `admin_org_bulk_add_members`.** If external docs, scripts, or examples reference `POST /members/bulk`, those break. Grep `examples/`, `docs/`, and the README before removing. Leave a deprecation shim for one release if external usage exists.
- **Who tests the toast system?** The `_layout.html` toast infrastructure exists but may not have integration tests. If not, add one using the existing playwright/e2e scaffolding, or punt it and rely on manual smoke.

## Appendix: the fixed deserializer (for reference)

`BulkAddMembersForm` in `src/protocol/web/admin.rs` now uses:

```rust
#[serde(default, deserialize_with = "deserialize_string_list")]
pub user_ids: Vec<String>,
```

with a custom visitor that accepts both `visit_str` (single scalar) and `visit_seq` (repeated keys). Empty scalar → empty vec. See the function body in `admin.rs` and the regression test `bulk_add_members_form_accepts_single_user_id` in `tests/admin_roles.rs`. The redesign above deletes the entire bulk-add flow, which is what actually makes the bug go away structurally — but the helper stays for P7's cleanup pass.
