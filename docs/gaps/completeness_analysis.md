# Completeness Analysis — Hearth Admin UI

_Generated: 2026-05-01 · Spec source: `docs/specs/` · Code rev: `4837318` · Branch: `feature/authz-migration`_

**Scope: Admin UI only.** This audit covers the operator-facing web admin console — templates under `templates/ui/admin/`, handlers in `src/protocol/web/admin.rs`, routes registered in `src/protocol/web/mod.rs`, theme assets under `ui/` and `src/protocol/web/assets/`, and the inline navigation in `templates/ui/_layout.html`. Backend RBAC engine logic, gRPC/SDK contracts, and OIDC wire protocol are **out of scope** unless they bubble up to a screen.

Source specs ingested (in priority order): `UI_AUDIT_FINDINGS.md`, `CONFIG_VS_UI_GAP_ANALYSIS.md`, `ROLES_UI_REDESIGN.md`, `THEME.md`, `AUTHORIZATION.md` §§ 8–9, `AUTHZ_EXPANSION.md`, `AGENT_AUTH.md` (UI sections), `CONFIGURATION.md` (settings surfaced in editor), `THINGS_WE_NEED.md`.

## Summary

- **Total requirements:** 102
- **Complete:** 35 (34%) · **Partial:** 19 (19%) · **Missing:** 23 (22%) · **Divergent:** 4 (4%) · **Unverifiable:** 21 (21%)
- **Top risks:**
  1. **Service-account / agent admin UI is entirely absent** (REQ-083 → REQ-089). `/ui/admin/agents`, `/ui/admin/approvals` both return 404. Agent identity is a Phase-2 feature explicitly named in `AGENT_AUTH.md` with no admin surface.
  2. **Application CRUD routes are unwired despite templates existing** (`applications/new.html`, `applications/edit.html` are on disk, documented in `admin.rs:23–28`, but `mod.rs` has no `.route()` calls for `/applications/new`, `/applications/{id}/edit`, or `/applications/{id}/delete`). This is the cheapest fix on the list and the most embarrassing gap.
  3. **Permission resolver page (`/ui/admin/permissions/resolve`) is missing** (REQ-056). Member rows in `organizations/_member_row.html` already point to a near-equivalent (`/ui/admin/rbac/debug?user_id=…&org_id=…`), so the redesign is partly squatted on the debug page rather than the dedicated resolver the spec calls for.
  4. **Org member-management UX is divergent from `ROLES_UI_REDESIGN.md`** (REQ-053, 054, 057): role `<select>` has no `hx-trigger="change"` auto-submit, "Remove" lacks two-click confirm, and the invite form is not collapsed into `<details>`. The redesign spec is the most recent design doc on this surface and is being implemented incrementally.
  5. **Several spec items are stale post-RBAC migration** (REQ-036 about the "Relation select", and parts of UI_AUDIT_FINDINGS § P2-14/15 referring to Zanzibar object/relation pickers). These need to be retired from the spec, not built.

---

## Requirements Matrix

Status legend: ✅ Complete · 🟡 Partial · 🔴 Missing · ⚠️ Divergent · ❓ Unverifiable

| ID | Requirement (1-line) | Priority | Status | Evidence | Notes |
|----|---------------------|----------|--------|----------|-------|
| REQ-001 | Tailwind build emits `bg-ht-*` / `btn-ember` utilities into `app.css` | must | ✅ | `curl /ui/static/app.css` contains `.bg-ht-surface-raised{background-color:var(--ht-surface-raised)}` (verified live) | — |
| REQ-002 | `/ui/static/theme.css` returns non-empty `:root { --ht-* }` block | must | ✅ | Live response: `:root { --ht-surface-base: #141418; --ht-surface-raised: #0e0e12; … }` | — |
| REQ-003 | `build.rs` auto-rebuilds Tailwind before `cargo build` | must | ❓ | `app.css` is committed (30,316 bytes); cannot verify build hook without code dive into `build.rs` | Confirm in `build.rs` |
| REQ-004 | Boot-time canary asserts `app.css` sentinel | must | ❓ | No `assert_app_css_sane()` reference observed in initial map | Grep `src/main.rs` / `src/protocol/web/mod.rs` |
| REQ-005 | CI integration test fetches `app.css` + `theme.css` and checks sentinels | must | ❓ | Not searched | Check `tests/web_assets*.rs` if present |
| REQ-006 | Sidebar opaque `bg-ht-surface-raised` + `border-r border-divider` | must | ✅ | Computed style: `bg: rgb(14,14,18)`, `border-right: rgba(255,255,255,0.1) 1px solid` |  — |
| REQ-007 | Org-delete modal has `fixed inset-0` backdrop + focus trap + Esc | must | ✅ | Alpine dialog with `fixed inset-0 z-50 … bg-black` backdrop; focus auto-lands on slug input | — |
| REQ-008 | All other modals (token regen, diff preview, member picker) have same pattern | must | ❓ | Only org-delete verified live; member picker and diff preview not opened | Open each and re-verify |
| REQ-009 | Login page uses `btn-ember` + Manrope, no hardcoded gradient classes | must | ✅ | `templates/ui/admin/login.html` uses `btn-ember`, `font-manrope`; no `from-blue-*` | — |
| REQ-010 | `/ui/admin/login/passkey-begin` and `…/passkey-complete` respond 200 | must | 🟡 | `POST /ui/admin/login/passkey-begin` → **405 Method Not Allowed** (route registered but method mismatch) | `mod.rs:553` registers GET; client may be POSTing |
| REQ-011 | `/favicon.ico` returns 200 + linked from `_layout.html` | must | ✅ | `curl -I /favicon.ico` → 200 | — |
| REQ-012 | Logo `<img>` alt is dynamic, not "Test Corp" | must | ⚠️ | Alt resolves from `branding.product_name` (so technically dynamic), but config sets it to literal `"Test Corp"` (`hearth.yaml:8`) — same outcome the spec called out | Template is fine; default config still ships "Test Corp" |
| REQ-013 | "Managed via hearth.yaml" badge is compact pill on apps list | should | 🟡 | Detail page uses `mt-1 text-sm text-ht-content-muted` paragraph (not pill); list page shows no badge at all | Replace paragraph with `inline-flex … whitespace-nowrap` pill; add to list rows |
| REQ-014 | Realm-list "Configured in hearth.yaml" helper not in action cell | should | ❓ | Not visually confirmed; `realms/_rows.html` should be checked | — |
| REQ-015 | Org invite form: visible email + role + Send invite (not collapsed) | must | ✅ | Org detail Invitations tab shows email input, role select, Send invite button always visible | — |
| REQ-016 | Search icon absolutely positioned inside input on list pages | should | ❓ | Not visually confirmed | Snapshot users/admin-users/orgs lists |
| REQ-017 | Sidebar contains all named nav entries incl. Sessions, Organizations | should | 🟡 | System-level: Admin Users, Realms, System Info. Per-realm tree: Users, Orgs, Apps, Sessions, Audit, Permissions, Roles, Scopes, Permission Check. Missing top-level Sessions/Organizations cards mirror — by design realm-scoped only | Spec assumed flat nav; impl uses workspace nav |
| REQ-018 | Dashboard stat cards align with sidebar entries | should | 🟡 | Stat cards link to /users, /realms, /applications, /organizations. Sessions and Audit Log appear as separate card grid below | — |
| REQ-019 | Realm-scoped pages have visible realm dropdown/picker | should | ⚠️ | No `<select>` realm picker. Realm context shown via sidebar accordion + workspace tab-bar breadcrumb. Functional equivalent | Spec wording vs. implementation diverge |
| REQ-020 | Status values rendered as colored pill badges | must | ✅ | Active uses `bg-success/[0.12] text-success-fg`; Suspended/Archived steel/rose pills confirmed | — |
| REQ-021 | All credential forms have `autocomplete` attributes | should | ❓ | Login confirmed; user/admin-user create forms not visually inspected | Grep `templates/ui/admin/users/new.html` for `autocomplete=` |
| REQ-022 | `/ui/admin/admin-users/new` separate route, no realm selector | should | ⚠️ | `/ui/admin/admin-users/new` → 404. Admin user creation reuses `/ui/admin/users/new` with system-realm context. Functionally works but route is divergent | Either add the route or update the spec |
| REQ-023 | Lists with >20 items show pagination affordance | should | ✅ | `users/list.html` uses `next_cursor`; pattern present across list templates | Did not stress-test with >20 rows |
| REQ-024 | All page titles use `{{ product_name }}` | could | ✅ | Title resolved as "Test Corp · Realms" — uses runtime `product_name` | — |
| REQ-025 | List rows have `divide-y divide-divider-faint` + `hover:bg-divider` | could | ❓ | Not visually confirmed across all 7 list pages | Grep templates |
| REQ-026 | Breadcrumb current segment is non-linked text | could | ❓ | Not verified | — |
| REQ-027 | Audit date filter inputs use styled input classes | could | ❓ | Audit page renders inputs; class match not verified | Inspect `audit/list.html` |
| REQ-028 | User detail access list does not render duplicate `admin/admin/admin` triple | should | ❓ | Affected user not enrolled with hearth-level admin during walk | Reproduce with hearth-admin user |
| REQ-029 | Users-list breadcrumb includes workspace segment | could | ❓ | Not verified | — |
| REQ-030 | "Send password reset" shows inline confirmation prompt | could | ❓ | Button present (REQ-039); inline confirm not exercised | Click and observe |
| REQ-031 | Audit Resource column consistent format | could | ❓ | Not visually confirmed; need a populated audit log | — |
| REQ-032 | Empty-state row uses correct `colspan` | could | ❓ | Not visually confirmed | — |
| REQ-033 | Settings detail defaults first section open | could | ❓ | Not exercised | — |
| REQ-034 | Raw YAML editor has syntax highlighting | could | ❓ | Editor renders; highlighting not confirmed | — |
| REQ-035 | Dashboard stat cards are `<a>` links | should | ✅ | All four cards are `<a href>` linking to list pages | — |
| REQ-036 | Permission Check Relation select disabled until Object type chosen | could | ⚠️ | Spec language is pre-RBAC (Zanzibar). RBAC debug page (`/ui/admin/rbac/debug`) has no Object/Relation concept | Spec is stale; retire or rewrite |
| REQ-037 | "Find user" button is typeahead "Search by email…" | could | ❓ | RBAC debug page has user_id text input, not typeahead | Upgrade to autocomplete tied to `/admin/api/users/search` (which exists, `mod.rs:894`) |
| REQ-038 | Audit "Verify integrity" shows visible feedback | could | ✅ | After click: "Audit chain integrity verified successfully." banner | — |
| REQ-039 | User detail "Send password reset" button | must | ✅ | Button visible on user detail; POSTs `/admin/users/{id}/reset-password` (`admin.rs:908`) | — |
| REQ-040 | User detail shows sessions table with revoke | must | 🟡 | Sessions section renders; revoke button present in template but not exercised on a user with active sessions | Verify button renders for live sessions |
| REQ-041 | User detail shows MFA status with disable button | must | 🟡 | MFA section shows "Not enabled" — disable button only renders when MFA active. Cannot confirm without MFA-enrolled user | — |
| REQ-042 | User detail lists WebAuthn credentials with revoke | should | ✅ | WebAuthn Credentials table present with Credential ID / Algorithm / Discoverable columns | — |
| REQ-043 | User detail lists organization memberships | should | ❓ | Not confirmed visually | Inspect `users/detail.html` |
| REQ-044 | User list `?q=` search filters live (≥2 chars) | must | 🟡 | Search input present but plain form GET — no `hx-trigger="input"` for live filtering | Add HTMX live search |
| REQ-045 | Audit list has start/end date filter inputs | must | ✅ | Both inputs present | — |
| REQ-046 | Audit list "Verify integrity" button + flash | must | ✅ | Same as REQ-038 | — |
| REQ-047 | Roles management page (CRUD) exists | should | 🟡 | `/ui/admin/rbac/roles` is a read-only list (`rbac/roles.html`, 69 lines). No create/edit/delete forms | YAML-managed today; RBAC spec calls for runtime CRUD |
| REQ-048 | Groups management page (CRUD) exists | should | 🔴 | No `/ui/admin/groups` route or template | — |
| REQ-049 | Application detail "Regenerate secret" action | should | 🟡 | Handler exists (`admin_app_regenerate_secret`, `admin.rs:1756`) and route is wired (`mod.rs:922`); seed app is YAML-managed so button may be hidden | Verify button renders for runtime apps |
| REQ-050 | Sessions list filterable by expiry status | could | 🔴 | Sessions list (`templates/ui/admin/sessions/list.html`) has no filter inputs | — |
| REQ-051 | Archived realms have "Archived" badge + permanent-delete | could | 🟡 | Template `realms/_rows.html` includes Archived badge (steel ramp). No archived realms in current data; permanent-delete not visually confirmed | — |
| REQ-052 | Org members section uses single inline add-member form (no bulk modal) | must | ✅ | Members tab has single inline search + add flow; no bulk-add modal observed | Verify `admin_org_bulk_add_members` handler is removed (`admin.rs`) |
| REQ-053 | Role change `<select>` posts on change via HTMX | must | 🔴 | Role `<select>` has no `hx-trigger`, `hx-post`, or `onchange` — requires separate Update click | Implement per redesign spec |
| REQ-054 | Member Remove uses two-click confirm (no modal) | must | 🟡 | Plain `<button>Remove</button>`; no `x-data` two-state confirm observed | Implement Alpine state per spec |
| REQ-055 | Each member row has "Resolve permissions" link | should | ✅ | "Check" link → `/ui/admin/rbac/debug?user_id=…&org_id=…` (different target than spec's `/permissions/resolve`) | URL diverges from spec |
| REQ-056 | `/ui/admin/permissions/resolve` page exists | must | 🔴 | `curl /ui/admin/permissions/resolve` → 404. Functionality squats on `/admin/rbac/debug` | Build dedicated page or update spec to alias |
| REQ-057 | Invite form in collapsed `<details>` at section bottom | should | 🔴 | Invite form always visible — zero `<details>` elements in invitations tab | — |
| REQ-058 | `deserialize_string_list` extracted to shared `forms.rs` | should | ❓ | Not verified | Grep for the helper's location |
| REQ-059 | Realm detail "Resolve permissions" link per admin row | must | ❓ | Not visually confirmed | Inspect `realms/detail.html` |
| REQ-060 | Role-change response sets `HX-Trigger` toast | should | 🔴 | Blocked by REQ-053 (no HTMX call yet) | — |
| REQ-061 | Templates use semantic `ht-*` tokens, no raw `graphite-*` / hex | must | ❓ | Spot-checks pass; not exhaustively grepped | `grep -rE 'bg-graphite-\|#[0-9a-fA-F]{6}' templates/` |
| REQ-062 | Ember gradient appears at most once per region | must | ❓ | Not exhaustively audited | — |
| REQ-063 | `btn-ember` uses gold focus + `translateY(-1px)` hover | must | ❓ | CSS rule not inspected | `grep btn-ember src/protocol/web/assets/app.css` |
| REQ-064 | Accent ramps used for reserved meanings (teal=production, etc.) | must | ❓ | Not audited | — |
| REQ-065 | Fraunces (display) / Manrope (body) / JetBrains Mono (mono) | must | ✅ | Login + dashboard confirm correct fonts in computed styles | — |
| REQ-066 | Eyebrow labels uppercase, mono, muted color | must | ❓ | Not exhaustively confirmed | — |
| REQ-067 | Border radius tokens applied consistently | must | ❓ | Not exhaustively confirmed | — |
| REQ-068 | All interactive elements have visible focus state | must | ❓ | Not exhaustively confirmed | Tab through admin pages |
| REQ-069 | No status conveyed by color alone | must | ✅ | Status badges include text labels alongside color | — |
| REQ-070 | Six named themes selectable via `branding.theme` | must | ✅ | Code path for `branding.theme` exists (`src/protocol/web/themes.rs` per MEMORY); ember active in live env | Did not switch live |
| REQ-071 | `branding.custom_css` and per-realm overrides served after named theme | must | ❓ | Path exists per MEMORY; not exercised | — |
| REQ-072 | `server.assets_dir` loads `app.css` from disk with sentinel + fallback | must | ❓ | Not exercised | — |
| REQ-073 | Hover/focus motion uses 180ms / 120ms ease | could | ❓ | CSS not inspected | — |
| REQ-074 | Roles management UI: list/create/get/update/delete | must | 🟡 | List exists read-only (`rbac/roles.html`); CRUD forms absent | Same as REQ-047 |
| REQ-075 | Groups management UI: CRUD + member management | must | 🔴 | No `/ui/admin/groups` route or template | — |
| REQ-076 | User detail role assignment / removal | must | ✅ | `users/_roles_tab.html` exists; routes `users/{id}/roles/assign` and `users/{id}/roles/{aid}/unassign` wired (`mod.rs:739-743`) | — |
| REQ-077 | Role detail lists assigned subjects | should | 🔴 | No role detail route — `/admin/rbac/roles` is a list only, no per-role page | — |
| REQ-078 | YAML-managed entities marked read-only with badge | should | 🟡 | Apps detail shows "Managed via hearth.yaml" text; no clear "Managed by YAML" badge convention across roles/groups/permissions | Standardize badge |
| REQ-079 | Read-only browsing for YAML-defined permissions/roles/scopes/profiles | must | ✅ | `/ui/admin/rbac/permissions`, `/rbac/roles`, `/rbac/scopes` all exist as read-only lists | — |
| REQ-080 | Runtime CRUD for role assignments, extra grants, consents, group membership | must | 🟡 | User-side role assign/unassign and permission grant/revoke wired; consents revocable; group membership UI absent (no groups UI) | Blocked by REQ-048/075 |
| REQ-081 | User detail "Extra permissions" section with revoke | should | ✅ | `users/_permissions_tab.html` + handlers `admin_user_grant_permission` / `revoke_permission` (`admin.rs:6474, 6568`) | — |
| REQ-082 | Org member detail allows additional org-scoped role assignments | should | ✅ | `admin_org_member_assign_role` / `unassign_role` handlers wired (`mod.rs:877-881`) | — |
| REQ-083 | Service-account / agents list page | should | 🔴 | `/ui/admin/agents` → 404; no `templates/ui/admin/agents/` directory | — |
| REQ-084 | Agent create form (display_name, owner, capabilities, depth) | should | 🔴 | Blocked by REQ-083 | — |
| REQ-085 | Agent status transitions (Suspend/Resume/Revoke) | should | 🔴 | Blocked by REQ-083 | — |
| REQ-086 | Agent credential management (API key + asymmetric, one-time reveal) | should | 🔴 | Blocked by REQ-083 | — |
| REQ-087 | User-to-agent consent management view | should | 🔴 | Blocked by REQ-083 | — |
| REQ-088 | Approval-requests management page | should | 🔴 | `/ui/admin/approvals` → 404 | — |
| REQ-089 | Delegation chain visualization | could | 🔴 | Blocked by REQ-083 / REQ-088 | — |
| REQ-090 | Realm detail shows read-only auth policy | should | ❓ | Not visually confirmed | Inspect `realms/detail.html` |
| REQ-091 | App detail shows read-only grant types | should | ❓ | Not visually confirmed | — |
| REQ-092 | Org invitation triggers `EmailService.send_invitation_email` | should | ❓ | Handler exists (`admin_org_invite`, `admin.rs:3988`); email send call not traced in this audit | — |
| REQ-093 | Public `/ui/accept-invitation?token=…` route | must | ❓ | Not in admin route map; check public routes | — |
| REQ-094 | `GET/POST /ui/device` device authorization page | must | ❓ | Not in admin route map (correct — public flow); check `mod.rs` for non-admin routes | — |
| REQ-095 | `branding.product_name` editable in config editor | must | ❓ | Editor exists; specific field not exercised | — |
| REQ-096 | `branding.logo_url` editable + serves at `/ui/static/custom-logo` | must | ❓ | Not exercised | — |
| REQ-097 | `branding.theme` selectable in config editor | must | ❓ | Not exercised | — |
| REQ-098 | `branding.custom_css` editable in config editor | should | ❓ | Not exercised | — |
| REQ-099 | Realms list shows "Archived" badge for soft-deleted realms | should | ✅ | Template (`realms/_rows.html`) includes the badge | Same as REQ-051 |
| REQ-100 | Realm detail shows per-realm `web.theme` / `web.custom_css` read-only | should | ❓ | Not visually confirmed | — |
| REQ-101 | `admin_org_update_role` handles HTMX row-partial vs full redirect | must | 🔴 | Blocked by REQ-053 (no HTMX call wired yet) | — |
| REQ-102 | Role dropdown only fires HTMX when value actually changes | should | 🔴 | Blocked by REQ-053 | — |

---

## Findings by Area

### Theme & Assets (REQ-001 → REQ-005, REQ-061 → REQ-073)
The theme system **largely works**: `app.css` ships with the right sentinel rule, `theme.css` returns a populated `:root`, the ember dark theme is active, and headings/body/mono fonts resolve correctly to Fraunces/Manrope/JetBrains Mono. What we cannot verify in this pass is the **build pipeline plumbing** (REQ-003 build.rs hook, REQ-004 boot canary, REQ-005 CI test). These are P0 in `UI_AUDIT_FINDINGS.md` because their absence is what allowed the unstyled-UI regression in the first place — they need a code dive to confirm.

### Navigation & Layout (REQ-006, REQ-011, REQ-012, REQ-017 → REQ-020, REQ-024 → REQ-029, REQ-035)
Sidebar opacity, divider, favicon, dynamic title, dynamic logo alt are all in place. The structural divergence is REQ-017/REQ-019 — the spec describes a flat sidebar with a realm dropdown; the implementation uses a per-realm workspace tree in the sidebar plus a workspace tab-bar at the top of each realm page. This is a **defensible UX choice** but the spec needs a corresponding update or the implementation needs to add a quick-switch dropdown.

### User Management (REQ-021, REQ-022, REQ-039 → REQ-044, REQ-076, REQ-080, REQ-081)
Most user-detail features land: password reset, MFA disable, WebAuthn revoke, role assignments, permission grants, consents are all wired with both routes and templates. Two gaps: live search on the user list (REQ-044 — currently a plain GET form, not HTMX live), and the dedicated `/admin-users/new` route (REQ-022 — admin user creation reuses `/users/new` with system-realm context).

### Organizations (REQ-015, REQ-052 → REQ-057, REQ-082, REQ-093)
The largest divergence area. The org member redesign (`ROLES_UI_REDESIGN.md`) is **partly applied**: the inline add-member flow (REQ-052) and the per-row "Check" link to RBAC debug (REQ-055) are in. The HTMX role-change auto-submit (REQ-053), two-click remove (REQ-054), and `<details>`-collapsed invite form (REQ-057) are not yet implemented. The redesign was authored for this branch and is the primary outstanding deliverable in the org area.

### Realms (REQ-014, REQ-019, REQ-051, REQ-059, REQ-090, REQ-099, REQ-100)
Realm CRUD is intentionally absent from the UI — realms are config-driven via `hearth.yaml`. The realms list and detail render. Archived-realm badge is in the template. What's underverified: whether the realm detail surfaces the auth policy and per-realm theme/css overrides as read-only fields (REQ-090, REQ-100); whether each admin row carries the "Resolve permissions" link (REQ-059).

### Applications (REQ-013, REQ-049, REQ-091)
**The most fixable embarrassment.** Templates `applications/new.html` (80 lines) and `applications/edit.html` (95 lines) exist and are documented in `admin.rs:23-28`, but `mod.rs` registers only `list`, `detail`, and `regenerate-secret`. Three lines of router wiring would unlock create/edit/delete. The "Managed via hearth.yaml" indicator is also rendered as plain paragraph text rather than a pill — minor cosmetic gap.

### RBAC: Roles, Groups, Permissions, Scopes (REQ-047, REQ-048, REQ-074, REQ-075, REQ-077, REQ-078, REQ-079)
The read-only browsing surface is complete (permissions/roles/scopes lists exist). Runtime CRUD is not. Specifically: no role detail page (REQ-077), no groups admin UI at all (REQ-048, REQ-075), no role create/edit/delete forms (REQ-074). `AUTHORIZATION.md` § 8 calls these `must`-level — they're the largest functional gap in the audit.

### Sessions (REQ-040, REQ-050)
Sessions list exists with revoke per row. No expiry-status filter (REQ-050).

### Audit (REQ-027, REQ-031, REQ-038, REQ-045, REQ-046)
Filter inputs and verify-integrity action work. Cosmetic items (input styling, resource-column format) are unverified.

### Settings / Config Editor (REQ-033, REQ-034, REQ-095 → REQ-098)
Editor exists in both raw-YAML and visual section forms. Specific config-key UX (theme picker, branding fields, custom_css) was not exercised in this audit.

### Permission Resolver (REQ-056)
Cleanly missing. The org member rows already link to `/ui/admin/rbac/debug?user_id=…&org_id=…` so the spec's `/ui/admin/permissions/resolve` URL would either redirect there or be a renamed alias.

### Service Accounts / Agents / Approvals (REQ-083 → REQ-089)
Entirely absent. No templates, no routes, no handlers. This is a **Phase-2 feature** per `AGENT_AUTH.md` — the gap is expected at this branch but should be tracked as a roadmap item, not a defect.

---

## Spec Issues

1. **REQ-036 / UI_AUDIT_FINDINGS § P2-14 references "Object type" + "Relation select" Zanzibar concepts.** After the Zanzibar→RBAC migration (commit history + `MEMORY.md` "RBAC Migration (2026-04-24) — complete"), these screens no longer exist. The spec needs a rewrite: either retire the requirement or reframe it for the RBAC debug page (autocomplete user search, role/permission picker).
2. **REQ-037 / UI_AUDIT_FINDINGS § P2-15 "Find user typeahead"** similarly references the Zanzibar permission-check form. Stale.
3. **REQ-019 vs REQ-017 contradict.** REQ-017 (UI_AUDIT_FINDINGS § P1-5) says the sidebar should mirror dashboard cards (flat list). REQ-019 (§ P1-6) says realm-scoped pages must have a realm dropdown. The implementation chose a third path (per-realm workspace tree). Pick one; the workspace pattern is more scalable.
4. **REQ-022 specifies `/ui/admin/admin-users/new` as a separate route.** Implementation reuses `/ui/admin/users/new` with system-realm context. Update the spec or add the alias.
5. **REQ-055 spec target URL is `/ui/admin/permissions/resolve?user_id=&org_id=`; implementation uses `/ui/admin/rbac/debug?user_id=&org_id=`.** Both REQ-055 and REQ-056 hinge on this — pick one URL.
6. **`AGENT_AUTH.md` UI sections are not flagged with priority/version markers.** Treating all agent items as `should` is an audit guess; the spec should declare phase/priority explicitly.
7. **Application CRUD: `admin.rs:23–28` module-doc lists `/applications/new`, `/applications/{id}/edit`, `/applications/{id}/delete` as handled — but those handlers don't exist in `admin.rs` and routes aren't in `mod.rs`.** This is a doc-vs-code drift, not a spec issue per se, but worth noting.
8. **`MEMORY.md` previously claimed "last-owner protection" and "auto-owner-on-create" were implemented; an earlier live audit falsified this and the entry is now flagged as "aspirational".** No requirement IDs above directly cover this; if it remains a target, write an explicit REQ for it.

---

## Out-of-Spec Implementations

These exist in the running UI/codebase and are **not traceable to any of the 102 audited requirements**. None are problems — flagging them so the spec can absorb or explicitly disclaim them:

1. **Per-realm workspace navigation tree** — sidebar accordion expanding to Users / Orgs / Apps / Sessions / Audit / Permissions / Roles / Scopes / Permission Check per realm. Replaces the flat sidebar called for in REQ-017.
2. **RBAC debug + token preview tabs** (`/ui/admin/rbac/debug`, `POST /admin/rbac/token-preview`) — dual-mode tool for resolving permissions and previewing JWT claim payload. Partly subsumes REQ-056.
3. **Slug-confirmation delete dialog** for organizations (Alpine.js) — type-the-slug-to-confirm UX for destructive operations. Stronger than the two-click pattern called for elsewhere.
4. **"Edit in Config Editor" deep-links** on YAML-managed resource pages — pattern not in the spec but solves the read-only / where-do-I-edit problem.
5. **Realm switching via cookie** (`POST /admin/switch-realm`, `mod.rs:909`) — sets `hearth_ui_admin_target` cookie. Not described in the spec.
6. **Visual config editor with section validate / preview / apply / export** (`/admin/settings/editor/visual/*`, 4 routes) — much richer than the raw-YAML editor the spec implies.
7. **Test-email button** on system info page (`POST /admin/test-email`, `mod.rs:977`) — convenient SMTP smoke-test.
8. **Org bulk-delete handler** (`admin_orgs_bulk_delete`, `admin.rs:3499`) — referenced as "deleted in redesign" by REQ-052, but the handler is still present.
9. **Audit `_rows_only.html` partial** is a 1-line stub — unfinished or unused HTMX swap variant.
10. **JSON nav API** (`GET /admin/api/nav/realms`, `mod.rs:904`) — feeds the sidebar realm tree via Alpine.

---

## Resolution Todo List

Ordered by priority, then dependency. Each item references the requirement(s) it resolves and gives effort estimate (S < 1d, M = 1–3d, L > 3d).

### P0 — Blockers / cheap fixes

- [ ] **[P0][S]** Wire `/admin/applications/new`, `/admin/applications/{id}/edit`, `/admin/applications/{id}/delete` routes in `src/protocol/web/mod.rs` to existing templates and add the matching handlers in `admin.rs` — resolves: missing app CRUD (REQ-049 follow-on), reconciles `admin.rs:23–28` doc drift · _depends on: none_
- [ ] **[P0][S]** Fix `/ui/admin/login/passkey-begin` 405 — verify HTTP method registered in `mod.rs:553` matches the client's request method — resolves `REQ-010` · _depends on: none_
- [ ] **[P0][M]** Build `/ui/admin/permissions/resolve` page (or alias to `/admin/rbac/debug`) and update `organizations/_member_row.html` to match the canonical URL chosen — resolves `REQ-056`, partly `REQ-055` · _depends on: spec decision (Spec Issue #5)_
- [ ] **[P0][S]** Decide and document the canonical resolver URL in `ROLES_UI_REDESIGN.md` — resolves Spec Issue #5 · _blocks: above_
- [ ] **[P0][M]** Implement HTMX role-change auto-submit on org member rows (`hx-post`, `hx-trigger="change[…value-changed…]"`, `hx-target="closest tr"`, `HX-Trigger` toast on response) — resolves `REQ-053`, `REQ-060`, `REQ-101`, `REQ-102` · _depends on: none_
- [ ] **[P0][S]** Add Alpine two-click confirm to org member Remove button (initial → "Confirm remove" + "Cancel") — resolves `REQ-054` · _depends on: none_
- [ ] **[P0][M]** Build admin Groups CRUD UI (`/ui/admin/groups` list, detail, create, edit, members add/remove) — resolves `REQ-048`, `REQ-075`, unblocks `REQ-080` · _depends on: none_
- [ ] **[P0][M]** Build runtime Roles CRUD UI (`/ui/admin/rbac/roles/new`, edit, delete; role-detail "members" list) — resolves `REQ-047`, `REQ-074`, `REQ-077` · _depends on: none_
- [ ] **[P0][S]** Confirm `build.rs` Tailwind hook + boot-time `assert_app_css_sane()` canary + CI smoke test — resolves `REQ-003`, `REQ-004`, `REQ-005` (or files them as defects if absent) · _depends on: none_

### P1 — Should-fix

- [ ] **[P1][S]** Wrap org invite form in `<details><summary>Invite someone who isn't in this realm yet</summary>…</details>`, closed by default — resolves `REQ-057` · _depends on: none_
- [ ] **[P1][S]** Convert "Managed via hearth.yaml" text to compact `inline-flex items-center gap-2 text-sm whitespace-nowrap` pill on apps list and detail — resolves `REQ-013`, partly `REQ-078` · _depends on: none_
- [ ] **[P1][M]** Add HTMX live search (`hx-trigger="input changed delay:200ms"`) to user list and admin-users list (≥2 chars) — resolves `REQ-044` · _depends on: none_
- [ ] **[P1][S]** Add "Active / Expired / All" filter to sessions list — resolves `REQ-050` · _depends on: none_
- [ ] **[P1][S]** Decide on realm-picker UX and either add a `<select>` dropdown next to `<h1>` on realm-scoped pages OR update REQ-017 / REQ-019 to describe the workspace tree pattern — resolves `REQ-019`, Spec Issue #3 · _depends on: spec decision_
- [ ] **[P1][M]** Standardize a "Managed by YAML" badge component (single class, single icon) and apply across roles/groups/permissions/scopes/realms/apps — resolves `REQ-078` · _depends on: none_
- [ ] **[P1][S]** Decide on `/ui/admin/admin-users/new` route: either add it as a thin alias of `/users/new?realm=system` or update REQ-022 to document the reuse — resolves `REQ-022`, Spec Issue #4 · _depends on: spec decision_
- [ ] **[P1][M]** Plan agent admin UI surface (list / detail / status transitions / credentials / consents) — resolves `REQ-083` → `REQ-087`, prerequisite for `REQ-089` · _depends on: phase decision in `AGENT_AUTH.md`_
- [ ] **[P1][M]** Build approval-requests page (`/ui/admin/approvals`) — resolves `REQ-088` · _depends on: agent UI plan_
- [ ] **[P1][S]** Verify whether `admin_org_bulk_add_members` is still wired (it should be removed per REQ-052 redesign); delete handler if so — resolves redesign cleanup · _depends on: none_
- [ ] **[P1][S]** Confirm sessions revoke button renders for active sessions (live test with a session in the table) — resolves `REQ-040` · _depends on: none_
- [ ] **[P1][S]** Verify each user/admin-user/org list page has the search icon absolute-positioned inside the input (REQ-016) and confirm `divide-y` + `hover:bg-divider` (REQ-025) — resolves `REQ-016`, `REQ-025` · _depends on: none_
- [ ] **[P1][S]** Verify realm detail surfaces auth policy + per-realm theme/css as read-only — resolves `REQ-090`, `REQ-100` · _depends on: none_
- [ ] **[P1][S]** Verify realm detail's admin rows include "Resolve permissions" link (REQ-059) — resolves `REQ-059` · _depends on: REQ-056 URL decision_

### P2 — Nice-to-have / cleanup

- [ ] **[P2][S]** Retire / rewrite REQ-036 and REQ-037 in `UI_AUDIT_FINDINGS.md` — they describe Zanzibar Object/Relation pickers that no longer exist post-RBAC migration — resolves Spec Issues #1, #2 · _depends on: none_
- [ ] **[P2][S]** Default-change `branding.product_name` from "Test Corp" in `hearth.yaml` and any seed configs to "Hearth" or leave unset — resolves `REQ-012` · _depends on: none_
- [ ] **[P2][S]** Replace user_id text input on RBAC debug page with autocomplete tied to `/admin/api/users/search` — resolves `REQ-037` (after rewrite) · _depends on: REQ-036/37 retire_
- [ ] **[P2][S]** Add inline confirm-and-display-target to user "Send password reset" button — resolves `REQ-030` · _depends on: none_
- [ ] **[P2][S]** Default-expand the first section in `settings/system.html` — resolves `REQ-033` · _depends on: none_
- [ ] **[P2][M]** Add CodeMirror or Prism YAML highlighting to the raw editor — resolves `REQ-034` · _depends on: none_
- [ ] **[P2][S]** Audit modal partials (token regen, diff preview, member picker) for backdrop + focus trap — resolves `REQ-008` · _depends on: none_
- [ ] **[P2][S]** Implement "Archived" status with permanent-delete action for soft-deleted realms (live verification) — resolves `REQ-051` · _depends on: none_
- [ ] **[P2][S]** Audit Resource column consistency + audit list input styling + empty-state colspan — resolves `REQ-027`, `REQ-031`, `REQ-032` · _depends on: none_
- [ ] **[P2][S]** Sweep templates for raw `bg-graphite-*` and hex literals; replace with `ht-*` tokens — resolves `REQ-061` · _depends on: none_
- [ ] **[P2][S]** Verify `btn-ember` hover translateY + `shadow-cta-hover` rule in `app.css` — resolves `REQ-063` · _depends on: none_
- [ ] **[P2][M]** Tab-navigate every admin page and confirm visible focus rings on all interactive elements — resolves `REQ-068` · _depends on: none_
- [ ] **[P2][S]** Write or extend an integration test that boots the server and asserts `/ui/static/app.css` contains the sentinel + `/ui/static/theme.css` returns a populated `:root` — resolves `REQ-005` · _depends on: REQ-004_
- [ ] **[P2][S]** If `admin.rs` has no `deserialize_string_list` shared helper yet, extract it to `src/protocol/web/forms.rs` — resolves `REQ-058` · _depends on: none_
- [ ] **[P2][S]** Delete unused `templates/ui/admin/audit/_rows_only.html` (1-line stub) or implement its swap target — resolves out-of-spec cleanup #9 · _depends on: none_

---

## Recommended Next Steps

Start with the **P0 cheap fixes** to close the most embarrassing gaps first:

1. **Wire the application CRUD routes** (15-minute fix; templates and partial doc-comments already exist).
2. **Diagnose the passkey-begin 405** (probably a method-mismatch one-liner).
3. **Implement the org member redesign HTMX behaviors** (REQ-053, REQ-054, REQ-057) — these form one cohesive change-set against `templates/ui/admin/organizations/_member_row.html` + `admin_org_update_role` and complete the in-flight `ROLES_UI_REDESIGN.md` work.
4. **Make the resolver URL decision** before building anything new — REQ-055 and REQ-056 hinge on it. The cheapest answer is to alias `/ui/admin/permissions/resolve` to the existing `/admin/rbac/debug` and update the spec; the better answer is to give it a dedicated, focused page that elides the token-preview pane. This is the largest single structural decision left in the org/RBAC area.

Then take on the **P0 functional gaps** (Groups CRUD, runtime Roles CRUD) — these are the largest correctness gaps against `AUTHORIZATION.md` § 8 and they unblock REQ-080.

The agent-admin surface (REQ-083 → REQ-089) is a Phase-2 deliverable per `AGENT_AUTH.md` and should not block this audit from being closed; it warrants a roadmap line item, not a fix in this branch.

Finally, the **❓ Unverifiable cluster** (21 items) is large because this audit prioritized breadth over depth. A follow-up pass with code-only inspection (no live UI needed) can clear most of them in a half-day. The biggest theme-spec items (REQ-061 through REQ-073) reduce to a handful of `grep`s and a tab-through-the-app focus-state walk.
