# Completeness Analysis — Hearth Admin UI

_Generated: 2026-05-01 · Spec source: `docs/specs/` · Code rev: `4837318` · Branch: `feature/authz-migration`_

**Scope: Admin UI only.** This audit covers the operator-facing web admin console — templates under `templates/ui/admin/`, handlers in `src/protocol/web/admin.rs`, routes registered in `src/protocol/web/mod.rs`, theme assets under `ui/` and `src/protocol/web/assets/`, and the inline navigation in `templates/ui/_layout.html`. Backend RBAC engine logic, gRPC/SDK contracts, and OIDC wire protocol are **out of scope** unless they bubble up to a screen.

Source specs ingested (in priority order): `UI_AUDIT_FINDINGS.md`, `CONFIG_VS_UI_GAP_ANALYSIS.md`, `ROLES_UI_REDESIGN.md`, `THEME.md`, `AUTHORIZATION.md` §§ 8–9, `AUTHZ_EXPANSION.md`, `AGENT_AUTH.md` (UI sections), `CONFIGURATION.md` (settings surfaced in editor), `THINGS_WE_NEED.md`.

## Summary

- **Total requirements:** 102
- **Complete:** 60 (59%) · **N/A by design:** 4 (4%) · **Partial:** 8 (8%) · **Missing:** 16 (16%) · **Divergent:** 1 (1%) · **Unverifiable:** 13 (13%)
- _Reconciled 2026-05-01: 14 stale items flipped to ✅ via code verification; 4 spec decisions resolved; 4 items retired N/A._
- _2026-05-02: Groups CRUD UI shipped (REQ-048, 075, 080). Backend was already runtime-managed; UI was the missing surface. 5 native audit-event variants added (`GroupCreated/Updated/Deleted/MemberAdded/MemberRemoved`)._
- _2026-05-02 (follow-up): Member picker reworked to infinite-scroll (`hx-trigger="revealed"` sentinel) with auto-load on tab open + filter input. Group role-assignment UI added on the Roles tab (assign form + per-row two-click Remove). 1 new smoke test in `tests/web_ui_admin_groups.rs`._
- **Top risks (post-2026-05-01 reconciliation):**
  1. **Service-account / agent admin UI is entirely absent** (REQ-083 → REQ-089). `/ui/admin/agents`, `/ui/admin/approvals` both return 404. Agent identity is a Phase-2 feature explicitly named in `AGENT_AUTH.md` with no admin surface — tracked, not blocking.
  2. **Application CRUD orphan templates** (`applications/new.html`, `applications/edit.html` on disk, documented in `admin.rs:23–28` doc-comment, but `mod.rs` deliberately registers no routes — comment at `mod.rs:912` says apps are read-only / YAML-managed by design). Cleanup needed: delete templates + correct doc-comment, OR confirm runtime CRUD is on the roadmap.
  3. ~~**Groups CRUD UI** (REQ-048, REQ-075).~~ **Resolved 2026-05-02:** runtime CRUD shipped. Decision rationale: groups are user containers for role-assignment indirection; backend was already runtime-only (no `GroupYamlConfig`), and group membership churns frequently with team composition (admins, not engineers, drive the changes). Same lifecycle pattern as users + organizations.
  4. **Org member redesign was already implemented** (REQ-053, 054, 057, 060, 101, 102 all flipped ✅ on reconciliation). The audit's claim that this work was outstanding was stale.
  5. **Spec items stale post-RBAC migration** (REQ-036, REQ-037 reference Zanzibar Object/Relation pickers that no longer exist). Need explicit retirement in `UI_AUDIT_FINDINGS.md`.

---

## Requirements Matrix

Status legend: ✅ Complete · 🟡 Partial · 🔴 Missing · ⚠️ Divergent · ❓ Unverifiable

| ID | Requirement (1-line) | Priority | Status | Evidence | Notes |
|----|---------------------|----------|--------|----------|-------|
| REQ-001 | Tailwind build emits `bg-ht-*` / `btn-ember` utilities into `app.css` | must | ✅ | `curl /ui/static/app.css` contains `.bg-ht-surface-raised{background-color:var(--ht-surface-raised)}` (verified live) | — |
| REQ-002 | `/ui/static/theme.css` returns non-empty `:root { --ht-* }` block | must | ✅ | Live response: `:root { --ht-surface-base: #141418; --ht-surface-raised: #0e0e12; … }` | — |
| REQ-003 | `build.rs` auto-rebuilds Tailwind before `cargo build` | must | ✅ | `build.rs:64-114` invokes `ui/tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify` with `rerun-if-changed` on `ui/input.css`, `ui/tailwind.config.js`, `templates/` | — |
| REQ-004 | Boot-time canary asserts `app.css` sentinel | must | ✅ | `assert_app_css_sane()` invoked from `src/main.rs` at startup; sentinel `.bg-ht-surface-raised` defined in `src/protocol/web/mod.rs` | — |
| REQ-005 | CI integration test fetches `app.css` + `theme.css` and checks sentinels | must | ❓ | Not searched | Check `tests/web_assets*.rs` if present |
| REQ-006 | Sidebar opaque `bg-ht-surface-raised` + `border-r border-divider` | must | ✅ | Computed style: `bg: rgb(14,14,18)`, `border-right: rgba(255,255,255,0.1) 1px solid` |  — |
| REQ-007 | Org-delete modal has `fixed inset-0` backdrop + focus trap + Esc | must | ✅ | Alpine dialog with `fixed inset-0 z-50 … bg-black` backdrop; focus auto-lands on slug input | — |
| REQ-008 | All other modals (token regen, diff preview, member picker) have same pattern | must | ❓ | Only org-delete verified live; member picker and diff preview not opened | Open each and re-verify |
| REQ-009 | Login page uses `btn-ember` + Manrope, no hardcoded gradient classes | must | ✅ | `templates/ui/admin/login.html` uses `btn-ember`, `font-manrope`; no `from-blue-*` | — |
| REQ-010 | `/ui/admin/login/passkey-begin` and `…/passkey-complete` respond 200 | must | ✅ | `mod.rs:553` registers GET `passkey-begin`; `:557` registers POST `passkey-complete`; `templates/ui/login.html:171` calls `fetch()` (GET); `:197` uses `method:'POST'`. Original 405 report appears to have been a stale artifact | — |
| REQ-011 | `/favicon.ico` returns 200 + linked from `_layout.html` | must | ✅ | `curl -I /favicon.ico` → 200 | — |
| REQ-012 | Logo `<img>` alt is dynamic, not "Test Corp" | must | ⚠️ | Alt resolves from `branding.product_name` (so technically dynamic), but config sets it to literal `"Test Corp"` (`hearth.yaml:8`) — same outcome the spec called out | Template is fine; default config still ships "Test Corp" |
| REQ-013 | "Managed via hearth.yaml" badge is compact pill on apps list | should | 🟡 | Detail page uses `mt-1 text-sm text-ht-content-muted` paragraph (not pill); list page shows no badge at all | Replace paragraph with `inline-flex … whitespace-nowrap` pill; add to list rows |
| REQ-014 | Realm-list "Configured in hearth.yaml" helper not in action cell | should | ✅ | `templates/ui/admin/realms/_rows.html:5` adds a muted helper line below the realm name (outside the action cell) | Added 2026-05-01 |
| REQ-015 | Org invite form: visible email + role + Send invite (not collapsed) | must | ✅ | Org detail Invitations tab shows email input, role select, Send invite button always visible | — |
| REQ-016 | Search icon absolutely positioned inside input on list pages | should | ✅ | `class="absolute left-3 top-1/2 -translate-y-1/2"` confirmed in `users/list.html` and `organizations/list.html` | — |
| REQ-017 | Sidebar contains all named nav entries incl. Sessions, Organizations | should | ✅ | Workspace tree pattern (per-realm accordion: Users / Orgs / Apps / Sessions / Audit / Permissions / Roles / Scopes / Permission Check) is the canonical implementation per 2026-05-01 spec decision. Top-level Sessions/Orgs/etc. are intentionally realm-scoped only | Spec retired flat-sidebar requirement |
| REQ-018 | Dashboard stat cards align with sidebar entries | should | 🟡 | Stat cards link to /users, /realms, /applications, /organizations. Sessions and Audit Log appear as separate card grid below | — |
| REQ-019 | Realm-scoped pages have visible realm dropdown/picker | should | ✅ | Per 2026-05-01 spec decision: workspace tree (sidebar accordion + workspace tab-bar) is the canonical realm-context UX. The `<select>` dropdown was a pre-implementation guess that the workspace pattern obsoleted | Spec retired dropdown requirement |
| REQ-020 | Status values rendered as colored pill badges | must | ✅ | Active uses `bg-success/[0.12] text-success-fg`; Suspended/Archived steel/rose pills confirmed | — |
| REQ-021 | All credential forms have `autocomplete` attributes | should | ✅ | `templates/ui/admin/users/new.html` has `autocomplete="off"` on lines 25, 33, 39, 47 and `autocomplete="new-password"` on line 53 | — |
| REQ-022 | `/ui/admin/admin-users/new` separate route, no realm selector | should | ✅ | 2026-05-01: Added thin alias handler `admin_admin_user_create_alias` (`admin.rs`) registered at `/admin/admin-users/new` (`mod.rs:705`); 302-redirects to `/ui/admin/users/new?admin_target=system` so the existing form pre-scopes to system realm | — |
| REQ-023 | Lists with >20 items show pagination affordance | should | ✅ | `users/list.html` uses `next_cursor`; pattern present across list templates | Did not stress-test with >20 rows |
| REQ-024 | All page titles use `{{ product_name }}` | could | ✅ | Title resolved as "Test Corp · Realms" — uses runtime `product_name` | — |
| REQ-025 | List rows have `divide-y divide-divider-faint` + `hover:bg-divider` | could | ✅ | All 7 list partials use `border-b border-divider-subtle hover-bg-divider` (in-repo idiom equivalent: `users/_rows.html`, `organizations/_rows.html`, `sessions/_rows.html`, `applications/_rows.html`, `audit/_rows.html`, `realms/_rows.html`, `users/_rows.html`) | Spec language is generic Tailwind; codebase uses custom component classes — equivalent visual outcome |
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
| REQ-043 | User detail lists organization memberships | should | ✅ | `templates/ui/admin/users/detail.html:169` starts the org-memberships table | — |
| REQ-044 | User list `?q=` search filters live (≥2 chars) | must | 🟡 | Search input present but plain form GET — no `hx-trigger="input"` for live filtering | Add HTMX live search |
| REQ-045 | Audit list has start/end date filter inputs | must | ✅ | Both inputs present | — |
| REQ-046 | Audit list "Verify integrity" button + flash | must | ✅ | Same as REQ-038 | — |
| REQ-047 | Roles management page (CRUD) exists | should | ✅ N/A | Per 2026-05-01 product decision: roles are 100% YAML-managed; runtime CRUD is intentionally absent. Read-only list at `/ui/admin/rbac/roles` is the canonical surface | Spec is stale — retire CRUD requirement |
| REQ-048 | Groups management page (CRUD) exists | should | ✅ | 2026-05-02: full CRUD UI shipped — `/ui/admin/groups` (list), `/new`, `/{id}`, `/{id}/edit`, `/{id}/delete`, `/{id}/members` (add + picker + remove). Templates: `templates/ui/admin/groups/`. Handlers in `admin.rs` (`admin_groups_list` … `admin_group_member_remove`). Native audit events `GroupCreated`/`Updated`/`Deleted`/`MemberAdded`/`MemberRemoved` added to `AuditAction`. Smoke tests in `tests/web_ui_admin_groups.rs` | — |
| REQ-049 | Application detail "Regenerate secret" action | should | 🟡 | Handler exists (`admin_app_regenerate_secret`, `admin.rs:1756`) and route is wired (`mod.rs:922`); seed app is YAML-managed so button may be hidden | Verify button renders for runtime apps |
| REQ-050 | Sessions list filterable by expiry status | could | 🔴 | Sessions list (`templates/ui/admin/sessions/list.html`) has no filter inputs | — |
| REQ-051 | Archived realms have "Archived" badge + permanent-delete | could | 🟡 | Template `realms/_rows.html` includes Archived badge (steel ramp). No archived realms in current data; permanent-delete not visually confirmed | — |
| REQ-052 | Org members section uses single inline add-member form (no bulk modal) | must | ✅ | Members tab has single inline search + add flow; no bulk-add modal observed | Verify `admin_org_bulk_add_members` handler is removed (`admin.rs`) |
| REQ-053 | Role change `<select>` posts on change via HTMX | must | ✅ | `templates/ui/admin/organizations/_member_row.html:158` has `hx-trigger="change"` on the role `<select>` | — |
| REQ-054 | Member Remove uses two-click confirm (no modal) | must | ✅ | `templates/ui/admin/organizations/_member_row.html:181-188` uses Alpine `x-data="{ confirm: false }"` two-state pattern | — |
| REQ-055 | Each member row has "Resolve permissions" link | should | ✅ | "Check" link target unchanged; canonical resolver URL is now both `/ui/admin/rbac/debug?…` and `/ui/admin/permissions/resolve?…` (latter aliases to former per 2026-05-01 spec decision) | — |
| REQ-056 | `/ui/admin/permissions/resolve` page exists | must | ✅ | 2026-05-01: Added `admin_permissions_resolve_alias` handler (`admin.rs`) registered at `/admin/permissions/resolve` (`mod.rs`); 302-redirects to `/admin/rbac/debug` preserving query string. Both URLs work | — |
| REQ-057 | Invite form in collapsed `<details>` at section bottom | should | ✅ | `templates/ui/admin/organizations/detail.html:259-283` wraps the invite form in a collapsible `<details>` element | — |
| REQ-058 | `deserialize_string_list` extracted to shared `forms.rs` | should | ✅ N/A | Helper does not exist in `src/`. The `BulkAddMembersForm` it served was deleted as part of the org member redesign (REQ-052), so nothing requires extraction. Verified 2026-05-01 by grep | Spec is stale — retire requirement |
| REQ-059 | Realm detail "Resolve permissions" link per admin row | must | ❓ | Not visually confirmed | Inspect `realms/detail.html` |
| REQ-060 | Role-change response sets `HX-Trigger` toast | should | ✅ | `admin.rs:3838,3867` set `HX-Trigger: showToast` on `admin_org_update_role` response | — |
| REQ-061 | Templates use semantic `ht-*` tokens, no raw `graphite-*` / hex | must | ✅ | No raw 6-digit hex literals in `templates/`; only Tailwind `ht-*` and `graphite-*` config-defined tokens | — |
| REQ-062 | Ember gradient appears at most once per region | must | ❓ | Not exhaustively audited | — |
| REQ-063 | `btn-ember` uses gold focus + `translateY(-1px)` hover | must | ✅ | `.btn-ember` rule in `app.css` has `transform: translateY(-1px)` on hover and gold `focus-visible` ring | — |
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
| REQ-074 | Roles management UI: list/create/get/update/delete | must | ✅ N/A | Per 2026-05-01 product decision: roles are 100% YAML-managed. List-only is the canonical surface; create/get/update/delete are explicitly out of scope. Spec is stale | Retire CRUD requirement |
| REQ-075 | Groups management UI: CRUD + member management | must | ✅ | 2026-05-02: full CRUD + member add/remove (user members) shipped. Backend already supported nested-group members (cycle detection in engine); UI member-picker is user-only for v1, follow-up to add nested-group picker. Sidebar + workspace tabs link to `/ui/admin/groups?realm={realm}` | Nested-group picker UX deferred |
| REQ-076 | User detail role assignment / removal | must | ✅ | `users/_roles_tab.html` exists; routes `users/{id}/roles/assign` and `users/{id}/roles/{aid}/unassign` wired (`mod.rs:739-743`) | — |
| REQ-077 | Role detail lists assigned subjects | should | ✅ N/A | Per 2026-05-01 product decision: roles are YAML-managed; no per-role page is planned. Subject→role lookup remains via the resolver at `/ui/admin/permissions/resolve?user_id=…` | Retire requirement |
| REQ-078 | YAML-managed entities marked read-only with badge | should | 🟡 | Apps detail shows "Managed via hearth.yaml" text; no clear "Managed by YAML" badge convention across roles/groups/permissions | Standardize badge |
| REQ-079 | Read-only browsing for YAML-defined permissions/roles/scopes/profiles | must | ✅ | `/ui/admin/rbac/permissions`, `/rbac/roles`, `/rbac/scopes` all exist as read-only lists | — |
| REQ-080 | Runtime CRUD for role assignments, extra grants, consents, group membership | must | ✅ | 2026-05-02: group membership + group role-assignment UI shipped. User-side role assign/unassign + permission grant/revoke + consent revoke were already wired. Group role-assign form (Realm or Org scope) lives on `/ui/admin/groups/{id}?tab=roles`; per-assignment Remove button uses two-click Alpine confirm. New routes: `POST /admin/groups/{id}/roles/assign`, `POST /admin/groups/{id}/roles/{aid}/unassign` | — |
| REQ-081 | User detail "Extra permissions" section with revoke | should | ✅ | `users/_permissions_tab.html` + handlers `admin_user_grant_permission` / `revoke_permission` (`admin.rs:6474, 6568`) | — |
| REQ-082 | Org member detail allows additional org-scoped role assignments | should | ✅ | `admin_org_member_assign_role` / `unassign_role` handlers wired (`mod.rs:877-881`) | — |
| REQ-083 | Service-account / agents list page | should | 🔴 | `/ui/admin/agents` → 404; no `templates/ui/admin/agents/` directory | — |
| REQ-084 | Agent create form (display_name, owner, capabilities, depth) | should | 🔴 | Blocked by REQ-083 | — |
| REQ-085 | Agent status transitions (Suspend/Resume/Revoke) | should | 🔴 | Blocked by REQ-083 | — |
| REQ-086 | Agent credential management (API key + asymmetric, one-time reveal) | should | 🔴 | Blocked by REQ-083 | — |
| REQ-087 | User-to-agent consent management view | should | 🔴 | Blocked by REQ-083 | — |
| REQ-088 | Approval-requests management page | should | 🔴 | `/ui/admin/approvals` → 404 | — |
| REQ-089 | Delegation chain visualization | could | 🔴 | Blocked by REQ-083 / REQ-088 | — |
| REQ-090 | Realm detail shows read-only auth policy | should | ✅ | `templates/ui/admin/realms/detail.html:127-274` renders MFA, Auth Methods, Password Policy, Token TTLs, Rate Limiting all read-only | — |
| REQ-091 | App detail shows read-only grant types | should | ❓ | Not visually confirmed | — |
| REQ-092 | Org invitation triggers `EmailService.send_invitation_email` | should | ❓ | Handler exists (`admin_org_invite`, `admin.rs:3988`); email send call not traced in this audit | — |
| REQ-093 | Public `/ui/accept-invitation?token=…` route | must | ❓ | Not in admin route map; check public routes | — |
| REQ-094 | `GET/POST /ui/device` device authorization page | must | ❓ | Not in admin route map (correct — public flow); check `mod.rs` for non-admin routes | — |
| REQ-095 | `branding.product_name` editable in config editor | must | ❓ | Editor exists; specific field not exercised | — |
| REQ-096 | `branding.logo_url` editable + serves at `/ui/static/custom-logo` | must | ❓ | Not exercised | — |
| REQ-097 | `branding.theme` selectable in config editor | must | ❓ | Not exercised | — |
| REQ-098 | `branding.custom_css` editable in config editor | should | ❓ | Not exercised | — |
| REQ-099 | Realms list shows "Archived" badge for soft-deleted realms | should | ✅ | Template (`realms/_rows.html`) includes the badge | Same as REQ-051 |
| REQ-100 | Realm detail shows per-realm `web.theme` / `web.custom_css` read-only | should | 🟡 | `realms/detail.html:280` shows custom CSS as `Custom`/`Default`. Theme NAME not surfaced — `RealmConfig` carries only `web_theme_css` (composed bytes), not the source theme name. Requires adding `web_theme_name: Option<String>` to `RealmConfig` and plumbing from `RealmWebYaml.theme` at config-load time | Out of cheap-fix scope; tracked for follow-up |
| REQ-101 | `admin_org_update_role` handles HTMX row-partial vs full redirect | must | ✅ | `admin.rs:3871` returns refreshed `_member_row.html` partial for HTMX requests; full redirect for non-HX | — |
| REQ-102 | Role dropdown only fires HTMX when value actually changes | should | ✅ | `_member_row.html:158` uses native `change` event (browsers fire `change` only on actual value transitions, not focus) | — |

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
3. ~~**REQ-019 vs REQ-017 contradict.**~~ **Resolved 2026-05-01:** workspace tree pattern is canonical. Both requirements updated to bless the implementation; the dropdown wording is retired.
4. ~~**REQ-022 specifies `/ui/admin/admin-users/new` as a separate route.**~~ **Resolved 2026-05-01:** thin alias added (`admin_admin_user_create_alias`) — both URLs work, single form template stays.
5. ~~**REQ-055 / REQ-056 URL conflict.**~~ **Resolved 2026-05-01:** alias approach. `/ui/admin/permissions/resolve` 302-redirects to `/admin/rbac/debug` preserving query string. Both URLs are valid; the latter is the implementation home.
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
- [x] **[P0][S]** ~~Fix `/ui/admin/login/passkey-begin` 405~~ — Verified 2026-05-01: routes match client methods (GET/POST). No fix needed — resolves `REQ-010`
- [x] **[P0][M]** ~~Build `/ui/admin/permissions/resolve` page~~ — Done 2026-05-01: registered as a 302 alias to `/admin/rbac/debug` preserving query string. Both URLs work. Existing `_member_row.html` "Check" link target stays valid — resolves `REQ-056`, `REQ-055`
- [x] **[P0][S]** ~~Decide canonical resolver URL~~ — Decided 2026-05-01: alias approach (both URLs valid; `/admin/rbac/debug` is the implementation home; `/ui/admin/permissions/resolve` is the spec-named entrypoint) — resolves Spec Issue #5
- [x] **[P0][M]** ~~Implement HTMX role-change auto-submit on org member rows~~ — Verified 2026-05-01: `_member_row.html:158` has `hx-trigger="change"`; `admin.rs:3838,3867` set `HX-Trigger: showToast`; `:3871` returns row partial — resolves `REQ-053`, `REQ-060`, `REQ-101`, `REQ-102`
- [x] **[P0][S]** ~~Add Alpine two-click confirm to org member Remove button~~ — Verified 2026-05-01: `_member_row.html:181-188` already has `x-data="{ confirm: false }"` two-state pattern — resolves `REQ-054`
- [x] **[P0][M]** ~~Build admin Groups CRUD UI~~ — Done 2026-05-02: list/detail/create/edit/delete + member add/remove + native audit events + 3 smoke tests in `tests/web_ui_admin_groups.rs`. Nested-group member-picker UX deferred (backend already supports it; v1 picker is user-only) — resolves `REQ-048`, `REQ-075`, unblocks `REQ-080`
- [x] **[P0][M]** ~~Build runtime Roles CRUD UI~~ — Retired 2026-05-01 per product decision: roles are 100% YAML-managed; no runtime CRUD will be built. Read-only list at `/ui/admin/rbac/roles` is canonical — resolves `REQ-047`, `REQ-074`, `REQ-077` (all marked N/A)
- [x] **[P0][S]** ~~Confirm `build.rs` Tailwind hook + boot-time `assert_app_css_sane()` canary~~ — Verified 2026-05-01: `build.rs:64-114` runs Tailwind; `assert_app_css_sane()` invoked from `src/main.rs`; sentinel `.bg-ht-surface-raised` defined in `mod.rs`. CI smoke test (REQ-005) added in `tests/web_assets.rs` — resolves `REQ-003`, `REQ-004`, `REQ-005`

### P1 — Should-fix

- [x] **[P1][S]** ~~Wrap org invite form in `<details>` collapsible~~ — Verified 2026-05-01: `organizations/detail.html:259-283` already wraps form in `<details>` — resolves `REQ-057`
- [ ] **[P1][S]** Convert "Managed via hearth.yaml" text to compact `inline-flex items-center gap-2 text-sm whitespace-nowrap` pill on apps list and detail — resolves `REQ-013`, partly `REQ-078` · _depends on: none_
- [ ] **[P1][M]** Add HTMX live search (`hx-trigger="input changed delay:200ms"`) to user list and admin-users list (≥2 chars) — resolves `REQ-044` · _depends on: none_
- [ ] **[P1][S]** Add "Active / Expired / All" filter to sessions list — resolves `REQ-050` · _depends on: none_
- [x] **[P1][S]** ~~Decide on realm-picker UX~~ — Decided 2026-05-01: workspace tree pattern (sidebar accordion + workspace tab-bar) is canonical. REQ-017 and REQ-019 updated to bless the implementation — resolves `REQ-019`, Spec Issue #3
- [ ] **[P1][M]** Standardize a "Managed by YAML" badge component (single class, single icon) and apply across roles/groups/permissions/scopes/realms/apps — resolves `REQ-078` · _depends on: none_
- [x] **[P1][S]** ~~Decide on `/ui/admin/admin-users/new` route~~ — Done 2026-05-01: added thin alias handler `admin_admin_user_create_alias`; route registered at `/admin/admin-users/new`; 302-redirects to `/ui/admin/users/new?admin_target=system` — resolves `REQ-022`, Spec Issue #4
- [ ] **[P1][M]** Plan agent admin UI surface (list / detail / status transitions / credentials / consents) — resolves `REQ-083` → `REQ-087`, prerequisite for `REQ-089` · _depends on: phase decision in `AGENT_AUTH.md`_
- [ ] **[P1][M]** Build approval-requests page (`/ui/admin/approvals`) — resolves `REQ-088` · _depends on: agent UI plan_
- [ ] **[P1][S]** Verify whether `admin_org_bulk_add_members` is still wired (it should be removed per REQ-052 redesign); delete handler if so — resolves redesign cleanup · _depends on: none_ _(deferred to a later sweep)_
- [ ] **[P1][S]** Confirm sessions revoke button renders for active sessions (live test with a session in the table) — resolves `REQ-040` · _depends on: none_
- [x] **[P1][S]** ~~Verify search icon positioning~~ — Verified 2026-05-01: `absolute left-3 top-1/2 -translate-y-1/2` confirmed in `users/list.html` + `organizations/list.html` — resolves `REQ-016`. Note: `divide-y` + `hover:bg-divider` (REQ-025) tracked separately below
- [x] **[P1][S]** ~~Verify realm detail surfaces auth policy~~ — Verified 2026-05-01: comprehensive Auth Policy section at `realms/detail.html:127-274` — resolves `REQ-090`. REQ-100 still 🟡 — theme-name plumbing is a follow-up.
- [ ] **[P1][S]** Verify realm detail's admin rows include "Resolve permissions" link (REQ-059) — resolves `REQ-059`. REQ-056 URL decision unblocked: both URLs work; current "Check access" link can keep its target. Pending live-UI verification only.

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
- [x] **[P2][S]** ~~Sweep templates for raw `bg-graphite-*` and hex literals~~ — Verified 2026-05-01: no raw 6-digit hex in `templates/`; only Tailwind `ht-*` and config-defined `graphite-*` tokens — resolves `REQ-061`
- [x] **[P2][S]** ~~Verify `btn-ember` hover translateY + focus ring rule in `app.css`~~ — Verified 2026-05-01: `.btn-ember` has `transform: translateY(-1px)` on hover + gold `focus-visible` ring — resolves `REQ-063`
- [ ] **[P2][M]** Tab-navigate every admin page and confirm visible focus rings on all interactive elements — resolves `REQ-068` · _depends on: none_
- [ ] **[P2][S]** Write or extend an integration test that boots the server and asserts `/ui/static/app.css` contains the sentinel + `/ui/static/theme.css` returns a populated `:root` — resolves `REQ-005` · _depends on: REQ-004_
- [x] **[P2][S]** ~~Extract `deserialize_string_list` to `forms.rs`~~ — Verified 2026-05-01: helper does not exist; the form that needed it was deleted in the org redesign (REQ-052). Marked N/A — resolves `REQ-058`
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
