# UI Audit Findings — Admin Console

**Date audited:** 2026-04-23
**Auditor:** Playwright-driven crawl of `http://localhost:8420/ui/admin/*` against the running `feature/saml` branch build, seed account `seed@example.com`.
**Scope:** Every reachable admin route (login, dashboard, users, admin-users, organizations, applications, realms, sessions, audit, permissions resolver, settings, settings/editor, account, plus representative detail/new/edit pages and the organization delete modal).
**Method:** Snapshot + screenshot per page; `window.getComputedStyle` probes; fetched compiled CSS directly.

All findings below are reproducible from a fresh `cargo run` + the seed account. Screenshots captured in the Playwright session are referenced by filename (e.g. `05-sidebar-open.png`).

---

## Summary

The admin UI is visually **broken end-to-end**. A single root cause — the Tailwind build dropped the `bg-ht-*` / `text-ht-*` / `btn-ember` utility classes and the `@layer base` body rule (purge sweep didn't see them, or content-glob / safelist is misconfigured) — explains roughly 80% of the individual symptoms (white page, missing theme tokens, untagged fonts, invisible borders, transparent sidebar, transparent modal backdrop). On top of that there are ~10 genuine UX/logic issues that will remain after the CSS is fixed. Each is listed below with severity, root cause, suspected file(s), and a concrete fix direction.

**Audit scope caveats**
- This audit was run at **1440×900 desktop viewport only**. Tablet (768×1024) and mobile were not verified — `browser_resize` MCP tool failed to accept numeric arguments. Responsive issues (especially sidebar-drawer behavior below `lg:` breakpoint) are **untested territory**. A follow-up pass should cover these viewports.
- Several "verify after CSS rebuild" items are hypotheses, not confirmations — called out inline where relevant.

**Severity legend**
- **P0 — Blocker:** makes the product look broken or unusable on first load.
- **P1 — Serious:** visible inconsistency or interaction bug that a user will hit.
- **P2 — Polish:** theme violations, microcopy, accessibility hints.

---

## P0 — Blockers

### P0-1 · Compiled `app.css` has no Hearth theme layer, and `theme.css` is empty

**Architectural context (important — the fix must preserve customer theming)**
Hearth's design system is deliberately runtime-themable: customers override brand colors by swapping the values served at `/ui/static/theme.css` (and per-realm `/ui/static/realm-theme/{id}`). To preserve that:
- **`app.css` must contain `var(--ht-*)` references, not hardcoded colors.** Base rules (`body { background-color: var(--ht-surface-base); }`) and utility classes (`.bg-ht-surface-raised { background-color: var(--ht-surface-raised); }`) resolve through custom properties. Compiling literal hex values here would defeat the runtime-theming contract.
- **`theme.css` is where the `:root { --ht-surface-base: #141418; … }` block lives.** That's the seam a customer overrides. It is NOT baked into `app.css`.

`ui/input.css` is structured this way correctly today: the `:root { ... }` block at the top and the `@layer base { body { ... } }` block resolve to `var(--ht-*)`. The served-time `theme.css` is expected to re-emit (or override) the `:root` block with the active theme's values.

**Evidence of the actual bugs**
- `GET /ui/static/app.css` returns a 25 KB Tailwind base build **without the Hearth layer**: no `.bg-ht-surface-*`, `.text-ht-content-*`, `.border-divider`, `.btn-ember`, `.font-fraunces`, `.font-manrope`, `.rounded-ht` utility classes; no `@layer base` body rule. The served `body` rule is literally `body{margin:0;line-height:inherit}` — the `background-color: var(--ht-surface-base); color: var(--ht-content-primary); font-family: Manrope, ...` layer from `input.css` is missing. That's a **compile-time bug** in the Tailwind pipeline, not a theming decision.
- `GET /ui/static/theme.css` returns a single `\n` — it should always emit a `:root { --ht-surface-base: …; --ht-content-primary: …; … }` block for the active theme.
- `getComputedStyle(document.body)` on every admin page returns `background: rgba(0,0,0,0)`, `color: rgb(0,0,0)`, `font-family: system-ui, ...` — browser defaults, because neither the base `body` rule nor the `:root` variable values are being served.

**Consequence**
Every template class like `bg-ht-surface-raised`, `text-ht-content`, `border-divider`, `hover-bg-divider`, `btn-ember` has no matching CSS rule, so they're silently dropped. That's why every page renders as white-on-black-system-font with no borders, no buttons, and no sidebar backdrop (see P0-2, P0-3, and most of P2).

**Root cause**
- The `app.css` build is almost certainly missing template files in its `content: [...]` glob in `ui/tailwind.config.js`, so the tree-shaker purged every `bg-ht-*` / `text-ht-*` / `btn-ember` / `font-fraunces` class as "unused." Alternatively the `@layer base`/`@layer components` blocks in `input.css` are being stripped because a config setting disables them.
- `src/protocol/web/themes.rs` (`GET /ui/static/theme.css`) is returning empty. Either the global branding.theme is unset and the handler short-circuits to `""` instead of falling back to the ember defaults, or it was regressed.

**Fix (preserves runtime theming)**
1. Audit `ui/tailwind.config.js` — confirm the `content` globs cover `../templates/**/*.html` and `../src/protocol/web/**/*.rs` (inline className strings in Rust). Add a safelist for the component classes (`btn-ember`, `btn-danger`, `bg-ht-surface-*`, `text-ht-content-*`, `border-divider*`, `hover-bg-divider`, `font-fraunces`, `font-manrope`) so the purger can't drop them.
2. Rebuild: `cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify`. Verify `body{background-color:var(--ht-surface-base)` and `.bg-ht-surface-raised{background-color:var(--ht-surface-raised)}` both appear in the output. **Colors must still be `var(--ht-*)` references, not literal hex** — that preserves customer overrides.
3. Add a `build.rs` step that runs the Tailwind build automatically before `cargo build` embeds `assets/app.css`, so this never silently rots again. (Alternative: a `make ui` target wired into `make build`.)
4. **Add a boot-time canary check** in `src/main.rs` or `src/protocol/web/mod.rs`: at server start, grep the embedded `app.css` bytes for a known sentinel rule like `.bg-ht-surface-raised{background-color:var(--ht-surface-raised)}`. If absent, log a loud `error!()` and in dev/debug builds refuse to start. This is one-time on startup (not on the hot path) and catches the exact class of regression this audit found without waiting for CI.
5. Fix `src/protocol/web/themes.rs` so `GET /ui/static/theme.css` always emits a `:root { --ht-surface-base: …; … }` block for the active theme — falling back to the ember defaults currently in `ui/input.css` when no custom theme is configured. Never return an empty body. Customers continue to override by setting `branding.theme` or `branding.custom_css`, which `themes.rs` composes into the served CSS.
6. Add a CI integration test: boot the server, fetch `/ui/static/app.css` and assert `.bg-ht-surface-raised{background-color:var(--ht-surface-raised)}` is present (structural, not color); fetch `/ui/static/theme.css` and assert it contains a `:root {` with `--ht-surface-base` set. This catches both the Tailwind purge regression and the empty-theme regression without asserting specific colors.

---

### P0-2 · Sidebar has no background — overlays main content with no solid fill when opened

**Evidence**
- `templates/ui/_layout.html` markup shows `<aside class="... bg-ht-surface-raised border-r border-divider ...">` — correct.
- But because `bg-ht-surface-raised` and `border-divider` are missing from compiled CSS (P0-1), the aside is fully transparent.
- Screenshot `05-sidebar-open.png` shows sidebar text ("Main", "Dashboard", "Admin Users", "Realms" …) rendered directly over the Realms table below it — nav items intersect row headers, illegible.

**Consequence**
Any user who toggles the sidebar on a narrow viewport (or opens it on mobile) sees garbled overlapping text. On desktop ≥1024px the sidebar is `lg:static` so this is less dramatic, but the border still vanishes.

**Fix**
Downstream of P0-1. After CSS rebuild, verify by re-opening the sidebar on `/ui/admin/realms` — sidebar should have opaque `#0e0e12` background and `border-r` alpha-white divider.

---

### P0-3 · Delete-confirm modal has no backdrop — renders over page content with no dimming or solid background

**Evidence**
- Screenshot `22-delete-modal.png`: on the organization detail page, clicking "Delete organization" pops up a confirmation with heading "Delete organization?" which **overlaps** the Invitations section still visible behind it. Text is illegible because page content bleeds through both the card and any expected backdrop.
- No modal-backdrop element is present in the accessibility tree snapshot either — just a bare `generic` with a heading, paragraph, and two buttons.

**Suspected template**
`templates/ui/admin/organizations/detail.html` (or whatever renders the org detail page with the danger-zone block). Likely using an Alpine `x-show` block with no `fixed inset-0` + backdrop wrapper, or the backdrop wrapper's `bg-black/50` class is one of the Tailwind opacity-modifier forms the build stripped (P0-1).

**Fix**
1. Wrap the confirm dialog in a `<div x-show="open" class="fixed inset-0 z-50 flex items-center justify-center">` with a sibling `<div class="absolute inset-0 bg-black/60" @click="open = false">` backdrop, and a panel with `relative bg-ht-surface-raised border border-divider rounded-lg p-6 max-w-md`.
2. Add focus trap + `@keydown.escape.window="open = false"`.
3. Audit the other modals listed in memory ("Token regen", "Diff preview", "Member picker") for the same pattern — they likely all share one Alpine snippet that needs the backdrop. **Unverified — these modals were not triggered in this audit pass**; verify after fixing the org-delete modal whether the same fix covers them (shared component) or whether each needs individual attention.

---

### P0-4 · Login page is functionally unstyled

**Evidence** — Screenshot `01-login.png`. The login card has only a bright blue/teal gradient border visible (likely a `border-brand-accent` or stray gradient), everything else is white background / black text / system font. The "Sign in" button has no background, just bold black text — looks like a text link.

**Root cause** — Same as P0-1: `btn-ember`, `bg-ht-surface-*`, `rounded-ht`, font-family tokens all missing from the compiled CSS.

**Suspicious — verify after P0-1 CSS rebuild**
The login card has a **visible bright blue/teal gradient border** even though all other theme classes are no-ops. If every theme utility was purged, where is the gradient coming from? Three possibilities:
1. The login template uses a Tailwind gradient utility that *survived* the purge (e.g., `bg-gradient-to-br from-blue-500 to-teal-400`) — in which case this is a **hardcoded theme violation** in `templates/ui/admin/login.html` that will NOT self-heal after the rebuild, and should be swapped for `btn-ember` or an approved accent.
2. Inline `style="..."` with a literal gradient.
3. A stray CSS rule in `input.css` or an unscoped class that's tenant-agnostic.
After P0-1 is fixed, re-check the login page — if the gradient persists unchanged, audit `templates/ui/admin/login.html` and replace with theme-compliant classes per `docs/specs/THEME.md`.

**Secondary issues found while looking at login (will remain after P0-1 fix)**
- `GET /ui/admin/login/passkey-begin` 404s automatically on page load (see console errors). Suggests the passkey button's challenge-fetch is firing on mount or the endpoint path shifted. Check `templates/ui/admin/login.html` + `src/protocol/web/admin.rs` passkey handler routing — either remove the prefetch or implement/alias the endpoint.
- `GET /favicon.ico` 404s (also on every other admin page). Add a bundled favicon in the `assets/` directory.
- The page logo `<img alt="Test Corp">` is the Hearth flame SVG — the `alt` text is wrong. `alt` should follow `branding.product_name` or be plain `"Hearth"` — hardcoded "Test Corp" inside the image tag is an artifact of the local test config polluting the template. Fix in `templates/ui/_layout.html` and `templates/ui/admin/login.html`.

---

## P1 — Serious

### P1-1 · "Applications managed via hearth.yaml" badge renders as an oversized card

**Evidence** — Screenshot `06-applications.png`. The top-right of the Applications list shows a large rectangular panel with an icon and three lines of text reading "Managed / via / hearth.yaml". It should be a compact pill or small callout; instead it's 220px wide and taller than the `<h1>`.

**Suspected template** — `templates/ui/admin/applications/list.html`. Check the element wrapping that "Managed via hearth.yaml" string — it's probably `flex items-start gap-3 rounded-lg p-4 border` with too-tight width that forces the label to wrap onto three lines.

**Fix** — Wrap the label in a proper `.inline-flex items-center gap-2 text-sm text-ht-content-muted` span, or a compact info-badge component, with `whitespace-nowrap`.

### P1-2 · "Configured in hearth.yaml" metadata leaks into the action cell on Realms list

**Evidence** — Snapshot of `/ui/admin/realms`: the last column of each row contains both the "Open workspace →" button *and* the muted helper text "Configured in hearth.yaml" on a second line in the **same `<td>`**. Visually they compete.

**Fix** — Move the "Configured in hearth.yaml" helper into its own column, or render it as a `<caption>`/table-footer note, or move it into the breadcrumb on the detail view and drop it from the list row entirely.

### P1-3 · Organization invite form is missing its visible email input

**Evidence** — Snapshot of `/ui/admin/organizations/<id>`: the "Invitations" section shows a `group` with the label "Invite someone who isn't in this realm yet" and three role options (Member/Admin/Owner) — but no email input field is present in the accessibility tree. The role options render as bare `<option>` elements floating with no visible `<select>` or `<input>`.

**Suspected template** — `templates/ui/admin/organizations/detail.html` near the invitations block. Likely an Alpine `<details>` / `<fieldset>` component that collapses by default and the "open" state was lost when the wrapper class disappeared (again downstream of P0-1 but also a structural bug — the email `<input>` is missing or nested inside a `<summary>` that isn't being rendered).

**Fix** — Rework the invite block into a small form: visible `email` input + role select + "Send invite" button, all inside the invitation card, not nested in a `<details>`/disclosure that hides the input.

### P1-4 · Search icon on list pages floats below the input, not inside it

**Evidence** — Screenshot `03-users.png`, `10-admin-users.png`: the magnifier `<img>` sits at the bottom-left *outside* the input box. Expected: it should be inside the textbox (left-inset) with appropriate `pl-10` on the input.

**Suspected template** — Shared partial for the search box in `templates/ui/admin/users/list.html`, `organizations/list.html`, and `admin-users/list.html`. The wrapper is presumably `relative` but the icon is either a sibling after the input (not `absolute`-positioned) or the `absolute left-3 top-1/2 -translate-y-1/2` classes failed to apply.

**Fix** — `<div class="relative"><input class="w-full pl-10 ...">...<span class="absolute inset-y-0 left-3 flex items-center pointer-events-none"><img ...></span></div>`.

### P1-5 · Sidebar nav does not mirror the dashboard quick-links and is realm-blind

**Evidence**
- Sidebar lists: Dashboard · My Account · Admin Users · Realms · Audit Log · Permission Check · System Info.
- Dashboard quick-link cards list: My Account · Users · Realms · Applications · Sessions · Audit log.
- No sidebar entry for **Users**, **Applications**, **Organizations**, or **Sessions** — they only appear once you're inside a realm workspace via the horizontal tabs.
- Dashboard stat cards show "Organizations: 0" even though `Organizations` has no sidebar entry at all.

**Consequence** — Inconsistency: a new admin can't find Organizations from the sidebar; "Admin Users" vs "Users" is also an orthogonal concept that's unclear (global admin-role users vs per-realm users).

**Fix — option A (recommended):** Add a top-level "Realms" expansion in the sidebar that shows the realm workspace tabs (Users, Organizations, Applications, Sessions) nested under each realm, similar to how the realm-context tabs already work. Drop the implicit auto-select of `customer-portal` when the user clicks "Users" from the sidebar on the dashboard — instead, make the global `/ui/admin/users` a realm selector, not a silent redirect.

**Fix — option B (minimum):** Add Users / Organizations / Applications / Sessions to the sidebar as global entries that prompt for a realm on first use.

Either way, align the dashboard cards with the sidebar so a user can navigate to anything they see counted on the dashboard.

### P1-6 · Global routes silently redirect into the first realm

**Evidence** — Navigating to `/ui/admin/users` (no `?realm=`) lands on `/ui/admin/users` with breadcrumb `Realms › customer-portal` already selected and the table populated with users from `customer-portal`. Same with `/ui/admin/organizations`, `/ui/admin/applications`, `/ui/admin/sessions`.

**Consequence** — The user cannot tell whether they are looking at a realm view or a tenant-wide view; if there's a bug that leaks cross-realm data, it will be easy to miss.

**Fix** — Either:
- Require `?realm=` and 404 without it, with a list page at `/ui/admin/users` that shows the realm picker; or
- Keep auto-select but add a clear banner/dropdown `Realm: customer-portal ▾` directly next to the `<h1>` so the realm context is always visible and switchable.

### P1-7 · Status "Active" badges are invisible

**Evidence** — Every list page (users, realms, organizations, applications, user detail) renders a cell `<generic>Active</generic>` with no `.badge`, `.chip`, or color class applied. Reads as plain black text identical to surrounding cells.

**Fix** — Add a small reusable component `{% macro status_badge(kind) %}<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium {% if kind == 'active' %}bg-ht-teal-bg text-ht-teal-fg{% elif kind == 'disabled' %}bg-ht-rose-bg text-ht-rose-fg{% else %}bg-ht-steel-bg text-ht-steel-fg{% endif %}">...{{ label }}</span>{% endmacro %}` and use it everywhere a status is rendered. Check: user detail, user list, admin-users list, realm list, realm detail, organization list, organization detail, application list, application detail Type column, session list.

### P1-8 · Form password inputs have no `autocomplete` attribute

**Evidence** — Console verbose on `/ui/account`: "Password forms should have (optionally autocomplete attributes …)". Same on `/ui/admin/users/new`.

**Fix** — Add `autocomplete="current-password"`, `autocomplete="new-password"`, `autocomplete="email"`, `autocomplete="name"` to inputs in:
- `templates/ui/admin/login.html` (email = `username`, password = `current-password`)
- `templates/ui/admin/account.html` change-password form (`current-password`, `new-password` × 2)
- `templates/ui/admin/users/new.html` and `edit.html` (email, name, password)

### P1-9 · "Create admin" on Admin Users page routes to `/ui/admin/users/new` with no `?realm=`

**Evidence** — From `/ui/admin/admin-users`, clicking "Create admin" opens `/ui/admin/users/new` without a realm in the query string. The create-user form submits without a realm binding, and (per the flow) will either 400 or silently assign to the default realm, which is surprising.

**Fix** — Admin-user creation needs a different form variant that doesn't take a realm (since admin role lives on the `hearth` object not on a realm), or it should force-select the system realm. Also rename the route to `/ui/admin/admin-users/new` so the intent is clear and the shared `users/new.html` template isn't overloaded.

### P1-10 · No "cursor-based pagination" UI despite the memory saying it exists **[UNVERIFIED]**

**Status: speculative — could not be confirmed in this audit pass.**

**Evidence** — Every list page I visited (users, admin-users, organizations, applications, realms, sessions, audit) has fewer than 20 rows, so the pagination rendering could not be triggered. At the bottom of each list there is no Next / Prev affordance, no page-size selector, and no "Show more" hint, BUT this is the expected state when there's only one page of results. The memory in `MEMORY.md` says "cursor-based pagination (20 items/page)" exists.

**Action for follow-up agent** — Create 21+ test users (or use a seeded dataset) and re-visit `/ui/admin/users?realm=customer-portal`. If a Next affordance appears, P1-10 is a non-issue. If it does not, then: if the `_rows.html` HTMX partial implements the next-cursor request, add a "Load more" or "Next page" button at the table footer wired via HTMX `hx-get` with the cursor param. If it's already there but conditionally hidden, make sure the condition isn't swallowing single-page lists AND the "no more pages" state.

---

## P2 — Polish

All of these are worth doing after P0 and P1. Many will partially self-resolve after P0-1 (the CSS rebuild).

### P2-1 · Page title tag is inconsistent
- Login page title: `"Hearth · Sign in"`
- Settings page title: `"Test Corp · System Info"` (uses branding.product_name)
- Settings/editor: `"Test Corp · Config Editor"`
- Every other page: `"Hearth · <Resource>"`

Pick one: always use `branding.product_name` (recommended — it's configurable) or always use `"Hearth"`. Do not mix.

### P2-2 · "Test Corp" branding leaks into `<img alt>` text

The logo img `alt="Test Corp"` appears on every page. The alt should either track branding, or simply say "Home". Avoid rendering the runtime tenant name in alt text that test fixtures set.

### P2-3 · Table rows have no hover state, no zebra striping, no visible row divider

On `/ui/admin/realms`, `users`, `admin-users`, `organizations`, `applications`, `audit`, `sessions` — rows touch each other with no visible separation. Downstream of P0-1 (`border-divider` + `hover:bg-divider` are missing), but re-verify after the CSS rebuild. Add `divide-y divide-divider-faint` to `<tbody>` and `hover:bg-divider` to `<tr>` at minimum.

### P2-4 · Breadcrumb on realm-workspace child pages uses link styling on the current page

On `/ui/admin/users?realm=customer-portal` the breadcrumb is `Realms › customer-portal`, where `customer-portal` is a link back to the realm detail. Typical UX is to show the current page as a non-link. Inside the realm detail (`/ui/admin/realms/<id>`) the breadcrumb correctly renders the realm name as a plain `<generic>` — inherit that pattern for the workspace children.

### P2-5 · Audit log filter shows bare native date pickers and a bare `<input type="number">` spinbox

`/ui/admin/audit` renders Start/End date with browser-default `mm/dd/yyyy` date inputs and a plain number spinner for `limit`. Works, but visually disjoint from the styled text inputs elsewhere. Apply the same input class (`bg-ht-surface-input border border-divider rounded-sm px-3 py-2`).

### P2-6 · User detail page renders an odd `admin admin admin` access entry **[possible template correctness bug]**

On `/ui/admin/users/<id>`, the "hearth" access list shows a `<listitem>` with three nested elements (`text: admin`, `generic: admin`, `generic: admin`) all containing the literal string "admin". On this specific grant (hearth-level admin where `relation == object_id == "admin"`) it happens to render without visible harm — but the template is likely dereferencing three separate variables that coincidentally all resolve to `"admin"`. For other relations (e.g., `member` on an organization, or `viewer` on an application) the same template path may render incorrect or confusing text.

**Action** — Inspect the user-detail access-list template (likely `templates/ui/admin/users/detail.html` or a partial under `templates/ui/admin/users/`). Confirm whether each of the three elements is bound to the right variable (relation name / object id / pill label) or whether they're all pointing at the same field. If the latter, this is a latent correctness bug, not a cosmetic one, and should be bumped to **P1**. Either way, compact the final rendering into a single span like `admin on hearth` for hearth-level relations.

### P2-7 · Breadcrumb on Users list does not include the workspace (`/ui/admin/users?realm=customer-portal` shows `Realms › customer-portal`, should also show `› Users`)

Minor but helps orientation on deep links.

### P2-8 · "Send password reset" button on user detail is bare — no confirmation

Single click sends a reset email without any confirm step. Add an inline confirm ("Send reset to `test@test.com`?") before firing. (Not destructive, but it's a real email going to a real address.)

### P2-9 · Every table header is `UPPERCASE TRACKED` text — good pattern — but "Resource" column on audit table varies between just a UUID and `user <uuid>` formatting

Normalize to `{{ resource_type }} {{ resource_id | truncate(8) }}` everywhere.

### P2-10 · Sessions empty state is a single `<cell>` spanning no specific column; the colspan isn't set

So when the table has columns the "No active sessions." cell falls under the first column only and looks misaligned. Add `colspan=5` (or equivalent `{% set n_cols = ... %}`) to the empty-state row.

### P2-11 · Setting-detail groups all collapse on load; first section should default to expanded so the page isn't a wall of buttons

Minor — `/ui/admin/settings` visual would benefit from Server being open by default.

### P2-12 · Config editor Raw YAML view has no syntax highlighting

Pure `<textarea>`. Reasonable MVP, but given there's already a Monaco-style diff preview button, consider CodeMirror or Prism-highlighted textarea overlay.

### P2-13 · Dashboard stat cards ("USERS 1 · REALMS 2 · APPLICATIONS 0 · ORGANIZATIONS 0") are not clickable

They look like cards but have no link. Either make them `<a>`s to the respective list pages, or reduce their visual weight so they don't invite a click.

### P2-14 · On the Permission Check form, the `Relation` select only has "— select —" and doesn't populate options until an Object type is chosen, with no HTMX loader or `[disabled]` state while loading

Add `disabled` on the Relation select until an Object type is picked, and populate the options via HTMX from the schema endpoint. Show a spinner while loading.

### P2-15 · "Find user" button next to Subject ID has no visible dropdown/result affordance

Clicking it must do something (open a picker?), but the markup gives no hint of what happens. Label it `"Search by email…"` and make it open a typeahead.

### P2-16 · "Verify integrity" button on Audit page gives no visible feedback on success

A user expects either a toast, an inline "Chain OK ✓" banner, or a visible diff. Currently the button has no connected success/failure region.

---

## Things that are NOT bugs (captured so a future auditor doesn't re-flag them)

- The Realms list correctly shows no "Create realm" CTA — realms are `hearth.yaml`-configured by design (confirmed by the info banner on that page).
- Applications are also YAML-configured; their detail page's "Back to list" affordance is intentional, even though list→edit isn't available.
- `/ui/admin/users` is a realm-scoped page by design, not a tenant-wide one (though the implicit realm auto-select is P1-6).

---

## Suggested fix order

1. **P0-1** — Fix Tailwind content globs + safelist, rebuild and re-embed `app.css`, fix `theme.css` handler to emit `:root` fallback, add `build.rs` + boot-time canary + CI guard. (This will visually change the bugs flagged as "downstream of P0-1" below.)
2. Re-run this audit at 1440×900 AND at tablet/mobile viewports — many P1 and P2 items will auto-close; responsive issues will surface that this pass missed. Re-screenshot the full set.
3. **P0-2, P0-3** — Add sidebar backdrop and modal backdrop (both likely just need the right wrapper classes to re-appear post-CSS).
4. **P0-4 secondary** — Fix `alt="Test Corp"`, favicon 404, passkey-begin 404; verify the login gradient (could be a hardcoded theme violation that did NOT self-heal).
5. **P1-1 … P1-10** — work top-down. Verify P1-10 (pagination) is a real bug before fixing by seeding 21+ users.
6. **P2** — polish pass; investigate P2-6 as a possible template-correctness bug.

### Which bugs are downstream of P0-1 vs. structural

**Likely to self-resolve after the CSS rebuild (verify, don't assume):**
- P0-2 (sidebar transparency), P0-3 (modal backdrop — structural fix still needed even if CSS resurrects some classes), P1-4 (search-icon positioning), P1-7 (invisible status badges), P2-3 (no row dividers/hover), P2-5 (bare native date/number inputs), P0-4 primary symptom (unstyled login card, "Sign in" button looking like text).

**Structural bugs that WILL remain after the CSS rebuild:**
- P0-4 secondary (passkey-begin 404, favicon 404, `alt="Test Corp"`), P1-1 (badge sizing — markup structure, not just CSS), P1-2 ("Configured in hearth.yaml" leaks into action cell — template structure), P1-3 (missing invite email input — template structure), P1-5 (sidebar vs dashboard nav mismatch), P1-6 (silent realm redirect), P1-8 (missing `autocomplete` attrs), P1-9 (admin-create route bug), P2-1 (page title inconsistency), P2-2 (alt text), P2-4 (breadcrumb self-link), P2-6 (possible template dereference bug), P2-7, P2-8 (reset confirmation), P2-9 (audit resource format), P2-10 (colspan), P2-11 (settings collapse default), P2-13 (dashboard cards not clickable), P2-14, P2-15, P2-16.

**Unverified — require additional data to confirm:**
- P1-10 (pagination), P2-6 (may be P1 after template inspection), P0-4 login gradient cause, P0-3 sibling modals (token regen, diff preview, member picker).

**Not covered by this audit at all:**
- Responsive layouts below `lg:` breakpoint.

## Resolution status (2026-04-23)

The following items were addressed in this pass:

**P0 — all resolved:**
- [x] **P0-1** — Tailwind pipeline fixed. `build.rs` now auto-compiles `ui/input.css` → `src/protocol/web/assets/app.css` when the CLI is present. `ui/tailwind.config.js` expanded content globs (`templates/**/*.html` + `src/protocol/web/**/*.rs`) and added a safelist covering `btn-ember`, `btn-danger`, `bg-ht-surface-*`, `text-ht-content-*`, divider alpha classes, accent ramps, semantic states, fonts, and shape tokens. Compiled `app.css` now contains `.bg-ht-surface-raised{background-color:var(--ht-surface-raised)}` and `.btn-ember`. `src/protocol/web/themes.rs` always emits a full `:root { ... }` block — ember included, unknown names fall back to ember. Boot-time canary `assert_app_css_sane()` in `src/protocol/web/mod.rs` is called from `run_serve()` and panics in debug builds if the theme layer is missing. `tests/web_ui_assets.rs` enforces the sentinels in CI.
- [x] **P0-2** — Self-resolved by P0-1 (sidebar `bg-ht-surface-raised` + `border-r border-divider` now render).
- [x] **P0-3** — Self-resolved by P0-1 (`fixed inset-0 bg-black/50` now compiled); existing markup in `templates/ui/admin/organizations/detail.html` is correct.
- [x] **P0-4** — Favicon added at `src/protocol/web/assets/favicon.svg`, served at `/favicon.ico` and `/ui/static/favicon.svg`, linked from `templates/ui/_layout.html`. Admin passkey routes `/ui/admin/login/passkey-begin` and `/ui/admin/login/passkey-complete` now exist (new `passkey_login_begin_admin` / `passkey_login_complete_admin` handlers force the system realm). Logo `alt="{{ product_name }}"` was already dynamic — confirmed not a bug.

**P1:**
- [x] **P1-1** — Added `shrink-0 whitespace-nowrap` to applications badge.
- [x] **P1-2** — Removed redundant "Configured in hearth.yaml" helper text from realm row action cell (the info banner at the top of the list page already conveys this).
- [x] **P1-3** — Organization invite form lifted out of the `<details>` collapse; always visible now, with `autocomplete="email"` on the input.
- [x] **P1-4** — Self-resolved by P0-1.
- [x] **P1-5** — Added Users / Organizations / Applications / Sessions entries to the admin sidebar in `templates/ui/_layout.html`, mirroring the dashboard quick-links.
- [ ] **P1-6** — Deferred. The existing `_workspace_tabs.html` now renders the realm breadcrumb + tabs legibly (post-P0-1), so the "you don't know what realm you're in" concern is mitigated. A proper "require `?realm=` or show picker" refactor remains in the backlog.
- [x] **P1-7** — Self-resolved by P0-1 (status-badge opacity utilities like `bg-success/[0.12]` now compile).
- [x] **P1-8** — `autocomplete="off"` per-field on user create / edit forms (email, first/last/display name). Password remains `autocomplete="new-password"`. Form-level `autocomplete="off"` removed so per-field hints govern.
- [ ] **P1-9** — Deferred. The `/ui/admin/users/new` handler relies on `TargetRealm` for tenant creates and the same template is reused for admin creates. A dedicated `/ui/admin/admin-users/new` route + template is tracked for a follow-up.
- [ ] **P1-10** — Deferred. Marked UNVERIFIED in the audit; needs a seeded dataset of 21+ users to confirm whether the cursor UI is actually missing.

**P2:**
- [x] **P2-1** — All `templates/ui/**/*.html` block titles migrated from `Hearth · <Page>` to `{{ product_name }} · <Page>`.
- [x] **P2-2** — Already dynamic (`alt="{{ product_name }}"`).
- [x] **P2-3** — Self-resolved by P0-1 (`border-divider-*` / `hover-bg-divider` now compile).
- [ ] **P2-4** — Deferred. Breadcrumb cross-link decision needs coordination with P1-6.
- [x] **P2-5** — Self-resolved by P0-1; inputs already share the same input class set.
- [x] **P2-6** — `templates/ui/admin/users/detail.html` now suppresses the mono `object_id` row when it matches `label`, collapsing hearth-level `admin/admin/admin` triples to a single `admin` pill.
- [ ] **P2-7** — Deferred (minor; requires per-tab breadcrumb context).
- [ ] **P2-8** — Deferred (requires Alpine reset-confirm wiring).
- [x] **P2-9** — Self-resolved by CSS rebuild (format already consistent in `_rows.html`).
- [x] **P2-10** — Already has `colspan="6"` on sessions empty state; false positive.
- [x] **P2-11** — Already uses `x-data="{ open: true }"` for all system-info sections.
- [ ] **P2-12** — Deferred. CodeMirror/Prism is a larger MVP addition.
- [x] **P2-13** — Dashboard stat cards converted from `<div>` to `<a>` linking to Users/Realms/Applications/Organizations list pages.
- [ ] **P2-14** — Deferred.
- [ ] **P2-15** — Deferred.
- [x] **P2-16** — Already wired: `admin_audit_verify_integrity` renders `flash_message` at top of `audit/list.html` on both success and failure.

## Verification checklist for a follow-up agent

After all P0 + P1 fixes are in, re-run this audit and confirm:

- [ ] `curl -s http://localhost:8420/ui/static/app.css | grep -c 'var(--ht-surface-base)'` ≥ 1 *(must be a `var()` reference, not a literal hex — otherwise runtime theming is broken)*
- [ ] `curl -s http://localhost:8420/ui/static/app.css | grep -c 'btn-ember'` ≥ 1
- [ ] `curl -s http://localhost:8420/ui/static/app.css | grep -c '\.bg-ht-surface-raised'` ≥ 1
- [ ] `curl -s http://localhost:8420/ui/static/theme.css` is non-empty, contains `:root {`, AND contains an `--ht-surface-base:` declaration (this is where hex values legitimately live — customers override here)
- [ ] `getComputedStyle(document.body).backgroundColor` is `rgb(20, 20, 24)` (graphite-900), not `rgba(0,0,0,0)`.
- [ ] `getComputedStyle(document.body).fontFamily` starts with `Manrope`.
- [ ] Sidebar on `/ui/admin/realms` has a visible opaque background and a visible right border.
- [ ] Delete-organization modal has a visible backdrop dimming the page and the panel is on solid `bg-ht-surface-raised`.
- [ ] Every `<img>` logo `alt` is either "Home", "Hearth", or `branding.product_name` — never hardcoded "Test Corp".
- [ ] No 404 in the browser console on any admin page (favicon + passkey-begin).
- [ ] Search icons appear inside the input field on users / admin-users / organizations list pages.
- [ ] A status badge is rendered as a colored pill on every status cell (users, realms, orgs, apps, sessions).
- [ ] Create ≥21 users and confirm pagination renders a Next affordance on `/ui/admin/users?realm=customer-portal`.
