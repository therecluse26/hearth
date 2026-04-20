# Gap Analysis: Backend vs Admin UI vs YAML Config

> **Purpose:** Map every backend capability to its UI and config coverage, recommend a **config-first** strategy that maximizes declarative YAML and minimizes UI configuration surface.
>
> **Philosophy:** Avoid "Keycloak configuration UI hell." Structural config belongs in source-controlled YAML. The Admin UI exists for operational/runtime tasks only.

---

## 1. Coverage Matrix

Legend: **YES** = implemented, **NO** = not implemented, **N/A** = not applicable to this surface.

### 1.1 Users

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| CRUD (create/read/update/delete) | `create_user`, `get_user`, `update_user`, `delete_user` | YES | N/A | Operational — UI is correct |
| List (paginated) | `list_users` | YES | N/A | OK |
| Search | `search_users` | ~~NO~~ **YES** (`admin_users_list` with `?q=` param) | N/A | ~~Add search to user list page~~ Done (B6) |
| Bulk create/disable | `bulk_create_users`, `bulk_disable_users` | NO | N/A | Leave as API-only |
| Password set (on create) | `set_password` | YES | N/A | OK |
| Admin password reset | `request_password_reset` | ~~NO~~ **YES** (`admin_user_send_reset`) | N/A | ~~Add "Send reset email" button~~ Done (B1) |
| Password change | `change_password` | NO | N/A | Self-service only — correct |
| MFA status view | `mfa_enabled` | ~~NO~~ **YES** (user detail page) | N/A | ~~Add to user detail~~ Done (B3) |
| MFA disable (admin) | `disable_mfa` | ~~NO~~ **YES** (`admin_user_disable_mfa`) | N/A | ~~Add to user detail~~ Done (B3) |
| WebAuthn credential list | `list_webauthn_credentials` | ~~NO~~ **YES** (user detail page) | N/A | ~~Add to user detail~~ Done (B4) |
| WebAuthn credential revoke | `revoke_webauthn_credential` | ~~NO~~ **YES** (`admin_user_revoke_webauthn`) | N/A | ~~Add to user detail~~ Done (B4) |
| Per-user session list | `list_sessions_by_user` | ~~NO~~ **YES** (user detail page) | N/A | ~~Add to user detail~~ Done (B2) |
| Per-user session revoke | `revoke_session` | **YES** (global list + per-user via `admin_user_revoke_session`) | N/A | ~~Add per-user revoke~~ Done (B2) |
| Per-user org memberships | `list_user_organizations` | ~~NO~~ **YES** (user detail page) | N/A | ~~Add to user detail~~ Done (B5) |
| Email verification | `issue_email_verification_token`, `verify_email_token` | NO | N/A | Self-service flow — correct |
| UserInfo | `userinfo` | NO | N/A | Protocol endpoint — correct |
| Password change (self-service) | `change_password` | YES (`/ui/account/password`) | N/A | OK — account self-service route exists |
| TOTP enroll/disable (self-service) | `enroll_totp`, `verify_totp_enrollment`, `totp_disable` | YES (`/ui/account/totp/*`) | N/A | OK — account self-service routes exist |

### 1.2 Applications (OAuth Clients)

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Create | `register_client` | YES (`admin_app_create_*`) | ~~NO~~ **YES** (`applications:` + `reconcile_applications()`) | ~~Move to YAML~~ Done (A3) |
| List | `list_clients` | YES | N/A | Keep UI for viewing |
| Get / Detail | `get_client` | YES (`admin_app_detail`) | N/A | Keep UI for viewing |
| Update (name, URIs) | `update_client` | YES (`admin_app_edit_*`) | ~~NO~~ **YES** (reconciliation updates) | ~~Move to YAML~~ Done (A3) |
| Delete | `delete_client` | YES (`admin_app_delete`) | N/A | Keep UI; YAML uses archive |
| Grant types | `UpdateClientRequest.grant_types` added (C1) | Shown read-only in detail | ~~NO~~ **YES** (`applications:` YAML) | ~~YAML config field~~ Done (C1 + A3) |
| Confidential toggle | Set at creation only | Create-only | ~~NO~~ **YES** (`applications:` YAML) | ~~YAML config field~~ Done (A3) |
| Secret regeneration | ~~No backend API exists~~ **YES** (`regenerate_client_secret()`) | NO | N/A | ~~Add API + YAML env var~~ API done (C2) |
| Scopes / permissions | Not implemented | NO | NO | Future: **YAML** |
| PKCE enforcement | Hardcoded (always verified when present) | NO | NO | Future: **YAML per-client** |

### 1.3 Organizations

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| CRUD | `create_organization`, `get_organization`, `update_organization`, `delete_organization` | YES (full form flow) | ~~NO~~ **YES** (`organizations:` + `reconcile_organizations()`) | ~~Move structural config to YAML~~ Done (A4) |
| List | `list_organizations` | YES | N/A | Keep UI |
| Slug lookup | `get_organization_by_slug` | YES (implicit) | N/A | OK |
| Members (add/remove/role) | `add_member`, `remove_member`, `update_member_role`, `get_membership`, `list_members` | YES | N/A | Operational — keep UI |
| Invitations (create/revoke/list) | `create_invitation`, `revoke_invitation`, `list_invitations` | YES (create, revoke, list) | N/A | Operational — keep UI |
| Invitation acceptance | `accept_invitation` | ~~NO~~ **YES** (`GET /ui/accept-invitation?token=...`) | N/A | ~~Add public acceptance route~~ Done (D2) |
| Invitation email delivery | `send_invitation_email()` | ~~NO~~ **YES** (wired to `EmailService` in `admin_org_invite`) | N/A | ~~Wire to EmailService~~ Done (D1) |
| `max_members` config | `OrganizationConfig` struct exists | NO | ~~NO~~ **YES** (`organizations:` YAML `config.max_members`) | ~~YAML config field~~ Done (A4) |
| List user's orgs | `list_user_organizations` | ~~NO~~ **YES** (user detail page) | N/A | ~~Add to user detail page~~ Done (B5) |

### 1.4 Realms

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| CRUD + reconciliation | `create_realm`, `get_realm`, `update_realm`, `delete_realm` | YES (list, detail, delete) | YES (`realms:` section + `reconcile_realms()`) | Working well |
| List | `list_realms` | YES | N/A | OK |
| Session TTL | Via `RealmConfig.session_ttl_micros` | NO (config-managed) | YES (`session_ttl`) | OK |
| Password hashing costs | Via `RealmConfig.password_memory_cost/time_cost` | NO (config-managed) | YES | OK |
| Email branding | Via `RealmConfig.email_branding` | NO (config-managed) | YES (`email.branding`) | OK |
| Web theme | Via `RealmConfig.web_theme_css` | NO (config-managed) | YES (`web.theme`) | OK |
| MFA policy (required/methods) | `RealmConfig.mfa_required` / `mfa_methods` | NO (config-managed) | ~~NO~~ **YES** (`auth.mfa_required`, `auth.mfa_methods`) | ~~Add to YAML~~ Done (A2) |
| Password policy (length, complexity) | `RealmConfig.password_policy` | NO (config-managed) | ~~NO~~ **YES** (`auth.password_policy.*`) | ~~Add to YAML~~ Done (A2) |
| Allowed auth methods | `RealmConfig.allowed_auth_methods` | NO (config-managed) | ~~NO~~ **YES** (`auth.allowed_auth_methods`) | ~~Add to YAML~~ Done (A2) |
| Token TTLs (access/refresh) | `RealmConfig.access_token_ttl_secs` / `refresh_token_ttl_secs` | NO (config-managed) | ~~NO~~ **YES** (global `token:` section + per-realm `auth.token.*`) | ~~Add to YAML~~ Done (A1 + A2) |
| Rate limit overrides | `RealmConfig.max_failed_logins` / `lockout_duration_secs` | NO (config-managed) | ~~NO~~ **YES** (`auth.rate_limit.*`) | ~~Add to YAML~~ Done (A2) |

### 1.5 OIDC / Token (Global)

| Capability | Backend Source | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Issuer | `OidcConfig.issuer` (default `"https://hearth.local"`) | NO | ~~NO~~ **YES** (`oidc.issuer`) | ~~Add `oidc:` YAML section~~ Done (A1) |
| Access token TTL | `TokenConfig.access_token_ttl_secs` (default 900s = 15min) | NO | ~~NO~~ **YES** (`token.access_token_ttl`) | ~~Add `token:` YAML section~~ Done (A1) |
| Refresh token TTL | `TokenConfig.refresh_token_ttl_secs` (default 604,800s = 7d) | NO | ~~NO~~ **YES** (`token.refresh_token_ttl`) | ~~Add `token:` YAML section~~ Done (A1) |
| Audience | `TokenConfig.audience` (default `"hearth"`) | NO | ~~NO~~ **YES** (`token.audience`) | ~~Add `token:` YAML section~~ Done (A1) |
| Auth code TTL | `OidcConfig.authorization_code_ttl_secs` (default 600s = 10min) | NO | ~~NO~~ **YES** (`oidc.authorization_code_ttl`) | ~~Add `oidc:` YAML section~~ Done (A1) |
| Nonce enforcement | `OidcConfig.enforce_nonces` (default `false`) | NO | ~~NO~~ **YES** (`oidc.enforce_nonces`) | ~~Add `oidc:` YAML section~~ Done (A1) |

### 1.6 OIDC Extended Flows

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Authorization code flow | `authorize`, `exchange_authorization_code` | NO | N/A | Protocol endpoints — correct |
| Client credentials flow | `client_credentials_token` | NO | N/A | Protocol endpoint — correct |
| Device authorization | `device_authorize` | NO | N/A | Protocol endpoint — correct |
| Device approval (user-facing) | `approve_device` | ~~NO~~ **YES** (`GET/POST /ui/device`) | N/A | ~~Add user-facing approval page~~ Done (D3) |
| Device token polling | `poll_device_token` | NO | N/A | Protocol endpoint — correct |
| Token revocation | `revoke_token` | NO | N/A | Protocol endpoint — correct |
| Token introspection | `introspect_token` | NO | N/A | Protocol endpoint — correct |
| OIDC Discovery | `oidc_discovery` | NO | N/A | Protocol endpoint — correct |
| JWKS | `jwks`, `realm_jwks` | NO | N/A | Protocol endpoint — correct |

### 1.7 Sessions (Admin)

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Global list | `list_sessions_by_realm` | YES (`admin_sessions_list`) | N/A | OK |
| Revoke | `revoke_session` | YES (`admin_session_revoke`) | N/A | OK |
| Per-user list | `list_sessions_by_user` | ~~NO~~ **YES** (user detail page) | N/A | ~~Add to user detail~~ Done (B2) |

### 1.8 Audit

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Query / list | `audit.query` | YES (`admin_audit_list`) | N/A | OK |
| Date range filtering | `AuditQuery.start_time/end_time` fields exist | ~~NO~~ **YES** (date inputs on audit list page) | N/A | ~~Add date range inputs~~ Done (B7) |
| Integrity verify | `audit.verify_integrity` | ~~NO~~ **YES** (`admin_audit_verify_integrity` button) | N/A | ~~Add to system info page~~ Done (B8) |
| Retention policy | NOT YET | NO | NO | Future: **YAML** |

### 1.9 Zanzibar (Authorization)

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Tuple CRUD | `write_tuples`, `delete_tuples`, `read_tuples` | NO | N/A | Operational — API is correct surface |
| Permission check | `check` | NO | N/A | API-only — correct |
| Expand | `expand` | NO | N/A | API-only — correct |
| Watch | `watch` | NO | N/A | API-only — correct |
| Namespace schemas | Per-realm JSON via `set_namespace_config` | NO | NO | Future: **YAML** |

### 1.10 Migration

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Import realm | `import_realm` | NO | N/A | CLI-only (`hearth migrate keycloak`) — correct |
| Import user | `import_user` | NO | N/A | CLI-only — correct |
| Import client | `import_client` | NO | N/A | CLI-only — correct |

Migration is inherently a one-time CLI operation. No UI or config surface needed.

### 1.11 Session Filtering (Global Admin)

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Filter by user | `list_sessions_by_user` exists | ~~NO~~ **YES** (per-user sessions on user detail page, §1.1) | N/A | ~~Add user filter~~ Done (B2) |
| Filter by expiry status | Could derive from `Session.expires_at` | **NO** | N/A | Low priority — nice-to-have |

---

## 2. Config Expansion Proposals

These proposals follow the existing reconciliation pattern established by `reconcile_realms()` in `src/identity/reconcile.rs`. The pattern: YAML is the source of truth for structural config; on startup, Hearth creates/updates/archives entities to match the declared state.

### Priority 1: OIDC & Token Configuration — DONE (A1)

~~Currently hardcoded in `OidcConfig::default()` and `TokenConfig::default()`.~~ Now configurable via `oidc:` and `token:` YAML sections. Defaults still apply when omitted.

**Current state:**
- `OidcConfig`: `issuer = "https://hearth.local"`, `authorization_code_ttl_secs = 600`, `enforce_nonces = false`
- `TokenConfig`: `issuer = "hearth"`, `audience = "hearth"`, `access_token_ttl_secs = 900`, `refresh_token_ttl_secs = 604_800`

**Proposed YAML:**

```yaml
oidc:
  issuer: "https://auth.example.com"
  authorization_code_ttl: "10m"
  enforce_nonces: true

token:
  issuer: "https://auth.example.com"   # should default to oidc.issuer
  audience: "https://auth.example.com"
  access_token_ttl: "15m"
  refresh_token_ttl: "7d"
```

**Files to modify:**
- `src/config/types.rs` — new `OidcYamlConfig` and `TokenYamlConfig` structs
- `src/config/mod.rs` — add fields to `Config`, validate duration strings, validate `issuer` is a URL
- `src/main.rs` — wire YAML values into `IdentityConfig { token, oidc, .. }`

**Note:** `token.issuer` and `oidc.issuer` are currently separate fields. The YAML layer should unify them: default `token.issuer` to `oidc.issuer` when omitted. Document that `oidc.issuer` is the canonical issuer URL and `token.issuer` exists for backward compatibility.

### Priority 2: Per-Realm Auth Policies — DONE (A2)

~~Extend `RealmYamlConfig` with auth policy knobs.~~ Implemented: `RealmAuthYaml` with `mfa_required`, `mfa_methods`, `allowed_auth_methods`, `password_policy`, `token` TTL overrides, and `rate_limit`. Fields are stored in `RealmConfig` and reconciled on startup. Enforcement is a separate follow-up.

**Proposed YAML extension:**

```yaml
realms:
  customer-portal:
    session_ttl: "12h"               # existing
    password_memory_cost: 65536      # existing
    password_time_cost: 3            # existing
    auth:
      mfa_required: false
      mfa_methods: ["totp", "webauthn"]
      allowed_auth_methods: ["password", "magic_link", "passkey"]
      password_policy:
        min_length: 12
        require_uppercase: true
        require_number: true
        require_special: false
      token:
        access_token_ttl: "15m"      # per-realm override of global
        refresh_token_ttl: "7d"
      rate_limit:
        max_failed_logins: 5
        lockout_duration: "15m"
```

**Files to modify:**
- `src/config/types.rs` — new `RealmAuthYaml`, `PasswordPolicyYaml`, `RateLimitYaml` structs; add `auth: Option<RealmAuthYaml>` to `RealmYamlConfig`
- `src/identity/types.rs` — extend `RealmConfig` with matching runtime fields
- `src/identity/reconcile.rs` — map YAML auth fields into `RealmConfig` during reconciliation
- `src/config/mod.rs` — validation (e.g., `min_length >= 8`, valid `mfa_methods` values)

**Enforcement approach:** These fields are *policy declarations* — they require corresponding enforcement code in the identity engine:
- `mfa_required`: check after password verification in login flow
- `password_policy`: validate in `set_password` / `change_password`
- `rate_limit`: feed into `RateLimiter` configuration per realm
- `allowed_auth_methods`: gate magic link, passkey, and password flows

### Priority 3: OAuth Client Declarations — DONE (A3, depends on C1)

~~OAuth clients are structural config.~~ Implemented: `ApplicationYamlConfig` with `name`, `redirect_uris`, `grant_types`, `confidential`, `client_secret` (env var support). `reconcile_applications()` creates/updates/archives clients with deterministic UUIDs (v5 namespace).

**Proposed YAML extension:**

```yaml
realms:
  customer-portal:
    applications:
      frontend-spa:
        name: "Customer Portal Frontend"
        redirect_uris:
          - "https://app.example.com/callback"
          - "https://app.example.com/silent-renew"
        grant_types: ["authorization_code"]
        confidential: false
      backend-service:
        name: "Customer Portal Backend"
        redirect_uris: []
        grant_types: ["client_credentials"]
        confidential: true
        client_secret: "${BACKEND_CLIENT_SECRET}"
```

**Reconciliation behavior:**
- **Create if missing:** hash secret, store client with generated `ClientId`
- **Update if changed:** update `client_name`, `redirect_uris`, `grant_types`; re-hash secret only if env var value changed (compare against stored hash)
- **Archive if removed from YAML:** soft-delete (reject token requests but preserve audit trail)
- **Client ID stability:** use deterministic ID derived from `realm_name + app_key` (e.g., `frontend-spa`) to ensure clients survive YAML re-reads without generating new IDs

**Files to modify:**
- `src/config/types.rs` — new `ApplicationYamlConfig` struct; add `applications: Option<HashMap<String, ApplicationYamlConfig>>` to `RealmYamlConfig`
- `src/identity/reconcile.rs` — new `reconcile_applications()` function
- `src/identity/oidc.rs` — extend `UpdateClientRequest` with `grant_types: Option<Vec<String>>`
- `src/identity/engine.rs` — implement `update_client` grant_types update path

~~**Backend gap:**~~ Resolved: `UpdateClientRequest` now includes `grant_types: Option<Vec<String>>` (C1).

### Priority 4: Organization Declarations — DONE (A4)

~~For B2B deployments where org structure is known at deploy time.~~ Implemented: `OrganizationYamlConfig` with `name`, `description`, `config.max_members`. `reconcile_organizations()` creates/updates/archives orgs with slug derived from YAML key.

**Proposed YAML extension:**

```yaml
realms:
  customer-portal:
    organizations:
      acme-corp:
        name: "Acme Corporation"
        description: "Primary customer account"
        config:
          max_members: 100
      beta-testers:
        name: "Beta Testers"
        config:
          max_members: 50
```

**Reconciliation behavior:** create/update/archive like realms. Slug derived from the YAML key (e.g., `acme-corp`). Members and invitations remain operational (API/UI only) — they are runtime bindings, not structural config.

**Files to modify:**
- `src/config/types.rs` — new `OrganizationYamlConfig` struct; add `organizations: Option<HashMap<String, OrganizationYamlConfig>>` to `RealmYamlConfig`
- `src/identity/reconcile.rs` — new `reconcile_organizations()` function

### Priority 5: Zanzibar Namespace Schemas (Future)

```yaml
realms:
  customer-portal:
    authz:
      namespaces:
        document:
          relations:
            owner: {}
            editor:
              union: [this, owner]
            viewer:
              union: [this, editor]
```

Lower priority — authz namespace config is an advanced feature. The backend already supports per-realm namespace JSON via `set_namespace_config`. YAML would be a convenience layer.

---

## 3. Admin UI Gaps Worth Fixing

These are operational tasks that inherently need a UI — they act on runtime data that cannot be pre-declared in YAML.

### P0 — High Value

**1. ~~User detail: "Send password reset" button~~ DONE (B1)**

- **Handler:** `admin_user_send_reset` in `src/protocol/web/admin.rs`
- **Template:** button in `templates/ui/admin/users/detail.html`
- **Route:** `POST /admin/users/{id}/reset-password`

**2. ~~User detail: per-user session list with revoke~~ DONE (B2)**

- **Handler:** `admin_user_detail` loads sessions; `admin_user_revoke_session` POST handler
- **Template:** sessions table in user detail page with per-session revoke buttons
- **Route:** `POST /admin/users/{id}/sessions/{sid}/revoke`

**3. ~~User detail: MFA status + disable~~ DONE (B3)**

- **Handler:** `admin_user_detail` queries `mfa_enabled()`; `admin_user_disable_mfa` POST handler
- **Template:** MFA status badge + disable button with Alpine confirmation dialog
- **Route:** `POST /admin/users/{id}/disable-mfa`

### P1 — Medium Value

**4. ~~User detail: WebAuthn credentials tab~~ DONE (B4)**

- **Handler:** `admin_user_detail` loads `list_webauthn_credentials()`; `admin_user_revoke_webauthn` POST handler
- **Template:** credentials table with credential ID, algorithm, discoverable flag, revoke button
- **Route:** `POST /admin/users/{id}/webauthn/{cred_id}/revoke`

**5. ~~User detail: organization memberships tab~~ DONE (B5)**

- **Handler:** `admin_user_detail` calls `list_user_organizations()`
- **Template:** org memberships table with org name (linked to detail), role badge

**6. ~~User list: search box~~ DONE (B6)**

- **Template:** search input on `templates/ui/admin/users/list.html`
- **Handler:** `admin_users_list` accepts `?q=` query parameter, uses `search_users()` when `q.len() >= 2`

### P1.5 — Functional Gaps (Missing Flows)

**7. ~~Invitation acceptance page~~ DONE (D1 + D2)**

- **Email delivery:** `admin_org_invite` wired to `EmailService.send_invitation_email()` (D1)
- **Email templates:** `templates/email/invitation.html` + `invitation.txt`
- **Acceptance route:** `GET /ui/accept-invitation?token=...` → `accept_invitation()` → success/error page (D2)

**8. ~~Device authorization approval page~~ DONE (D3)**

- **Route:** `GET /ui/device` → form with user_code input; `POST /ui/device` → `approve_device(realm, user_code, user_id)`
- **Template:** `templates/ui/device_approve.html` (authenticated, with flash messages)

**9. ~~Audit list: date range filters~~ DONE (B7)**

- **Template:** start/end date inputs added to `templates/ui/admin/audit/list.html`
- **Handler:** `admin_audit_list` passes `start_date`/`end_date` to `AuditQuery.start_time`/`end_time`

**10. ~~Audit integrity verification~~ DONE (B8)**

- **Handler:** `admin_audit_verify_integrity` POST in `admin.rs`
- **Route:** `POST /admin/audit/verify`
- **Template:** "Verify integrity" button on audit list page with flash result

### P2 — Low Priority

**11. Application edit: grant types** — Only needed if applications stay UI-managed. Deprioritized if YAML config (Priority 3) is implemented first.

**12. Organization edit: max_members** — Only needed if orgs stay UI-managed. Deprioritized if YAML config (Priority 4) is implemented first.

---

## 4. Items That MUST Stay Operational (UI/API Only)

These are runtime/transactional data — cannot be declared statically:

| Category | Why |
|---|---|
| **Users** | Created via registration, onboarding, migration, or admin UI |
| **Sessions** | Created by login, expired/revoked at runtime |
| **Credentials** | Passwords, TOTP secrets, WebAuthn keys, recovery codes |
| **Tokens** | JWTs, auth codes, device codes, magic links |
| **Audit logs** | Append-only event stream |
| **Organization memberships** | Runtime user-org bindings |
| **Organization invitations** | Created/accepted/revoked at runtime |
| **Zanzibar tuples** | Runtime permission assignments |

---

## 5. Implementation Order

### Phase A: Config Expansion (no UI changes needed) — ALL DONE

| Step | What | Key Files | Depends On | Status |
|---|---|---|---|---|
| A1 | `oidc:` and `token:` YAML sections | `config/types.rs`, `config/mod.rs`, `main.rs` | — | **DONE** |
| A2 | Per-realm auth policies | `config/types.rs`, `identity/types.rs`, `identity/reconcile.rs` | A1 (for `token` defaults) | **DONE** |
| A3 | Application declarations + reconciliation | `config/types.rs`, `identity/reconcile.rs`, `identity/oidc.rs`, `identity/engine.rs` | C1 (`UpdateClientRequest.grant_types`) | **DONE** |
| A4 | Organization declarations + reconciliation | `config/types.rs`, `identity/reconcile.rs` | — | **DONE** |

### Phase B: User Detail Page Enhancement (UI, using existing backend APIs) — ALL DONE

| Step | What | Key Files | Depends On | Status |
|---|---|---|---|---|
| B1 | Password reset button | `admin.rs`, `templates/ui/admin/users/detail.html` | — | **DONE** |
| B2 | Per-user session list + revoke | `admin.rs`, user detail template | — | **DONE** |
| B3 | MFA status display + disable button | `admin.rs`, user detail template | — | **DONE** |
| B4 | WebAuthn credential list + revoke | `admin.rs`, user detail template | — | **DONE** |
| B5 | Organization memberships tab | `admin.rs`, user detail template | — | **DONE** |
| B6 | User list search box | `admin.rs`, `templates/ui/admin/users/list.html` | — | **DONE** |
| B7 | Audit date range filters | `admin.rs`, `templates/ui/admin/audit/list.html` | — | **DONE** |
| B8 | Audit integrity verification | `admin.rs`, audit list template | — | **DONE** |

### Phase C: Backend Gaps (required before some config features) — ALL DONE

| Step | What | Key Files | Depends On | Status |
|---|---|---|---|---|
| C1 | Add `grant_types` to `UpdateClientRequest` | `identity/oidc.rs`, `identity/engine.rs` | — | **DONE** |
| C2 | Client secret regeneration API | `identity/mod.rs`, `identity/engine.rs` | — | **DONE** |

### Phase D: Missing Functional Flows — ALL DONE

| Step | What | Key Files | Depends On | Status |
|---|---|---|---|---|
| D1 | Invitation email delivery | `admin.rs`, `identity/email/service.rs`, `templates/email/invitation.*` | EmailService exists | **DONE** |
| D2 | Invitation acceptance route | `web/mod.rs`, `handlers.rs`, `templates/ui/accept_invitation.html` | D1 | **DONE** |
| D3 | Device authorization approval page | `web/mod.rs`, `handlers.rs`, `templates/ui/device_approve.html` | — | **DONE** |

**Execution order (completed):** C1 → C2 → A1 → A2 → A3 → A4 → B1–B5 → B6 → B7–B8 → D1 → D2 → D3

---

## 6. Verification Checklist

- [x] Cross-referenced all 81 `IdentityEngine` trait methods against UI handlers and config types
- [x] Cross-referenced all 3 `AuditEngine` trait methods (append, query, verify_integrity)
- [x] Cross-referenced all 6 `AuthorizationEngine` trait methods (check, expand, write_tuples, set/get_namespace, watch)
- [x] Audited all 50+ registered routes in `src/protocol/web/mod.rs`
- [x] ~~Verified `UpdateClientRequest` fields: only `client_name` and `redirect_uris` (no `grant_types`)~~ Now includes `grant_types` (C1)
- [x] Verified `RealmConfig` fields: `session_ttl_micros`, `password_memory_cost`, `password_time_cost`, `email_branding`, `web_theme_css`
- [x] Verified `RealmYamlConfig` fields: `session_ttl`, `password_memory_cost`, `password_time_cost`, `email`, `web`
- [x] Verified `OidcConfig` defaults: issuer `"https://hearth.local"`, auth code TTL 600s, enforce_nonces false
- [x] Verified `TokenConfig` defaults: issuer `"hearth"`, audience `"hearth"`, access 900s, refresh 604,800s
- [x] ~~Confirmed `hearth.example.yaml` has no `oidc:`, `token:`, or `applications:` sections~~ Now has all three (A1, A3)
- [x] Confirmed reconciliation pattern: `reconcile_realms()` creates/updates/archives based on YAML diff
- [x] ~~Confirmed admin handler inventory: 30+ handlers, no user detail enhancements~~ Now 40+ handlers with full user detail (B1–B5)
- [x] ~~Confirmed user detail template: shows only ID, email, status, edit link, delete button~~ Now shows sessions, MFA, WebAuthn, org memberships, action buttons (B1–B5)
- [x] ~~Identified `accept_invitation` dead end~~ Resolved: email delivery (D1) + acceptance route (D2) implemented
- [x] ~~Identified `approve_device` missing page~~ Resolved: `GET/POST /ui/device` implemented (D3)
- [x] ~~Identified `AuditQuery.start_time/end_time` unused in UI~~ Resolved: date inputs added (B7)
- [x] ~~Identified `verify_integrity` unexposed~~ Resolved: `POST /admin/audit/verify` handler added (B8)
- [x] Confirmed account self-service routes exist: `/ui/account/password`, `/ui/account/totp/*`
- [x] Confirmed migration methods are CLI-only (correct — no UI/config needed)
