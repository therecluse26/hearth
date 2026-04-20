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
| Search | `search_users` | NO (only in org member picker via `admin_api_user_search`) | N/A | **Add search to user list page** |
| Bulk create/disable | `bulk_create_users`, `bulk_disable_users` | NO | N/A | Leave as API-only |
| Password set (on create) | `set_password` | YES | N/A | OK |
| Admin password reset | `request_password_reset` | NO | N/A | **Add "Send reset email" button** to user detail |
| Password change | `change_password` | NO | N/A | Self-service only — correct |
| MFA status view | `mfa_enabled` | NO | N/A | **Add to user detail** |
| MFA disable (admin) | `disable_mfa` | NO | N/A | **Add to user detail** |
| WebAuthn credential list | `list_webauthn_credentials` | NO | N/A | **Add to user detail** |
| WebAuthn credential revoke | `revoke_webauthn_credential` | NO | N/A | **Add to user detail** |
| Per-user session list | `list_sessions_by_user` | NO (global list only via `admin_sessions_list`) | N/A | **Add to user detail** |
| Per-user session revoke | `revoke_session` | YES (from global list) | N/A | **Add per-user revoke** |
| Per-user org memberships | `list_user_organizations` | NO | N/A | **Add to user detail** |
| Email verification | `issue_email_verification_token`, `verify_email_token` | NO | N/A | Self-service flow — correct |
| UserInfo | `userinfo` | NO | N/A | Protocol endpoint — correct |

### 1.2 Applications (OAuth Clients)

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Create | `register_client` | YES (`admin_app_create_*`) | NO | **Move to YAML** (declarative) |
| List | `list_clients` | YES | N/A | Keep UI for viewing |
| Get / Detail | `get_client` | YES (`admin_app_detail`) | N/A | Keep UI for viewing |
| Update (name, URIs) | `update_client` | YES (`admin_app_edit_*`) | NO | **Move to YAML** |
| Delete | `delete_client` | YES (`admin_app_delete`) | N/A | Keep UI; YAML uses archive |
| Grant types | Stored on `OAuthClient.grant_types` but `UpdateClientRequest` has no `grant_types` field | Shown read-only in detail | NO | **YAML config field** |
| Confidential toggle | Set at creation only | Create-only | NO | **YAML config field** |
| Secret regeneration | No backend API exists | NO | N/A | **Add API + YAML env var** pattern |
| Scopes / permissions | Not implemented | NO | NO | Future: **YAML** |
| PKCE enforcement | Hardcoded (always verified when present) | NO | NO | Future: **YAML per-client** |

### 1.3 Organizations

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| CRUD | `create_organization`, `get_organization`, `update_organization`, `delete_organization` | YES (full form flow) | NO | **Move structural config to YAML** |
| List | `list_organizations` | YES | N/A | Keep UI |
| Slug lookup | `get_organization_by_slug` | YES (implicit) | N/A | OK |
| Members (add/remove/role) | `add_member`, `remove_member`, `update_member_role`, `get_membership`, `list_members` | YES | N/A | Operational — keep UI |
| Invitations (create/revoke/list) | `create_invitation`, `accept_invitation`, `revoke_invitation`, `list_invitations` | YES | N/A | Operational — keep UI |
| `max_members` config | `OrganizationConfig` struct exists | NO | NO | **YAML config field** |
| List user's orgs | `list_user_organizations` | NO (only from org detail side) | N/A | **Add to user detail page** |

### 1.4 Tenants

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| CRUD + reconciliation | `create_tenant`, `get_tenant`, `update_tenant`, `delete_tenant` | YES (list, detail, delete) | YES (`tenants:` section + `reconcile_tenants()`) | Working well |
| List | `list_tenants` | YES | N/A | OK |
| Session TTL | Via `TenantConfig.session_ttl_micros` | NO (config-managed) | YES (`session_ttl`) | OK |
| Password hashing costs | Via `TenantConfig.password_memory_cost/time_cost` | NO (config-managed) | YES | OK |
| Email branding | Via `TenantConfig.email_branding` | NO (config-managed) | YES (`email.branding`) | OK |
| Web theme | Via `TenantConfig.web_theme_css` | NO (config-managed) | YES (`web.theme`) | OK |
| MFA policy (required/methods) | NOT YET | NO | NO | **Add to YAML** (`auth.mfa_*`) |
| Password policy (length, complexity) | NOT YET | NO | NO | **Add to YAML** (`auth.password_policy`) |
| Allowed auth methods | NOT YET | NO | NO | **Add to YAML** (`auth.allowed_auth_methods`) |
| Token TTLs (access/refresh) | Hardcoded in `TokenConfig::default()` (900s / 604,800s) | NO | NO | **Add to YAML** (`token:` section) |
| Rate limit overrides | Hardcoded defaults | NO | NO | **Add to YAML** (`auth.rate_limit`) |

### 1.5 OIDC / Token (Global)

| Capability | Backend Source | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Issuer | `OidcConfig.issuer` (default `"https://hearth.local"`) | NO | NO | **Add `oidc:` YAML section** |
| Access token TTL | `TokenConfig.access_token_ttl_secs` (default 900s = 15min) | NO | NO | **Add `token:` YAML section** |
| Refresh token TTL | `TokenConfig.refresh_token_ttl_secs` (default 604,800s = 7d) | NO | NO | **Add `token:` YAML section** |
| Audience | `TokenConfig.audience` (default `"hearth"`) | NO | NO | **Add `token:` YAML section** |
| Auth code TTL | `OidcConfig.authorization_code_ttl_secs` (default 600s = 10min) | NO | NO | **Add `oidc:` YAML section** |
| Nonce enforcement | `OidcConfig.enforce_nonces` (default `false`) | NO | NO | **Add `oidc:` YAML section** |

### 1.6 Sessions

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Global list | `list_sessions_by_tenant` | YES (`admin_sessions_list`) | N/A | OK |
| Revoke | `revoke_session` | YES (`admin_session_revoke`) | N/A | OK |
| Per-user list | `list_sessions_by_user` | NO | N/A | **Add to user detail** (see §1.1) |

### 1.7 Audit

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Query / list | `audit.query` | YES (`admin_audit_list`) | N/A | OK |
| Integrity verify | `audit.verify_integrity` | NO | N/A | Could expose in system info |
| Retention policy | NOT YET | NO | NO | Future: **YAML** |

### 1.8 Zanzibar (Authorization)

| Capability | Backend Method | Admin UI | YAML Config | Recommendation |
|---|---|---|---|---|
| Tuple CRUD | `write_tuples`, `delete_tuples`, `read_tuples` | NO | N/A | Operational — API is correct surface |
| Permission check | `check` | NO | N/A | API-only — correct |
| Expand | `expand` | NO | N/A | API-only — correct |
| Watch | `watch` | NO | N/A | API-only — correct |
| Namespace schemas | Per-tenant JSON via `set_namespace_config` | NO | NO | Future: **YAML** |

---

## 2. Config Expansion Proposals

These proposals follow the existing reconciliation pattern established by `reconcile_tenants()` in `src/identity/reconcile.rs`. The pattern: YAML is the source of truth for structural config; on startup, Hearth creates/updates/archives entities to match the declared state.

### Priority 1: OIDC & Token Configuration

Currently hardcoded in `OidcConfig::default()` and `TokenConfig::default()`. These are deployment-time decisions that should not require code changes.

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

### Priority 2: Per-Tenant Auth Policies

Extend `TenantYamlConfig` with auth policy knobs that feed into `TenantConfig`. These are deployment-time decisions about how a tenant's users authenticate.

**Proposed YAML extension:**

```yaml
tenants:
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
        access_token_ttl: "15m"      # per-tenant override of global
        refresh_token_ttl: "7d"
      rate_limit:
        max_failed_logins: 5
        lockout_duration: "15m"
```

**Files to modify:**
- `src/config/types.rs` — new `TenantAuthYaml`, `PasswordPolicyYaml`, `RateLimitYaml` structs; add `auth: Option<TenantAuthYaml>` to `TenantYamlConfig`
- `src/identity/types.rs` — extend `TenantConfig` with matching runtime fields
- `src/identity/reconcile.rs` — map YAML auth fields into `TenantConfig` during reconciliation
- `src/config/mod.rs` — validation (e.g., `min_length >= 8`, valid `mfa_methods` values)

**Enforcement approach:** These fields are *policy declarations* — they require corresponding enforcement code in the identity engine:
- `mfa_required`: check after password verification in login flow
- `password_policy`: validate in `set_password` / `change_password`
- `rate_limit`: feed into `RateLimiter` configuration per tenant
- `allowed_auth_methods`: gate magic link, passkey, and password flows

### Priority 3: OAuth Client Declarations

OAuth clients are structural config — they define how applications integrate with Hearth. Follow the tenant reconciliation pattern.

**Proposed YAML extension:**

```yaml
tenants:
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
- **Client ID stability:** use deterministic ID derived from `tenant_name + app_key` (e.g., `frontend-spa`) to ensure clients survive YAML re-reads without generating new IDs

**Files to modify:**
- `src/config/types.rs` — new `ApplicationYamlConfig` struct; add `applications: Option<HashMap<String, ApplicationYamlConfig>>` to `TenantYamlConfig`
- `src/identity/reconcile.rs` — new `reconcile_applications()` function
- `src/identity/oidc.rs` — extend `UpdateClientRequest` with `grant_types: Option<Vec<String>>`
- `src/identity/engine.rs` — implement `update_client` grant_types update path

**Backend gap:** `UpdateClientRequest` currently only has `client_name` and `redirect_uris`. Must add `grant_types` field before YAML reconciliation can manage it (see Phase C).

### Priority 4: Organization Declarations

For B2B deployments where org structure is known at deploy time.

**Proposed YAML extension:**

```yaml
tenants:
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

**Reconciliation behavior:** create/update/archive like tenants. Slug derived from the YAML key (e.g., `acme-corp`). Members and invitations remain operational (API/UI only) — they are runtime bindings, not structural config.

**Files to modify:**
- `src/config/types.rs` — new `OrganizationYamlConfig` struct; add `organizations: Option<HashMap<String, OrganizationYamlConfig>>` to `TenantYamlConfig`
- `src/identity/reconcile.rs` — new `reconcile_organizations()` function

### Priority 5: Zanzibar Namespace Schemas (Future)

```yaml
tenants:
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

Lower priority — authz namespace config is an advanced feature. The backend already supports per-tenant namespace JSON via `set_namespace_config`. YAML would be a convenience layer.

---

## 3. Admin UI Gaps Worth Fixing

These are operational tasks that inherently need a UI — they act on runtime data that cannot be pre-declared in YAML.

### P0 — High Value

**1. User detail: "Send password reset" button**

Backend has `request_password_reset()`. This is the most commonly needed admin action after user creation — a user forgot their password and calls support.

- **Handler:** new `admin_user_send_reset` in `src/protocol/web/admin.rs`
- **Template:** button in `templates/ui/admin/users/detail.html`
- **Flow:** POST → `request_password_reset(tenant, email)` → flash "Reset email sent"

**2. User detail: per-user session list with revoke**

Backend has `list_sessions_by_user()` and `revoke_session()`. Currently sessions are only viewable in a global flat list (`admin_sessions_list`). Per-user view is essential for incident response ("revoke all sessions for this compromised user").

- **Handler:** fold into `admin_user_detail` (load sessions alongside user data)
- **Template:** sessions table partial within user detail, with per-session revoke button
- **HTMX:** revoke via `hx-delete` with `hx-target` to remove the row

**3. User detail: MFA status + disable**

Backend has `mfa_enabled()` and `disable_mfa()`. Show enrollment status (TOTP enrolled, WebAuthn credential count, recovery codes remaining). Admin disable button for lockout recovery.

- **Handler:** query MFA status in `admin_user_detail`; new `admin_user_disable_mfa` POST handler
- **Template:** MFA section in user detail with status badges and disable button with confirmation dialog

### P1 — Medium Value

**4. User detail: WebAuthn credentials tab**

`list_webauthn_credentials()` + `revoke_webauthn_credential()`. View and revoke individual passkeys.

- **Handler:** fold credential list into user detail; new `admin_user_revoke_webauthn` POST handler
- **Template:** credentials table with device name, created date, last used, revoke button

**5. User detail: organization memberships tab**

`list_user_organizations()`. See a user's orgs and roles from the user side (currently only visible from org detail).

- **Handler:** call `list_user_organizations()` in `admin_user_detail`
- **Template:** simple table of org name (linked to org detail), role, joined date

**6. User list: search box**

`search_users()` exists and is already wired for the org member picker (`admin_api_user_search`). Just needs a text input on the main user list page.

- **Template:** search input with `hx-get` to filter the user list
- **Handler:** extend `admin_users_list` to accept `?q=` query parameter

### P2 — Low Priority

**7. Application edit: grant types** — Only needed if applications stay UI-managed. Deprioritized if YAML config (Priority 3) is implemented first.

**8. Organization edit: max_members** — Only needed if orgs stay UI-managed. Deprioritized if YAML config (Priority 4) is implemented first.

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

### Phase A: Config Expansion (no UI changes needed)

| Step | What | Key Files | Depends On |
|---|---|---|---|
| A1 | `oidc:` and `token:` YAML sections | `config/types.rs`, `config/mod.rs`, `main.rs` | — |
| A2 | Per-tenant auth policies | `config/types.rs`, `identity/types.rs`, `identity/reconcile.rs` | A1 (for `token` defaults) |
| A3 | Application declarations + reconciliation | `config/types.rs`, `identity/reconcile.rs`, `identity/oidc.rs`, `identity/engine.rs` | C1 (`UpdateClientRequest.grant_types`) |
| A4 | Organization declarations + reconciliation | `config/types.rs`, `identity/reconcile.rs` | — |

### Phase B: User Detail Page Enhancement (UI, using existing backend APIs)

| Step | What | Key Files | Depends On |
|---|---|---|---|
| B1 | Password reset button | `admin.rs`, `templates/ui/admin/users/detail.html` | — |
| B2 | Per-user session list + revoke | `admin.rs`, new partial template | — |
| B3 | MFA status display + disable button | `admin.rs`, user detail template | — |
| B4 | WebAuthn credential list + revoke | `admin.rs`, user detail template | — |
| B5 | Organization memberships tab | `admin.rs`, user detail template | — |
| B6 | User list search box | `admin.rs`, `templates/ui/admin/users/list.html` | — |

### Phase C: Backend Gaps (required before some config features)

| Step | What | Key Files | Depends On |
|---|---|---|---|
| C1 | Add `grant_types` to `UpdateClientRequest` | `identity/oidc.rs`, `identity/engine.rs` | — |
| C2 | Client secret regeneration API | `identity/mod.rs`, `identity/engine.rs` | — |

**Recommended execution:** C1 → A1 → A2 → B1–B3 (parallel) → A3 → A4 → B4–B6 (parallel) → C2

---

## 6. Verification Checklist

- [x] Cross-referenced all 69 `IdentityEngine` trait methods against UI handlers and config types
- [x] Verified `UpdateClientRequest` fields: only `client_name` and `redirect_uris` (no `grant_types`)
- [x] Verified `TenantConfig` fields: `session_ttl_micros`, `password_memory_cost`, `password_time_cost`, `email_branding`, `web_theme_css`
- [x] Verified `TenantYamlConfig` fields: `session_ttl`, `password_memory_cost`, `password_time_cost`, `email`, `web`
- [x] Verified `OidcConfig` defaults: issuer `"https://hearth.local"`, auth code TTL 600s, enforce_nonces false
- [x] Verified `TokenConfig` defaults: issuer `"hearth"`, audience `"hearth"`, access 900s, refresh 604,800s
- [x] Confirmed `hearth.example.yaml` has no `oidc:`, `token:`, or `applications:` sections
- [x] Confirmed reconciliation pattern: `reconcile_tenants()` creates/updates/archives based on YAML diff
- [x] Confirmed admin handler inventory: 30+ handlers, no user detail enhancements (MFA, sessions, WebAuthn)
- [x] Confirmed user detail template: shows only ID, email, status, edit link, delete button
