# Migrating from Auth0

This guide walks you through moving an existing Auth0 tenant to Hearth. Because Auth0 has no single-endpoint realm export (unlike Keycloak), you first assemble a migration bundle from several Management API calls, then import it with a single command.

> **Both the bundler and the importer are provided.** A reference Node.js bundler script lives at `examples/auth0-migration-bundler/`. The Hearth importer is the `hearth migrate auth0` CLI command.

---

## Conceptual mapping

| Auth0 concept | Hearth equivalent | Notes |
|---|---|---|
| **Tenant** | **Realm** | One Auth0 tenant maps to one Hearth realm. The tenant `name` becomes the realm name. |
| **Application** (client) | **Application** (OAuth client) | `client_id`, `callbacks` (redirect URIs), and grant types map directly. |
| **User** | **User** | Email, name, email-verified, and blocked status all import. |
| **Role** | **Role** | Auth0 roles become Hearth RBAC roles with the same name. Assignments are preserved. |
| **Organization** | **Organization** | Auth0 organizations import with their member lists and per-member role assignments. |
| **Connection** (Google, SAML, AD) | Not yet available | See [Out of scope](#out-of-scope). |
| **Actions / Rules / Hooks** | Not applicable | Hearth uses a built-in auth policy engine instead. |
| **MFA factors** | Not migrated | Auth0 does not export TOTP secrets; users must re-enroll. |

---

## Step 1 — Assemble the migration bundle

Auth0 does not provide a single export endpoint. You must call several Management API endpoints and merge the results into a bundle JSON. A reference Node.js script at `examples/auth0-migration-bundler/` does this automatically.

### Prerequisites

- Auth0 Management API access (Machine-to-Machine application with `read:users`, `read:clients`, `read:organizations`, `read:roles` scopes)
- Node.js 18 or later

### Run the bundler

```bash
cd examples/auth0-migration-bundler/
npm install

AUTH0_DOMAIN=your-tenant.auth0.com \
AUTH0_CLIENT_ID=<m2m-client-id> \
AUTH0_CLIENT_SECRET=<m2m-client-secret> \
  node bundle.js --output auth0-bundle.json
```

The script calls:
- `GET /api/v2/users` (paginated, with credential export if enabled)
- `GET /api/v2/clients`
- `GET /api/v2/organizations` + members + member role assignments per org
- `GET /api/v2/roles` + role assignments per role

The resulting `auth0-bundle.json` has this shape:

```json
{
  "tenant": { "name": "your-tenant", "id": "<optional-uuid>" },
  "users": [ ... ],
  "clients": [ ... ],
  "organizations": [ ... ],
  "roles": [ ... ]
}
```

### Credential export note

Auth0 only exports password hashes if you have the **bulk user export** feature enabled and have contacted Auth0 support to include `custom_password_hash`. Without this, users will be imported without a password credential and must set a new password via the magic-link / passwordless flow on first login.

The `custom_password_hash` field follows Auth0's bulk-import shape. Hearth imports bcrypt hashes natively and verifies them without re-hashing. On the user's next successful login, Hearth transparently upgrades the credential to Argon2id.

---

## Step 2 — Dry-run validation

Validate the bundle against Hearth's importer before writing any data:

```bash
hearth migrate auth0 \
  --file auth0-bundle.json \
  --dry-run
```

The printed report shows:
- Tenant name resolved from the bundle
- Users found, imported, and skipped (with skip reasons — e.g., no email address, unsupported credential algorithm)
- OAuth clients found and imported
- Organizations and member assignments
- Roles created and assigned

No data directory is needed for a dry run.

---

## Step 3 — Import

```bash
hearth migrate auth0 \
  --file auth0-bundle.json \
  --data-dir /var/lib/hearth
```

**Optional flags:**

| Flag | Purpose |
|---|---|
| `--realm <uuid>` | Force the realm to a specific UUID instead of the tenant's `id` field (or a fresh UUID). Useful for predictable realm IDs that your apps reference. |
| `--dry-run` | Validate without writing. |

The import is atomic at the WAL record level. If interrupted, re-running the import converges to a clean state.

---

## What the importer handles

The Auth0 importer (`src/identity/migration/auth0.rs`) processes:

- **Tenant** → realm name and optional realm UUID
- **Users** — email, given name, family name, nickname, email-verified flag, blocked (→ `UserStatus::Disabled`)
- **Password credentials** — bcrypt hashes via `custom_password_hash` are passed through as PHC strings and verified natively. Unsupported algorithms are noted in the report; those users import without a credential.
- **Auth0 user IDs** — when the `user_id` is a valid UUID (e.g. `550e8400-e29b-41d4-a716-446655440000`), it is preserved as the Hearth `UserId`. Non-UUID IDs (e.g. `auth0|abc123`, `google-oauth2|...`) generate a fresh UUID — record the mapping if you need to correlate.
- **OAuth clients** — client ID, redirect URIs (`callbacks`), grant types, public/confidential designation
- **Roles** — created in the Hearth RBAC engine; assignments to users are preserved
- **Organizations** — created as Hearth Organizations; member lists and per-member roles are applied

---

## Step 4 — Start Hearth

```yaml
# hearth.yaml
storage:
  data_dir: /var/lib/hearth

oidc:
  issuer: "https://auth.example.com"
```

```bash
hearth serve -c hearth.yaml
```

Verify the server is healthy:
```bash
curl http://127.0.0.1:8420/health
```

---

## Step 5 — Post-migration checklist

### Verify user count

```bash
curl -H "Authorization: Bearer <admin-token>" \
  http://127.0.0.1:8420/admin/realms/<realm-id>/users | jq length
```

Users without an email address in Auth0 are skipped — the migration report counts them.

### Test a login

```bash
curl -X POST http://127.0.0.1:8420/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=user@example.com&password=<password>&client_id=<client-id>"
```

### Verify the OIDC discovery document

```bash
curl http://127.0.0.1:8420/.well-known/openid-configuration | jq .issuer
```

The `issuer` must match the value your applications currently trust. If your apps previously used `https://your-tenant.auth0.com/` as the issuer, you will need to update their configuration to point to the Hearth issuer.

### Update application configuration

Auth0 applications were configured with:
- **Domain:** `your-tenant.auth0.com`
- **JWKS URI:** `https://your-tenant.auth0.com/.well-known/jwks.json`
- **Token endpoint:** `https://your-tenant.auth0.com/oauth/token`

Replace all of these with Hearth equivalents:
- **Domain:** `auth.example.com` (your Hearth host)
- **JWKS URI:** `https://auth.example.com/.well-known/jwks.json`
- **Token endpoint:** `https://auth.example.com/token`
- **Authorization endpoint:** `https://auth.example.com/authorize`

### Update redirect URIs

Confirm every application's redirect URIs are registered in Hearth. Edit via the admin UI at `/ui/admin/applications/<client-id>/edit`. The match is exact (scheme, host, port, path, no trailing slash variation).

### Update Auth0 Management API references

Any service that called Auth0's Management API (`/api/v2/users`, etc.) must migrate to Hearth's admin API. Refer to the Hearth API reference for equivalent endpoints.

### Plan MFA re-enrollment

Auth0 does not export TOTP secrets or WebAuthn credentials. Users who had MFA enabled in Auth0 must re-enroll their authenticator in Hearth. Announce the re-enrollment requirement to users before switching traffic.

### Verify role and organization assignments

```bash
curl -H "Authorization: Bearer <admin-token>" \
  "http://127.0.0.1:8420/admin/realms/<realm-id>/users/<user-id>/roles"
```

Spot-check a representative set of users against the Auth0 role list.

---

## Out of scope

| Auth0 feature | Status in Hearth | Action required |
|---|---|---|
| **Federated connections** (Google OAuth, SAML, LDAP, AD) | Not yet available | Track on roadmap; users must use a local Hearth credential in the interim |
| **MFA factors** (TOTP, WebAuthn, SMS) | Not exported by Auth0 | Users must re-enroll after migration |
| **Actions / Rules / Hooks** | Not applicable | Implement equivalent logic in your application or wait for Hearth's planned hook surface |
| **Session tokens** | Not migrated | All users must log in again after switchover |
| **Social login providers** | Not yet available | Users who authenticated only via social login must reset their password |
| **Custom domains** | Configuration only | Configure `oidc.issuer` and TLS in `hearth.yaml`; no import needed |
| **Auth0 Marketplace integrations** | Not applicable | Evaluate Hearth webhook support for post-login event delivery |
| **Delta / incremental sync** | Not implemented | Re-run a full import for any incremental user additions before the cutover window |

---

## Rollback plan

Auth0 and the Hearth data directory are independent. To roll back:

1. Stop traffic to Hearth.
2. Route traffic back to Auth0.
3. Investigate and fix the issue.
4. Re-run `hearth migrate auth0 --file auth0-bundle.json --data-dir /var/lib/hearth` after clearing the data directory or using `--dry-run` to re-validate.
