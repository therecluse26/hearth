# Auth0 → Hearth Migration Bundler

Assembles an Auth0 tenant into a single JSON bundle that Hearth's
`migrate auth0` subcommand can import.

Unlike Keycloak, Auth0 does not expose a single "tenant export" endpoint.
The operator has to fan out across several Management API endpoints and
stitch the results together. This script does exactly that, and emits the
result in the bundle shape defined by
[`src/identity/migration/auth0.rs`](../../src/identity/migration/auth0.rs).

## Prerequisites

- Node.js 18+
- An Auth0 M2M (machine-to-machine) application authorized against the
  Management API with these scopes:

  | Scope | Purpose |
  |---|---|
  | `read:users` | Users |
  | `read:clients` | Applications |
  | `read:client_keys` | Plaintext client secrets (only if you set `INCLUDE_SECRETS=1`) |
  | `read:organizations` | Organizations + members + member roles |
  | `read:roles` | Realm roles + assignments |

## Usage

```bash
cd examples/auth0-migration-bundler
npm install

export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_CLIENT_ID=xxxxx
export AUTH0_CLIENT_SECRET=xxxxx

# Optional: preserve your Auth0 tenant id as the Hearth realm id.
# Must be a UUID. Auth0 tenant ids are NOT UUIDs — generate one with
# `uuidgen` if you want to pin it.
# export AUTH0_TENANT_ID=$(uuidgen)

# Optional: carry over plaintext client secrets. Without this, Hearth
# will generate fresh secrets and you'll need to update each client app.
# export INCLUDE_SECRETS=1

node bundle.mjs > tenant.json
```

Progress goes to stderr; the JSON bundle goes to stdout. Redirect to a
file or pipe straight into `hearth`:

```bash
# Via file:
node bundle.mjs > tenant.json
hearth migrate auth0 --file tenant.json --data-dir /var/lib/hearth
```

## What the bundle contains

```json
{
  "tenant": { "name": "your-tenant", "id": "<optional-uuid>" },
  "users": [
    {
      "user_id": "auth0|abc123",
      "email": "alice@example.com",
      "email_verified": true,
      "blocked": false,
      "given_name": "Alice",
      "family_name": "Anderson",
      "custom_password_hash": {
        "algorithm": "bcrypt",
        "hash": { "value": "$2a$10$..." }
      }
    }
  ],
  "clients": [
    {
      "client_id": "ZXhhbXBsZWNsaWVudGlkMTIzNDU",
      "name": "My App",
      "callbacks": ["https://app.example.com/callback"],
      "grant_types": ["authorization_code", "refresh_token"],
      "app_type": "regular_web"
    }
  ],
  "organizations": [
    {
      "id": "org_abc",
      "name": "engineering",
      "display_name": "Engineering",
      "members": [
        { "user_id": "auth0|abc123", "roles": ["admin"] }
      ]
    }
  ],
  "roles": [
    {
      "id": "rol_xyz",
      "name": "admin",
      "description": "Realm administrator",
      "assignments": ["auth0|abc123"]
    }
  ]
}
```

## Password hash export — the important caveat

**Auth0 does not export password hashes by default.** The `/users`
endpoint returns account metadata but not the stored hash. To include
hashes you need:

1. The connection was created with "Import Users to Auth0" and
   "Require Username" as applicable, so that Auth0 knows it's a legacy
   hash store.
2. An Auth0 support request to enable hash export on that connection
   (enterprise plans).
3. The returned hashes are usually bcrypt (`$2a$` / `$2b$`). Hearth's
   `verify_password` accepts these natively — no re-hashing needed.

If you can't get hashes: operators run the migration without them, and
Hearth issues password-reset emails on first login. The bundler will
simply omit `custom_password_hash` for those users; they land in
`UserStatus::PendingVerification` (if `email_verified=false`) or
`UserStatus::Active` with `credential: None` (verify_password will
error, forcing a reset flow).

## What's out of scope

- **MFA factors.** Auth0 seals TOTP secrets and WebAuthn credentials;
  neither the API nor the bundler can retrieve them. Users re-enroll MFA
  on their next login after the migration.
- **Federated-identity connections.** Google / SAML / Active Directory
  configs are Auth0-specific. Hearth's own federation module
  (`src/identity/federation/`) is YAML-configured at deploy time.
- **Rules, Actions, Hooks.** Server-side Auth0 logic has no Hearth
  equivalent and is deliberately excluded.
- **Delta / incremental sync.** This bundler is one-shot. Re-running it
  overwrites `tenant.json`.

## Reference

- Hearth importer source: [`src/identity/migration/auth0.rs`](../../src/identity/migration/auth0.rs)
- Credential adapter: [`src/identity/migration/auth0_credentials.rs`](../../src/identity/migration/auth0_credentials.rs)
- Auth0 Management API docs: <https://auth0.com/docs/api/management/v2>
- Bulk user export pathway: <https://auth0.com/docs/manage-users/user-migration/bulk-user-exports>
