# Migrating from Keycloak

This guide walks you through moving an existing Keycloak deployment to Hearth. You will export your Keycloak data, import it into Hearth's embedded storage, verify the result, and update your application configuration.

> **Scope of this guide:** Keycloak realm exports produced by Keycloak 21 and later. The importer handles PBKDF2-SHA256 and PBKDF2-SHA512 password credentials natively. Users with bcrypt or other hashes are imported without a credential and must reset their passwords on first login.

---

## Conceptual mapping

Understanding the terminology difference is the first step. Hearth borrows the "realm" concept from Keycloak but uses it consistently across every feature.

| Keycloak concept | Hearth equivalent | Notes |
|---|---|---|
| **Realm** | **Realm** | Direct equivalent. One Hearth realm = one Keycloak realm. |
| **Client** | **Application** (OAuth client) | Same OAuth 2.0 semantics; Hearth calls them "applications" in the UI. |
| **Realm role** | **Role** | Roles are scoped to a realm. Client roles are not imported (see [Out of scope](#out-of-scope)). |
| **Role mapping** | **Role assignment** | The RBAC engine stores the same subject → role relationship. |
| **User** | **User** | Email, name, and status fields map directly. |
| **Group** | **Organization** (B2B) or **Group** (RBAC) | Keycloak groups used for access control become RBAC groups; groups used for B2B tenancy become Organizations. |
| **Identity provider (IdP federation)** | Not yet available | See [Out of scope](#out-of-scope). |
| **Authentication flow** | **Auth policy** (per-realm) | Hearth supports password, passkey, TOTP, and magic-link; custom SPI flows do not migrate. |
| **Client scope** | **Scope bundle** | Scope bundles are configured in `hearth.yaml`; they are not imported from Keycloak. |
| **Session** | **Session** | Existing sessions are not migrated — users must log in again after migration. |

---

## Step 1 — Export from Keycloak

### Full realm export

```bash
# Replace <realm> with your realm name
/opt/keycloak/bin/kc.sh export \
  --realm <realm> \
  --users realm_file \
  --file keycloak-export.json
```

For Keycloak running in Docker:
```bash
docker exec -it keycloak /opt/keycloak/bin/kc.sh export \
  --realm <realm> \
  --users realm_file \
  --file /tmp/keycloak-export.json

docker cp keycloak:/tmp/keycloak-export.json ./keycloak-export.json
```

> **Important:** Use `--users realm_file` (not `--users different_files`) so that all users are included in the single export file. The importer expects the standard single-file format.

---

## Step 2 — Dry-run validation

Before writing anything, validate the export against Hearth's importer to see what will be imported and catch any surprises:

```bash
hearth migrate keycloak \
  --file keycloak-export.json \
  --dry-run
```

The report printed to stdout shows:
- Realm name resolved from the export
- Number of users found, imported, and skipped (with skip reasons)
- Number of OAuth clients found and imported
- Realm roles found and created
- Any credential algorithm mismatches (users that will be imported without a password credential)

A dry run uses a temporary in-memory store and makes no changes to any data directory.

---

## Step 3 — Import

Decide on a data directory. For a fresh deployment this is typically `/var/lib/hearth` (created automatically if it does not exist):

```bash
hearth migrate keycloak \
  --file keycloak-export.json \
  --data-dir /var/lib/hearth
```

**Optional flags:**

| Flag | Purpose |
|---|---|
| `--realm <uuid>` | Force the realm to a specific UUID instead of using the one from the export. Useful when you need a predictable realm ID to match pre-configured applications. |
| `--dry-run` | Validate without writing (see Step 2). |

The command prints the same migration report as the dry run, but this time all records are written to the WAL. The operation is atomic at the record level — if the process is interrupted mid-import, WAL replay on next startup discards any incomplete records and you can re-run the import.

---

## What the importer handles

The Keycloak importer (`src/identity/migration/keycloak.rs`) processes:

- **Realm** — name, ID, and basic configuration
- **Users** — email, given name, family name, email-verified flag, enabled/disabled status
- **Password credentials** — PBKDF2-SHA256 and PBKDF2-SHA512 are preserved verbatim as PHC strings. Hearth verifies them natively without re-hashing. On the user's next successful login, Hearth transparently upgrades the credential to Argon2id.
- **Realm roles** — created and assigned to the users who held them in Keycloak
- **OAuth clients** — client ID, redirect URIs, grant types, and confidential/public designation

---

## Step 4 — Start Hearth

Point `hearth.yaml` at the populated data directory and start the server:

```yaml
storage:
  data_dir: /var/lib/hearth

oidc:
  issuer: "https://auth.example.com"   # Must match the issuer your apps expect
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

Work through this list before directing production traffic to Hearth.

### Verify users imported correctly

```bash
# Requires an admin token — see /admin/bootstrap for dev or your hearth.yaml admin config
curl -H "Authorization: Bearer <admin-token>" \
  http://127.0.0.1:8420/admin/realms/<realm-id>/users | jq length
```

Compare the count against Keycloak. Users skipped during import appear in the migration report with a reason.

### Test a login

Use the login UI or the token endpoint directly to confirm at least one password-credential user can authenticate:

```bash
curl -X POST http://127.0.0.1:8420/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=user@example.com&password=<password>&client_id=<client-id>"
```

### Verify the OIDC discovery document

```bash
curl http://127.0.0.1:8420/.well-known/openid-configuration | jq .issuer
```

The `issuer` field must exactly match the value configured in `oidc.issuer` and the value your applications have hard-coded or discovered previously.

### Update redirect URIs in your applications

Keycloak's client admin URL is no longer relevant. For each OAuth application, confirm that the redirect URIs configured on the application in Hearth match what your app sends. Edit via:
- Admin UI: `/ui/admin/applications/<client-id>/edit`
- Or update `hearth.yaml` under `realms.<name>.clients` and run `hearth config reload`

### Rotate signing keys (recommended)

Keycloak and Hearth use different signing algorithms (Keycloak defaults to RS256; Hearth uses Ed25519). Because the algorithms differ, tokens issued by Keycloak are not valid in Hearth and vice versa. No key material is imported from Keycloak — Hearth generates a fresh Ed25519 key per realm on first startup.

Inform your application teams of the new JWKS endpoint:
```
GET /.well-known/jwks.json
```

Any application that hard-codes or long-caches the Keycloak public key must be updated to fetch from the Hearth JWKS endpoint.

### Verify role assignments

```bash
curl -H "Authorization: Bearer <admin-token>" \
  "http://127.0.0.1:8420/admin/realms/<realm-id>/users/<user-id>/roles"
```

Cross-check at least a representative sample of role assignments against Keycloak.

### Plan MFA re-enrollment

TOTP secrets and WebAuthn credentials are not included in Keycloak's realm export. After migration, users with MFA enabled in Keycloak will need to re-enroll their authenticator in Hearth. Coordinate the re-enrollment window before switching traffic.

---

## Out of scope

The following Keycloak features do not migrate automatically. They require manual configuration or are not yet implemented in Hearth.

| Keycloak feature | Status in Hearth | Action required |
|---|---|---|
| **Client roles** | Not imported | Recreate as realm roles manually if needed |
| **Groups** (used as RBAC containers) | Not imported | Recreate as Hearth RBAC groups in `hearth.yaml` |
| **Identity provider federation** (Google, SAML, LDAP) | Not yet available | Track on the roadmap; users must authenticate with a local credential in the interim |
| **Custom authentication flows / SPI** | Not applicable | Hearth uses a built-in auth policy engine; SPI extensions do not port |
| **TOTP / WebAuthn credentials** | Not exported by Keycloak | Users must re-enroll after migration |
| **Session tokens** | Not migrated | All users must log in again after switchover |
| **Custom themes** | Not imported | Recreate using Hearth's [theming system](../../docs/specs/THEME.md) |
| **Events / audit history** | Not imported | Hearth starts a fresh audit log on migration |
| **Client scopes** | Not imported | Recreate as [scope bundles](rbac.md) in `hearth.yaml` |

---

## Rollback plan

Because the Hearth import writes to a separate data directory and Keycloak is unchanged, rollback is straightforward:

1. Stop traffic to Hearth.
2. Route traffic back to Keycloak.
3. Investigate the issue.
4. Re-run the import after fixing the problem (the import is idempotent for most records).
