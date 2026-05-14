# SCIM Provisioning Guide

**Audience:** operators integrating an external identity provider (Okta, Azure AD / Entra ID, Google Workspace, JumpCloud) for automated user provisioning and deprovisioning.

Hearth implements SCIM 2.0 (RFC 7643 + RFC 7644) at `/scim/v2/`. When you configure your IdP to point at this endpoint, it can push user and group changes to Hearth automatically — creating accounts, updating profiles, suspending leavers, and syncing group memberships.

## Prerequisites

- A running Hearth instance (see [Quick Start](../../README.md#quick-start)).
- An admin token or access to `hearth.yaml` to configure the SCIM bearer token.
- The realm UUID you want to provision into.

## Enabling SCIM for a realm

SCIM is enabled per realm by setting a static bearer token in `hearth.yaml`. Hearth stores only the SHA-256 hash of this token — the plaintext is never persisted after startup.

```yaml
realms:
  my-realm:
    scim:
      bearer_token: "${SCIM_PROVISIONING_TOKEN}"
```

`${SCIM_PROVISIONING_TOKEN}` is resolved from the environment at startup. Use a securely-generated random value:

```bash
openssl rand -hex 32
```

After editing `hearth.yaml`, restart Hearth. SCIM requests are rejected with `403 Forbidden` for any realm that has no bearer token configured.

## Authentication

Every SCIM request must include two headers:

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <your-token>` |
| `X-Realm-ID` | The realm UUID (not the realm name) |

```bash
SCIM_TOKEN="your-provisioning-token"
REALM_ID="<realm-uuid>"

curl -X GET "http://127.0.0.1:8420/scim/v2/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Realm-ID: $REALM_ID"
```

Rate limit: shared with the admin surface — 100 requests/minute per realm.

## Base URL

```
http://<host>:<port>/scim/v2/
```

In production with TLS: `https://<host>/scim/v2/`

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/scim/v2/ServiceProviderConfig` | Capability advertisement (RFC 7643 §5) |
| `GET` | `/scim/v2/ResourceTypes` | Supported resource types |
| `GET` | `/scim/v2/Schemas` | Schema definitions |
| `GET` `POST` | `/scim/v2/Users` | List / create users |
| `GET` `PUT` `PATCH` `DELETE` | `/scim/v2/Users/{id}` | Read / replace / update / delete a user |
| `GET` `POST` | `/scim/v2/Groups` | List / create groups |
| `GET` `PUT` `PATCH` `DELETE` | `/scim/v2/Groups/{id}` | Read / replace / update / delete a group |

## User provisioning

### Create a user

```bash
curl -X POST "http://127.0.0.1:8420/scim/v2/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com",
    "externalId": "okta-user-abc123",
    "name": {
      "givenName": "Alice",
      "familyName": "Smith"
    },
    "displayName": "Alice Smith",
    "emails": [{"value": "alice@example.com", "primary": true}],
    "active": true
  }'
```

### Update a user (PATCH)

Hearth supports PATCH operations on these paths:

| Path | Maps to |
|------|---------|
| `active` | Account enabled / disabled |
| `name.givenName` | First name |
| `name.familyName` | Last name |
| `displayName` | Display name |
| `emails` | Email list (primary address persisted) |

```bash
curl -X PATCH "http://127.0.0.1:8420/scim/v2/Users/<id>" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "active", "value": false}
    ]
  }'
```

Setting `active: false` disables the Hearth account. The user cannot log in until re-enabled.

### Deprovision a user

```bash
curl -X DELETE "http://127.0.0.1:8420/scim/v2/Users/<id>" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Realm-ID: $REALM_ID"
```

This permanently removes the user and all associated sessions, credentials, and indexes within the realm.

## Group provisioning

### Create a group

```bash
curl -X POST "http://127.0.0.1:8420/scim/v2/Groups" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering",
    "externalId": "okta-group-eng",
    "members": [
      {"value": "<hearth-user-id>", "$ref": "/scim/v2/Users/<hearth-user-id>", "display": "Alice Smith"}
    ]
  }'
```

SCIM groups map to Hearth groups in the realm. Group memberships created via SCIM are visible in the Admin UI and used in RBAC role resolution.

## Attribute mapping reference

| SCIM attribute | Hearth field | Notes |
|---------------|--------------|-------|
| `id` | `UserId` | Server-assigned; omit on POST |
| `externalId` | External ID index | Stored for IdP correlation |
| `userName` | Email / username | Hearth treats this as the primary email |
| `name.givenName` | First name | |
| `name.familyName` | Last name | |
| `displayName` | Display name | Falls back to `userName` if absent |
| `emails[primary=true].value` | Primary email | Only the primary address is persisted |
| `active` | Account status | `true` → Active; `false` → Disabled |
| `meta.created` | Created timestamp | ISO 8601, read-only |
| `meta.lastModified` | Updated timestamp | ISO 8601, read-only |
| `meta.version` | ETag (`W/"<micros>"`) | Weak ETag for optimistic concurrency |

Unknown incoming attributes are silently ignored.

## Filtering

The `filter` query parameter supports these operators on User and Group resources:

`eq`, `ne`, `co` (contains), `sw` (starts-with), `ew` (ends-with), `pr` (present), combined with `and` / `or`.

```
GET /scim/v2/Users?filter=userName eq "alice@example.com"
GET /scim/v2/Users?filter=active eq true
```

## Pagination

Use `startIndex` (1-based) and `count` for page navigation:

```
GET /scim/v2/Users?startIndex=1&count=25
```

Response wraps results in a `ListResponse`:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 150,
  "startIndex": 1,
  "itemsPerPage": 25,
  "Resources": [...]
}
```

Maximum scan per request: 1 000 records. For large realms, iterate with `startIndex`.

## Configuring Okta

1. In your Okta Admin console go to **Applications → Your App → Provisioning → Integration**.
2. Set **SCIM connector base URL** to `https://<your-hearth-host>/scim/v2`.
3. Set **Unique identifier field for users** to `userName`.
4. Set **Authentication Mode** to **HTTP Header** with your bearer token.
5. Add a custom HTTP header `X-Realm-ID` with your realm UUID.
6. Enable: **Import Users**, **Create Users**, **Update User Attributes**, **Deactivate Users**.

## Configuring Azure AD / Entra ID

1. Open your Enterprise Application → **Provisioning**.
2. Set **Provisioning Mode** to **Automatic**.
3. Set **Tenant URL** to `https://<your-hearth-host>/scim/v2`.
4. Set **Secret Token** to your SCIM bearer token.
5. Entra ID does not support custom headers natively for SCIM. Use an API gateway or reverse proxy to inject `X-Realm-ID: <realm-uuid>` before requests reach Hearth.

## Known limitations

The following SCIM features are deferred to a future hardening release:

- Bracketed PATCH filter paths (e.g., `members[value eq "id"]`).
- `/Bulk`, `/Me`, sorting (`sortBy`, `sortOrder`), and attribute projection (`attributes`, `excludedAttributes`).
- Enterprise User Schema extension (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`).
- `If-Match` enforcement (ETag sent on responses but not enforced on inbound `If-Match`).

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `403 Forbidden` | SCIM not enabled for realm (no `bearer_token` in config), or wrong realm UUID in `X-Realm-ID`. |
| `401 Unauthorized` | Bearer token mismatch. |
| `400 Bad Request` / `invalidValue` | Missing `X-Realm-ID` header, or non-UUID value. |
| `429 Too Many Requests` | Rate limit exceeded (100 req/min per realm). Back off and retry. |
| User created but cannot log in | `active` was `false` on provisioning. Send a PATCH to set `active: true`. |
