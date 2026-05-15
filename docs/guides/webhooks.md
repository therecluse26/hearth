# Webhooks Guide

**Audience:** operators and developers integrating Hearth into external systems.

Hearth delivers real-time audit events to HTTP endpoints you control. Each event is signed with HMAC-SHA256 so you can verify it came from Hearth. This guide covers creating subscriptions, filtering events, verifying delivery signatures, and inspecting the delivery log.

---

## Prerequisites

All webhook admin endpoints require:

- `Authorization: Bearer <token>` — a valid JWT with the `hearth.admin` permission.
- `X-Realm-ID: <realm-id>` — the realm whose webhooks you are managing.

Bootstrap the admin token with `POST /admin/bootstrap` (dev-only) or issue one via the OIDC token endpoint. Rate limit: 100 requests/minute per admin user.

---

## Creating a subscription

```http
POST /admin/webhooks
Authorization: Bearer <token>
X-Realm-ID: <realm-id>
Content-Type: application/json

{
  "url": "https://your-server.example.com/hearth-events",
  "secret": "a-random-secret-at-least-16-bytes",
  "enabled": true,
  "event_filters": ["user_created", "user_deleted", "session_revoked"]
}
```

**Response: 201 Created**

```json
{
  "id": "wh_<uuid>",
  "realm_id": "<realm-id>",
  "url": "https://your-server.example.com/hearth-events",
  "secret": "a-random-secret-at-least-16-bytes",
  "enabled": true,
  "event_filters": ["user_created", "user_deleted", "session_revoked"],
  "created_at": 1715000000000000,
  "updated_at": 1715000000000000
}
```

**Field constraints:**

| Field | Constraint |
|---|---|
| `url` | Must be a valid HTTPS or HTTP URL. |
| `secret` | Minimum 16 bytes. Stored in plaintext; treat as a credential. |
| `enabled` | Defaults to `true` if omitted. |
| `event_filters` | Array of event type strings. Empty array (or omitted) subscribes to all events. |

---

## Event types

Pass any subset of these strings in `event_filters`. An empty array delivers every event type.

| Category | Event types |
|---|---|
| Users | `user_created` · `user_updated` · `user_deleted` |
| Credentials | `credential_set` · `credential_changed` · `credential_verified` |
| Sessions | `session_created` · `session_revoked` |
| Tokens | `token_issued` · `token_refreshed` |
| Realms | `realm_created` · `realm_updated` · `realm_deleted` |
| OAuth clients | `client_registered` · `client_updated` · `client_deleted` · `authorization_code_issued` · `authorization_code_exchanged` · `client_consent_granted` · `client_consent_revoked` · `consent_required_on_refresh` |
| Consent | `consent_granted` · `consent_denied` · `consent_revoked` |
| RBAC | `role_assigned` · `role_revoked` · `user_permission_granted` · `user_permission_revoked` |
| Groups | `group_created` · `group_updated` · `group_deleted` · `group_member_added` · `group_member_removed` · `group_member_role_changed` |
| Organizations | `org_created` · `org_updated` · `org_deleted` |
| Federation | `federation_login_started` · `federation_login_completed` · `federation_account_linked` · `federation_account_unlinked` · `federation_jit_provisioned` |
| SAML | `saml_login_initiated` · `saml_login_completed` · `saml_login_failed` · `saml_idp_authn_request_received` · `saml_idp_response_issued` · `saml_idp_initiated_sso` · `saml_slo_requested` · `saml_slo_completed` |
| SCIM | `scim_user_created` · `scim_user_updated` · `scim_user_deleted` · `scim_group_created` · `scim_group_updated` · `scim_group_deleted` |
| Admin | `bulk_users_created` · `bulk_users_disabled` |
| Security | `login_failed` · `login_locked` · `ip_login_limit_exceeded` |

---

## Delivery payload

Hearth sends a `POST` request to your endpoint with a JSON body containing the audit event:

```json
{
  "id": "evt_<uuid>",
  "realm_id": "<realm-id>",
  "actor": "user_<uuid>",
  "action": "user_created",
  "resource_type": "user",
  "resource_id": "user_<uuid>",
  "timestamp": 1715000000000000,
  "metadata": { "email": "new@example.com" },
  "integrity_hash": "<sha256-hash-chain-value>"
}
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique audit event ID (`evt_<uuid>`). |
| `realm_id` | string | Realm this event belongs to. |
| `actor` | string | Who performed the action — user ID, `"system"`, etc. |
| `action` | string | The event type (see table above). |
| `resource_type` | string | Type of affected resource (`"user"`, `"session"`, `"realm"`, etc.). |
| `resource_id` | string | ID of the affected resource. |
| `timestamp` | integer | Microseconds since Unix epoch. |
| `metadata` | object/null | Optional extra context (IP address, user-agent, etc.). Absent when `null`. |
| `integrity_hash` | string | SHA-256 hash chain value for tamper detection. |

**HTTP headers on each delivery:**

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Hearth-Signature-256` | `sha256=<hex>` — HMAC-SHA256 of the body using your subscription secret. |
| `X-Hearth-Event` | The event type string (same as `action` in the body). |
| `X-Hearth-Delivery` | Unique delivery attempt ID. |

---

## Verifying signatures

**Always verify the `X-Hearth-Signature-256` header before processing an event.**

Hearth computes the signature as:

```
HMAC-SHA256(secret, request_body_bytes)
```

and encodes it as `sha256=<lowercase-hex>`.

Example verification in Python:

```python
import hashlib
import hmac

def verify_signature(secret: str, body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header)
```

Example verification in Node.js:

```js
const crypto = require("crypto");

function verifySignature(secret, body, header) {
  const expected = "sha256=" + crypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("hex");
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(header));
}
```

**Use constant-time comparison** (`hmac.compare_digest` / `crypto.timingSafeEqual`) to prevent timing attacks.

---

## Retry behaviour

Hearth retries failed deliveries up to **5 attempts** total with exponential backoff:

| Attempt | Delay before retry |
|---|---|
| 1 (immediate) | 0 s |
| 2 | 5 s |
| 3 | 25 s |
| 4 | 125 s (~2 min) |
| 5 | 625 s (~10 min) |

A delivery is considered successful when your endpoint returns a **2xx** status code. Any other response (including network errors) is treated as a failure. After 5 failed attempts the delivery is marked `failed` and no further retries occur.

**Your endpoint must respond within the HTTP client timeout.** Return `200 OK` immediately and process the event asynchronously to avoid timeouts causing spurious retries.

---

## Listing and updating subscriptions

**List all subscriptions for a realm:**

```http
GET /admin/webhooks
Authorization: Bearer <token>
X-Realm-ID: <realm-id>
```

Add `?enabled_only=true` to return only active subscriptions.

**Update a subscription** (all fields optional; omitted fields are unchanged):

```http
PUT /admin/webhooks/wh_<uuid>
Authorization: Bearer <token>
X-Realm-ID: <realm-id>
Content-Type: application/json

{
  "url": "https://new-endpoint.example.com/events",
  "secret": "new-secret-at-least-16-bytes",
  "enabled": false,
  "event_filters": ["login_failed", "login_locked"]
}
```

**Delete a subscription:**

```http
DELETE /admin/webhooks/wh_<uuid>
Authorization: Bearer <token>
X-Realm-ID: <realm-id>
```

---

## Inspecting delivery logs

```http
GET /admin/webhooks/wh_<uuid>/deliveries?limit=50
Authorization: Bearer <token>
X-Realm-ID: <realm-id>
```

Query parameters:

| Parameter | Default | Maximum | Description |
|---|---|---|---|
| `limit` | `50` | `200` | Number of delivery records to return. |

Response:

```json
{
  "deliveries": [
    {
      "id": "wdl_<uuid>",
      "webhook_id": "wh_<uuid>",
      "realm_id": "<realm-id>",
      "event_id": "evt_<uuid>",
      "attempt": 1,
      "status": "Success",
      "response_status": 200,
      "attempted_at": 1715000000000000
    },
    {
      "id": "wdl_<uuid>",
      "webhook_id": "wh_<uuid>",
      "realm_id": "<realm-id>",
      "event_id": "evt_<uuid>",
      "attempt": 2,
      "status": "Failed",
      "error_message": "HTTP error: connection refused",
      "attempted_at": 1715000005000000
    }
  ]
}
```

**`status`** is either `"Success"` (2xx response) or `"Failed"` (network error or non-2xx).

---

## Security recommendations

- Use a secret with at least 32 random bytes (minimum enforced: 16).
- Rotate the secret by updating the subscription with a new `secret` value.
- Always verify the signature before acting on an event.
- Use HTTPS endpoints in production; HTTP endpoints are accepted but deliver events in plaintext.
- Disable a subscription (`"enabled": false`) rather than deleting it when you need to pause delivery without losing the configuration.
