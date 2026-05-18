# Hearth Concepts

**Audience:** backend developers who know OAuth 2.0 / OIDC basics and want to understand how Hearth's building blocks fit together before writing integration code.

If you want to skip straight to running commands, see [Getting Started](getting-started.md).

---

## Realms

A **realm** is a fully isolated tenant namespace. Every user, session, OAuth client, role assignment, and signing key belongs to exactly one realm. Data never crosses realm boundaries — every storage key is prefixed with the realm ID at the lowest layer, and every OIDC endpoint is realm-scoped via the `X-Realm-ID` request header.

### When to use one realm vs. many

| Scenario | Recommendation |
|---|---|
| Single product, all users belong to you | One realm — let Hearth auto-create `default` by omitting `realms:` in `hearth.yaml` |
| B2B SaaS, users are your customers' employees | One realm per product environment; use **organizations** within the realm for per-customer isolation |
| Separate products with independent user bases and auth policies | One realm per product |
| Dev / staging / prod environments | One realm per environment — separate signing keys, separate rate limits |

Realms are declared in `hearth.yaml` and reconciled at startup. A realm absent from YAML is archived (soft-deleted) and visible in the Admin UI with an "Archived" badge. Use `hearth realm create` to generate a UUID offline without a running server.

### URL routing

Every HTTP request includes `X-Realm-ID: <uuid>`. Hearth uses this to scope storage lookups, select the correct Ed25519 signing key, and enforce that the bearer token's realm matches the target realm. A mismatch returns `401`.

For production deployments with subdomain-per-tenant routing, configure your reverse proxy to inject `X-Realm-ID` from the subdomain, and set each realm's `oidc.issuer` to its subdomain URL.

---

## Claims-based RBAC

Hearth uses **claims-based RBAC**: permissions are resolved once at token-issue time and embedded directly in the JWT. Downstream services check `payload.permissions` locally — no network round-trip to Hearth at authorization time.

```
Request arrives at your API
        │
        ▼
  Verify JWT signature        ← one crypto op, no I/O
  against JWKS (cached)
        │
        ▼
  Read payload.permissions    ← array lookup, ~100ns
  ["billing.read", ...]
        │
        ▼
  Allow or deny               ← local decision, zero latency
```

### The tradeoff

Because permissions are baked into the token, revoking a role does not immediately invalidate existing access tokens — it takes effect when the current token expires and the user fetches a new one. The default access token TTL is 15 minutes. For immediate revocation, revoke the user's refresh token via `POST /revoke`; this terminates the session and forces re-authentication.

### How roles, groups, and permissions compose

```
Permission   — fine-grained capability string: "billing.write"
     ↑
Role         — named permission bundle: "billing-admin" → [billing.read, billing.write]
     ↑
Assignment   — binds a role to a user or group, scoped to a realm or organization
     ↑
Group        — collection of users: "finance-team" → [user-a, user-b]
```

At token-issue time, Hearth resolves permissions in three passes:

1. Collect all roles assigned directly to the user (realm-scoped and org-scoped)
2. Collect all roles assigned to groups the user belongs to
3. Expand every role to its permission set, following `parents` transitively
4. De-duplicate and sort; embed as `roles`, `groups`, `permissions` in the JWT

Roles can declare `parents` — a child role inherits all parent permissions without repeating them in config.

### The JWT payload

```json
{
  "sub":         "usr_01hx...",
  "iss":         "https://auth.example.com",
  "aud":         "hearth",
  "iat":         1715000000,
  "exp":         1715000900,
  "roles":       ["billing-admin"],
  "groups":      ["finance-team"],
  "permissions": ["billing.read", "billing.write"],
  "oid":         "org_01hy..."
}
```

`roles` and `groups` carry names/slugs (not IDs) for readability in logs and SDK helpers. `permissions` is the authoritative surface your code checks. `oid` is set when the token was issued in the context of an organization.

### Scope bundles vs. RBAC permissions

OAuth scopes (`openid`, `profile`, `email`, `billing:manage`) and RBAC permissions are separate axes:

- **Scopes** are what the *OAuth client* requests — they filter which claims appear in the token and limit what the client can do on behalf of the user.
- **Permissions** are what the *user* is allowed to do — resolved from roles regardless of scope.

A scope bundle maps a scope string to a subset of permissions. Even if a user has `billing.write`, a token issued with `scope=openid profile` will not include that permission. This lets you issue narrowly-scoped tokens for third-party integrations without changing the user's underlying role assignments.

---

## Token lifecycle

```
  User authenticates
        │
        ▼
  POST /authorize  ──►  authorization code  (10-min TTL, single-use)
        │
        ▼
  POST /token      ──►  access token  (15-min TTL, signed JWT)
                   ──►  refresh token (7-day TTL, opaque, rotates on use)
        │
        │  access token expires
        ▼
  POST /token (grant_type=refresh_token)
        │
        ▼
  new access token + new refresh token
        │
        │  logout / revocation
        ▼
  POST /revoke  ──►  refresh token revoked, entire grant family invalidated
```

### Refresh token rotation

Every use of a refresh token issues a *new* refresh token and invalidates the old one. If a refresh token is presented a second time (i.e., a token was stolen and used in parallel), Hearth detects the reuse and revokes the **entire grant family** — all access and refresh tokens derived from that original login. This prevents silent session hijacking.

### Key endpoints

| Endpoint | Purpose |
|---|---|
| `POST /authorize` | Starts auth code flow; returns a short-lived, single-use code |
| `POST /token` | Exchanges code → tokens, or rotates a refresh token |
| `GET  /userinfo` | Returns scope-filtered profile claims for a valid access token |
| `POST /revoke` | Revokes a refresh token and its entire grant family |
| `POST /introspect` | Server-side token validation (RFC 7662); use when you can't verify Ed25519 locally |
| `GET  /jwks` | Per-realm Ed25519 public keys for local JWT verification |

### JWKS and signing keys

Each realm has its own Ed25519 signing key, stored under the system realm namespace and lazy-loaded on first use. The key is rotated when you delete and recreate a realm. The JWKS endpoint publishes the current public key; your services should cache it and refresh on unknown `kid`.

---

## Multi-tenancy routing in depth

Hearth exposes a flat URL namespace — there are no `/realms/{id}/` path prefixes. Realm routing is header-based:

```
X-Realm-ID: 018e4f2a-3b1c-7d8e-9f0a-1b2c3d4e5f6a
```

This keeps URLs clean and lets you route multiple realms behind a single Hearth instance. In a multi-realm deployment:

```
browser → nginx (sets X-Realm-ID from subdomain) → Hearth
tenant-a.auth.example.com  →  realm-id-A
tenant-b.auth.example.com  →  realm-id-B
```

Set each realm's `oidc.issuer` to its public URL (`https://tenant-a.auth.example.com`). OIDC Discovery at `/.well-known/openid-configuration` returns the issuer matching the header, so OIDC clients discover the correct metadata automatically.

---

## Organizations

**Organizations** are B2B customer groups that live *inside* a realm. They give you per-customer role assignments without creating a separate realm per customer.

```
Realm: "my-saas"
  ├── Organization: "acme-corp"      (org_01...)
  │     ├── member: alice  (role: org.admin)
  │     └── member: bob    (role: org.member)
  └── Organization: "globex"         (org_02...)
        └── member: carol  (role: org.owner)
```

When a user's token is issued in an org context, the `oid` claim is set and org-scoped role assignments contribute to `permissions`. Alice's `billing.write` permission from `org.admin` only applies when `oid` matches `acme-corp` — she cannot access Globex data.

→ See [Organizations guide](organizations.md) for invitation flows, membership management, and cascading deletes.

---

## Further reading

- [Getting Started](getting-started.md) — hands-on curl walkthrough
- [RBAC guide](rbac.md) — creating roles, assigning permissions, managing groups, SDK helpers
- [Organizations guide](organizations.md) — B2B multi-tenancy within a realm
- [Security hardening](security-hardening.md) — production TLS, token TTLs, rate limiting
- [Configuration reference](../../README.md#configuration) — full `hearth.yaml` option list
