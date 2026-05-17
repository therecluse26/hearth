# Getting Started with Hearth

**Goal:** First authenticated request in your app. **Time:** ~5 minutes.

**Prerequisites:** A Rust toolchain plus `curl` (and `jq` for JSON parsing).

---

## 1. Start Hearth in dev mode

```bash
make dev
# or: cargo run -- serve --dev
```

`--dev` binds to `http://127.0.0.1:8420`, uses in-memory storage, enables the bootstrap endpoint, and auto-starts the built-in **mailcatcher** (email inbox at `http://127.0.0.1:8420/dev/mail`). **Data does not persist across restarts.** For a persistent environment, omit `--dev` and point to a config file.

Verify it is running:
```bash
curl -fsS http://127.0.0.1:8420/health
# → {"status":"ok"}
```

## 2. Bootstrap a realm and admin token

```bash
BOOTSTRAP=$(curl -fsS -X POST http://127.0.0.1:8420/admin/bootstrap)
REALM_ID=$(echo "$BOOTSTRAP" | jq -r .realm_id)
ADMIN_TOKEN=$(echo "$BOOTSTRAP" | jq -r .access_token)
USER_ID=$(echo "$BOOTSTRAP" | jq -r .user_id)

echo "Realm: $REALM_ID"
```

The response contains `realm_id`, `user_id`, `access_token`, `refresh_token`, and a `quickstart` field — ready-to-copy shell commands with your realm ID and admin token already interpolated.

> **Production note:** This endpoint returns `404 Not Found` outside `--dev` mode. In production, create your realm via `hearth.yaml` and issue credentials through normal OAuth flows.

## 3. Register an OAuth application

```bash
CLIENT=$(curl -fsS -X POST http://127.0.0.1:8420/clients \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name":   "my-app",
    "redirect_uris": ["https://myapp.example.com/callback"]
  }')

CLIENT_ID=$(echo "$CLIENT" | jq -r .client_id)
CLIENT_SECRET=$(echo "$CLIENT" | jq -r .client_secret)
```

Store `client_secret` server-side only — never expose it in browser or mobile code. For public clients (browser SPAs, native apps), add `"public": true` to the request body and omit `client_secret` entirely.

## 4. Run the PKCE authorization code flow

PKCE prevents authorization code interception. Generate a verifier locally and send only the derived challenge to Hearth:

```bash
CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')
```

Request an authorization code. In dev mode, pass `user_id` directly — in production, Hearth redirects users to its login page and `user_id` is not accepted:

```bash
CODE=$(curl -fsS -X POST http://127.0.0.1:8420/authorize \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\":             \"$CLIENT_ID\",
    \"redirect_uri\":          \"https://myapp.example.com/callback\",
    \"response_type\":         \"code\",
    \"scope\":                 \"openid profile email\",
    \"state\":                 \"$(openssl rand -hex 16)\",
    \"code_challenge\":        \"$CODE_CHALLENGE\",
    \"code_challenge_method\": \"S256\",
    \"user_id\":               \"$USER_ID\"
  }" | jq -r .code)
```

Exchange the code for tokens:

```bash
TOKENS=$(curl -fsS -X POST http://127.0.0.1:8420/token \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "redirect_uri=https://myapp.example.com/callback" \
  --data-urlencode "code_verifier=$CODE_VERIFIER")

ACCESS_TOKEN=$(echo "$TOKENS" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r .refresh_token)
echo "Expires in: $(echo "$TOKENS" | jq -r .expires_in)s"
```

## 5. Inspect the JWT claims

Decode the access token payload without signature verification (for inspection only):

```bash
echo "$ACCESS_TOKEN" \
  | cut -d. -f2 \
  | tr '_-' '/+' \
  | awk '{ pad=(4-length($0)%4)%4; for(i=0;i<pad;i++) $0=$0"="; print }' \
  | base64 -d \
  | jq '{sub, roles, groups, permissions, exp}'
```

Expected output:
```json
{
  "sub":         "<user-uuid>",
  "roles":       ["realm.admin"],
  "groups":      [],
  "permissions": ["hearth.admin", "realm.read", "realm.write", "realm.admin"],
  "exp":         1234567890
}
```

The `permissions` array is the authorization surface your app checks. It is resolved at token-issue time — no network call needed at request time.

## 6. Protect a route in your app

Fetch Hearth's public signing keys from the JWKS endpoint and verify the token cryptographically. The `X-Realm-ID` header scopes the response to your realm's Ed25519 key.

**Node.js** (requires [`jose`](https://github.com/panva/jose)):

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.HEARTH_URL}/jwks`),
  { headers: { 'X-Realm-ID': process.env.HEARTH_REALM_ID } }
);

export async function requirePermission(req, res, next, permission) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'missing_token' });

  const { payload } = await jwtVerify(token, JWKS, {
    issuer:   process.env.HEARTH_ISSUER,   // e.g. "https://auth.example.com"
    audience: 'hearth',
  });

  if (!payload.permissions?.includes(permission))
    return res.status(403).json({ error: 'forbidden' });

  req.user = payload;
  next();
}
```

**Python** (requires [`python-jose[cryptography]`](https://python-jose.readthedocs.io/)):

```python
import requests
from jose import jwt, jwk

def _get_key(token: str, realm_id: str):
    r = requests.get(f'{HEARTH_URL}/jwks', headers={'X-Realm-ID': realm_id})
    r.raise_for_status()
    kid = jwt.get_unverified_header(token).get('kid')
    for k in r.json()['keys']:
        if k.get('kid') == kid:
            return jwk.construct(k)
    raise ValueError('signing key not found')

def require_permission(token: str, permission: str) -> dict:
    key = _get_key(token, HEARTH_REALM_ID)
    payload = jwt.decode(token, key.to_dict(), algorithms=['EdDSA'],
                         audience='hearth', issuer=HEARTH_ISSUER)
    assert permission in payload.get('permissions', []), 'Forbidden'
    return payload
```

> **JWKS caching:** `createRemoteJWKSet` caches keys automatically. In Python, cache `_get_key` results (e.g., with `functools.lru_cache(ttl=...)`) to avoid a JWKS fetch on every request.

## Next steps

| Topic | Guide |
|---|---|
| Local dev, mailcatcher email inbox | [Local dev guide](local-dev.md) |
| Realms, RBAC, and token lifecycle explained | [Conceptual model](concepts.md) |
| Create roles, assign permissions, manage groups | [RBAC guide](rbac.md) |
| B2B multi-tenancy within a realm | [Organizations guide](organizations.md) |
| Production config, TLS, email | [Configuration reference](../../README.md#configuration) |
| Import from Keycloak | [Migration guide](../../README.md#migrating-from-keycloak) |
