# Hearth TypeScript SDK

TypeScript client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/sdk-spec.md).

## Installation

```bash
npm install @hearth/sdk
# or
yarn add @hearth/sdk
# or
pnpm add @hearth/sdk
```

**Peer dependencies:** React (`>=17 <20`) is optional. Only required for the `HearthProvider` / `useHasPermission` hooks.

---

## Quick start

```typescript
import { createHearth, HearthClient } from "@hearth/sdk";

// Low-level HTTP client — auth flows, token exchange, admin ops
const client = new HearthClient({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
});

// RBAC facade — local, synchronous permission checks from the JWT
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => localStorage.getItem("access_token"),
});
```

`HearthClient` is for server-side or client-side HTTP operations (token exchange, admin CRUD, JWKS). `createHearth` gives you a zero-network RBAC facade that reads claims from the JWT in memory.

---

## Auth code flow (with PKCE)

PKCE is the secure default for every OAuth authorization code flow — required for public clients, recommended for confidential clients.

```typescript
import { HearthClient } from "@hearth/sdk";
import { createHash, randomBytes } from "crypto"; // Node.js built-in

const client = new HearthClient({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
});

// 1. Generate PKCE verifier and challenge
const codeVerifier = randomBytes(32).toString("hex"); // 64 unreserved chars
const codeChallenge = createHash("sha256")
  .update(codeVerifier)
  .digest("base64url"); // base64url, no padding

// 2. Start the authorization request
const { code } = await client.authorize({
  clientId: "<client-id>",
  redirectUri: "https://app.example.com/callback",
  scope: "openid profile email",
  state: randomBytes(16).toString("hex"), // CSRF token
  userId: "<authenticated-user-uuid>",    // resolved user on your backend
  codeChallenge,
  codeChallengeMethod: "S256",
});

// 3. Exchange the code for tokens
const tokens = await client.exchangeCode({
  clientId: "<client-id>",
  code,
  redirectUri: "https://app.example.com/callback",
  codeVerifier,
});

// tokens.access_token  — short-lived JWT (check tokens.expires_in)
// tokens.id_token      — OIDC identity token
// tokens.refresh_token — rotate with refreshTokens()

// 4. Refresh before expiry
const refreshed = await client.refreshTokens("<client-id>", tokens.refresh_token);
```

---

## RBAC capabilities

All synchronous helpers decode the JWT returned by `getToken()` **locally** — no network call, no cache, no lock. When the token is absent or malformed, every predicate returns `false`.

```typescript
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => sessionStorage.getItem("access_token"),
});
```

### `hasPermission(permission: string): boolean`

Returns `true` iff the JWT `permissions` claim contains `permission`. Use this for feature gates and API guards.

```typescript
if (hearth.hasPermission("docs.versions.read")) {
  renderVersionHistory();
}
```

### `hasRole(role: string): boolean`

Returns `true` iff the JWT `roles` claim contains `role`. Useful for UI personalization and coarse-grained access.

```typescript
if (hearth.hasRole("billing-admin")) {
  renderBillingPanel();
}
```

### `inGroup(group: string): boolean`

Returns `true` iff the JWT `groups` claim contains the group slug.

```typescript
if (hearth.inGroup("engineering")) {
  renderInternalToolingLink();
}
```

### `inOrg(org: string): boolean`

Returns `true` iff the JWT `oid` claim equals the given org ID.

```typescript
if (hearth.inOrg("org_acme")) {
  renderAcmeContent();
}
```

### `client.permissions(): Promise<MePermissionsResponse>`

Calls `GET /v1/me/permissions` and returns the **freshly-resolved** RBAC claim set from the server. Unlike the synchronous helpers above, this reflects any role/group assignments made since the JWT was issued.

```typescript
const { roles, groups, permissions } = await hearth.client.permissions();
```

Use `client.permissions()` when you need post-issuance accuracy (e.g., after an admin operation). For every other check, prefer the synchronous local helpers — they're faster and don't touch the network.

---

## React integration

The React hooks are exported from the main `@hearth/sdk` package. No subpath import needed.

```tsx
import {
  createHearth,
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "@hearth/sdk";

// 1. Create the facade once at app startup
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => localStorage.getItem("access_token"),
});

// 2. Mount the provider at the root of your React tree
function App() {
  return (
    <HearthProvider client={hearth}>
      <Router />
    </HearthProvider>
  );
}

// 3. Use hooks anywhere in the tree — no prop drilling
function NavBar() {
  const canEdit   = useHasPermission("docs.write");
  const isAdmin   = useHasRole("admin");
  const inEng     = useInGroup("engineering");
  const isAcme    = useInOrg("org_acme");

  return (
    <nav>
      {canEdit   && <a href="/editor">Editor</a>}
      {isAdmin   && <a href="/admin">Admin</a>}
      {inEng     && <a href="/internal">Internal tools</a>}
      {isAcme    && <a href="/acme">Acme portal</a>}
    </nav>
  );
}
```

All hooks return `false` when no `HearthProvider` is mounted, making them safe to call in tests without a provider.

---

## UserInfo endpoint

Returns OIDC claims filtered by the granted scopes. `sub` is always present; `name` requires `profile` scope; `email` and `email_verified` require `email` scope.

```typescript
const info = await client.userinfo(accessToken);
// info.sub            — stable user identifier
// info.name           — display name (if profile scope granted)
// info.email          — email address (if email scope granted)
// info.email_verified — boolean (if email scope granted)
```

---

## JWKS and discovery

```typescript
// Retrieve the realm's public signing keys (for local JWT verification)
const jwks = await client.jwks();
// jwks.keys — array of JWK entries (kty, crv, x, kid, use, alg)

// Retrieve the OIDC discovery document
const discovery = await client.discovery();
// Standard OIDC Core 1.0 metadata
```

Use the JWKS with a library like `jose` to verify access tokens on your backend:

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("https://hearth.example.com/jwks"),
);

const { payload } = await jwtVerify(accessToken, JWKS, {
  issuer: "https://hearth.example.com",
  audience: "<client-id>",
});
```

---

## Admin API

`AdminClient` wraps the `/admin/*` endpoints. Obtain one from any `HearthClient` instance using a bearer token that carries the `hearth.admin` permission.

```typescript
const admin = client.admin(accessToken);
```

### Users

```typescript
// Create a user
const user = await admin.createUser({
  email: "alice@example.com",
  displayName: "Alice",
});

// List users (paginated)
const page = await admin.listUsers({ limit: 50 });
// page.items: User[], page.next_cursor: string | null

// Get a user by ID
const user = await admin.getUser("<user-id>");

// Update a user
const updated = await admin.updateUser("<user-id>", {
  displayName: "Alice Smith",
  status: "active",
});

// Delete a user
await admin.deleteUser("<user-id>");
```

### Realms

```typescript
// Create a realm
const realm = await admin.createRealm({ name: "acme-corp" });

// List realms (paginated)
const page = await admin.listRealms({ limit: 20 });
// page.items: Realm[], page.next_cursor: string | null

// Get a realm by ID
const realm = await admin.getRealm("<realm-id>");

// Update a realm
const updated = await admin.updateRealm("<realm-id>", {
  status: "suspended",
});

// Delete a realm (cascades users, sessions, clients, assignments)
await admin.deleteRealm("<realm-id>");
```

---

## Error handling

All methods throw `HearthError` on non-2xx responses.

```typescript
import { HearthClient, HearthError } from "@hearth/sdk";

try {
  const tokens = await client.exchangeCode({ ... });
} catch (err) {
  if (err instanceof HearthError) {
    console.error(`HTTP ${err.status}:`, err.body);
  } else {
    throw err;
  }
}
```

`HearthError.status` is the HTTP status code. `HearthError.body` is the parsed JSON response body (or the raw string if parsing fails).

---

## Dev bootstrap (development only)

The bootstrap endpoint creates a realm, admin user, session, assigns the `realm.admin` role, and returns tokens. It is available only when Hearth is running with `--dev`. In production, it returns 404.

```typescript
import { HearthClient } from "@hearth/sdk";

const { realm_id, user_id, access_token, refresh_token } =
  await HearthClient.bootstrap("http://127.0.0.1:8420");

// Use realm_id and access_token to make subsequent requests
const client = new HearthClient({
  baseUrl: "http://127.0.0.1:8420",
  realmId: realm_id,
});
const admin = client.admin(access_token);
```

---

## Type reference

```typescript
// HearthClientConfig — constructor argument for HearthClient
interface HearthClientConfig {
  baseUrl: string;   // Hearth server base URL, e.g. "https://hearth.example.com"
  realmId: string;   // Realm UUID to scope all requests to
}

// HearthOptions — argument to createHearth()
interface HearthOptions {
  baseUrl: string;
  realmId: string;
  getToken: () => string | null | undefined; // called on every predicate check
}

// HearthFacade — returned by createHearth()
interface HearthFacade {
  hasPermission(permission: string): boolean;
  hasRole(role: string): boolean;
  inGroup(group: string): boolean;
  inOrg(org: string): boolean;
  client: { permissions(): Promise<MePermissionsResponse> };
}

// AuthorizeParams
interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  userId: string;
  responseType?: string;       // default: "code"
  codeChallenge?: string;      // S256 challenge; required for PKCE
  codeChallengeMethod?: string; // "S256"
  nonce?: string;              // echoed in the ID token
}

// TokenExchangeParams
interface TokenExchangeParams {
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier?: string; // required when codeChallenge was sent on authorize
}

// TokenResponse
interface TokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;   // "Bearer"
  expires_in: number;   // seconds
  refresh_token: string;
}

// UserInfoResponse
interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
}

// MePermissionsResponse — from GET /v1/me/permissions
interface MePermissionsResponse {
  roles: string[];
  groups: string[];
  permissions: string[];
  scope: string;
}

// User
interface User {
  id: string;
  email: string;
  display_name: string;
  status: string;
  created_at?: number; // Unix epoch seconds
  updated_at?: number;
}

// Realm
interface Realm {
  id: string;
  name: string;
  status: string;
  config: Record<string, unknown> | null;
  created_at?: number;
  updated_at?: number;
}

// OAuthClient — returned by registerClient()
interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at?: number;
}

// PageResponse<T> — paginated list
interface PageResponse<T> {
  items: T[];
  next_cursor: string | null; // pass as cursor on the next request, or null if last page
}

// HearthError
class HearthError extends Error {
  status: number;   // HTTP status code
  body: unknown;    // parsed JSON error body
}
```


## Troubleshooting

**`DiscoveryError`** — verify `issuerUrl` is reachable and returns a valid `/.well-known/openid-configuration`.

**`JWKSFetchError`** — check network connectivity to the JWKS endpoint. The SDK retries once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — JWT signature does not match any key in the JWKS. If the server recently rotated keys the SDK will re-fetch once automatically; persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured audience. Verify `clientId` matches the audience your authorization server issues.

See [docs/sdk-spec.md](../../docs/sdk-spec.md) Section 5 for the full error taxonomy.
