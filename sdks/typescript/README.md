# Hearth TypeScript SDK

TypeScript client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

## Installation

```bash
npm install @hearth/sdk
```

## Quick start

```typescript
import { createHearth, HearthClient } from "@hearth/sdk";

// Low-level HTTP client
const client = new HearthClient({
  baseUrl: "https://hearth.example.com",
  realmId: "your-realm-id",
});

// RBAC facade (reads claims from a JWT without network calls)
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "your-realm-id",
  getToken: () => localStorage.getItem("access_token"),
});
```

## RBAC capabilities

All permission checks are synchronous and local — they decode the JWT returned
by `getToken()` without making any network calls.

### `hasPermission(permission: string): boolean`

Returns `true` iff the JWT `permissions` claim contains `permission`.

```typescript
if (hearth.hasPermission("docs.versions.read")) {
  // show version history
}
```

### `hasRole(role: string): boolean`

Returns `true` iff the JWT `roles` claim contains `role`. Useful for UI
personalization and federation.

```typescript
if (hearth.hasRole("billing-admin")) {
  // show billing panel
}
```

### `inGroup(group: string): boolean`

Returns `true` iff the JWT `groups` claim contains the group slug.

```typescript
if (hearth.inGroup("engineering")) {
  // show internal tooling link
}
```

### `inOrg(org: string): boolean`

Returns `true` iff the JWT `oid` claim equals the given org ID.

```typescript
if (hearth.inOrg("org_acme")) {
  // show Acme-specific content
}
```

### `client.permissions(): Promise<MePermissionsResponse>`

Calls `GET /v1/me/permissions` and returns the freshly-resolved RBAC claim set
from the server. Unlike the synchronous helpers above, this reflects any
role/group assignments made since the JWT was issued.

```typescript
const { roles, groups, permissions } = await hearth.client.permissions();
```

## User attributes

User attributes are free-form key/value strings stored on the user record
(`user.attributes`). They are projected into JWT claims through the realm's
claim profile configuration in `hearth.yaml`. Attributes flow through the
standard JWT decoder — access them from the parsed token payload using your
preferred JWT library.

## Revoking OAuth consent

Revokes a previously granted OAuth consent for a connected application. After
revocation, the application's refresh tokens are invalidated and the user will
be prompted to re-consent on the next authorization request.

### `revokeConsent(clientId: string): Promise<void>`

```typescript
// Revoke consent for the application identified by clientId
await client.revokeConsent("client-id-to-revoke");
```

Calls `DELETE /v1/me/applications/{clientId}` with the current bearer token.

## React integration

```tsx
import { HearthProvider, useHasPermission, useHasRole } from "@hearth/sdk/react";

function App() {
  return (
    <HearthProvider client={hearth}>
      <MyComponent />
    </HearthProvider>
  );
}

function MyComponent() {
  const canEdit = useHasPermission("docs.write");
  const isAdmin = useHasRole("admin");
  // ...
}
```

## Auth code flow

```typescript
// 1. Start the flow
const { code } = await client.authorize({
  clientId: "my-client",
  redirectUri: "https://app.example.com/callback",
  scope: "openid profile email",
  state: crypto.randomUUID(),
  userId: "user-id",
});

// 2. Exchange the code for tokens
const tokens = await client.exchangeCode({
  clientId: "my-client",
  code,
  redirectUri: "https://app.example.com/callback",
});

// 3. Refresh when the access token expires
const refreshed = await client.refreshTokens("my-client", tokens.refresh_token);
```

## UserInfo endpoint

```typescript
const info = await client.userinfo(accessToken);
// info.sub, info.name, info.email, info.email_verified
```

## JWKS and discovery

```typescript
const jwks = await client.jwks();
const discovery = await client.discovery();
```
