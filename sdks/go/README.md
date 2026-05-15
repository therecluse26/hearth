# Hearth Go SDK

Go client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/sdk-spec.md).

## Installation

```bash
go get github.com/therecluse26/hearth/sdks/go
```

## Quick start

```go
import "github.com/therecluse26/hearth/sdks/go/hearth"

client := hearth.NewClient("https://hearth.example.com", "your-realm-id")
```

## RBAC capabilities

All permission checks are synchronous and local — they decode the JWT without
making any network calls. Returns `false` for an empty or malformed token.

### `HasPermission(token, permission string) bool`

Returns `true` iff the JWT `permissions` claim contains `permission`.

```go
if client.HasPermission(accessToken, "docs.versions.read") {
    // show version history
}
```

### `HasRole(token, role string) bool`

Returns `true` iff the JWT `roles` claim contains `role`. Useful for UI
personalization and federation.

```go
if client.HasRole(accessToken, "billing-admin") {
    // show billing panel
}
```

### `InGroup(token, groupSlug string) bool`

Returns `true` iff the JWT `groups` claim contains the group slug.

```go
if client.InGroup(accessToken, "engineering") {
    // show internal tooling link
}
```

### `InOrg(token, orgID string) bool`

Returns `true` iff the JWT `oid` claim equals the given org ID.

```go
if client.InOrg(accessToken, "org_acme") {
    // show Acme-specific content
}
```

### `Permissions(ctx, token) (*MePermissionsResponse, error)`

Calls `GET /v1/me/permissions` and returns the freshly-resolved RBAC claim set
from the server. Unlike the synchronous helpers above, this reflects any
role/group assignments made since the JWT was issued.

```go
perms, err := client.Permissions(ctx, accessToken)
if err != nil {
    return err
}
// perms.Roles, perms.Groups, perms.Permissions
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

### `RevokeConsent(ctx context.Context, clientID string) error`

```go
err := client.RevokeConsent(ctx, "client-id-to-revoke")
if err != nil {
    return fmt.Errorf("revoke consent: %w", err)
}
```

Calls `DELETE /v1/me/applications/{clientID}` with the current bearer token.
The bearer token must be supplied via the `Authorization` header — wrap the
call with a token-aware transport or pass the token using the admin client
helper.

## Auth code flow

```go
// 1. Start the flow
resp, err := client.Authorize(ctx, hearth.AuthorizeRequest{
    ClientID:    "my-client",
    RedirectURI: "https://app.example.com/callback",
    Scope:       "openid profile email",
    State:       uuid.NewString(),
    UserID:      "user-id",
})

// 2. Exchange the code for tokens
tokens, err := client.ExchangeCode(ctx, hearth.TokenRequest{
    ClientID:    "my-client",
    Code:        resp.Code,
    RedirectURI: "https://app.example.com/callback",
})

// 3. Refresh when the access token expires
refreshed, err := client.RefreshTokens(ctx, "my-client", tokens.RefreshToken)
```

## UserInfo endpoint

```go
info, err := client.UserInfo(ctx, accessToken)
// info.Sub, info.Name, info.Email, info.EmailVerified
```

## Admin client

```go
admin := client.Admin(accessToken)

// Create a user
user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
    Email:       "alice@example.com",
    DisplayName: "Alice",
})

// Create a realm
realm, err := admin.CreateRealm(ctx, hearth.CreateRealmRequest{Name: "acme"})
```

## Dev bootstrap (development only)

```go
resp, err := hearth.Bootstrap(ctx, "http://localhost:8080")
// resp.RealmID, resp.UserID, resp.AccessToken, resp.RefreshToken
```
