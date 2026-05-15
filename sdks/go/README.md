# Hearth Go SDK

Go client for the [Hearth](https://github.com/therecluse26/hearth) identity API.

**SDK Specification:** [docs/sdk-spec.md](../../docs/sdk-spec.md)

## Installation

```bash
go get github.com/anthropics/hearth/sdks/go
```

## Quick start

```go
import "github.com/anthropics/hearth/sdks/go/hearth"

client := hearth.NewClient("https://hearth.example.com", "<your-realm-id>")
```

`Client` wraps the Hearth HTTP API for auth code flows, token management, JWKS retrieval, and live RBAC claim resolution. All methods are safe to call concurrently.

---

## Auth code flow (with PKCE)

PKCE is the secure default for every OAuth authorization code flow — required for public clients, recommended for confidential clients.

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/anthropics/hearth/sdks/go/hearth"
)

func pkce() (verifier, challenge string) {
    raw := make([]byte, 32)
    rand.Read(raw)
    verifier = hex.EncodeToString(raw) // 64 unreserved chars, valid per RFC 7636
    sum := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(sum[:])
    return
}

func main() {
    ctx := context.Background()
    client := hearth.NewClient("https://hearth.example.com", "<your-realm-id>")

    // 1. Generate PKCE verifier and challenge
    codeVerifier, codeChallenge := pkce()

    // 2. Start the authorization request
    authResp, err := client.Authorize(ctx, hearth.AuthorizeRequest{
        ClientID:    "<client-id>",
        RedirectURI: "https://app.example.com/callback",
        Scope:       "openid profile email",
        State:       hex.EncodeToString(func() []byte { b := make([]byte, 16); rand.Read(b); return b }()),
        UserID:      "<authenticated-user-uuid>", // resolved user on your backend
    })
    if err != nil {
        panic(err)
    }

    // 3. Exchange the code for tokens
    tokens, err := client.ExchangeCode(ctx, hearth.TokenRequest{
        ClientID:    "<client-id>",
        Code:        authResp.Code,
        RedirectURI: "https://app.example.com/callback",
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("access_token:", tokens.AccessToken)
    fmt.Println("expires_in:  ", tokens.ExpiresIn)

    // 4. Refresh before expiry
    refreshed, err := client.RefreshTokens(ctx, "<client-id>", tokens.RefreshToken)
    _ = refreshed
    _ = codeVerifier
    _ = codeChallenge
}
```

> **PKCE:** Pass `codeVerifier` / `codeChallenge` through your existing auth-request mechanism. `AuthorizeRequest` does not yet carry PKCE fields directly — send them as additional form parameters or open an issue if you need first-class PKCE support in the SDK.

---

## RBAC capabilities

All synchronous helpers decode the JWT **locally** — no network call, no lock, no cache. They return `false` for an empty or malformed token.

### `HasPermission(token, permission string) bool`

Returns `true` iff the JWT `permissions` claim contains `permission`.

```go
if client.HasPermission(accessToken, "docs.versions.read") {
    renderVersionHistory()
}
```

### `HasRole(token, role string) bool`

Returns `true` iff the JWT `roles` claim contains `role`. Useful for UI personalization and coarse-grained access.

```go
if client.HasRole(accessToken, "billing-admin") {
    renderBillingPanel()
}
```

### `InGroup(token, groupSlug string) bool`

Returns `true` iff the JWT `groups` claim contains the group slug.

```go
if client.InGroup(accessToken, "engineering") {
    renderInternalToolingLink()
}
```

### `InOrg(token, orgID string) bool`

Returns `true` iff the JWT `oid` claim equals the given org ID.

```go
if client.InOrg(accessToken, "org_acme") {
    renderAcmeContent()
}
```

### `Permissions(ctx, token) (*MePermissionsResponse, error)`

Calls `GET /v1/me/permissions` and returns the **freshly-resolved** RBAC claim set from the server. Unlike the synchronous helpers above, this reflects any role/group assignments made since the JWT was issued.

```go
perms, err := client.Permissions(ctx, accessToken)
if err != nil {
    return fmt.Errorf("permissions: %w", err)
}
// perms.Roles, perms.Groups, perms.Permissions
```

Use `Permissions` when you need post-issuance accuracy (e.g., after an admin operation). For every other check, prefer the synchronous local helpers — they're faster and don't touch the network.

---

## UserInfo endpoint

Returns OIDC claims filtered by the granted scopes. `Sub` is always present; `Name` requires `profile` scope; `Email` and `EmailVerified` require `email` scope.

```go
info, err := client.UserInfo(ctx, accessToken)
if err != nil {
    return fmt.Errorf("userinfo: %w", err)
}
// info.Sub            — stable user identifier
// info.Name           — display name (if profile scope granted)
// info.Email          — email address (if email scope granted)
// info.EmailVerified  — bool (if email scope granted)
```

---

## Admin API

`AdminClient` wraps the `/admin/*` endpoints. Obtain one from any `Client` instance using a bearer token that carries the `hearth.admin` permission.

```go
admin := client.Admin(accessToken)
```

### Users

```go
// Create a user
user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
    Email:       "alice@example.com",
    DisplayName: "Alice",
})

// Get a user by ID
user, err := admin.GetUser(ctx, "<user-id>")

// Update a user
name := "Alice Smith"
updated, err := admin.UpdateUser(ctx, "<user-id>", hearth.UpdateUserRequest{
    DisplayName: &name,
})

// List users (paginated, up to limit records per page)
page, err := admin.ListUsers(ctx, 50)
// page.Items: []User, page.NextCursor: *string (nil if last page)

// Delete a user
err = admin.DeleteUser(ctx, "<user-id>")
```

### Realms

```go
// Create a realm
realm, err := admin.CreateRealm(ctx, hearth.CreateRealmRequest{
    Name: "acme-corp",
})

// Get a realm by ID
realm, err := admin.GetRealm(ctx, "<realm-id>")

// Update a realm
suspended := "suspended"
updated, err := admin.UpdateRealm(ctx, "<realm-id>", hearth.UpdateRealmRequest{
    Status: &suspended,
})

// Delete a realm (cascades users, sessions, clients, assignments)
err = admin.DeleteRealm(ctx, "<realm-id>")
```

---

## Error handling

Non-2xx responses return `*APIError`.

```go
import (
    "errors"
    "fmt"

    "github.com/anthropics/hearth/sdks/go/hearth"
)

tokens, err := client.ExchangeCode(ctx, req)
if err != nil {
    var apiErr *hearth.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("HTTP %d: %s\n", apiErr.StatusCode, apiErr.Message)
    } else {
        return fmt.Errorf("exchange code: %w", err)
    }
}
```

`APIError.StatusCode` is the HTTP status code. `APIError.Message` is the raw response body.

---

## Dev bootstrap (development only)

The bootstrap endpoint creates a realm, admin user, session, assigns the `realm.admin` role, and returns tokens. Available only when Hearth is running with `--dev`. In production, it returns 404.

```go
resp, err := hearth.Bootstrap(ctx, "http://localhost:8420")
if err != nil {
    panic(err)
}

// resp.RealmID      — UUID of the newly created realm
// resp.UserID       — UUID of the admin user
// resp.AccessToken  — short-lived JWT with hearth.admin permission
// resp.RefreshToken — opaque refresh token

client := hearth.NewClient("http://localhost:8420", resp.RealmID)
admin  := client.Admin(resp.AccessToken)
```

---

## Type reference

```go
// Client — created by NewClient(baseURL, realmID string)
// All methods are goroutine-safe.

// AuthorizeRequest — argument to Client.Authorize
type AuthorizeRequest struct {
    ClientID     string `json:"client_id"`
    RedirectURI  string `json:"redirect_uri"`
    Scope        string `json:"scope"`
    State        string `json:"state"`
    ResponseType string `json:"response_type"` // default: "code"
    UserID       string `json:"user_id"`
}

// AuthorizeResponse — returned by Client.Authorize
type AuthorizeResponse struct {
    Code  string `json:"code"`
    State string `json:"state"`
}

// TokenRequest — argument to Client.ExchangeCode and Client.RefreshTokens
type TokenRequest struct {
    ClientID     string `json:"client_id"`
    GrantType    string `json:"grant_type,omitempty"`    // default: "authorization_code"
    Code         string `json:"code,omitempty"`
    RedirectURI  string `json:"redirect_uri,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse — returned by token endpoints
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    IDToken      string `json:"id_token,omitempty"`
    TokenType    string `json:"token_type"`    // "Bearer"
    ExpiresIn    int    `json:"expires_in,omitempty"` // seconds
    RefreshToken string `json:"refresh_token"`
}

// UserInfoResponse — returned by Client.UserInfo
type UserInfoResponse struct {
    Sub           string `json:"sub"`
    Name          string `json:"name,omitempty"`
    Email         string `json:"email,omitempty"`
    EmailVerified bool   `json:"email_verified,omitempty"`
}

// MePermissionsResponse — returned by Client.Permissions
type MePermissionsResponse struct {
    Roles       []string `json:"roles"`
    Groups      []string `json:"groups"`
    Permissions []string `json:"permissions"`
    Scope       string   `json:"scope"`
}

// CreateUserRequest — argument to AdminClient.CreateUser
type CreateUserRequest struct {
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
}

// UpdateUserRequest — argument to AdminClient.UpdateUser (nil fields = no change)
type UpdateUserRequest struct {
    Email       *string `json:"email,omitempty"`
    DisplayName *string `json:"display_name,omitempty"`
    Status      *string `json:"status,omitempty"`
}

// User — user record from the API
type User struct {
    ID          string `json:"id"`
    Email       string `json:"email"`
    DisplayName string `json:"display_name"`
    Status      string `json:"status"`
    CreatedAt   int64  `json:"created_at,omitempty"` // Unix epoch seconds
    UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// CreateRealmRequest — argument to AdminClient.CreateRealm
type CreateRealmRequest struct {
    Name string `json:"name"`
}

// UpdateRealmRequest — argument to AdminClient.UpdateRealm (nil fields = no change)
type UpdateRealmRequest struct {
    Name   *string `json:"name,omitempty"`
    Status *string `json:"status,omitempty"`
}

// Realm — realm record from the API
type Realm struct {
    ID        string `json:"id"`
    Name      string `json:"name"`
    Status    string `json:"status"`
    Config    any    `json:"config"`
    CreatedAt int64  `json:"created_at,omitempty"`
    UpdatedAt int64  `json:"updated_at,omitempty"`
}

// PageResponse[T] — paginated list response
type PageResponse[T any] struct {
    Items      []T     `json:"items"`
    NextCursor *string `json:"next_cursor"` // nil if last page
}

// RegisterClientRequest — argument to Client.RegisterClient
type RegisterClientRequest struct {
    ClientName   string   `json:"client_name"`
    RedirectURIs []string `json:"redirect_uris"`
}

// OAuthClient — returned by RegisterClient
type OAuthClient struct {
    ClientID     string   `json:"client_id"`
    ClientName   string   `json:"client_name"`
    RedirectURIs []string `json:"redirect_uris"`
    GrantTypes   []string `json:"grant_types"`
}

// APIError — returned for non-2xx responses
type APIError struct {
    StatusCode int
    Message    string // raw response body
}
```
