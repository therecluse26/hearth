# Hearth Kotlin / JVM SDK

Official Kotlin/JVM client library for [Hearth](../../README.md) — an open-source identity server.

Coroutines-first API with full OIDC/JWT support out of the box.

---

## Installation

### Gradle (Kotlin DSL)

```kotlin
implementation("io.hearth:hearth-core:0.1.0")
```

### Maven

```xml
<dependency>
  <groupId>io.hearth</groupId>
  <artifactId>hearth-core</artifactId>
  <version>0.1.0</version>
</dependency>
```

---

## Quickstart — under 5 minutes to first verified token

```kotlin
import io.hearth.sdk.HearthClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    val client = HearthClient(
        issuerUrl = "https://auth.example.com",
        clientId  = "my-app",
        clientSecret = "my-secret",
    )

    // Verify an access token (validates signature, exp, iss, aud)
    val claims = client.verifyToken(accessToken)
    println("User: ${claims.subject()}")
    println("Roles: ${claims.roles()}")
    println("Admin? ${claims.hasRole("admin")}")
    println("Can read? ${claims.hasPermission("user:read")}")
}
```

---

## Configuration

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `issuerUrl` | String | Yes | Root URL of the Hearth instance |
| `clientId` | String | Conditional | Required for auth code, refresh, client credentials |
| `clientSecret` | String | Conditional | Required for confidential client flows and introspection |
| `jwksTtl` | Long (ms) | No | JWKS cache TTL override. Default: 1 hour. Min: 5 min |
| `introspectionEndpointOverride` | String | No | Override the discovered introspection URL |
| `httpTimeoutMs` | Long | No | Timeout for all HTTP calls. Default: 10 000 ms |
| `expectedAudience` | String | No | Required `aud` value. Defaults to `clientId` |

---

## OAuth 2.0 Flows

### Authorization Code + PKCE

```kotlin
val resp = client.authorize(AuthorizeRequest(
    clientId    = "my-app",
    redirectUri = "https://myapp.com/callback",
    scope       = "openid profile",
    state       = "random-state",
    codeChallenge = pkce.challenge,
    codeChallengeMethod = "S256",
))
// Redirect user to resp.code ... then on callback:
val tokens = client.exchangeCode(
    code         = req.param("code"),
    redirectUri  = "https://myapp.com/callback",
    codeVerifier = pkce.verifier,
)
```

### Client Credentials

```kotlin
val tokens = client.clientCredentials(scope = "api:read")
```

### Refresh Token

```kotlin
val tokens = client.refreshTokens(existingRefreshToken)
```

### Device Flow

```kotlin
val device = client.deviceAuthorization(scope = "openid")
println("Visit ${device.verificationUri} and enter: ${device.userCode}")

// Poll until authorized (respect device.interval seconds between polls)
var tokens: TokenResponse? = null
while (tokens == null) {
    delay(device.interval * 1000L)
    tokens = client.pollDeviceToken(device.deviceCode)
}
```

### Magic Link

```kotlin
val tokens = client.exchangeMagicLink(magicToken)
```

---

## Token Verification

```kotlin
// Full verification: signature, exp, iss, aud
val claims = client.verifyToken(accessToken)

// Claims API
claims.subject()          // "user-123"
claims.issuer()           // "https://auth.example.com"
claims.audiences()        // ["my-app"]
claims.expiry()           // java.time.Instant
claims.issuedAt()         // java.time.Instant
claims.scope()            // "read write"
claims.scopes()           // ["read", "write"]
claims.hasScope("write")  // true
claims.hasRole("admin")   // reads Hearth `roles` claim
claims.hasPermission("user:delete")  // reads Hearth `permissions` claim
claims.get("custom_field")  // raw claim value
```

### JWKS Caching

JWKS keys are cached by `kid` — old keys are **not** discarded during rotation, preventing
verification failures when some tokens still carry the old key ID. TTL respects
`Cache-Control: max-age` from the JWKS endpoint, clamped between 5 minutes and 24 hours.

---

## Token Introspection (RFC 7662)

```kotlin
val result = client.introspect(token)
if (result.active) {
    println("Subject: ${result.sub}")
    println("Scope: ${result.scope}")
}
```

Introspection results are **never cached** — per RFC 7662, token state can change at any time.

---

## Admin API

```kotlin
val admin = client.admin(adminAccessToken)

// Users
val user  = admin.createUser(CreateUserRequest("alice@example.com", "Alice"))
val found = admin.getUser(user.id)
admin.updateUser(user.id, UpdateUserRequest(status = "suspended"))
admin.deleteUser(user.id)
val page  = admin.listUsers(limit = 50)

// Realms
val realm = admin.createRealm(CreateRealmRequest("my-realm"))
admin.updateRealm(realm.id, UpdateRealmRequest(name = "production"))
admin.deleteRealm(realm.id)

// OAuth client registration
val oauthClient = admin.registerClient(
    RegisterClientRequest("My App", listOf("https://myapp.com/callback"))
)
```

---

## Error Handling

All errors extend `HearthException`:

| Exception | When thrown |
|-----------|-------------|
| `ConfigurationError` | Missing required config, invalid issuer URL |
| `DiscoveryError` | OIDC discovery unreachable or returned invalid JSON |
| `JWKSFetchError` | JWKS endpoint unreachable or returned invalid response |
| `TokenExpiredError` | `exp` claim is in the past |
| `TokenNotYetValidError` | `nbf` claim is in the future beyond clock skew |
| `TokenInvalidError` | Bad signature, malformed JWT, algorithm mismatch |
| `TokenIssuerError` | `iss` does not match configured issuer |
| `TokenAudienceError` | `aud` does not contain expected audience |
| `IntrospectionError` | Introspection endpoint unreachable or returned error |
| `ApiError` | Admin/OAuth API returned non-2xx |

```kotlin
try {
    val claims = client.verifyToken(token)
} catch (e: TokenExpiredError) {
    println("Token expired — ask user to re-authenticate")
} catch (e: TokenInvalidError) {
    println("Token signature is invalid")
} catch (e: HearthException) {
    println("Auth error: ${e.message}")
}
```

**Tokens and secrets never appear in error messages or stack traces.**

---

## Troubleshooting

**`DiscoveryError: OIDC discovery endpoint unreachable`**
→ Check that `issuerUrl` is correct and reachable from your service. Hearth must be running.

**`TokenExpiredError`**
→ Refresh the token using `client.refreshTokens(refreshToken)`.

**`TokenAudienceError`**
→ Ensure `clientId` matches the `aud` claim in the token. Or set `expectedAudience = null` for pure resource servers.

**`ConfigurationError: clientId and clientSecret are required for token introspection`**
→ Set both `clientId` and `clientSecret` in `HearthClient` config.

**`JWKSFetchError`**
→ The JWKS endpoint (`/jwks`) is unreachable. Check network connectivity and TLS.

---

## Compatibility

| SDK version | Minimum Hearth server |
|------------|----------------------|
| 0.1.x      | 0.1.0                |

Requires Java 17+ or Kotlin 2.0+.

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
