# hearth-sdk (Rust)

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/sdk-spec.md).

Rust SDK for the [Hearth](https://github.com/hearthauth/hearth) identity platform.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hearth-sdk = { path = "../sdks/rust" }  # or from crates.io once published
```

## Quickstart

```rust
use hearth_sdk::{HearthClient, HearthConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HearthClient::new(HearthConfig {
        issuer_url: "https://auth.example.com".to_string(),
        client_id: Some("my-app".to_string()),
        ..Default::default()
    })?;

    // Verify a token received in a request
    let claims = client.verify_token("eyJ...").await?;
    println!("Subject: {}", claims.subject());
    println!("Has admin role: {}", claims.has_role("admin"));

    Ok(())
}
```

## API Reference

### `HearthClient`

| Method | Description |
|--------|-------------|
| `HearthClient::new(config)` | Construct a new client; auto-discovers OIDC endpoints |
| `verify_token(token)` | Verify a JWT and return typed Claims |
| `introspect(token)` | Call the introspection endpoint (RFC 7662) |

### Claims API (spec §4)

| Method | Returns |
|--------|---------|
| `subject()` | `&str` |
| `issuer()` | `&str` |
| `audiences()` | `&[String]` |
| `expiry()` | `DateTime<Utc>` |
| `issued_at()` | `DateTime<Utc>` |
| `jwt_id()` | `&str` |
| `scope()` | `&str` |
| `scopes()` | `Vec<&str>` |
| `has_scope(s)` | `bool` |
| `has_role(r)` | `bool` |
| `has_permission(p)` | `bool` |
| `get(claim)` | `Option<&serde_json::Value>` |

### Error Types (spec §5)

| Type | When raised |
|------|-------------|
| `ConfigurationError` | Missing or invalid config |
| `DiscoveryError` | OIDC discovery endpoint unreachable |
| `JWKSFetchError` | JWKS endpoint unreachable or invalid |
| `TokenExpiredError` | `exp` in the past |
| `TokenNotYetValidError` | `nbf` in the future |
| `TokenInvalidError` | Signature invalid or malformed JWT |
| `TokenIssuerError` | `iss` mismatch |
| `TokenAudienceError` | `aud` mismatch |
| `IntrospectionError` | Introspection endpoint error |

## Troubleshooting

**`DiscoveryError` on startup** — verify `issuer_url` is reachable and returns a valid `/.well-known/openid-configuration` document.

**`JWKSFetchError` during verification** — check network connectivity to the JWKS endpoint. The SDK retries once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — the JWT signature does not match any key in the JWKS. If the server recently rotated keys, the SDK will re-fetch once automatically; persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured `client_id`. Verify `client_id` matches the audience your authorization server issues.

## Spec Conformance

This SDK is audited against the [Hearth SDK Common Specification](../../docs/sdk-spec.md). CI enforces conformance on every PR via `scripts/check-sdk-conformance.sh`.

## License

MIT
