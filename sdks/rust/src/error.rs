/// Hearth SDK error type — spec §5.
///
/// The `HearthError` enum covers both HTTP-level API errors and all
/// client-side errors required by spec §5.
#[derive(Debug, thiserror::Error)]
pub enum HearthError {
    // ── HTTP / network layer ─────────────────────────────────────────────

    #[error("HTTP {status}: {message}")]
    Api {
        status: u16,
        message: String,
        details: Option<serde_json::Value>,
    },

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),

    // ── Spec §5 error types ──────────────────────────────────────────────

    /// The client is misconfigured (e.g. missing base URL or realm ID).
    #[error("configuration error: {message}")]
    ConfigurationError { message: String },

    /// The OIDC discovery document could not be fetched or parsed.
    #[error("discovery error from {url}: {message}")]
    DiscoveryError { url: String, message: String },

    /// The JWKS document could not be retrieved or parsed.
    #[error("JWKS fetch error from {url}: {message}")]
    JWKSFetchError { url: String, message: String },

    /// A token's `exp` claim is in the past.
    #[error("token expired at unix={expired_at}")]
    TokenExpiredError { expired_at: i64 },

    /// A token's `nbf` claim is in the future.
    #[error("token not yet valid until unix={not_before}")]
    TokenNotYetValidError { not_before: i64 },

    /// A token fails structural or signature validation.
    #[error("token invalid: {reason}")]
    TokenInvalidError { reason: String },

    /// The token's `iss` claim does not match the expected issuer.
    #[error("token issuer mismatch: expected {expected:?}, got {actual:?}")]
    TokenIssuerError { expected: String, actual: String },

    /// The token's `aud` claim does not include the expected audience.
    #[error("token audience mismatch: expected {expected:?}, got {actual:?}")]
    TokenAudienceError {
        expected: String,
        actual: Vec<String>,
    },

    /// A token introspection request failed or returned inactive.
    #[error("introspection error: {message}")]
    IntrospectionError { message: String },
}
