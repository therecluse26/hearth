//! Magic Link / Passwordless authentication.
//!
//! Generates single-use, time-limited tokens bound to an email address.
//! Hearth generates the token and returns it — the consuming application
//! handles email delivery.
//!
//! Tokens are stored as SHA-256 hashes. The plaintext is returned exactly
//! once via [`MagicLinkResponse`] and never persisted.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use base64::Engine as _;
use ring::rand::SecureRandom;

use crate::identity::error::IdentityError;

/// Magic link expiry: 15 minutes in microseconds.
pub(crate) const MAGIC_LINK_EXPIRY_MICROS: i64 = 15 * 60 * 1_000_000;

/// Password reset token expiry: 30 minutes in microseconds.
pub(crate) const PASSWORD_RESET_EXPIRY_MICROS: i64 = 30 * 60 * 1_000_000;

/// Number of random bytes for a magic link token.
pub(crate) const MAGIC_LINK_TOKEN_BYTES: usize = 32;

/// Stored state for a pending magic link.
///
/// Persisted under `magic:link:{sha256_hex_of_token}` within the realm's
/// key space. The plaintext token is never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredMagicLink {
    /// The email address this link was requested for.
    pub email: String,
    /// The user ID if the email was already registered at request time.
    /// `None` if the email was unknown (account will be created on validation).
    pub user_id: Option<String>,
    /// When this link was created (Unix microseconds).
    pub created_at_micros: i64,
    /// Whether this link has already been used.
    pub used: bool,
}

/// Stored state for a pending password reset token.
///
/// Persisted under `rst:token:{sha256_hex_of_token}` within the realm's
/// key space. The plaintext token is never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredPasswordReset {
    /// The email address this reset was requested for.
    pub email: String,
    /// The user ID whose password will be reset.
    pub user_id: String,
    /// When this token was created (Unix microseconds).
    pub created_at_micros: i64,
    /// Whether this token has already been used.
    pub used: bool,
}

/// Zeroize-on-drop wrapper for a magic link token plaintext.
///
/// **Security**: Intentionally does NOT implement `Display` or content-revealing
/// `Debug`. The inner bytes are zeroed from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct MagicLinkToken {
    value: String,
}

impl MagicLinkToken {
    /// Creates a new magic link token from a base64url-encoded string.
    pub(crate) fn new(value: String) -> Self {
        Self { value }
    }

    /// Returns the token value (for one-time inclusion in the response).
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MagicLinkToken(***)")
    }
}

/// Response returned when a magic link is requested.
///
/// Contains the opaque token string that should be sent to the user
/// (e.g., embedded in an email link). The token is shown exactly once.
#[derive(Debug)]
pub struct MagicLinkResponse {
    /// The plaintext token (base64url-encoded, 32 random bytes).
    token: String,
}

impl MagicLinkResponse {
    /// Creates a new magic link response.
    pub(crate) fn new(token: String) -> Self {
        Self { token }
    }

    /// Returns the magic link token.
    ///
    /// This value should be delivered to the user (e.g., as a URL parameter)
    /// and is only available at request time.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Generates a random magic link token.
///
/// Produces 32 random bytes and encodes them as a URL-safe base64 string
/// (no padding). Uses `ring::rand::SystemRandom` for cryptographic randomness.
pub(crate) fn generate_magic_link_token() -> Result<MagicLinkToken, IdentityError> {
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; MAGIC_LINK_TOKEN_BYTES];
    rng.fill(&mut bytes)
        .map_err(|_| IdentityError::SigningError {
            reason: "failed to generate magic link token".to_string(),
        })?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    Ok(MagicLinkToken::new(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_link_token_debug_redacted() {
        let token = MagicLinkToken::new("secret-value".to_string());
        let debug = format!("{token:?}");
        assert!(
            !debug.contains("secret-value"),
            "Debug should not reveal token: {debug}"
        );
        assert!(debug.contains("***"), "Debug should show redacted: {debug}");
    }

    #[test]
    fn generate_token_produces_nonempty_value() {
        let token = generate_magic_link_token().expect("generate");
        assert!(!token.as_str().is_empty(), "token should not be empty");
    }

    #[test]
    fn generate_token_produces_unique_values() {
        let t1 = generate_magic_link_token().expect("generate");
        let t2 = generate_magic_link_token().expect("generate");
        assert_ne!(t1.as_str(), t2.as_str(), "tokens should be unique");
    }

    #[test]
    fn stored_magic_link_roundtrip() {
        let stored = StoredMagicLink {
            email: "alice@example.com".to_string(),
            user_id: Some("user-123".to_string()),
            created_at_micros: 1_000_000,
            used: false,
        };
        let bytes = serde_json::to_vec(&stored).expect("serialize");
        let deserialized: StoredMagicLink = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(deserialized.email, "alice@example.com");
        assert_eq!(deserialized.user_id, Some("user-123".to_string()));
        assert!(!deserialized.used);
    }

    #[test]
    fn magic_link_response_exposes_token() {
        let resp = MagicLinkResponse::new("my-token".to_string());
        assert_eq!(resp.token(), "my-token");
    }
}
