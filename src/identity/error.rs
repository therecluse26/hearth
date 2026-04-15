//! Identity engine error types.

use std::fmt;

/// Errors originating from the identity engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
    /// The requested tenant was not found.
    TenantNotFound,
    /// The tenant is suspended; operations are denied.
    TenantSuspended,
    /// A tenant with the given name already exists.
    DuplicateTenantName,
    /// The requested user was not found.
    UserNotFound,
    /// A user with the given email already exists in this tenant.
    DuplicateEmail,
    /// The input failed validation.
    InvalidInput {
        /// Description of what was invalid.
        reason: String,
    },
    /// No credential found for this user.
    CredentialNotFound,
    /// The provided credential was invalid (e.g., wrong password).
    InvalidCredential {
        /// Description of why the credential was invalid.
        reason: String,
    },
    /// The requested session was not found, expired, or revoked.
    ///
    /// Intentionally conflates not-found, expired, and revoked for
    /// enumeration resistance — callers cannot distinguish the three.
    SessionNotFound,
    /// The token is invalid (malformed, bad signature, unsupported algorithm).
    ///
    /// Intentionally vague to prevent information leakage about why
    /// validation failed.
    InvalidToken,
    /// The token has expired.
    TokenExpired,
    /// A cryptographic signing or key generation error.
    SigningError {
        /// Description of the signing failure (no secrets).
        reason: String,
    },
    /// The OAuth client was not found or is invalid.
    InvalidClient,
    /// The redirect URI does not match any registered URI for the client.
    InvalidRedirectUri,
    /// The authorization code is not found, expired, already used, or invalid.
    InvalidAuthorizationCode,
    /// A generic OAuth error for code exchange failures (e.g., PKCE mismatch).
    InvalidGrant {
        /// Description of why the grant was invalid.
        reason: String,
    },
    /// Too many failed credential attempts; the account is temporarily locked.
    ///
    /// Intentionally vague to avoid leaking lockout state to attackers.
    RateLimited,
    /// An error from the underlying storage layer.
    Storage(Box<dyn std::error::Error + Send + Sync>),
    /// Serialization or deserialization failed.
    Serialization {
        /// Description of the serialization failure.
        reason: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TenantNotFound => write!(f, "tenant not found"),
            Self::TenantSuspended => write!(f, "tenant is suspended"),
            Self::DuplicateTenantName => write!(f, "a tenant with this name already exists"),
            Self::UserNotFound => write!(f, "user not found"),
            Self::DuplicateEmail => write!(f, "a user with this email already exists"),
            Self::InvalidInput { reason } => write!(f, "invalid input: {reason}"),
            Self::CredentialNotFound => write!(f, "no credential found for this user"),
            Self::InvalidCredential { reason } => {
                write!(f, "invalid credential: {reason}")
            }
            Self::SessionNotFound => write!(f, "session not found"),
            Self::InvalidToken => write!(f, "invalid token"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::SigningError { reason } => write!(f, "signing error: {reason}"),
            Self::InvalidClient => write!(f, "invalid client"),
            Self::InvalidRedirectUri => write!(f, "invalid redirect URI"),
            Self::InvalidAuthorizationCode => write!(f, "invalid authorization code"),
            Self::InvalidGrant { reason } => write!(f, "invalid grant: {reason}"),
            Self::RateLimited => write!(f, "too many failed attempts"),
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            Self::TenantNotFound
            | Self::TenantSuspended
            | Self::DuplicateTenantName
            | Self::UserNotFound
            | Self::DuplicateEmail
            | Self::InvalidInput { .. }
            | Self::CredentialNotFound
            | Self::InvalidCredential { .. }
            | Self::SessionNotFound
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::SigningError { .. }
            | Self::InvalidClient
            | Self::InvalidRedirectUri
            | Self::InvalidAuthorizationCode
            | Self::InvalidGrant { .. }
            | Self::RateLimited
            | Self::Serialization { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_tenant_not_found() {
        let err = IdentityError::TenantNotFound;
        let display = format!("{err}");
        assert!(display.contains("tenant not found"), "got: {display}");
    }

    #[test]
    fn display_tenant_suspended() {
        let err = IdentityError::TenantSuspended;
        let display = format!("{err}");
        assert!(display.contains("suspended"), "got: {display}");
    }

    #[test]
    fn display_duplicate_tenant_name() {
        let err = IdentityError::DuplicateTenantName;
        let display = format!("{err}");
        assert!(display.contains("already exists"), "got: {display}");
    }

    #[test]
    fn display_user_not_found() {
        let err = IdentityError::UserNotFound;
        let display = format!("{err}");
        assert!(display.contains("user not found"), "got: {display}");
    }

    #[test]
    fn display_duplicate_email() {
        let err = IdentityError::DuplicateEmail;
        let display = format!("{err}");
        assert!(display.contains("already exists"), "got: {display}");
    }

    #[test]
    fn display_invalid_input() {
        let err = IdentityError::InvalidInput {
            reason: "email missing @".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid input"), "got: {display}");
        assert!(display.contains("email missing @"), "got: {display}");
    }

    #[test]
    fn display_storage() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = IdentityError::Storage(Box::new(io_err));
        let display = format!("{err}");
        assert!(display.contains("storage error"), "got: {display}");
        assert!(display.contains("file missing"), "got: {display}");
    }

    #[test]
    fn display_serialization() {
        let err = IdentityError::Serialization {
            reason: "invalid JSON".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("serialization error"), "got: {display}");
        assert!(display.contains("invalid JSON"), "got: {display}");
    }

    #[test]
    fn implements_error_trait() {
        let err = IdentityError::UserNotFound;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn source_storage_has_inner() {
        let io_err = std::io::Error::other("disk full");
        let err = IdentityError::Storage(Box::new(io_err));
        assert!(err.source().is_some(), "Storage variant should have source");
    }

    #[test]
    fn display_credential_not_found() {
        let err = IdentityError::CredentialNotFound;
        let display = format!("{err}");
        assert!(display.contains("no credential found"), "got: {display}");
    }

    #[test]
    fn display_invalid_credential() {
        let err = IdentityError::InvalidCredential {
            reason: "wrong password".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid credential"), "got: {display}");
        assert!(display.contains("wrong password"), "got: {display}");
    }

    #[test]
    fn display_session_not_found() {
        let err = IdentityError::SessionNotFound;
        let display = format!("{err}");
        assert!(display.contains("session not found"), "got: {display}");
    }

    #[test]
    fn display_invalid_token() {
        let err = IdentityError::InvalidToken;
        let display = format!("{err}");
        assert!(display.contains("invalid token"), "got: {display}");
    }

    #[test]
    fn display_token_expired() {
        let err = IdentityError::TokenExpired;
        let display = format!("{err}");
        assert!(display.contains("token expired"), "got: {display}");
    }

    #[test]
    fn display_signing_error() {
        let err = IdentityError::SigningError {
            reason: "key generation failed".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("signing error"), "got: {display}");
        assert!(display.contains("key generation failed"), "got: {display}");
    }

    #[test]
    fn display_invalid_client() {
        let err = IdentityError::InvalidClient;
        let display = format!("{err}");
        assert!(display.contains("invalid client"), "got: {display}");
    }

    #[test]
    fn display_invalid_redirect_uri() {
        let err = IdentityError::InvalidRedirectUri;
        let display = format!("{err}");
        assert!(display.contains("invalid redirect URI"), "got: {display}");
    }

    #[test]
    fn display_invalid_authorization_code() {
        let err = IdentityError::InvalidAuthorizationCode;
        let display = format!("{err}");
        assert!(
            display.contains("invalid authorization code"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_grant() {
        let err = IdentityError::InvalidGrant {
            reason: "PKCE mismatch".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid grant"), "got: {display}");
        assert!(display.contains("PKCE mismatch"), "got: {display}");
    }

    #[test]
    fn source_others_none() {
        assert!(IdentityError::TenantNotFound.source().is_none());
        assert!(IdentityError::TenantSuspended.source().is_none());
        assert!(IdentityError::DuplicateTenantName.source().is_none());
        assert!(IdentityError::UserNotFound.source().is_none());
        assert!(IdentityError::DuplicateEmail.source().is_none());
        assert!(IdentityError::CredentialNotFound.source().is_none());
        assert!(IdentityError::SessionNotFound.source().is_none());
        assert!(IdentityError::InvalidToken.source().is_none());
        assert!(IdentityError::TokenExpired.source().is_none());
        assert!(IdentityError::InvalidClient.source().is_none());
        assert!(IdentityError::InvalidRedirectUri.source().is_none());
        assert!(IdentityError::InvalidAuthorizationCode.source().is_none());
        assert!((IdentityError::InvalidInput {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::InvalidCredential {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::SigningError {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::InvalidGrant {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::RateLimited.source().is_none());
        assert!((IdentityError::Serialization {
            reason: "x".to_string()
        })
        .source()
        .is_none());
    }
}
