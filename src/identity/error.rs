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
    /// The client secret is invalid.
    ///
    /// Intentionally vague — does not distinguish wrong vs. expired
    /// for enumeration resistance.
    InvalidClientSecret,
    /// The device authorization is still pending user action.
    AuthorizationPending,
    /// The device is polling too frequently; must slow down.
    SlowDown,
    /// The device authorization code has expired.
    DeviceCodeExpired,
    /// The device authorization was denied by the user.
    DeviceCodeDenied,
    /// The token has been revoked (grant family revoked).
    TokenRevoked,
    /// The requested grant type is not supported for this client.
    UnsupportedGrantType,
    /// Password authentication succeeded but MFA verification is required.
    MfaRequired,
    /// The TOTP code or recovery code is invalid.
    InvalidMfaCode,
    /// MFA is not enabled for this user.
    MfaNotEnabled,
    /// MFA is already enabled; disable it before re-enrolling.
    MfaAlreadyEnabled,
    /// A `WebAuthn` registration ceremony failed.
    WebAuthnRegistrationFailed {
        /// Description of the failure (no secrets).
        reason: String,
    },
    /// A `WebAuthn` authentication ceremony failed.
    WebAuthnAuthenticationFailed {
        /// Description of the failure (no secrets).
        reason: String,
    },
    /// The requested `WebAuthn` credential was not found.
    WebAuthnCredentialNotFound,
    /// The attestation provided during registration is invalid or unsupported.
    InvalidAttestation {
        /// Description of the attestation failure.
        reason: String,
    },
    /// The assertion provided during authentication is invalid.
    InvalidAssertion {
        /// Description of the assertion failure.
        reason: String,
    },
    /// The caller is not authorized to perform this operation.
    ///
    /// Used for admin API access control. Intentionally vague to
    /// prevent information leakage about what resources exist.
    Unauthorized,
    /// The requested OAuth client was not found.
    ClientNotFound,
    /// The magic link token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    MagicLinkTokenInvalid,
    /// The email-verification token is invalid, expired, or already used.
    ///
    /// Intentionally conflates not-found, expired, and already-used for
    /// enumeration resistance — callers cannot distinguish the three.
    VerificationTokenInvalid,
    /// The user account has not yet verified their email address.
    ///
    /// Returned by `create_session` when a user in `PendingVerification`
    /// status attempts to log in. Callers should direct the user to the
    /// email-verification flow.
    UserNotVerified,
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
            Self::InvalidClientSecret => write!(f, "invalid client secret"),
            Self::AuthorizationPending => write!(f, "authorization pending"),
            Self::SlowDown => write!(f, "polling too frequently"),
            Self::DeviceCodeExpired => write!(f, "device code expired"),
            Self::DeviceCodeDenied => write!(f, "device authorization denied"),
            Self::TokenRevoked => write!(f, "token has been revoked"),
            Self::UnsupportedGrantType => write!(f, "unsupported grant type"),
            Self::MfaRequired => write!(f, "MFA verification required"),
            Self::InvalidMfaCode => write!(f, "invalid MFA code"),
            Self::MfaNotEnabled => write!(f, "MFA is not enabled for this user"),
            Self::MfaAlreadyEnabled => write!(f, "MFA is already enabled"),
            Self::WebAuthnRegistrationFailed { reason } => {
                write!(f, "WebAuthn registration failed: {reason}")
            }
            Self::WebAuthnAuthenticationFailed { reason } => {
                write!(f, "WebAuthn authentication failed: {reason}")
            }
            Self::WebAuthnCredentialNotFound => write!(f, "WebAuthn credential not found"),
            Self::InvalidAttestation { reason } => {
                write!(f, "invalid attestation: {reason}")
            }
            Self::InvalidAssertion { reason } => {
                write!(f, "invalid assertion: {reason}")
            }
            Self::Unauthorized => write!(f, "forbidden"),
            Self::ClientNotFound => write!(f, "client not found"),
            Self::MagicLinkTokenInvalid => write!(f, "invalid or expired magic link"),
            Self::VerificationTokenInvalid => write!(f, "invalid or expired verification link"),
            Self::UserNotVerified => write!(f, "user email not verified"),
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
            | Self::InvalidClientSecret
            | Self::AuthorizationPending
            | Self::SlowDown
            | Self::DeviceCodeExpired
            | Self::DeviceCodeDenied
            | Self::TokenRevoked
            | Self::UnsupportedGrantType
            | Self::MfaRequired
            | Self::InvalidMfaCode
            | Self::MfaNotEnabled
            | Self::MfaAlreadyEnabled
            | Self::WebAuthnRegistrationFailed { .. }
            | Self::WebAuthnAuthenticationFailed { .. }
            | Self::WebAuthnCredentialNotFound
            | Self::InvalidAttestation { .. }
            | Self::InvalidAssertion { .. }
            | Self::Unauthorized
            | Self::ClientNotFound
            | Self::MagicLinkTokenInvalid
            | Self::VerificationTokenInvalid
            | Self::UserNotVerified
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
    fn display_invalid_client_secret() {
        let err = IdentityError::InvalidClientSecret;
        let display = format!("{err}");
        assert!(display.contains("invalid client secret"), "got: {display}");
    }

    #[test]
    fn display_authorization_pending() {
        let err = IdentityError::AuthorizationPending;
        let display = format!("{err}");
        assert!(display.contains("authorization pending"), "got: {display}");
    }

    #[test]
    fn display_slow_down() {
        let err = IdentityError::SlowDown;
        let display = format!("{err}");
        assert!(display.contains("polling too frequently"), "got: {display}");
    }

    #[test]
    fn display_device_code_expired() {
        let err = IdentityError::DeviceCodeExpired;
        let display = format!("{err}");
        assert!(display.contains("device code expired"), "got: {display}");
    }

    #[test]
    fn display_device_code_denied() {
        let err = IdentityError::DeviceCodeDenied;
        let display = format!("{err}");
        assert!(display.contains("denied"), "got: {display}");
    }

    #[test]
    fn display_token_revoked() {
        let err = IdentityError::TokenRevoked;
        let display = format!("{err}");
        assert!(display.contains("revoked"), "got: {display}");
    }

    #[test]
    fn display_unsupported_grant_type() {
        let err = IdentityError::UnsupportedGrantType;
        let display = format!("{err}");
        assert!(display.contains("unsupported grant type"), "got: {display}");
    }

    #[test]
    fn display_mfa_required() {
        let err = IdentityError::MfaRequired;
        let display = format!("{err}");
        assert!(
            display.contains("MFA verification required"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_mfa_code() {
        let err = IdentityError::InvalidMfaCode;
        let display = format!("{err}");
        assert!(display.contains("invalid MFA code"), "got: {display}");
    }

    #[test]
    fn display_mfa_not_enabled() {
        let err = IdentityError::MfaNotEnabled;
        let display = format!("{err}");
        assert!(display.contains("not enabled"), "got: {display}");
    }

    #[test]
    fn display_mfa_already_enabled() {
        let err = IdentityError::MfaAlreadyEnabled;
        let display = format!("{err}");
        assert!(display.contains("already enabled"), "got: {display}");
    }

    #[test]
    fn display_webauthn_registration_failed() {
        let err = IdentityError::WebAuthnRegistrationFailed {
            reason: "challenge mismatch".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("WebAuthn registration failed"),
            "got: {display}"
        );
        assert!(display.contains("challenge mismatch"), "got: {display}");
    }

    #[test]
    fn display_webauthn_authentication_failed() {
        let err = IdentityError::WebAuthnAuthenticationFailed {
            reason: "signature invalid".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("WebAuthn authentication failed"),
            "got: {display}"
        );
    }

    #[test]
    fn display_webauthn_credential_not_found() {
        let err = IdentityError::WebAuthnCredentialNotFound;
        let display = format!("{err}");
        assert!(
            display.contains("WebAuthn credential not found"),
            "got: {display}"
        );
    }

    #[test]
    fn display_invalid_attestation() {
        let err = IdentityError::InvalidAttestation {
            reason: "unsupported format".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid attestation"), "got: {display}");
    }

    #[test]
    fn display_invalid_assertion() {
        let err = IdentityError::InvalidAssertion {
            reason: "counter replay".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid assertion"), "got: {display}");
    }

    #[test]
    fn display_unauthorized() {
        let err = IdentityError::Unauthorized;
        let display = format!("{err}");
        assert!(display.contains("forbidden"), "got: {display}");
    }

    #[test]
    fn display_client_not_found() {
        let err = IdentityError::ClientNotFound;
        let display = format!("{err}");
        assert!(display.contains("client not found"), "got: {display}");
    }

    #[test]
    fn display_magic_link_token_invalid() {
        let err = IdentityError::MagicLinkTokenInvalid;
        let display = format!("{err}");
        assert!(
            display.contains("invalid or expired magic link"),
            "got: {display}"
        );
    }

    #[test]
    fn display_verification_token_invalid() {
        let err = IdentityError::VerificationTokenInvalid;
        let display = format!("{err}");
        assert!(
            display.contains("invalid or expired verification link"),
            "got: {display}"
        );
    }

    #[test]
    fn display_user_not_verified() {
        let err = IdentityError::UserNotVerified;
        let display = format!("{err}");
        assert!(display.contains("not verified"), "got: {display}");
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
        assert!(IdentityError::InvalidClientSecret.source().is_none());
        assert!(IdentityError::AuthorizationPending.source().is_none());
        assert!(IdentityError::SlowDown.source().is_none());
        assert!(IdentityError::DeviceCodeExpired.source().is_none());
        assert!(IdentityError::DeviceCodeDenied.source().is_none());
        assert!(IdentityError::TokenRevoked.source().is_none());
        assert!(IdentityError::UnsupportedGrantType.source().is_none());
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
        assert!(IdentityError::MfaRequired.source().is_none());
        assert!(IdentityError::InvalidMfaCode.source().is_none());
        assert!(IdentityError::MfaNotEnabled.source().is_none());
        assert!(IdentityError::MfaAlreadyEnabled.source().is_none());
        assert!((IdentityError::WebAuthnRegistrationFailed {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::WebAuthnAuthenticationFailed {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::WebAuthnCredentialNotFound.source().is_none());
        assert!((IdentityError::InvalidAttestation {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((IdentityError::InvalidAssertion {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!(IdentityError::Unauthorized.source().is_none());
        assert!(IdentityError::ClientNotFound.source().is_none());
        assert!(IdentityError::MagicLinkTokenInvalid.source().is_none());
        assert!(IdentityError::VerificationTokenInvalid.source().is_none());
        assert!(IdentityError::UserNotVerified.source().is_none());
        assert!(IdentityError::RateLimited.source().is_none());
        assert!((IdentityError::Serialization {
            reason: "x".to_string()
        })
        .source()
        .is_none());
    }
}
