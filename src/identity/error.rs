//! Identity engine error types.

use std::fmt;

/// Errors originating from the identity engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
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
            Self::UserNotFound => write!(f, "user not found"),
            Self::DuplicateEmail => write!(f, "a user with this email already exists"),
            Self::InvalidInput { reason } => write!(f, "invalid input: {reason}"),
            Self::CredentialNotFound => write!(f, "no credential found for this user"),
            Self::InvalidCredential { reason } => {
                write!(f, "invalid credential: {reason}")
            }
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            Self::UserNotFound
            | Self::DuplicateEmail
            | Self::InvalidInput { .. }
            | Self::CredentialNotFound
            | Self::InvalidCredential { .. }
            | Self::Serialization { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

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
    fn source_others_none() {
        assert!(IdentityError::UserNotFound.source().is_none());
        assert!(IdentityError::DuplicateEmail.source().is_none());
        assert!(IdentityError::CredentialNotFound.source().is_none());
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
        assert!((IdentityError::Serialization {
            reason: "x".to_string()
        })
        .source()
        .is_none());
    }
}
