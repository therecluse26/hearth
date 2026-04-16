//! Errors for migration from external identity providers.
//!
//! The migration layer can fail for reasons distinct from the identity or
//! authorization engines (malformed export files, unsupported KDF
//! parameters, etc.). Callers observe a single unified error type that
//! transparently wraps lower-layer failures via `From`.

use std::fmt;

use crate::authz::AuthzError;
use crate::identity::error::IdentityError;

/// Error produced by any migration operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// The export file could not be parsed (malformed JSON, missing
    /// required fields, or structurally invalid data).
    ParseError {
        /// Human-readable explanation of what failed to parse.
        reason: String,
    },
    /// A credential in the export used a KDF algorithm this importer does
    /// not support (e.g. `pbkdf2-sha512`). The owning user is imported
    /// without a credential and the algorithm is echoed in the returned
    /// `MigrationReport.warnings`.
    UnsupportedAlgorithm {
        /// Algorithm name as reported by the source system.
        algorithm: String,
    },
    /// Underlying identity-engine error while writing a tenant, user, or
    /// client.
    Identity(IdentityError),
    /// Underlying authorization-engine error while writing role tuples.
    Authz(AuthzError),
    /// Filesystem error while reading an export file.
    Io(std::io::Error),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError { reason } => write!(f, "failed to parse export: {reason}"),
            Self::UnsupportedAlgorithm { algorithm } => write!(
                f,
                "unsupported password hashing algorithm: {algorithm} \
                 (use `--reset-credentials` to import without credentials)"
            ),
            Self::Identity(e) => write!(f, "identity engine error: {e}"),
            Self::Authz(e) => write!(f, "authorization engine error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Authz(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::ParseError { .. } | Self::UnsupportedAlgorithm { .. } => None,
        }
    }
}

impl From<IdentityError> for MigrationError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<AuthzError> for MigrationError {
    fn from(e: AuthzError) -> Self {
        Self::Authz(e)
    }
}

impl From<std::io::Error> for MigrationError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for MigrationError {
    fn from(e: serde_json::Error) -> Self {
        Self::ParseError {
            reason: e.to_string(),
        }
    }
}
