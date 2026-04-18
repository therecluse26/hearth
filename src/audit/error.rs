//! Audit engine error types.

use std::fmt;

/// Errors originating from the audit engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    /// The audit log integrity check failed (tamper detected).
    IntegrityViolation {
        /// Description of the integrity failure.
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

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegrityViolation { reason } => {
                write!(f, "audit integrity violation: {reason}")
            }
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            Self::IntegrityViolation { .. } | Self::Serialization { .. } => None,
        }
    }
}

impl From<crate::storage::StorageError> for AuditError {
    fn from(err: crate::storage::StorageError) -> Self {
        Self::Storage(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_integrity_violation() {
        let err = AuditError::IntegrityViolation {
            reason: "hash mismatch at event 5".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("integrity violation"), "got: {display}");
        assert!(display.contains("hash mismatch"), "got: {display}");
    }

    #[test]
    fn display_storage() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = AuditError::Storage(Box::new(io_err));
        let display = format!("{err}");
        assert!(display.contains("storage error"), "got: {display}");
    }

    #[test]
    fn display_serialization() {
        let err = AuditError::Serialization {
            reason: "invalid JSON".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("serialization error"), "got: {display}");
    }

    #[test]
    fn implements_error_trait() {
        let err = AuditError::IntegrityViolation {
            reason: "test".to_string(),
        };
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn source_storage_has_inner() {
        let io_err = std::io::Error::other("disk full");
        let err = AuditError::Storage(Box::new(io_err));
        assert!(err.source().is_some());
    }

    #[test]
    fn source_others_none() {
        assert!((AuditError::IntegrityViolation {
            reason: "x".to_string()
        })
        .source()
        .is_none());
        assert!((AuditError::Serialization {
            reason: "x".to_string()
        })
        .source()
        .is_none());
    }
}
