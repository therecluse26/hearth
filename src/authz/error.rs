//! Authorization engine error types.

use std::fmt;

/// Errors originating from the authorization engine.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthzError {
    /// A relationship tuple has invalid or malformed fields.
    InvalidTuple {
        /// Description of what was invalid.
        reason: String,
    },
    /// Graph traversal exceeded the configured maximum depth.
    MaxDepthExceeded,
    /// An object or subject reference is malformed.
    InvalidReference {
        /// Description of what was invalid.
        reason: String,
    },
    /// A conditional write precondition was not met.
    ///
    /// Returned when `TouchIfAbsent` finds an existing tuple or
    /// `DeleteIfPresent` finds no tuple. The entire batch is rejected.
    PreconditionFailed {
        /// Description of which precondition failed.
        reason: String,
    },
    /// The namespace configuration is invalid or a tuple violates the schema.
    InvalidNamespace {
        /// Description of the namespace violation.
        reason: String,
    },
    /// The caller is not authorized to perform this operation.
    Unauthorized {
        /// Description of the authorization failure.
        reason: String,
    },
    /// An error from the underlying storage layer.
    Storage(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for AuthzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTuple { reason } => write!(f, "invalid tuple: {reason}"),
            Self::MaxDepthExceeded => write!(f, "graph traversal exceeded maximum depth"),
            Self::InvalidReference { reason } => write!(f, "invalid reference: {reason}"),
            Self::PreconditionFailed { reason } => write!(f, "precondition failed: {reason}"),
            Self::InvalidNamespace { reason } => write!(f, "invalid namespace: {reason}"),
            Self::Unauthorized { reason } => write!(f, "unauthorized: {reason}"),
            Self::Storage(err) => write!(f, "storage error: {err}"),
        }
    }
}

impl std::error::Error for AuthzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            Self::InvalidTuple { .. }
            | Self::MaxDepthExceeded
            | Self::InvalidReference { .. }
            | Self::PreconditionFailed { .. }
            | Self::InvalidNamespace { .. }
            | Self::Unauthorized { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn authz_error_display_invalid_tuple() {
        let err = AuthzError::InvalidTuple {
            reason: "empty relation".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid tuple"), "got: {display}");
        assert!(display.contains("empty relation"), "got: {display}");
    }

    #[test]
    fn authz_error_display_max_depth() {
        let err = AuthzError::MaxDepthExceeded;
        let display = format!("{err}");
        assert!(display.contains("maximum depth"), "got: {display}");
    }

    #[test]
    fn authz_error_display_invalid_reference() {
        let err = AuthzError::InvalidReference {
            reason: "missing type".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid reference"), "got: {display}");
        assert!(display.contains("missing type"), "got: {display}");
    }

    #[test]
    fn authz_error_display_storage() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = AuthzError::Storage(Box::new(io_err));
        let display = format!("{err}");
        assert!(display.contains("storage error"), "got: {display}");
        assert!(display.contains("file missing"), "got: {display}");
    }

    #[test]
    fn authz_error_implements_error_trait() {
        let err = AuthzError::MaxDepthExceeded;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn authz_error_source_storage() {
        let io_err = std::io::Error::other("disk full");
        let err = AuthzError::Storage(Box::new(io_err));
        assert!(err.source().is_some(), "Storage variant should have source");
    }

    #[test]
    fn authz_error_display_precondition_failed() {
        let err = AuthzError::PreconditionFailed {
            reason: "tuple already exists".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("precondition failed"), "got: {display}");
        assert!(display.contains("tuple already exists"), "got: {display}");
    }

    #[test]
    fn authz_error_display_invalid_namespace() {
        let err = AuthzError::InvalidNamespace {
            reason: "unknown type".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("invalid namespace"), "got: {display}");
        assert!(display.contains("unknown type"), "got: {display}");
    }

    #[test]
    fn authz_error_display_unauthorized() {
        let err = AuthzError::Unauthorized {
            reason: "missing tenant".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("unauthorized"), "got: {display}");
        assert!(display.contains("missing tenant"), "got: {display}");
    }

    #[test]
    fn authz_error_source_others_none() {
        let err = AuthzError::InvalidTuple {
            reason: "bad".to_string(),
        };
        assert!(err.source().is_none());

        let err = AuthzError::MaxDepthExceeded;
        assert!(err.source().is_none());

        let err = AuthzError::InvalidReference {
            reason: "bad".to_string(),
        };
        assert!(err.source().is_none());

        let err = AuthzError::PreconditionFailed {
            reason: "bad".to_string(),
        };
        assert!(err.source().is_none());

        let err = AuthzError::InvalidNamespace {
            reason: "bad".to_string(),
        };
        assert!(err.source().is_none());

        let err = AuthzError::Unauthorized {
            reason: "bad".to_string(),
        };
        assert!(err.source().is_none());
    }
}
