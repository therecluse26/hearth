//! RBAC engine error types.
//!
//! Errors are layer-local per ARCHITECTURE.md § 5: upper layers convert via
//! `From` rather than passing `RbacError` through.

use std::fmt;

use crate::storage::StorageError;

use super::types::{CycleKind, TraversalKind};

/// Errors originating from the RBAC engine.
#[non_exhaustive]
#[derive(Debug)]
pub enum RbacError {
    /// No role exists with the given ID or name in this realm.
    RoleNotFound,
    /// No group exists with the given ID or slug in this realm.
    GroupNotFound,
    /// No role assignment with the given ID exists in this realm.
    AssignmentNotFound,
    /// A role with this name already exists in the realm.
    DuplicateRoleName,
    /// A group with this slug already exists in the realm.
    DuplicateGroupSlug,
    /// The supplied permission string failed § 2.5 grammar validation.
    InvalidPermission {
        /// Human-readable reason for the rejection.
        reason: String,
    },
    /// The supplied role name did not meet engine validation rules.
    InvalidRoleName {
        /// Human-readable reason for the rejection.
        reason: String,
    },
    /// The supplied group slug did not meet engine validation rules.
    InvalidGroupSlug {
        /// Human-readable reason for the rejection.
        reason: String,
    },
    /// A cycle was detected while traversing role-parent or group-member edges.
    CycleDetected {
        /// Which graph the cycle was detected in.
        kind: CycleKind,
        /// The offending entity (e.g. role ID / group slug involved in the cycle).
        entity: String,
    },
    /// A traversal exceeded the depth limit declared in AUTHORIZATION.md § 2.6.
    DepthExceeded {
        /// Which traversal the limit applies to.
        kind: TraversalKind,
        /// The configured depth limit.
        limit: usize,
    },
    /// A traversal exceeded the breadth limit declared in AUTHORIZATION.md § 2.6.
    BreadthExceeded {
        /// Which traversal the limit applies to.
        kind: TraversalKind,
        /// The configured breadth limit.
        limit: usize,
    },
    /// The resolved JWT claim set exceeded the configured size ceiling.
    TokenSizeExceeded {
        /// Identifier of the limit (e.g. `"permissions_per_token"`).
        limit: String,
        /// Numeric value of the limit.
        limit_value: usize,
        /// Actual value measured at token issuance.
        actual: usize,
    },
    /// An operator-defined role attempted to include a reserved-namespace
    /// permission (e.g. `hearth.*`).
    ReservedNamespace {
        /// The offending permission string.
        permission: String,
    },
    /// One or more requested OAuth scopes could not be granted.
    ///
    /// Returned by `resolve_with_scopes` when a `ThirdParty` client requests
    /// a scope outside its `declared_scopes`, or when no requested scope is
    /// satisfiable by the user's effective permission set.
    InvalidScope {
        /// Human-readable reason (no sensitive data).
        reason: String,
    },
    /// The underlying storage layer returned an error.
    Storage(Box<dyn std::error::Error + Send + Sync>),
    /// Serialization or deserialization of a stored record failed.
    Serialization {
        /// Description of the failure (no sensitive content).
        reason: String,
    },
}

impl fmt::Display for RbacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleNotFound => f.write_str("role not found"),
            Self::GroupNotFound => f.write_str("group not found"),
            Self::AssignmentNotFound => f.write_str("role assignment not found"),
            Self::DuplicateRoleName => f.write_str("role name already exists in realm"),
            Self::DuplicateGroupSlug => f.write_str("group slug already exists in realm"),
            Self::InvalidPermission { reason } => write!(f, "invalid permission: {reason}"),
            Self::InvalidRoleName { reason } => write!(f, "invalid role name: {reason}"),
            Self::InvalidGroupSlug { reason } => write!(f, "invalid group slug: {reason}"),
            Self::CycleDetected { kind, entity } => {
                write!(f, "cycle detected in {kind} at entity '{entity}'")
            }
            Self::DepthExceeded { kind, limit } => {
                write!(f, "{kind} traversal exceeded depth limit of {limit}")
            }
            Self::BreadthExceeded { kind, limit } => {
                write!(f, "{kind} traversal exceeded breadth limit of {limit}")
            }
            Self::TokenSizeExceeded {
                limit,
                limit_value,
                actual,
            } => write!(
                f,
                "token size limit '{limit}' exceeded: {actual} > {limit_value}"
            ),
            Self::ReservedNamespace { permission } => write!(
                f,
                "permission '{permission}' is in the reserved namespace and may not be granted by operator roles"
            ),
            Self::InvalidScope { reason } => write!(f, "invalid_scope: {reason}"),
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { reason } => write!(f, "serialization error: {reason}"),
        }
    }
}

impl std::error::Error for RbacError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(&**err),
            _ => None,
        }
    }
}

impl From<StorageError> for RbacError {
    fn from(err: StorageError) -> Self {
        Self::Storage(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_covers_simple_variants() {
        assert!(format!("{}", RbacError::RoleNotFound).contains("role"));
        assert!(format!("{}", RbacError::GroupNotFound).contains("group"));
        assert!(format!("{}", RbacError::AssignmentNotFound).contains("assignment"));
        assert!(format!("{}", RbacError::DuplicateRoleName).contains("role"));
        assert!(format!("{}", RbacError::DuplicateGroupSlug).contains("group"));
    }

    #[test]
    fn display_invalid_permission_includes_reason() {
        let e = RbacError::InvalidPermission {
            reason: "uppercase not allowed".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("invalid permission"));
        assert!(s.contains("uppercase"));
    }

    #[test]
    fn display_cycle_detected_includes_kind_and_entity() {
        let e = RbacError::CycleDetected {
            kind: CycleKind::RoleComposition,
            entity: "role_abc".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("role_composition"));
        assert!(s.contains("role_abc"));
    }

    #[test]
    fn display_depth_exceeded_includes_limit() {
        let e = RbacError::DepthExceeded {
            kind: TraversalKind::GroupMembership,
            limit: 10,
        };
        let s = format!("{e}");
        assert!(s.contains("group_membership"));
        assert!(s.contains("10"));
    }

    #[test]
    fn display_breadth_exceeded_includes_limit() {
        let e = RbacError::BreadthExceeded {
            kind: TraversalKind::GroupMembership,
            limit: 1000,
        };
        let s = format!("{e}");
        assert!(s.contains("1000"));
    }

    #[test]
    fn display_token_size_exceeded_includes_numbers() {
        let e = RbacError::TokenSizeExceeded {
            limit: "permissions_per_token".to_string(),
            limit_value: 100,
            actual: 127,
        };
        let s = format!("{e}");
        assert!(s.contains("permissions_per_token"));
        assert!(s.contains("100"));
        assert!(s.contains("127"));
    }

    #[test]
    fn display_reserved_namespace_includes_permission() {
        let e = RbacError::ReservedNamespace {
            permission: "hearth.admin".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("hearth.admin"));
        assert!(s.contains("reserved"));
    }

    #[test]
    fn display_serialization_includes_reason() {
        let e = RbacError::Serialization {
            reason: "bad json".to_string(),
        };
        assert!(format!("{e}").contains("bad json"));
    }

    #[test]
    fn storage_source_chains() {
        let io = std::io::Error::other("disk gone");
        let err = RbacError::Storage(Box::new(io));
        assert!(err.source().is_some());
    }

    #[test]
    fn other_source_is_none() {
        assert!(RbacError::RoleNotFound.source().is_none());
    }

    #[test]
    fn implements_error_trait() {
        let _: &dyn std::error::Error = &RbacError::RoleNotFound;
    }

    #[test]
    fn from_storage_error_preserves_as_storage_variant() {
        let io = std::io::Error::other("underlying");
        let se = StorageError::Io(io);
        let r: RbacError = se.into();
        match r {
            RbacError::Storage(_) => {}
            other => panic!("expected Storage variant, got {other:?}"),
        }
    }
}
