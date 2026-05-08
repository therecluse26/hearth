//! Actor attribution and request-scoped audit context.
//!
//! Every security-critical mutation records *who* performed the action.
//! The [`Actor`] enum forces call sites to be explicit about identity
//! at compile time rather than relying on `&str` shortcuts.

use crate::core::{ClientId, UserId};

/// The principal that triggered an auditable mutation.
///
/// Every variant forces the caller to provide a typed identifier.
/// This gives compile-time evidence that the actor was considered
/// for every mutation — including ambiguous ones where a target
/// user and an admin user are both in scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actor {
    /// A user acting on their own behalf (self-service) or on
    /// behalf of another user (admin-initiated).
    User(UserId),
    /// An OAuth/SCIM/gRPC client authenticated via bearer token or
    /// client credentials.
    Client(ClientId),
    /// The Hearth system itself (startup, reconciliation, background
    /// tasks).
    System,
    /// An unauthenticated caller (self-registration, public endpoints).
    Anonymous,
}

impl Actor {
    /// Returns the string label used in [`CreateAuditEvent::actor`].
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Actor::User(id) => id.as_uuid().to_string(),
            Actor::Client(id) => id.as_uuid().to_string(),
            Actor::System => "system".to_string(),
            Actor::Anonymous => "anonymous".to_string(),
        }
    }
}

/// Request-scoped context passed into the identity engine when the
/// protocol layer knows who initiated the operation.
///
/// The engine uses this to populate audit events.  When `None` is
/// passed the engine picks a sane default (`Actor::System` for
/// admin-style operations, `Actor::User(target_user_id)` when a
/// `UserId` parameter is available).
#[derive(Clone, Debug)]
pub struct AuditContext {
    /// Who is performing the operation.
    pub actor: Actor,
    /// Optional supplemental metadata (e.g. `{"via": "admin_api"}`
    /// or `{"protocol": "scim"}`).  Merged into the audit event's
    /// `metadata` field at record time.
    pub metadata: Option<serde_json::Value>,
}
