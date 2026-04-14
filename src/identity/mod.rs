//! Identity engine: users, credentials, sessions, tenants, and tokens.
//!
//! Domain logic layer that orchestrates authentication flows.
//! Depends on `storage` (for persistence) and `core` (for shared types).
//! May call `authz` (lateral dependency). Never the reverse.

mod engine;
pub mod error;
pub(crate) mod keys;
mod types;
mod validation;

pub use engine::{EmbeddedIdentityEngine, IdentityConfig};
pub use error::IdentityError;
pub use types::{CreateUserRequest, UpdateUserRequest, User, UserStatus};

use crate::core::{TenantId, UserId};

/// Trait defining the identity engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `TenantId` for multi-tenant isolation.
pub trait IdentityEngine: Send + Sync {
    /// Creates a new user in the given tenant.
    ///
    /// Validates input, normalizes the email, checks uniqueness, generates
    /// a `UserId`, and persists the user record with both primary and email
    /// index entries.
    fn create_user(
        &self,
        tenant_id: &TenantId,
        request: &CreateUserRequest,
    ) -> Result<User, IdentityError>;

    /// Retrieves a user by ID. Returns `None` if not found.
    fn get_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<User>, IdentityError>;

    /// Retrieves a user by email address. Returns `None` if not found.
    ///
    /// The email is normalized (lowercase, trimmed, NFC) before lookup.
    fn get_user_by_email(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<Option<User>, IdentityError>;

    /// Updates an existing user's fields.
    ///
    /// Only non-`None` fields in the request are applied. If the email changes,
    /// the old email index is removed and a new one is created (with uniqueness check).
    fn update_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        request: &UpdateUserRequest,
    ) -> Result<User, IdentityError>;

    /// Deletes a user by ID, removing both primary and email index entries.
    ///
    /// Returns `IdentityError::UserNotFound` if the user does not exist.
    fn delete_user(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<(), IdentityError>;
}
