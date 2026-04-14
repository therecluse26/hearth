//! Identity engine: users, credentials, sessions, tenants, and tokens.
//!
//! Domain logic layer that orchestrates authentication flows.
//! Depends on `storage` (for persistence) and `core` (for shared types).
//! May call `authz` (lateral dependency). Never the reverse.

pub(crate) mod credentials;
mod engine;
pub mod error;
pub(crate) mod keys;
mod types;
mod validation;

pub use credentials::{CleartextPassword, CredentialConfig};
pub use engine::{EmbeddedIdentityEngine, IdentityConfig, SessionConfig};
pub use error::IdentityError;
pub use types::{CreateUserRequest, Session, UpdateUserRequest, User, UserStatus};

use crate::core::{SessionId, TenantId, UserId};

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

    /// Sets (or replaces) the password for a user.
    ///
    /// Hashes the password using Argon2id with the configured parameters
    /// and stores the credential. The user must exist.
    fn set_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<(), IdentityError>;

    /// Verifies a password against the stored credential for a user.
    ///
    /// Returns `Ok(true)` if the password matches, `Ok(false)` if it does
    /// not match. Returns `Err` if the user or credential does not exist.
    ///
    /// If the stored credential uses a legacy algorithm (bcrypt/scrypt),
    /// a successful verification will automatically upgrade the hash to
    /// Argon2id.
    fn verify_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<bool, IdentityError>;

    /// Changes a user's password after verifying the old one.
    ///
    /// Returns `Err(InvalidCredential)` if the old password is wrong.
    /// Returns `Err(CredentialNotFound)` if no credential exists.
    fn change_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        old_password: &CleartextPassword,
        new_password: &CleartextPassword,
    ) -> Result<(), IdentityError>;

    // ===== Session management =====

    /// Creates a new session bound to the given user.
    ///
    /// Generates a random `SessionId`, sets TTL from configuration,
    /// and persists the session record. The user must exist.
    fn create_session(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Session, IdentityError>;

    /// Looks up a session by ID.
    ///
    /// Returns `Ok(Some(session))` only if the session exists, is not
    /// expired, and has not been revoked. Returns `Ok(None)` for all
    /// other cases (enumeration resistance).
    fn get_session(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError>;

    /// Revokes a session immediately.
    ///
    /// After revocation, `get_session` will return `None`.
    /// Returns `Err(SessionNotFound)` if the session does not exist.
    fn revoke_session(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<(), IdentityError>;

    /// Refreshes a session, extending its TTL from the current time.
    ///
    /// Returns the updated session. Returns `Err(SessionNotFound)` if
    /// the session does not exist, is expired, or has been revoked.
    fn refresh_session(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError>;
}
