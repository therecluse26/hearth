//! Identity engine: users, credentials, sessions, tenants, and tokens.
//!
//! Domain logic layer that orchestrates authentication flows.
//! Depends on `storage` (for persistence) and `core` (for shared types).
//! May call `authz` (lateral dependency). Never the reverse.

pub(crate) mod credentials;
mod engine;
pub mod error;
pub(crate) mod keys;
pub mod oidc;
pub mod tokens;
mod types;
mod validation;

pub use credentials::{CleartextPassword, CredentialConfig};
pub use engine::{EmbeddedIdentityEngine, IdentityConfig, RateLimitConfig, SessionConfig};
pub use error::IdentityError;
pub use oidc::{
    AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod, OAuthClient, OidcConfig,
    OidcDiscoveryDocument, OidcTokenResponse, RegisterClientRequest, TokenExchangeRequest,
};
pub use tokens::{
    decode_claims_unverified, validate_token_with_time, verify_token_signature, IssueTokenRequest,
    Jwk, JwksDocument, SigningKey, TokenClaims, TokenConfig, TokenPair,
};
pub use types::{
    CreateTenantRequest, CreateUserRequest, Session, Tenant, TenantConfig, TenantStatus,
    UpdateTenantRequest, UpdateUserRequest, User, UserStatus,
};

use crate::core::{SessionId, TenantId, UserId};

/// Trait defining the identity engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `TenantId` for multi-tenant isolation.
///
/// # Tenant lifecycle
///
/// Phase 1 adds first-class tenant management. Tenants are stored in a
/// system namespace and each tenant gets an independent Ed25519 signing
/// key for token issuance.
pub trait IdentityEngine: Send + Sync {
    // ===== Tenant lifecycle =====

    /// Creates a new tenant with the given configuration.
    ///
    /// Generates a `TenantId`, creates a per-tenant Ed25519 signing key,
    /// and persists both the tenant record and key material.
    fn create_tenant(&self, request: &CreateTenantRequest) -> Result<Tenant, IdentityError>;

    /// Retrieves a tenant by ID. Returns `None` if not found.
    fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<Tenant>, IdentityError>;

    /// Updates an existing tenant's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_tenant(
        &self,
        tenant_id: &TenantId,
        request: &UpdateTenantRequest,
    ) -> Result<Tenant, IdentityError>;

    /// Deletes a tenant and all associated data.
    ///
    /// Cascading deletion removes all users, sessions, credentials,
    /// authorization tuples, OAuth clients, and the tenant's signing key.
    fn delete_tenant(&self, tenant_id: &TenantId) -> Result<(), IdentityError>;

    /// Returns the JWKS document for a specific tenant.
    ///
    /// Each tenant has its own signing key, so its JWKS document contains
    /// only that tenant's public key.
    fn tenant_jwks(&self, tenant_id: &TenantId) -> Result<JwksDocument, IdentityError>;

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

    // ===== Token management =====

    /// Issues an access/refresh token pair for a session.
    ///
    /// The user and session must exist and be valid. Tokens are signed
    /// with Ed25519 and contain claims binding the token to the user,
    /// session, and tenant.
    fn issue_tokens(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TokenPair, IdentityError>;

    /// Validates a token via session lookup (internal hot path).
    ///
    /// Extracts the session ID from the token without verifying the
    /// signature (Hearth trusts its own tokens). Looks up the session
    /// and checks validity. Returns the decoded claims only if the
    /// session is still active.
    fn validate_token(
        &self,
        tenant_id: &TenantId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError>;

    /// Refreshes tokens: validates the refresh token, then issues a new pair.
    ///
    /// The refresh token's session must still be valid. The session's TTL
    /// is also refreshed. Returns a new token pair with updated expiration.
    fn refresh_tokens(
        &self,
        tenant_id: &TenantId,
        refresh_token: &str,
    ) -> Result<TokenPair, IdentityError>;

    /// Returns the JWKS document containing public keys for external verification.
    fn jwks(&self) -> JwksDocument;

    // ===== OIDC / OAuth 2.0 =====

    /// Registers a new OAuth 2.0 client.
    ///
    /// Validates the client name and redirect URIs, generates a `ClientId`,
    /// and persists the client record.
    fn register_client(
        &self,
        tenant_id: &TenantId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    /// Initiates an OAuth 2.0 authorization code flow.
    ///
    /// Validates the client, redirect URI, response type, and state parameter.
    /// Generates a cryptographically random authorization code, stores it
    /// (hashed), and returns the code with the echoed state.
    fn authorize(
        &self,
        tenant_id: &TenantId,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, IdentityError>;

    /// Exchanges an authorization code for access, ID, and refresh tokens.
    ///
    /// Validates the code (exists, not expired, not used, correct client and
    /// redirect URI), verifies PKCE if a code challenge was present, marks
    /// the code as used, creates a session, and issues tokens.
    fn exchange_authorization_code(
        &self,
        tenant_id: &TenantId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError>;

    /// Returns the OIDC Discovery document.
    ///
    /// Contains metadata about the provider's endpoints, supported response
    /// types, signing algorithms, and PKCE methods.
    fn oidc_discovery(&self) -> OidcDiscoveryDocument;
}
