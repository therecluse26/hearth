//! Identity engine: users, credentials, sessions, tenants, and tokens.
//!
//! Domain logic layer that orchestrates authentication flows.
//! Depends on `storage` (for persistence) and `core` (for shared types).
//! May call `authz` (lateral dependency). Never the reverse.

pub(crate) mod credentials;
pub mod email;
mod engine;
pub mod error;
pub(crate) mod keys;
pub(crate) mod magic_link;
pub mod migration;
pub mod oidc;
pub mod onboarding;
pub mod reconcile;
pub mod tokens;
pub(crate) mod totp;
mod types;
mod validation;
pub(crate) mod webauthn;

pub use credentials::{CleartextPassword, CredentialConfig};
pub use email::{
    ApiKey, EmailBranding, EmailError, EmailMessage, EmailSender, EmailService, LoggingEmailSender,
    MailgunEmailSender, MailtrapEmailSender, PostmarkEmailSender, SendgridEmailSender,
    SharedEmailSender, StubHttpTransport,
};
pub use engine::{EmbeddedIdentityEngine, IdentityConfig, RateLimitConfig, SessionConfig};
pub use error::IdentityError;
pub use magic_link::MagicLinkResponse;
pub use oidc::{
    AuthorizationRequest, AuthorizationResponse, ClientCredentialsRequest,
    ClientCredentialsResponse, CodeChallengeMethod, DeviceAuthorizationRequest,
    DeviceAuthorizationResponse, DeviceCodeStatus, IntrospectionResponse, OAuthClient, OidcConfig,
    OidcDiscoveryDocument, OidcTokenResponse, RegisterClientRequest, TokenExchangeRequest,
    TokenIntrospectionRequest, TokenRevocationRequest, UpdateClientRequest, UserInfoResponse,
};
pub use tokens::{
    decode_claims_unverified, validate_token_with_time, verify_token_signature, IssueTokenRequest,
    Jwk, JwksDocument, SigningKey, TokenClaims, TokenConfig, TokenPair,
};
pub use totp::{RecoveryCodes, TotpEnrollment};
pub use types::{
    BulkResult, CreateInvitationRequest, CreateOrganizationRequest, CreateTenantRequest,
    CreateUserRequest, ImportClientRequest, ImportUserRequest, InvitationStatus, MigrationReport,
    Organization, OrganizationConfig, OrganizationInvitation, OrganizationMembership,
    OrganizationRole, OrganizationStatus, Page, PasswordPolicy, RawCredential, Session,
    SessionContext, Tenant, TenantConfig, TenantStatus, UpdateOrganizationRequest,
    UpdateTenantRequest, UpdateUserRequest, User, UserStatus,
};
pub use webauthn::{
    fuzz_parse_webauthn, AuthenticationOptions, CompleteAuthenticationParams, RegistrationOptions,
    WebAuthnAuthResult, WebAuthnCredentialInfo,
};

use crate::core::{InvitationId, OrganizationId, SessionId, TenantId, UserId};

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

    /// Retrieves a tenant by name. Returns `None` if not found.
    ///
    /// Uses the `tenant:name:{name}` index for O(1) lookup.
    fn get_tenant_by_name(&self, name: &str) -> Result<Option<Tenant>, IdentityError>;

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
    ///
    /// `context` carries optional device and network metadata (IP, User-Agent)
    /// captured at the point of authentication. Pass `&SessionContext::default()`
    /// for API-originated or test sessions without browser context.
    fn create_session(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        context: &SessionContext,
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

    /// Lists all sessions belonging to a user, with cursor-based pagination.
    ///
    /// Sessions are returned newest-first by their UUID ordering in the
    /// `ses:user:{user_uuid}:{session_uuid}` index.
    fn list_sessions_by_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError>;

    /// Lists all sessions in a tenant, with cursor-based pagination.
    ///
    /// Sessions are returned by their UUID ordering in the
    /// `ses:id:{session_uuid}` primary key space.
    fn list_sessions_by_tenant(
        &self,
        tenant_id: &TenantId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError>;

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

    // ===== OAuth 2.0 Extended (Step 22) =====

    /// Issues an access token via the Client Credentials Grant (RFC 6749 §4.4).
    ///
    /// Verifies the client secret using Argon2id, then issues an access token
    /// scoped to the client (no user context). Per RFC 6749 §4.4.3, refresh
    /// tokens SHOULD NOT be included.
    fn client_credentials_token(
        &self,
        tenant_id: &TenantId,
        request: &ClientCredentialsRequest,
    ) -> Result<ClientCredentialsResponse, IdentityError>;

    /// Initiates a Device Authorization Grant (RFC 8628).
    ///
    /// Generates a device code and a short user code, stores them, and
    /// returns the verification URI and polling interval.
    fn device_authorize(
        &self,
        tenant_id: &TenantId,
        request: &DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse, IdentityError>;

    /// Approves a device authorization by user code.
    ///
    /// Transitions the device code status from `Pending` to `Approved`.
    fn approve_device(
        &self,
        tenant_id: &TenantId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Polls for a device authorization token (RFC 8628 §3.4).
    ///
    /// Returns tokens if the user has approved, or an appropriate error
    /// (`AuthorizationPending`, `SlowDown`, `DeviceCodeExpired`, `DeviceCodeDenied`).
    fn poll_device_token(
        &self,
        tenant_id: &TenantId,
        device_code: &str,
        client_id: &crate::core::ClientId,
    ) -> Result<OidcTokenResponse, IdentityError>;

    /// Revokes a token (RFC 7009).
    ///
    /// For access tokens: extracts session ID and revokes the session.
    /// For refresh tokens: looks up the grant family and marks it revoked.
    fn revoke_token(
        &self,
        tenant_id: &TenantId,
        request: &TokenRevocationRequest,
    ) -> Result<(), IdentityError>;

    /// Introspects a token (RFC 7662).
    ///
    /// Returns `active: true` with metadata if the token is valid, or
    /// `active: false` for expired, revoked, or invalid tokens.
    fn introspect_token(
        &self,
        tenant_id: &TenantId,
        request: &TokenIntrospectionRequest,
    ) -> Result<IntrospectionResponse, IdentityError>;

    // ===== MFA / TOTP (Step 23) =====

    /// Begins TOTP enrollment for a user.
    ///
    /// Generates a secret, provisioning URI, and 8 recovery codes.
    /// The MFA state is stored in a disabled state until verified via
    /// `verify_totp_enrollment()`.
    fn enroll_totp(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<TotpEnrollment, IdentityError>;

    /// Verifies the initial TOTP setup code and enables MFA.
    ///
    /// The user must have a pending enrollment (from `enroll_totp()`).
    /// After success, MFA is active and `verify_totp()` must be used
    /// for subsequent authentication.
    fn verify_totp_enrollment(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a TOTP code for an authenticated user.
    ///
    /// Enforces rate limiting (5 attempts / 5 min lockout) and
    /// replay protection (rejects codes for already-used time steps).
    fn verify_totp(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a single-use recovery code.
    ///
    /// On success, the code is consumed and cannot be reused.
    fn verify_recovery_code(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Disables MFA for a user, removing all TOTP state.
    fn disable_mfa(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<(), IdentityError>;

    /// Returns whether MFA is currently enabled for a user.
    fn mfa_enabled(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<bool, IdentityError>;

    // ===== WebAuthn / Passkeys (Step 24) =====

    /// Starts a `WebAuthn` registration ceremony.
    ///
    /// Generates a challenge and returns it along with the challenge key
    /// for use in `complete_webauthn_registration()`.
    fn start_webauthn_registration(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        options: &RegistrationOptions,
    ) -> Result<Vec<u8>, IdentityError>;

    /// Completes a `WebAuthn` registration ceremony.
    ///
    /// Validates the attestation response, extracts the credential, and
    /// stores it. Returns the credential info.
    fn complete_webauthn_registration(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        client_data_json: &[u8],
        attestation_object: &[u8],
        origin: &str,
        discoverable: bool,
    ) -> Result<WebAuthnCredentialInfo, IdentityError>;

    /// Starts a `WebAuthn` authentication ceremony.
    ///
    /// Generates a challenge. If `user_id` is `None`, this is a
    /// discoverable credential (username-less) flow.
    fn start_webauthn_authentication(
        &self,
        tenant_id: &TenantId,
        user_id: Option<&UserId>,
        options: &AuthenticationOptions,
    ) -> Result<Vec<u8>, IdentityError>;

    /// Completes a `WebAuthn` authentication ceremony.
    ///
    /// Validates the assertion, verifies the signature, updates the
    /// sign counter, and returns the authentication result.
    fn complete_webauthn_authentication(
        &self,
        tenant_id: &TenantId,
        params: &CompleteAuthenticationParams<'_>,
    ) -> Result<WebAuthnAuthResult, IdentityError>;

    /// Lists all `WebAuthn` credentials for a user.
    fn list_webauthn_credentials(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Vec<WebAuthnCredentialInfo>, IdentityError>;

    /// Revokes (deletes) a `WebAuthn` credential.
    fn revoke_webauthn_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), IdentityError>;

    // ===== Magic Link / Passwordless (Step 25) =====

    /// Requests a magic link token for the given email address.
    ///
    /// Generates a random 32-byte token, stores its SHA-256 hash, and
    /// returns the plaintext token exactly once. The consuming application
    /// is responsible for delivering the token to the user (e.g., via email).
    ///
    /// For enumeration resistance, this method always succeeds regardless
    /// of whether the email is registered. If the email is unknown, the
    /// link is still created — account creation happens at validation time.
    fn request_magic_link(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<MagicLinkResponse, IdentityError>;

    /// Validates a magic link token and returns the associated user.
    ///
    /// On success, marks the token as used (single-use enforcement).
    /// If the email was not registered at request time, a new user account
    /// is created automatically.
    ///
    /// Returns `Err(MagicLinkTokenInvalid)` if the token is not found,
    /// expired, or already used. The error is intentionally vague for
    /// enumeration resistance.
    fn validate_magic_link(
        &self,
        tenant_id: &TenantId,
        token: &str,
    ) -> Result<UserId, IdentityError>;

    // ===== Password reset =====

    /// Requests a password reset token for the given email address.
    ///
    /// If the email belongs to an existing user, generates a random token,
    /// stores its SHA-256 hash under `rst:token:{hash}`, and returns
    /// `Some(plaintext_token)`. If the email is unknown, returns `None`.
    ///
    /// Unlike magic links, password reset tokens MUST NOT auto-create
    /// accounts for unknown emails.
    ///
    /// Rate-limited per email address (reuses magic link rate tracker).
    fn request_password_reset(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<Option<String>, IdentityError>;

    /// Resets a user's password using a password reset token.
    ///
    /// Validates the token (exists, not expired, not used), marks it as
    /// used, sets the new password via `set_password()`, and returns the
    /// user ID.
    ///
    /// Returns `Err(PasswordResetTokenInvalid)` if the token is not found,
    /// expired, or already used. Intentionally vague for enumeration
    /// resistance.
    fn reset_password_with_token(
        &self,
        tenant_id: &TenantId,
        token: &str,
        new_password: &CleartextPassword,
    ) -> Result<UserId, IdentityError>;

    // ===== Email verification (onboarding) =====

    /// Issues an email-verification token bound to the given user.
    ///
    /// Generates 32 random bytes (base64url), stores the SHA-256 hash
    /// with a 24-hour expiry, and returns the plaintext token once for
    /// inclusion in a verification URL. The plaintext is never persisted.
    fn issue_email_verification_token(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<String, IdentityError>;

    /// Consumes an email-verification token and activates the user.
    ///
    /// Looks up the token by SHA-256 hash, validates expiry and single-use
    /// semantics, then transitions the user from `PendingVerification` to
    /// `Active`. Deletes the token entry on success.
    ///
    /// Returns `Err(VerificationTokenInvalid)` if the token is not found,
    /// expired, or already used. Intentionally vague for enumeration
    /// resistance.
    fn verify_email_token(
        &self,
        tenant_id: &TenantId,
        token: &str,
    ) -> Result<UserId, IdentityError>;

    // ===== UserInfo (OIDC Core §5.3) =====

    /// Returns user claims for the `UserInfo` endpoint.
    ///
    /// Validates the access token, looks up the user, and returns claims
    /// filtered by the token's granted scopes. Per OIDC Core §5.3, the
    /// `sub` claim is always included; other claims depend on scope:
    /// - `profile`: `name`
    /// - `email`: `email`, `email_verified`
    fn userinfo(
        &self,
        tenant_id: &TenantId,
        access_token: &str,
    ) -> Result<UserInfoResponse, IdentityError>;

    // ===== Admin API (Step 27) =====

    /// Lists users with cursor-based pagination.
    ///
    /// Returns at most `limit` users. If more exist, `Page::next_cursor`
    /// contains the cursor for the next page.
    fn list_users(
        &self,
        tenant_id: &TenantId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<User>, IdentityError>;

    /// Searches users by substring match on email or display name.
    ///
    /// Case-insensitive substring match. Returns up to `limit` matches.
    /// Query must be at least 2 characters; shorter queries return empty.
    fn search_users(
        &self,
        tenant_id: &TenantId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<User>, IdentityError>;

    /// Lists tenants with cursor-based pagination.
    ///
    /// Tenants are stored under the system tenant namespace, so no
    /// `tenant_id` parameter is needed for scoping.
    fn list_tenants(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Tenant>, IdentityError>;

    /// Lists OAuth clients with cursor-based pagination.
    fn list_clients(
        &self,
        tenant_id: &TenantId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OAuthClient>, IdentityError>;

    /// Retrieves a single OAuth client by ID.
    fn get_client(
        &self,
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError>;

    /// Updates an existing OAuth client's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_client(
        &self,
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
        request: &UpdateClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    /// Regenerates the client secret for a confidential OAuth client.
    ///
    /// Generates a new random secret, hashes it with Argon2id, updates the
    /// stored client, and returns the plaintext secret exactly once. The
    /// old secret is permanently invalidated.
    ///
    /// Returns `Err(ClientNotFound)` if the client does not exist.
    /// Returns `Err(InvalidInput)` if the client is a public client (no secret).
    fn regenerate_client_secret(
        &self,
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
    ) -> Result<String, IdentityError>;

    /// Deletes an OAuth client by ID.
    fn delete_client(
        &self,
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError>;

    /// Creates multiple users in a single batch operation.
    ///
    /// Each item is processed independently — individual failures do not
    /// abort the batch. Returns a `BulkResult` for each input item.
    fn bulk_create_users(
        &self,
        tenant_id: &TenantId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError>;

    /// Disables multiple users in a single batch operation.
    ///
    /// Each item is processed independently — individual failures do not
    /// abort the batch. Returns a `BulkResult` for each input item.
    fn bulk_disable_users(
        &self,
        tenant_id: &TenantId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError>;

    // ===== Organizations =====

    /// Creates a new organization within a tenant.
    ///
    /// Validates the slug, checks uniqueness, and persists the org record
    /// with primary and slug index entries.
    fn create_organization(
        &self,
        tenant_id: &TenantId,
        request: &CreateOrganizationRequest,
    ) -> Result<Organization, IdentityError>;

    /// Retrieves an organization by ID. Returns `None` if not found.
    fn get_organization(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Retrieves an organization by slug. Returns `None` if not found.
    fn get_organization_by_slug(
        &self,
        tenant_id: &TenantId,
        slug: &str,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Updates an existing organization's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_organization(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        request: &UpdateOrganizationRequest,
    ) -> Result<Organization, IdentityError>;

    /// Deletes an organization and all associated data.
    ///
    /// Cascading deletion removes all memberships (forward + reverse indexes),
    /// invitations (primary + token + email dedup + list indexes), Zanzibar
    /// tuples, slug index, and the org record. Idempotent.
    fn delete_organization(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError>;

    /// Lists all organizations in a tenant with cursor-based pagination.
    fn list_organizations(
        &self,
        tenant_id: &TenantId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Organization>, IdentityError>;

    /// Adds a user as a member of an organization.
    ///
    /// Creates bidirectional membership indexes (org→user and user→org).
    /// If an authorization engine is configured, writes the corresponding
    /// Zanzibar tuples atomically.
    fn add_member(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Removes a user from an organization.
    ///
    /// Enforces last-owner protection: if the user is the sole Owner,
    /// returns `Err(LastOwner)`. Deletes both membership indexes and
    /// any Zanzibar tuples.
    fn remove_member(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Updates a member's role within an organization.
    ///
    /// Enforces last-owner protection when downgrading from Owner.
    /// Updates both membership indexes and Zanzibar tuples atomically.
    fn update_member_role(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        user_id: &UserId,
        new_role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Retrieves a specific membership. Returns `None` if not a member.
    fn get_membership(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<OrganizationMembership>, IdentityError>;

    /// Lists all members of an organization with cursor-based pagination.
    fn list_members(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError>;

    /// Lists all organizations a user belongs to with cursor-based pagination.
    fn list_user_organizations(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError>;

    /// Creates an invitation to join an organization.
    ///
    /// Generates a 32-byte random token, stores the SHA-256 hash, and
    /// returns the invitation record plus the plaintext token (for email
    /// delivery). The plaintext token is never stored.
    fn create_invitation(
        &self,
        tenant_id: &TenantId,
        request: &CreateInvitationRequest,
    ) -> Result<(OrganizationInvitation, String), IdentityError>;

    /// Accepts an invitation using the plaintext token.
    ///
    /// Hashes the token, looks up the invitation, validates status and
    /// expiry, creates the membership, marks the invitation as accepted,
    /// and returns the new membership.
    fn accept_invitation(
        &self,
        tenant_id: &TenantId,
        token: &str,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Revokes a pending invitation.
    fn revoke_invitation(
        &self,
        tenant_id: &TenantId,
        invitation_id: &InvitationId,
    ) -> Result<(), IdentityError>;

    /// Lists invitations for an organization with cursor-based pagination.
    fn list_invitations(
        &self,
        tenant_id: &TenantId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationInvitation>, IdentityError>;

    // ===== Migration / import (Phase 1 Step 30) =====

    /// Imports a tenant, optionally with a caller-supplied `TenantId`.
    ///
    /// Unlike `create_tenant`, this allows preserving an external system's
    /// realm/organization UUID. Returns `DuplicateTenantName` or a
    /// tenant-id-conflict error if one already exists with the same id.
    fn import_tenant(
        &self,
        request: &CreateTenantRequest,
        requested_id: Option<TenantId>,
    ) -> Result<Tenant, IdentityError>;

    /// Imports a user with a pre-hashed credential from an external system.
    ///
    /// Preserves the source-system hash verbatim so users can authenticate
    /// with their existing passwords. New hashes produced by Hearth
    /// (via `change_password`) are always Argon2id; successful verification
    /// against the imported hash auto-upgrades it in place on first login.
    fn import_user(
        &self,
        tenant_id: &TenantId,
        request: &ImportUserRequest,
    ) -> Result<User, IdentityError>;

    /// Imports an OAuth 2.0 client from an external system.
    ///
    /// Preserves the source-system client identifier if provided. The
    /// supplied `client_secret` (if any) is hashed with Argon2id at
    /// import time — the source system's hashed secret is not reusable
    /// because Hearth's storage format requires Argon2id.
    fn import_client(
        &self,
        tenant_id: &TenantId,
        request: &ImportClientRequest,
    ) -> Result<OAuthClient, IdentityError>;
}
