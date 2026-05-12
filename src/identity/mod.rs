//! Identity engine: users, credentials, sessions, realms, and tokens.
//!
//! Domain logic layer that orchestrates authentication flows.
//! Depends on `storage` (for persistence) and `core` (for shared types).
//! May call `authz` (lateral dependency). Never the reverse.

pub mod claims_config;
pub(crate) mod cleanup;
pub(crate) mod credentials;
pub mod email;
mod engine;
pub mod error;
pub mod federation;
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
pub use engine::{
    EmbeddedIdentityEngine, IdentityConfig, RateLimitConfig, SessionConfig, TokenIssuanceContext,
};
pub use error::IdentityError;
pub use magic_link::MagicLinkResponse;
pub use oidc::{
    AuthorizationRequest, AuthorizationResponse, ClientCredentialsRequest,
    ClientCredentialsResponse, ClientTrustLevel, CodeChallengeMethod, DeviceAuthorizationRequest,
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
    canonicalize_scopes, BulkResult, ConsentDecision, ConsentListEntry, ConsentRecord,
    CreateInvitationRequest, CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest,
    DcrPolicy, ImportClientRequest, ImportUserRequest, InvitationStatus, MigrationReport,
    Organization, OrganizationConfig, OrganizationInvitation, OrganizationMembership,
    OrganizationRole, OrganizationStatus, Page, PasswordPolicy, PendingAuthorizationRequest,
    RawCredential, Realm, RealmConfig, RealmStatus, RegisterUserRequest, RegisterUserResponse,
    RegistrationPolicy, Session, SessionContext, UpdateOrganizationRequest, UpdateRealmRequest,
    UpdateUserRequest, User, UserStatus,
};
pub use webauthn::{
    fuzz_parse_webauthn, AuthenticationOptions, CompleteAuthenticationParams, RegistrationOptions,
    WebAuthnAuthResult, WebAuthnCredentialInfo,
};

use crate::core::{InvitationId, OrganizationId, RealmId, SessionId, UserId};

/// Trait defining the identity engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `RealmId` for multi-realm isolation.
///
/// # Realm lifecycle
///
/// Phase 1 adds first-class realm management. Realms are stored in a
/// system namespace and each realm gets an independent Ed25519 signing
/// key for token issuance.
pub trait IdentityEngine: Send + Sync {
    // ===== Realm lifecycle =====

    /// Creates a new realm with the given configuration.
    ///
    /// Generates a `RealmId`, creates a per-realm Ed25519 signing key,
    /// and persists both the realm record and key material.
    fn create_realm(&self, request: &CreateRealmRequest) -> Result<Realm, IdentityError>;

    /// Retrieves a realm by ID. Returns `None` if not found.
    fn get_realm(&self, realm_id: &RealmId) -> Result<Option<Realm>, IdentityError>;

    /// Retrieves a realm by name. Returns `None` if not found.
    ///
    /// Uses the `realm:name:{name}` index for O(1) lookup.
    fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IdentityError>;

    /// Updates an existing realm's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_realm(
        &self,
        realm_id: &RealmId,
        request: &UpdateRealmRequest,
    ) -> Result<Realm, IdentityError>;

    /// Deletes a realm and all associated data.
    ///
    /// Cascading deletion removes all users, sessions, credentials,
    /// authorization tuples, OAuth clients, and the realm's signing key.
    fn delete_realm(&self, realm_id: &RealmId) -> Result<(), IdentityError>;

    /// Returns the JWKS document for a specific realm.
    ///
    /// Each realm has its own signing key, so its JWKS document contains
    /// only that realm's public key.
    fn realm_jwks(&self, realm_id: &RealmId) -> Result<JwksDocument, IdentityError>;

    /// Creates a new user in the given realm.
    ///
    /// Validates input, normalizes the email, checks uniqueness, generates
    /// a `UserId`, and persists the user record with both primary and email
    /// index entries.
    ///
    /// Rejects the reserved system realm with `SystemRealmProtected`.
    /// To create an administrator, use [`Self::create_admin_user`].
    fn create_user(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
    ) -> Result<User, IdentityError>;

    /// Creates a new user record in the reserved system realm.
    ///
    /// This is the only public entry point that writes into the system
    /// realm. It does *not* grant the `realm.admin` RBAC role —
    /// callers (onboarding, admin UI) must issue the corresponding
    /// `assign_role` call themselves so the two writes sit next to each
    /// other at the call site rather than hidden inside the engine.
    fn create_admin_user(&self, request: &CreateUserRequest) -> Result<User, IdentityError>;

    /// Retrieves a user by ID. Returns `None` if not found.
    fn get_user(&self, realm_id: &RealmId, user_id: &UserId)
        -> Result<Option<User>, IdentityError>;

    /// Retrieves a user by email address. Returns `None` if not found.
    ///
    /// The email is normalized (lowercase, trimmed, NFC) before lookup.
    fn get_user_by_email(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IdentityError>;

    /// Updates an existing user's fields.
    ///
    /// Only non-`None` fields in the request are applied. If the email changes,
    /// the old email index is removed and a new one is created (with uniqueness check).
    fn update_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        request: &UpdateUserRequest,
    ) -> Result<User, IdentityError>;

    /// Deletes a user by ID, removing both primary and email index entries.
    ///
    /// Returns `IdentityError::UserNotFound` if the user does not exist.
    fn delete_user(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError>;

    /// Sets (or replaces) the password for a user.
    ///
    /// Hashes the password using Argon2id with the configured parameters
    /// and stores the credential. The user must exist.
    fn set_password(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<bool, IdentityError>;

    /// Changes a user's password after verifying the old one.
    ///
    /// Returns `Err(InvalidCredential)` if the old password is wrong.
    /// Returns `Err(CredentialNotFound)` if no credential exists.
    fn change_password(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError>;

    /// Revokes a session immediately.
    ///
    /// After revocation, `get_session` will return `None`.
    /// Returns `Err(SessionNotFound)` if the session does not exist.
    fn revoke_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<(), IdentityError>;

    /// Refreshes a session, extending its TTL from the current time.
    ///
    /// Returns the updated session. Returns `Err(SessionNotFound)` if
    /// the session does not exist, is expired, or has been revoked.
    fn refresh_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError>;

    /// Lists all sessions belonging to a user, with cursor-based pagination.
    ///
    /// Sessions are returned newest-first by their UUID ordering in the
    /// `ses:user:{user_uuid}:{session_uuid}` index.
    fn list_sessions_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError>;

    /// Lists all sessions in a realm, with cursor-based pagination.
    ///
    /// Sessions are returned by their UUID ordering in the
    /// `ses:id:{session_uuid}` primary key space.
    fn list_sessions_by_realm(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError>;

    // ===== Token management =====

    /// Issues an access/refresh token pair for a session.
    ///
    /// The user and session must exist and be valid. Tokens are signed
    /// with Ed25519 and contain claims binding the token to the user,
    /// session, and realm.
    fn issue_tokens(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TokenPair, IdentityError>;

    /// Issues a token pair with explicit OAuth / org context.
    ///
    /// Compared to the plain `issue_tokens`, this method additionally:
    /// - Looks up the `OAuthClient` identified by `ctx.client_id` (if any)
    ///   and uses it as the client context for claim-profile gate evaluation.
    /// - Passes `ctx.granted_scopes` to the claim-profile resolver so
    ///   scope-gated claim mappings are evaluated correctly.
    /// - Embeds `ctx.oid` as the `oid` (org context) claim.
    ///
    /// The existing `issue_tokens` is a thin wrapper that calls this method
    /// with `TokenIssuanceContext::default()`.
    fn issue_tokens_with_context(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
        ctx: &TokenIssuanceContext,
    ) -> Result<TokenPair, IdentityError>;

    /// Validates a token via session lookup (internal hot path).
    ///
    /// Extracts the session ID from the token without verifying the
    /// signature (Hearth trusts its own tokens). Looks up the session
    /// and checks validity. Returns the decoded claims only if the
    /// session is still active.
    fn validate_token(&self, realm_id: &RealmId, token: &str)
        -> Result<TokenClaims, IdentityError>;

    /// Refreshes tokens: validates the refresh token, then issues a new pair.
    ///
    /// The refresh token's session must still be valid. The session's TTL
    /// is also refreshed. Returns a new token pair with updated expiration.
    fn refresh_tokens(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    /// Initiates an OAuth 2.0 authorization code flow.
    ///
    /// Validates the client, redirect URI, response type, and state parameter.
    /// Generates a cryptographically random authorization code, stores it
    /// (hashed), and returns the code with the echoed state.
    fn authorize(
        &self,
        realm_id: &RealmId,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, IdentityError>;

    /// Exchanges an authorization code for access, ID, and refresh tokens.
    ///
    /// Validates the code (exists, not expired, not used, correct client and
    /// redirect URI), verifies PKCE if a code challenge was present, marks
    /// the code as used, creates a session, and issues tokens.
    fn exchange_authorization_code(
        &self,
        realm_id: &RealmId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError>;

    /// Returns the OIDC Discovery document.
    ///
    /// Contains metadata about the provider's endpoints, supported response
    /// types, signing algorithms, and PKCE methods.
    fn oidc_discovery(&self) -> OidcDiscoveryDocument;

    /// Returns a per-realm OIDC Discovery document.
    ///
    /// The `issuer` in the returned document is `{base_issuer}/realms/{name}`,
    /// enabling distinct OIDC issuers per realm. All endpoint URLs are prefixed
    /// with the per-realm issuer.
    ///
    /// Returns `RealmNotFound` when the realm does not exist.
    fn realm_oidc_discovery(
        &self,
        realm_id: &RealmId,
    ) -> Result<OidcDiscoveryDocument, IdentityError>;

    // ===== OAuth 2.0 Extended (Step 22) =====

    /// Issues an access token via the Client Credentials Grant (RFC 6749 §4.4).
    ///
    /// Verifies the client secret using Argon2id, then issues an access token
    /// scoped to the client (no user context). Per RFC 6749 §4.4.3, refresh
    /// tokens SHOULD NOT be included.
    fn client_credentials_token(
        &self,
        realm_id: &RealmId,
        request: &ClientCredentialsRequest,
    ) -> Result<ClientCredentialsResponse, IdentityError>;

    /// Initiates a Device Authorization Grant (RFC 8628).
    ///
    /// Generates a device code and a short user code, stores them, and
    /// returns the verification URI and polling interval.
    fn device_authorize(
        &self,
        realm_id: &RealmId,
        request: &DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse, IdentityError>;

    /// Approves a device authorization by user code.
    ///
    /// Transitions the device code status from `Pending` to `Approved`.
    fn approve_device(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Polls for a device authorization token (RFC 8628 §3.4).
    ///
    /// Returns tokens if the user has approved, or an appropriate error
    /// (`AuthorizationPending`, `SlowDown`, `DeviceCodeExpired`, `DeviceCodeDenied`).
    fn poll_device_token(
        &self,
        realm_id: &RealmId,
        device_code: &str,
        client_id: &crate::core::ClientId,
    ) -> Result<OidcTokenResponse, IdentityError>;

    /// Revokes a token (RFC 7009).
    ///
    /// For access tokens: extracts session ID and revokes the session.
    /// For refresh tokens: looks up the grant family and marks it revoked.
    fn revoke_token(
        &self,
        realm_id: &RealmId,
        request: &TokenRevocationRequest,
    ) -> Result<(), IdentityError>;

    /// Introspects a token (RFC 7662).
    ///
    /// Returns `active: true` with metadata if the token is valid, or
    /// `active: false` for expired, revoked, or invalid tokens.
    fn introspect_token(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<TotpEnrollment, IdentityError>;

    /// Verifies the initial TOTP setup code and enables MFA.
    ///
    /// The user must have a pending enrollment (from `enroll_totp()`).
    /// After success, MFA is active and `verify_totp()` must be used
    /// for subsequent authentication.
    fn verify_totp_enrollment(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a TOTP code for an authenticated user.
    ///
    /// Enforces rate limiting (5 attempts / 5 min lockout) and
    /// replay protection (rejects codes for already-used time steps).
    fn verify_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Verifies a single-use recovery code.
    ///
    /// On success, the code is consumed and cannot be reused.
    fn verify_recovery_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError>;

    /// Disables MFA for a user, removing all TOTP state.
    fn disable_mfa(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError>;

    /// Returns whether MFA is currently enabled for a user.
    fn mfa_enabled(&self, realm_id: &RealmId, user_id: &UserId) -> Result<bool, IdentityError>;

    /// Generates a new set of recovery codes, replacing any existing ones.
    ///
    /// Requires MFA to be already enabled. Returns the new plaintext codes
    /// (shown once; hashes are stored immediately).
    fn regenerate_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<String>, IdentityError>;

    /// Returns the plaintext pending recovery codes if the user has a pending
    /// enrollment (codes not yet confirmed/hashed). Returns `None` if MFA is
    /// already enabled or there is no pending enrollment.
    fn load_pending_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<Vec<String>>, IdentityError>;

    // ===== WebAuthn / Passkeys (Step 24) =====

    /// Starts a `WebAuthn` registration ceremony.
    ///
    /// Generates a challenge and returns it along with the challenge key
    /// for use in `complete_webauthn_registration()`.
    fn start_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        options: &RegistrationOptions,
    ) -> Result<Vec<u8>, IdentityError>;

    /// Completes a `WebAuthn` registration ceremony.
    ///
    /// Validates the attestation response, extracts the credential, and
    /// stores it. Returns the credential info.
    fn complete_webauthn_registration(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        user_id: Option<&UserId>,
        options: &AuthenticationOptions,
    ) -> Result<Vec<u8>, IdentityError>;

    /// Completes a `WebAuthn` authentication ceremony.
    ///
    /// Validates the assertion, verifies the signature, updates the
    /// sign counter, and returns the authentication result.
    fn complete_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        params: &CompleteAuthenticationParams<'_>,
    ) -> Result<WebAuthnAuthResult, IdentityError>;

    /// Lists all `WebAuthn` credentials for a user.
    fn list_webauthn_credentials(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<WebAuthnCredentialInfo>, IdentityError>;

    /// Revokes (deletes) a `WebAuthn` credential.
    fn revoke_webauthn_credential(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
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
    fn validate_magic_link(&self, realm_id: &RealmId, token: &str)
        -> Result<UserId, IdentityError>;

    // ===== Self-service registration =====

    /// Registers a new user via the public signup flow.
    ///
    /// Enforces the realm's [`RegistrationPolicy`], applies per-email
    /// (3/hr) and per-IP (10/hr) rate limits, creates the user in
    /// [`UserStatus::PendingVerification`], sets their password, and
    /// issues an email-verification token. The plaintext token is
    /// returned exactly once so the caller can email it to the user.
    ///
    /// For enumeration resistance, a request targeting an already-registered
    /// email returns `Ok` with an unusable token rather than an error.
    fn register_user(
        &self,
        realm_id: &RealmId,
        request: &RegisterUserRequest,
    ) -> Result<RegisterUserResponse, IdentityError>;

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
        realm_id: &RealmId,
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
        realm_id: &RealmId,
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
        realm_id: &RealmId,
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
    fn verify_email_token(&self, realm_id: &RealmId, token: &str) -> Result<UserId, IdentityError>;

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
        realm_id: &RealmId,
        access_token: &str,
    ) -> Result<UserInfoResponse, IdentityError>;

    // ===== Admin API (Step 27) =====

    /// Lists users with cursor-based pagination.
    ///
    /// Returns at most `limit` users. If more exist, `Page::next_cursor`
    /// contains the cursor for the next page.
    fn list_users(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<User>, IdentityError>;

    /// Searches users by substring match on email or display name.
    ///
    /// Case-insensitive substring match. Returns up to `limit` matches.
    /// Query must be at least 2 characters; shorter queries return empty.
    fn search_users(
        &self,
        realm_id: &RealmId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<User>, IdentityError>;

    /// Lists realms with cursor-based pagination.
    ///
    /// Realms are stored under the system realm namespace, so no
    /// `realm_id` parameter is needed for scoping.
    fn list_realms(&self, cursor: Option<&str>, limit: usize)
        -> Result<Page<Realm>, IdentityError>;

    /// Lists OAuth clients with cursor-based pagination.
    fn list_clients(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OAuthClient>, IdentityError>;

    /// Retrieves a single OAuth client by ID.
    fn get_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError>;

    /// Updates an existing OAuth client's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_client(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<String, IdentityError>;

    /// Deletes an OAuth client by ID.
    fn delete_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError>;

    /// Creates multiple users in a single batch operation.
    ///
    /// Each item is processed independently — individual failures do not
    /// abort the batch. Returns a `BulkResult` for each input item.
    fn bulk_create_users(
        &self,
        realm_id: &RealmId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError>;

    /// Disables multiple users in a single batch operation.
    ///
    /// Each item is processed independently — individual failures do not
    /// abort the batch. Returns a `BulkResult` for each input item.
    fn bulk_disable_users(
        &self,
        realm_id: &RealmId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError>;

    // ===== Organizations =====

    /// Creates a new organization within a realm.
    ///
    /// Validates the slug, checks uniqueness, and persists the org record
    /// with primary and slug index entries.
    fn create_organization(
        &self,
        realm_id: &RealmId,
        request: &CreateOrganizationRequest,
    ) -> Result<Organization, IdentityError>;

    /// Retrieves an organization by ID. Returns `None` if not found.
    fn get_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Retrieves an organization by slug. Returns `None` if not found.
    fn get_organization_by_slug(
        &self,
        realm_id: &RealmId,
        slug: &str,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Updates an existing organization's fields.
    ///
    /// Only non-`None` fields in the request are applied.
    fn update_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        request: &UpdateOrganizationRequest,
    ) -> Result<Organization, IdentityError>;

    /// Deletes an organization and all associated data.
    ///
    /// Cascading deletion removes all memberships (forward + reverse indexes),
    /// invitations (primary + token + email dedup + list indexes), RBAC
    /// role assignments, slug index, and the org record. Idempotent.
    fn delete_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError>;

    /// Lists all organizations in a realm with cursor-based pagination.
    fn list_organizations(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Organization>, IdentityError>;

    /// Adds a user as a member of an organization.
    ///
    /// Creates bidirectional membership indexes (org→user and user→org).
    /// If an authorization engine is configured, writes the corresponding
    /// RBAC role assignments atomically.
    fn add_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Removes a user from an organization.
    ///
    /// Enforces last-owner protection: if the user is the sole Owner,
    /// returns `Err(LastOwner)`. Deletes both membership indexes and
    /// any RBAC role assignments.
    fn remove_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Updates a member's role within an organization.
    ///
    /// Enforces last-owner protection when downgrading from Owner.
    /// Updates both membership indexes and RBAC role assignments atomically.
    fn update_member_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        new_role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Retrieves a specific membership. Returns `None` if not a member.
    fn get_membership(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<OrganizationMembership>, IdentityError>;

    /// Lists all members of an organization with cursor-based pagination.
    fn list_members(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError>;

    /// Lists all organizations a user belongs to with cursor-based pagination.
    fn list_user_organizations(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        request: &CreateInvitationRequest,
    ) -> Result<(OrganizationInvitation, String), IdentityError>;

    /// Accepts an invitation using the plaintext token.
    ///
    /// Hashes the token, looks up the invitation, validates status and
    /// expiry, creates the membership, marks the invitation as accepted,
    /// and returns the new membership.
    fn accept_invitation(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<OrganizationMembership, IdentityError>;

    /// Revokes a pending invitation.
    fn revoke_invitation(
        &self,
        realm_id: &RealmId,
        invitation_id: &InvitationId,
    ) -> Result<(), IdentityError>;

    /// Lists invitations for an organization with cursor-based pagination.
    fn list_invitations(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationInvitation>, IdentityError>;

    // ===== OAuth Consent =====

    /// Returns the user's consent record for a specific OAuth client, if any.
    fn get_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<ConsentRecord>, IdentityError>;

    /// Lists every consent the given user has granted in this realm.
    ///
    /// Each entry is joined with the current client name and logo URL for
    /// UI rendering. Clients that no longer exist (orphaned consents) are
    /// filtered out — callers see only live consents.
    fn list_consents_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<ConsentListEntry>, IdentityError>;

    /// Upserts a consent record, merging `approved_scopes` into any
    /// pre-existing granted scopes. Returns the resulting canonical record.
    fn grant_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
        approved_scopes: &[String],
    ) -> Result<ConsentRecord, IdentityError>;

    /// Revokes the user's consent for a specific client. Returns
    /// `ConsentNotFound` if no record existed. Idempotent from the
    /// caller's perspective — the HTTP layer translates to 404.
    fn revoke_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError>;

    /// Revokes every consent granted by the user in this realm. Returns
    /// the number of records deleted.
    fn revoke_all_consents_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError>;

    /// Stores an in-flight pending authorization request awaiting consent.
    ///
    /// The ticket is an opaque, single-use identifier. The engine generates
    /// it and persists the request under `oauth:pending_auth:{ticket}` with
    /// a short TTL (typically 10 minutes). Returns the ticket.
    fn put_pending_authorization(
        &self,
        realm_id: &RealmId,
        request: &PendingAuthorizationRequest,
    ) -> Result<String, IdentityError>;

    /// Retrieves and deletes the pending authorization request for `ticket`.
    ///
    /// Single-use: the record is deleted whether or not the caller
    /// succeeds in using it. Returns `ConsentTicketNotFound` if the ticket
    /// doesn't exist or was already consumed; `ConsentTicketExpired` if
    /// past `expires_at`.
    fn take_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<PendingAuthorizationRequest, IdentityError>;

    /// Non-destructive read of a pending authorization ticket. Used by
    /// the consent page to render client name + scope list without
    /// consuming the ticket. Returns `Ok(None)` when the ticket does not
    /// exist or has been consumed. Returns `Err(ConsentTicketExpired)`
    /// when the ticket exists but is past its `expires_at` — in that
    /// case the caller should treat it as invalid (the POST path will
    /// delete the stale record on next take).
    fn get_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<Option<PendingAuthorizationRequest>, IdentityError>;

    /// Issues an authorization code for a previously-approved authorization
    /// request. Unlike [`IdentityEngine::authorize`], this variant skips
    /// the consent gating and is called only after consent has been
    /// recorded (or explicitly bypassed for a trusted client). Returns
    /// the authorization code response.
    #[allow(clippy::too_many_arguments)]
    fn issue_authorization_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &crate::core::ClientId,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
        nonce: Option<String>,
    ) -> Result<AuthorizationResponse, IdentityError>;

    // ===== External IdP federation (Phase 2: Gap #5) =====

    /// Persists (or updates) an external IdP connector for a realm.
    fn register_idp(&self, config: &federation::IdpConfig) -> Result<(), IdentityError>;

    /// Retrieves a connector by id.
    fn get_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<Option<federation::IdpConfig>, IdentityError>;

    /// Retrieves a connector by operator-assigned name (e.g., `"google"`).
    fn get_idp_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<federation::IdpConfig>, IdentityError>;

    /// Lists all connectors registered in a realm.
    fn list_idps(&self, realm_id: &RealmId) -> Result<Vec<federation::IdpConfig>, IdentityError>;

    /// Deletes a connector and all its external-identity links.
    fn delete_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError>;

    /// Persists a state bag under its `state_token` for a federation
    /// login round trip. 10-minute TTL enforced by `take_federation_state`.
    fn put_federation_state(&self, bag: &federation::StateBag) -> Result<(), IdentityError>;

    /// Retrieves and deletes a state bag (single-use). Returns
    /// `FederationInvalidState` on miss or expiry.
    fn take_federation_state(
        &self,
        realm_id: &RealmId,
        state_token: &str,
    ) -> Result<federation::StateBag, IdentityError>;

    /// Persists a pending confirm-to-link ticket.
    fn put_confirm_link_ticket(
        &self,
        ticket: &federation::ConfirmLinkTicket,
    ) -> Result<(), IdentityError>;

    /// Retrieves and deletes a confirm-to-link ticket (single-use).
    fn take_confirm_link_ticket(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<federation::ConfirmLinkTicket, IdentityError>;

    /// Attaches an external identity to a Hearth user. Idempotent on
    /// `(user, idp)` — re-linking the same tuple replaces the external
    /// sub. Returns `FederationAlreadyLinked` if the external identity
    /// is currently owned by a *different* user in the realm.
    fn link_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<(), IdentityError>;

    /// Severs a user's link to a specific connector. `FederationNotLinked`
    /// when no such link exists.
    fn unlink_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError>;

    /// Resolves an external identity to its Hearth `UserId`. `None` when
    /// no Hearth user has linked this upstream subject in this realm.
    fn find_user_by_external_identity(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<Option<UserId>, IdentityError>;

    /// Enumerates a user's linked external identities for the
    /// `/ui/account/linked-accounts` page. Returns `(idp_id, external_sub)`
    /// pairs.
    fn list_external_identities_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<(crate::core::IdpId, String)>, IdentityError>;

    // ===== SAML 2.0 =====

    /// Returns (or lazily creates) this realm's RSA signing key used for
    /// SAML metadata and `<Response>`/`<Assertion>` signing.
    ///
    /// Off the hot path: RSA keygen is slow and happens once per realm.
    fn get_or_create_saml_signing_key(
        &self,
        realm_id: &RealmId,
        issuer_cn: &str,
    ) -> Result<std::sync::Arc<crate::identity::tokens::RsaSigningKey>, IdentityError>;

    /// Registers (or updates) a SAML Service Provider in a realm.
    fn register_saml_sp(
        &self,
        realm_id: &RealmId,
        sp: &federation::saml::SamlServiceProvider,
    ) -> Result<(), IdentityError>;

    /// Resolves a registered SP by its entity ID.
    fn get_saml_sp_by_entity_id(
        &self,
        realm_id: &RealmId,
        entity_id: &str,
    ) -> Result<Option<federation::saml::SamlServiceProvider>, IdentityError>;

    /// Resolves a registered SP by operator-assigned key.
    fn get_saml_sp_by_key(
        &self,
        realm_id: &RealmId,
        sp_key: &str,
    ) -> Result<Option<federation::saml::SamlServiceProvider>, IdentityError>;

    /// Lists all registered SPs in a realm.
    fn list_saml_sps(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<federation::saml::SamlServiceProvider>, IdentityError>;

    /// Deletes a registered SP.
    fn delete_saml_sp(&self, realm_id: &RealmId, sp_key: &str) -> Result<(), IdentityError>;

    /// Persists a SAML state bag (SP-initiated login; 10-minute TTL).
    fn put_saml_state(&self, bag: &federation::saml::SamlStateBag) -> Result<(), IdentityError>;

    /// Retrieves and deletes a SAML state bag (single-use).
    fn take_saml_state(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<federation::saml::SamlStateBag, IdentityError>;

    /// Marks an assertion ID consumed for this IdP (replay guard).
    /// Returns `SamlReplay` if the ID has already been seen.
    fn mark_saml_assertion_consumed(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        assertion_id: &str,
    ) -> Result<(), IdentityError>;

    /// Records that the IdP issued an assertion to an SP for a user session.
    /// Enables SLO fan-out at logout time.
    fn record_saml_sp_session(
        &self,
        realm_id: &RealmId,
        registration: &federation::saml::SamlSessionRegistration,
    ) -> Result<(), IdentityError>;

    /// Enumerates an IdP-issued session's SP registrations for SLO.
    fn list_saml_sp_sessions(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Vec<federation::saml::SamlSessionRegistration>, IdentityError>;

    // ===== Migration / import (Phase 1 Step 30) =====

    /// Imports a realm, optionally with a caller-supplied `RealmId`.
    ///
    /// Unlike `create_realm`, this allows preserving an external system's
    /// realm/organization UUID. Returns `DuplicateRealmName` or a
    /// realm-id-conflict error if one already exists with the same id.
    fn import_realm(
        &self,
        request: &CreateRealmRequest,
        requested_id: Option<RealmId>,
    ) -> Result<Realm, IdentityError>;

    /// Imports a user with a pre-hashed credential from an external system.
    ///
    /// Preserves the source-system hash verbatim so users can authenticate
    /// with their existing passwords. New hashes produced by Hearth
    /// (via `change_password`) are always Argon2id; successful verification
    /// against the imported hash auto-upgrades it in place on first login.
    fn import_user(
        &self,
        realm_id: &RealmId,
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
        realm_id: &RealmId,
        request: &ImportClientRequest,
    ) -> Result<OAuthClient, IdentityError>;

    // ===== SCIM externalId management =====

    /// Sets the SCIM `externalId` for a user. Replaces any prior value.
    ///
    /// Returns `DuplicateScimExternalId` when the `external_id` is already
    /// associated with a different user in this realm.
    fn set_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        external_id: &str,
    ) -> Result<(), IdentityError>;

    /// Clears the SCIM `externalId` for a user, if one was set.
    /// Idempotent — no error when none is present.
    fn clear_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError>;

    /// Returns the SCIM `externalId` associated with the user, if any.
    fn get_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<String>, IdentityError>;

    /// Resolves a SCIM `externalId` to the Hearth user that owns it.
    fn find_user_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<User>, IdentityError>;

    /// Sets the SCIM `externalId` for an organization (group).
    fn set_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        external_id: &str,
    ) -> Result<(), IdentityError>;

    /// Clears the SCIM `externalId` for an organization. Idempotent.
    fn clear_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError>;

    /// Returns the SCIM `externalId` associated with the organization, if any.
    fn get_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<String>, IdentityError>;

    /// Resolves a SCIM `externalId` to the Hearth organization that owns it.
    fn find_group_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<Organization>, IdentityError>;

    /// Sweeps expired entities (authorization codes, device codes,
    /// pending authorization tickets, grant families) from storage.
    ///
    /// Called periodically by a background task. Returns deletion counts
    /// per entity type. Errors from individual sweeps are logged and
    /// counted; the function always returns stats (best-effort).
    fn sweep_expired(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::identity::cleanup::CleanupStats, IdentityError>;
}
