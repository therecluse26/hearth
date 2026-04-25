//! OIDC domain logic: OAuth 2.0 Authorization Code Flow with PKCE.
//!
//! Contains client registration, authorization code issuance/exchange,
//! PKCE validation, and OIDC Discovery document construction.
//!
//! This is domain logic — no HTTP or wire format dependencies. The protocol
//! layer will be a thin adapter that translates HTTP requests into calls to
//! these types and `IdentityEngine` methods.

use serde::{Deserialize, Serialize};

use crate::core::{ClientId, RealmId, Timestamp};

/// Client trust posture used by authz and consent evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTrustLevel {
    FirstParty,
    ThirdParty,
}

impl Default for ClientTrustLevel {
    fn default() -> Self {
        Self::FirstParty
    }
}

/// Configuration for OIDC / OAuth 2.0 operations.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Time-to-live for authorization codes, in seconds.
    ///
    /// Default: 10 minutes (600 seconds). RFC 6749 recommends a maximum
    /// lifetime of 10 minutes.
    pub authorization_code_ttl_secs: i64,

    /// The issuer URL used in discovery documents and ID tokens.
    ///
    /// Must match the `iss` claim in issued tokens.
    pub issuer: String,

    /// Whether to enforce nonce uniqueness in authorization requests.
    ///
    /// When enabled, duplicate nonces in authorization requests are
    /// rejected to prevent replay attacks.
    pub enforce_nonces: bool,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl_secs: 600, // 10 minutes
            issuer: "https://hearth.local".to_string(),
            enforce_nonces: false,
        }
    }
}

/// Request to register a new OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct RegisterClientRequest {
    /// Human-readable client name.
    pub client_name: String,
    /// Allowed redirect URIs (at least one required for public clients).
    pub redirect_uris: Vec<String>,
    /// Optional client secret for confidential clients.
    ///
    /// If provided, the secret is hashed with Argon2id and stored.
    /// The raw secret is returned once in the registration response
    /// and never stored. If `None`, this is a public client.
    pub client_secret: Option<String>,
    /// OAuth 2.0 grant types this client is allowed to use.
    ///
    /// Defaults to `["authorization_code"]` if not specified.
    pub grant_types: Vec<String>,
    /// Whether user consent is required before issuing authorization codes.
    ///
    /// Defaults to `true`. Set to `false` only for first-party / trusted
    /// clients where the user has an implicit trust relationship with the
    /// client (e.g. first-party SSO inside an enterprise realm).
    pub require_consent: bool,
    /// Optional URL to a client logo displayed on the consent screen.
    pub client_logo_url: Option<String>,
    /// Stable slug for managed clients; runtime registrations may omit it.
    pub slug: Option<String>,
    /// Authz trust posture for this client.
    pub trust_level: ClientTrustLevel,
    /// Scopes this client is allowed to request.
    pub declared_scopes: Vec<String>,
    /// Whether a realm-scoped consent can cover all org contexts.
    pub consent_spans_orgs: bool,
}

impl Default for RegisterClientRequest {
    fn default() -> Self {
        Self {
            client_name: String::new(),
            redirect_uris: Vec::new(),
            client_secret: None,
            grant_types: Vec::new(),
            require_consent: true,
            client_logo_url: None,
            slug: None,
            trust_level: ClientTrustLevel::FirstParty,
            declared_scopes: Vec::new(),
            consent_spans_orgs: false,
        }
    }
}

/// A registered OAuth 2.0 client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthClient {
    /// Unique client identifier.
    client_id: ClientId,
    /// Human-readable client name.
    client_name: String,
    /// Stable human-readable slug used by YAML refs and mapper gates.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    slug: String,
    /// Allowed redirect URIs.
    redirect_uris: Vec<String>,
    /// When the client was registered.
    created_at: Timestamp,
    /// Argon2id hash of the client secret (confidential clients only).
    ///
    /// `None` for public clients. Uses `#[serde(default)]` for backward
    /// compatibility with existing stored public clients from Phase 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret_hash: Option<String>,
    /// OAuth 2.0 grant types this client is allowed to use.
    #[serde(default)]
    grant_types: Vec<String>,
    /// Whether user consent is required before issuing authorization codes.
    ///
    /// Defaults to `true` for backward compatibility with records persisted
    /// before consent was introduced.
    #[serde(default = "default_require_consent")]
    require_consent: bool,
    /// Optional URL to a client logo displayed on the consent screen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_logo_url: Option<String>,
    /// Authz trust posture.
    #[serde(default)]
    trust_level: ClientTrustLevel,
    /// Scopes this client may request.
    #[serde(default)]
    declared_scopes: Vec<String>,
    /// Whether a realm-level consent covers all org contexts.
    #[serde(default)]
    consent_spans_orgs: bool,
}

fn default_require_consent() -> bool {
    true
}

impl OAuthClient {
    /// Creates a new OAuth client. Used internally by the identity engine.
    pub(crate) fn new(
        client_id: ClientId,
        client_name: String,
        redirect_uris: Vec<String>,
        created_at: Timestamp,
    ) -> Self {
        Self {
            client_id,
            client_name,
            slug: String::new(),
            redirect_uris,
            created_at,
            client_secret_hash: None,
            grant_types: vec!["authorization_code".to_string()],
            require_consent: true,
            client_logo_url: None,
            trust_level: ClientTrustLevel::FirstParty,
            declared_scopes: Vec::new(),
            consent_spans_orgs: false,
        }
    }

    /// Creates a new confidential OAuth client with a secret hash.
    pub(crate) fn new_confidential(
        client_id: ClientId,
        client_name: String,
        redirect_uris: Vec<String>,
        created_at: Timestamp,
        client_secret_hash: String,
        grant_types: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            client_name,
            slug: String::new(),
            redirect_uris,
            created_at,
            client_secret_hash: Some(client_secret_hash),
            grant_types,
            require_consent: true,
            client_logo_url: None,
            trust_level: ClientTrustLevel::FirstParty,
            declared_scopes: Vec::new(),
            consent_spans_orgs: false,
        }
    }

    /// Returns the client's unique identifier.
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the client's human-readable name.
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// Returns the stable client slug.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Returns the client's registered redirect URIs.
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }

    /// Returns when the client was registered.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the client secret hash, if this is a confidential client.
    pub fn client_secret_hash(&self) -> Option<&str> {
        self.client_secret_hash.as_deref()
    }

    /// Returns whether this client is confidential (has a secret).
    pub fn is_confidential(&self) -> bool {
        self.client_secret_hash.is_some()
    }

    /// Returns the grant types allowed for this client.
    pub fn grant_types(&self) -> &[String] {
        &self.grant_types
    }

    /// Sets the grant types for this client.
    pub(crate) fn set_grant_types(&mut self, grant_types: Vec<String>) {
        self.grant_types = grant_types;
    }

    /// Sets the client name. Used internally during updates.
    pub(crate) fn set_client_name(&mut self, name: String) {
        self.client_name = name;
    }

    /// Sets the redirect URIs. Used internally during updates.
    pub(crate) fn set_redirect_uris(&mut self, uris: Vec<String>) {
        self.redirect_uris = uris;
    }

    /// Sets the client secret hash. Used internally during secret regeneration.
    pub(crate) fn set_client_secret_hash(&mut self, hash: String) {
        self.client_secret_hash = Some(hash);
    }

    /// Returns whether user consent is required before this client can
    /// receive an authorization code. Trusted first-party clients opt out.
    pub fn require_consent(&self) -> bool {
        self.require_consent
    }

    /// Sets whether user consent is required. Used during admin updates.
    pub(crate) fn set_require_consent(&mut self, require: bool) {
        self.require_consent = require;
    }

    /// Returns the optional logo URL displayed on the consent screen.
    pub fn client_logo_url(&self) -> Option<&str> {
        self.client_logo_url.as_deref()
    }

    /// Returns the client trust level.
    pub fn trust_level(&self) -> ClientTrustLevel {
        self.trust_level
    }

    /// Returns the declared scopes.
    pub fn declared_scopes(&self) -> &[String] {
        &self.declared_scopes
    }

    /// Returns whether consent spans org contexts.
    pub fn consent_spans_orgs(&self) -> bool {
        self.consent_spans_orgs
    }

    /// Sets the client logo URL. `None` clears it. Used during admin updates.
    pub(crate) fn set_client_logo_url(&mut self, url: Option<String>) {
        self.client_logo_url = url;
    }

    /// Sets the stable slug.
    pub(crate) fn set_slug(&mut self, slug: String) {
        self.slug = slug;
    }

    /// Sets the trust level.
    pub(crate) fn set_trust_level(&mut self, trust_level: ClientTrustLevel) {
        self.trust_level = trust_level;
    }

    /// Sets the declared scope allowlist.
    pub(crate) fn set_declared_scopes(&mut self, declared_scopes: Vec<String>) {
        self.declared_scopes = declared_scopes;
    }

    /// Sets whether consent spans org contexts.
    pub(crate) fn set_consent_spans_orgs(&mut self, value: bool) {
        self.consent_spans_orgs = value;
    }
}

/// Request to update an existing OAuth 2.0 client.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Debug, Clone, Default)]
pub struct UpdateClientRequest {
    /// New client display name.
    pub client_name: Option<String>,
    /// New set of redirect URIs.
    pub redirect_uris: Option<Vec<String>>,
    /// New set of allowed grant types.
    pub grant_types: Option<Vec<String>>,
    /// Whether user consent is required (trusted-client bypass).
    pub require_consent: Option<bool>,
    /// Logo URL for the consent screen. Passing `Some(None)` clears it;
    /// `None` leaves it untouched.
    pub client_logo_url: Option<Option<String>>,
    /// Updated stable slug.
    pub slug: Option<String>,
    /// Updated trust posture.
    pub trust_level: Option<ClientTrustLevel>,
    /// Updated declared scope allowlist.
    pub declared_scopes: Option<Vec<String>>,
    /// Updated org-spanning consent behavior.
    pub consent_spans_orgs: Option<bool>,
}

/// The PKCE code challenge method.
///
/// Only `S256` is supported. `plain` is a security anti-pattern and
/// is deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// SHA-256 hash of the code verifier.
    S256,
}

/// Request to initiate an OAuth 2.0 authorization.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The client requesting authorization.
    pub client_id: ClientId,
    /// The redirect URI (must match a registered URI).
    pub redirect_uri: String,
    /// Requested scopes (space-delimited).
    pub scope: String,
    /// Opaque state value for CSRF protection (MUST be non-empty).
    pub state: String,
    /// Optional RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// Response type (must be "code" for authorization code flow).
    pub response_type: String,
    /// The authenticated user granting authorization.
    pub user_id: crate::core::UserId,
    /// PKCE code challenge (base64url-encoded SHA-256 hash).
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (must be S256 if present).
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// Optional nonce for replay protection.
    ///
    /// When nonce enforcement is enabled (`OidcConfig::enforce_nonces`),
    /// duplicate nonces are rejected.
    pub nonce: Option<String>,
}

/// Response from a successful authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizationResponse {
    /// The authorization code (raw, base64url-encoded).
    code: String,
    /// The state value echoed back for CSRF verification.
    state: String,
}

impl AuthorizationResponse {
    /// Creates a new authorization response.
    pub(crate) fn new(code: String, state: String) -> Self {
        Self { code, state }
    }

    /// Returns the authorization code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the state value.
    pub fn state(&self) -> &str {
        &self.state
    }
}

/// Request to exchange an authorization code for tokens.
#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    /// The client exchanging the code.
    pub client_id: ClientId,
    /// The authorization code to exchange.
    pub code: String,
    /// The redirect URI (must match the one used during authorization).
    pub redirect_uri: String,
    /// PKCE code verifier (required if `code_challenge` was sent during authorization).
    pub code_verifier: Option<String>,
}

/// Response from a successful token exchange.
#[derive(Debug, Clone)]
pub struct OidcTokenResponse {
    /// The access token (JWT).
    access_token: String,
    /// The OIDC ID token (JWT).
    id_token: String,
    /// The token type (always "Bearer").
    token_type: String,
    /// Seconds until the access token expires.
    expires_in: i64,
    /// The refresh token (JWT).
    refresh_token: String,
}

impl OidcTokenResponse {
    /// Creates a new OIDC token response.
    pub(crate) fn new(
        access_token: String,
        id_token: String,
        token_type: String,
        expires_in: i64,
        refresh_token: String,
    ) -> Self {
        Self {
            access_token,
            id_token,
            token_type,
            expires_in,
            refresh_token,
        }
    }

    /// Returns the access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the OIDC ID token.
    pub fn id_token(&self) -> &str {
        &self.id_token
    }

    /// Returns the token type (always "Bearer").
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns seconds until the access token expires.
    pub fn expires_in(&self) -> i64 {
        self.expires_in
    }

    /// Returns the refresh token.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

/// Internal storage representation of an authorization code.
///
/// Stored by SHA-256 hash of the raw code value for security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredAuthorizationCode {
    /// SHA-256 hex digest of the raw code.
    pub(crate) code_hash: String,
    /// The client that requested authorization.
    pub(crate) client_id: ClientId,
    /// The user who granted authorization.
    pub(crate) user_id: crate::core::UserId,
    /// The redirect URI used during authorization.
    pub(crate) redirect_uri: String,
    /// Requested scopes.
    pub(crate) scope: String,
    /// PKCE code challenge (if provided).
    pub(crate) code_challenge: Option<String>,
    /// PKCE code challenge method (if provided).
    pub(crate) code_challenge_method: Option<CodeChallengeMethod>,
    /// When the code was issued.
    pub(crate) created_at: Timestamp,
    /// When the code expires.
    pub(crate) expires_at: Timestamp,
    /// Whether the code has already been used.
    pub(crate) used: bool,
    /// The nonce from the authorization request (echoed in ID token per OIDC Core §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,
}

/// OIDC Discovery document (`OpenID` Connect Discovery 1.0).
///
/// Contains metadata about the `OpenID` Provider's configuration.
/// All REQUIRED fields per `OpenID` Connect Discovery 1.0 §3 are included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcDiscoveryDocument {
    /// The issuer identifier URL.
    pub issuer: String,
    /// URL of the authorization endpoint.
    pub authorization_endpoint: String,
    /// URL of the token endpoint.
    pub token_endpoint: String,
    /// URL of the JWKS endpoint.
    pub jwks_uri: String,
    /// URL of the `UserInfo` endpoint (OIDC Core §5.3).
    pub userinfo_endpoint: String,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported response modes (OIDC Core §3).
    pub response_modes_supported: Vec<String>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Claims supported by this provider.
    pub claims_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// URL of the dynamic client registration endpoint (RFC 7591).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// URL of the device authorization endpoint (RFC 8628).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// URL of the token revocation endpoint (RFC 7009).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// URL of the token introspection endpoint (RFC 7662).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
}

// ===== Client Credentials Grant =====

/// Request for the OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4).
#[derive(Debug, Clone)]
pub struct ClientCredentialsRequest {
    /// The client requesting tokens.
    pub client_id: ClientId,
    /// The client secret for authentication.
    pub client_secret: String,
    /// Requested scope (space-delimited).
    pub scope: Option<String>,
}

/// Response from a client credentials grant.
///
/// Per RFC 6749 §4.4.3, refresh tokens SHOULD NOT be included.
#[derive(Debug, Clone)]
pub struct ClientCredentialsResponse {
    /// The access token (JWT).
    access_token: String,
    /// The token type (always "Bearer").
    token_type: String,
    /// Seconds until the access token expires.
    expires_in: i64,
    /// The scope granted.
    scope: Option<String>,
}

impl ClientCredentialsResponse {
    /// Creates a new client credentials response.
    pub(crate) fn new(
        access_token: String,
        token_type: String,
        expires_in: i64,
        scope: Option<String>,
    ) -> Self {
        Self {
            access_token,
            token_type,
            expires_in,
            scope,
        }
    }

    /// Returns the access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the token type.
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Returns seconds until expiration.
    pub fn expires_in(&self) -> i64 {
        self.expires_in
    }

    /// Returns the granted scope.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

// ===== Device Authorization (RFC 8628) =====

/// Request for the Device Authorization Grant (RFC 8628).
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationRequest {
    /// The client requesting device authorization.
    pub client_id: ClientId,
    /// Requested scope (space-delimited).
    pub scope: Option<String>,
}

/// Response from a device authorization request (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,
    /// The end-user verification code (short, displayed to user).
    pub user_code: String,
    /// The end-user verification URI.
    pub verification_uri: String,
    /// Seconds until the device code expires.
    pub expires_in: i64,
    /// Minimum polling interval in seconds.
    pub interval: i64,
}

/// Status of a device authorization code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceCodeStatus {
    /// Awaiting user action.
    Pending,
    /// User approved the authorization.
    Approved {
        /// The user who approved.
        user_id: crate::core::UserId,
    },
    /// User denied the authorization.
    Denied,
    /// The device code has expired.
    Expired,
}

/// Internal storage representation of a device authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredDeviceCode {
    /// The device code (hashed in storage key).
    pub(crate) device_code_hash: String,
    /// The user code (short, displayed to user).
    pub(crate) user_code: String,
    /// The client that requested authorization.
    pub(crate) client_id: ClientId,
    /// The realm context.
    pub(crate) realm_id: RealmId,
    /// Requested scope.
    pub(crate) scope: Option<String>,
    /// Current status.
    pub(crate) status: DeviceCodeStatus,
    /// When the code was issued.
    pub(crate) created_at: Timestamp,
    /// When the code expires.
    pub(crate) expires_at: Timestamp,
    /// Minimum polling interval in seconds.
    pub(crate) interval: i64,
    /// Last time the device polled (for rate limiting).
    pub(crate) last_polled_at: Option<Timestamp>,
}

// ===== Grant Family (Refresh Token Rotation) =====

/// Tracks a grant family for refresh token rotation and theft detection.
///
/// Each authorization code exchange or client credentials grant creates
/// a family. On refresh, the hash is rotated. If a stale hash is presented,
/// the entire family (and its session) is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredGrantFamily {
    /// Unique family identifier.
    pub(crate) family_id: String,
    /// SHA-256 hex of the current valid refresh token.
    pub(crate) current_refresh_hash: String,
    /// The session bound to this family.
    pub(crate) session_id: crate::core::SessionId,
    /// The realm owning this family.
    pub(crate) realm_id: RealmId,
    /// Whether this family has been revoked (e.g., theft detection).
    pub(crate) revoked: bool,
    /// When the family was created.
    pub(crate) created_at: Timestamp,
}

// ===== Token Revocation (RFC 7009) =====

/// Request to revoke an OAuth 2.0 token (RFC 7009).
#[derive(Debug, Clone)]
pub struct TokenRevocationRequest {
    /// The token to revoke (access or refresh).
    pub token: String,
    /// Optional hint about the token type.
    pub token_type_hint: Option<String>,
}

// ===== Token Introspection (RFC 7662) =====

/// Request for token introspection (RFC 7662).
#[derive(Debug, Clone)]
pub struct TokenIntrospectionRequest {
    /// The token to introspect.
    pub token: String,
    /// Optional hint about the token type.
    pub token_type_hint: Option<String>,
}

/// Response from token introspection (RFC 7662).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    pub active: bool,
    /// The scope associated with the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Client identifier for the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Subject (user/client) of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Token expiration time (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issued-at time (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Token type (e.g., "access" or "refresh").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Issuer of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

impl IntrospectionResponse {
    /// Returns an inactive introspection response.
    ///
    /// Per RFC 7662, an inactive response MUST contain `active: false`
    /// and MAY omit all other fields.
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            exp: None,
            iat: None,
            token_type: None,
            iss: None,
            aud: None,
        }
    }
}

// ===== UserInfo (OIDC Core §5.3) =====

/// Response from the `UserInfo` endpoint (OIDC Core §5.3).
///
/// The `sub` claim is always returned. Other claims are filtered by
/// the access token's granted scopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInfoResponse {
    /// Subject — the user ID. Always present.
    pub sub: String,
    /// User's email address. Present when scope includes `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email is verified. Present when scope includes `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// User's display name. Present when scope includes `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Additional declaratively-shaped claims.
    #[serde(default, flatten)]
    pub custom: std::collections::BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_config_default_values() {
        let config = OidcConfig::default();
        assert_eq!(config.authorization_code_ttl_secs, 600);
        assert_eq!(config.issuer, "https://hearth.local");
    }

    #[test]
    fn oauth_client_serde_round_trip() {
        let client = OAuthClient::new(
            ClientId::generate(),
            "Test App".to_string(),
            vec!["https://app.example.com/callback".to_string()],
            Timestamp::from_micros(1_700_000_000_000_000),
        );

        let json = serde_json::to_string(&client).expect("serialize");
        let deserialized: OAuthClient = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(client, deserialized);
    }

    #[test]
    fn oauth_client_accessors() {
        let client_id = ClientId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let client = OAuthClient::new(
            client_id.clone(),
            "My App".to_string(),
            vec![
                "https://app.example.com/cb".to_string(),
                "https://app.example.com/alt".to_string(),
            ],
            now,
        );

        assert_eq!(client.client_id(), &client_id);
        assert_eq!(client.client_name(), "My App");
        assert_eq!(client.redirect_uris().len(), 2);
        assert_eq!(client.created_at(), now);
    }

    #[test]
    fn authorization_response_accessors() {
        let resp = AuthorizationResponse::new("code123".to_string(), "state456".to_string());
        assert_eq!(resp.code(), "code123");
        assert_eq!(resp.state(), "state456");
    }

    #[test]
    fn oidc_token_response_accessors() {
        let resp = OidcTokenResponse::new(
            "access".to_string(),
            "id".to_string(),
            "Bearer".to_string(),
            900,
            "refresh".to_string(),
        );
        assert_eq!(resp.access_token(), "access");
        assert_eq!(resp.id_token(), "id");
        assert_eq!(resp.token_type(), "Bearer");
        assert_eq!(resp.expires_in(), 900);
        assert_eq!(resp.refresh_token(), "refresh");
    }

    #[test]
    fn stored_authorization_code_serde_round_trip() {
        let code = StoredAuthorizationCode {
            code_hash: "abc123".to_string(),
            client_id: ClientId::generate(),
            user_id: crate::core::UserId::generate(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid".to_string(),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            created_at: Timestamp::from_micros(1_000_000),
            expires_at: Timestamp::from_micros(2_000_000),
            used: false,
            nonce: Some("test-nonce-abc".to_string()),
        };

        let json = serde_json::to_string(&code).expect("serialize");
        let deserialized: StoredAuthorizationCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.code_hash, code.code_hash);
        assert!(!deserialized.used);
    }

    #[test]
    fn discovery_document_serde_round_trip() {
        let doc = OidcDiscoveryDocument {
            issuer: "https://hearth.local".to_string(),
            authorization_endpoint: "https://hearth.local/authorize".to_string(),
            token_endpoint: "https://hearth.local/token".to_string(),
            jwks_uri: "https://hearth.local/.well-known/jwks.json".to_string(),
            userinfo_endpoint: "https://hearth.local/userinfo".to_string(),
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec!["query".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            scopes_supported: vec!["openid".to_string()],
            claims_supported: vec!["sub".to_string()],
            token_endpoint_auth_methods_supported: vec!["none".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
            registration_endpoint: None,
            device_authorization_endpoint: Some(
                "https://hearth.local/device/authorize".to_string(),
            ),
            revocation_endpoint: Some("https://hearth.local/revoke".to_string()),
            introspection_endpoint: Some("https://hearth.local/introspect".to_string()),
        };

        let json = serde_json::to_string(&doc).expect("serialize");
        let deserialized: OidcDiscoveryDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(doc, deserialized);
    }
}
