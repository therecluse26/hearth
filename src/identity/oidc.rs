//! OIDC domain logic: OAuth 2.0 Authorization Code Flow with PKCE.
//!
//! Contains client registration, authorization code issuance/exchange,
//! PKCE validation, and OIDC Discovery document construction.
//!
//! This is domain logic — no HTTP or wire format dependencies. The protocol
//! layer will be a thin adapter that translates HTTP requests into calls to
//! these types and `IdentityEngine` methods.

use serde::{Deserialize, Serialize};

use crate::core::{ClientId, Timestamp};

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
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl_secs: 600, // 10 minutes
            issuer: "https://hearth.local".to_string(),
        }
    }
}

/// Request to register a new OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct RegisterClientRequest {
    /// Human-readable client name.
    pub client_name: String,
    /// Allowed redirect URIs (at least one required).
    pub redirect_uris: Vec<String>,
}

/// A registered OAuth 2.0 client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthClient {
    /// Unique client identifier.
    client_id: ClientId,
    /// Human-readable client name.
    client_name: String,
    /// Allowed redirect URIs.
    redirect_uris: Vec<String>,
    /// When the client was registered.
    created_at: Timestamp,
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
            redirect_uris,
            created_at,
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

    /// Returns the client's registered redirect URIs.
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }

    /// Returns when the client was registered.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }
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
    /// Response type (must be "code" for authorization code flow).
    pub response_type: String,
    /// The authenticated user granting authorization.
    pub user_id: crate::core::UserId,
    /// PKCE code challenge (base64url-encoded SHA-256 hash).
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (must be S256 if present).
    pub code_challenge_method: Option<CodeChallengeMethod>,
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
}

/// OIDC Discovery document (`OpenID` Connect Discovery 1.0).
///
/// Contains metadata about the `OpenID` Provider's configuration.
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
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
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
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            scopes_supported: vec!["openid".to_string()],
            token_endpoint_auth_methods_supported: vec!["none".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
        };

        let json = serde_json::to_string(&doc).expect("serialize");
        let deserialized: OidcDiscoveryDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(doc, deserialized);
    }
}
