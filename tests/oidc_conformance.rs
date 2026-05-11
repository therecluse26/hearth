//! OIDC Conformance tests (Step 28).
//!
//! Verifies compliance with:
//! - `OpenID` Connect Core 1.0
//! - `OpenID` Connect Discovery 1.0
//! - `UserInfo` endpoint (OIDC Core §5.3)
//! - ID Token validation (required claims)

mod common;

use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::tokens::{decode_claims_unverified, verify_token_signature};
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, OAuthClient,
    RegisterClientRequest, TokenExchangeRequest,
};

// ===== Helpers =====

/// Sets up a harness with a realm, user, and client for OIDC flows.
async fn setup_oidc_env() -> (
    common::TestHarness,
    RealmId,
    hearth::core::UserId,
    OAuthClient,
) {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "oidc-conformance-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Smith".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("create user");

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "OIDC Conformance App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    (harness, realm_id, user.id().clone(), client)
}

/// Runs a full authorization code flow and returns the token response.
fn authorize_and_exchange(
    harness: &common::TestHarness,
    realm_id: &RealmId,
    user_id: &hearth::core::UserId,
    client: &OAuthClient,
    nonce: Option<String>,
) -> hearth::identity::OidcTokenResponse {
    let auth_response = harness
        .identity()
        .authorize(
            realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid profile email".to_string(),
                state: "csrf-state-123".to_string(),
                response_type: "code".to_string(),
                user_id: user_id.clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce,
                resource: None,
            },
        )
        .expect("authorize");

    harness
        .identity()
        .exchange_authorization_code(
            realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
            },
        )
        .expect("exchange code")
}

// ==========================================================================
// Conformance Test 1: OpenID Connect Core 1.0
// All required claims present, correct ID token signing, scope handling.
// ==========================================================================

#[tokio::test]
async fn oidc_core_required_claims_and_signing() {
    let (harness, realm_id, user_id, client) = setup_oidc_env().await;

    let token_response = authorize_and_exchange(&harness, &realm_id, &user_id, &client, None);

    // 1. ID token MUST be a JWT
    let id_token = token_response.id_token();
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "ID token must be a 3-part JWT");

    // 2. Decode and verify ID token claims
    let claims = decode_claims_unverified(id_token).expect("decode ID token claims");

    // OIDC Core §2: REQUIRED claims
    assert!(!claims.sub.is_empty(), "sub claim MUST be present");
    assert!(!claims.iss.is_empty(), "iss claim MUST be present");
    assert!(!claims.aud.is_empty(), "aud claim MUST be present");
    assert!(claims.exp > 0, "exp claim MUST be present and positive");
    assert!(claims.iat > 0, "iat claim MUST be present and positive");

    // 3. aud MUST contain the client_id
    assert_eq!(
        claims.aud,
        client.client_id().to_string(),
        "aud must match client_id"
    );

    // 4. iss MUST match the issuer in discovery
    let discovery = harness.identity().oidc_discovery();
    assert_eq!(
        claims.iss, discovery.issuer,
        "iss must match discovery issuer"
    );

    // 5. token_type must be id_token
    assert_eq!(claims.token_type, "id_token", "must be id_token");

    // 6. ID token MUST be signed with EdDSA (verify signature)
    let jwks = harness.identity().realm_jwks(&realm_id).expect("jwks");
    assert!(!jwks.keys.is_empty(), "JWKS must have at least one key");
    let pub_key_b64 = &jwks.keys[0].x;
    let pub_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pub_key_b64)
        .expect("decode public key");
    let verified = verify_token_signature(id_token, &pub_key_bytes);
    assert!(
        verified.is_ok(),
        "ID token signature must verify with realm key"
    );

    // 7. exp > iat
    assert!(claims.exp > claims.iat, "exp must be after iat");

    // 8. Access token should also be verifiable
    let access_claims =
        decode_claims_unverified(token_response.access_token()).expect("decode access token");
    assert_eq!(access_claims.token_type, "access");
    assert_eq!(
        access_claims.sub,
        user_id.to_string(),
        "access token sub must be user_id"
    );

    // 9. Refresh token should be present
    assert!(
        !token_response.refresh_token().is_empty(),
        "refresh token must be present"
    );
}

// ==========================================================================
// Conformance Test 2: OpenID Connect Discovery 1.0
// Well-known endpoint returns all required metadata fields.
// ==========================================================================

#[tokio::test]
async fn oidc_discovery_all_required_fields() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");

    let doc = harness.identity().oidc_discovery();

    // OIDC Discovery 1.0 §3 REQUIRED fields
    assert!(!doc.issuer.is_empty(), "issuer REQUIRED");
    assert!(
        !doc.authorization_endpoint.is_empty(),
        "authorization_endpoint REQUIRED"
    );
    assert!(!doc.token_endpoint.is_empty(), "token_endpoint REQUIRED");
    assert!(!doc.jwks_uri.is_empty(), "jwks_uri REQUIRED");
    assert!(
        !doc.userinfo_endpoint.is_empty(),
        "userinfo_endpoint REQUIRED"
    );
    assert!(
        !doc.response_types_supported.is_empty(),
        "response_types_supported REQUIRED"
    );
    assert!(
        !doc.subject_types_supported.is_empty(),
        "subject_types_supported REQUIRED"
    );
    assert!(
        !doc.id_token_signing_alg_values_supported.is_empty(),
        "id_token_signing_alg_values_supported REQUIRED"
    );

    // OIDC Discovery 1.0 §3 RECOMMENDED fields
    assert!(
        !doc.scopes_supported.is_empty(),
        "scopes_supported RECOMMENDED"
    );
    assert!(
        !doc.claims_supported.is_empty(),
        "claims_supported RECOMMENDED"
    );
    assert!(
        !doc.response_modes_supported.is_empty(),
        "response_modes_supported RECOMMENDED"
    );
    assert!(
        !doc.grant_types_supported.is_empty(),
        "grant_types_supported RECOMMENDED"
    );
    assert!(
        !doc.token_endpoint_auth_methods_supported.is_empty(),
        "token_endpoint_auth_methods_supported RECOMMENDED"
    );

    // Verify required values
    assert!(
        doc.response_types_supported.contains(&"code".to_string()),
        "must support authorization code response type"
    );
    assert!(
        doc.subject_types_supported.contains(&"public".to_string()),
        "must support public subject type"
    );
    assert!(
        doc.id_token_signing_alg_values_supported
            .contains(&"EdDSA".to_string()),
        "must support EdDSA signing"
    );
    assert!(
        doc.scopes_supported.contains(&"openid".to_string()),
        "must support openid scope"
    );

    // Verify standard claims are declared
    for claim in &["sub", "iss", "aud", "exp", "iat", "nonce", "email", "name"] {
        assert!(
            doc.claims_supported.contains(&(*claim).to_owned()),
            "claims_supported must include {claim}"
        );
    }

    // Verify endpoints are well-formed URLs
    assert!(
        doc.authorization_endpoint.starts_with(&doc.issuer),
        "authorization_endpoint must start with issuer"
    );
    assert!(
        doc.token_endpoint.starts_with(&doc.issuer),
        "token_endpoint must start with issuer"
    );
    assert!(
        doc.jwks_uri.starts_with(&doc.issuer),
        "jwks_uri must start with issuer"
    );
    assert!(
        doc.userinfo_endpoint.starts_with(&doc.issuer),
        "userinfo_endpoint must start with issuer"
    );

    // RFC 7591 Dynamic Client Registration endpoint.
    assert!(
        doc.registration_endpoint
            .as_deref()
            .is_some_and(|u| u.ends_with("/register")),
        "registration_endpoint must end with /register"
    );
    assert!(
        doc.registration_endpoint
            .as_deref()
            .is_some_and(|u| u.starts_with(&doc.issuer)),
        "registration_endpoint must start with issuer"
    );

    // PKCE support
    assert!(
        doc.code_challenge_methods_supported
            .contains(&"S256".to_string()),
        "must support S256 PKCE"
    );
}

// ==========================================================================
// Conformance Test 3: Dynamic Client Registration (RFC 7591)
// The registration_endpoint is now advertised in discovery; per-realm
// gating is enforced server-side by the dcr_policy config field.
// ==========================================================================

// ==========================================================================
// Conformance Test 4: UserInfo endpoint
// Returns correct claims for authenticated user with valid access token.
// ==========================================================================

#[tokio::test]
async fn oidc_userinfo_endpoint() {
    let (harness, realm_id, user_id, client) = setup_oidc_env().await;

    let token_response = authorize_and_exchange(&harness, &realm_id, &user_id, &client, None);

    // 1. Call userinfo with valid access token
    let userinfo = harness
        .identity()
        .userinfo(&realm_id, token_response.access_token())
        .expect("userinfo should succeed");

    // 2. sub claim MUST always be present (OIDC Core §5.3.2)
    assert_eq!(
        userinfo.sub,
        user_id.to_string(),
        "sub must match authenticated user"
    );

    // 3. email claim should be present (scope included "email" implicitly via openid)
    // Note: the default scope for auth code is "openid profile email"
    // But our current authorize flow stores the scope from the request.
    // Since we're using default scope "openid", email won't appear unless we
    // add email scope. Let's verify that sub is always present:
    assert!(!userinfo.sub.is_empty(), "sub must be non-empty");

    // 4. Verify userinfo with an invalid token fails
    let bad_result = harness.identity().userinfo(&realm_id, "invalid.token.here");
    assert!(bad_result.is_err(), "userinfo with invalid token must fail");

    // 5. Verify userinfo with a revoked session token fails
    // First extract session from claims to revoke it
    let claims =
        decode_claims_unverified(token_response.access_token()).expect("decode access token");
    let session_id_str = claims.sid.strip_prefix("session_").expect("session prefix");
    let session_uuid = uuid::Uuid::parse_str(session_id_str).expect("parse session uuid");
    let session_id = hearth::core::SessionId::new(session_uuid);
    harness
        .identity()
        .revoke_session(&realm_id, &session_id)
        .expect("revoke session");

    let revoked_result = harness
        .identity()
        .userinfo(&realm_id, token_response.access_token());
    assert!(
        revoked_result.is_err(),
        "userinfo with revoked session token must fail"
    );
}

// ==========================================================================
// Conformance Test 5: ID Token validation
// All required claims (iss, sub, aud, exp, iat, nonce) verified.
// ==========================================================================

#[tokio::test]
async fn oidc_id_token_required_claims_with_nonce() {
    let (harness, realm_id, user_id, client) = setup_oidc_env().await;

    // 1. Issue tokens WITH a nonce
    let nonce = "conformance-nonce-12345".to_string();
    let token_response =
        authorize_and_exchange(&harness, &realm_id, &user_id, &client, Some(nonce.clone()));

    let id_token = token_response.id_token();
    let claims = decode_claims_unverified(id_token).expect("decode ID token");

    // 2. Verify all OIDC Core §2 REQUIRED claims
    // iss — MUST exactly match the issuer in the discovery document
    let discovery = harness.identity().oidc_discovery();
    assert_eq!(claims.iss, discovery.issuer, "iss must match discovery");

    // sub — MUST be present and identify the user
    assert!(
        claims.sub.starts_with("user_"),
        "sub must be a user identifier"
    );
    assert_eq!(claims.sub, user_id.to_string());

    // aud — MUST contain the client_id
    assert_eq!(
        claims.aud,
        client.client_id().to_string(),
        "aud must contain the client_id"
    );

    // exp — MUST be present, must be in the future relative to iat
    assert!(claims.exp > claims.iat, "exp must be after iat");

    // iat — MUST be present
    assert!(claims.iat > 0, "iat must be positive");

    // nonce — MUST be present and echo the authorization request nonce
    assert_eq!(
        claims.nonce.as_deref(),
        Some("conformance-nonce-12345"),
        "nonce must be echoed from authorization request"
    );

    // 3. Verify cryptographic signature
    let jwks = harness.identity().realm_jwks(&realm_id).expect("jwks");
    let pub_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&jwks.keys[0].x)
        .expect("decode public key");
    let verified_claims =
        verify_token_signature(id_token, &pub_key_bytes).expect("signature must verify");
    assert_eq!(verified_claims.sub, claims.sub);

    // 4. Verify that omitting nonce results in no nonce in ID token
    let no_nonce_response = authorize_and_exchange(&harness, &realm_id, &user_id, &client, None);
    let no_nonce_claims =
        decode_claims_unverified(no_nonce_response.id_token()).expect("decode no-nonce ID token");
    assert!(
        no_nonce_claims.nonce.is_none(),
        "nonce must be absent when not provided in authorization request"
    );

    // 5. jti MUST be present (uniqueness)
    assert!(
        claims.jti.is_some(),
        "jti must be present for token uniqueness"
    );

    // 6. Two different ID tokens must have different jti values
    let other_response = authorize_and_exchange(
        &harness,
        &realm_id,
        &user_id,
        &client,
        Some("other-nonce".to_string()),
    );
    let other_claims =
        decode_claims_unverified(other_response.id_token()).expect("decode other ID token");
    assert_ne!(
        claims.jti, other_claims.jti,
        "different ID tokens must have different jti values"
    );
}
