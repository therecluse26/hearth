//! Integration tests for OIDC / OAuth 2.0 Authorization Code Flow.
//!
//! Black box tests via `TestHarness` — exercises OIDC operations
//! through the public `IdentityEngine` trait.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::TenantId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateUserRequest, RegisterClientRequest,
    TokenExchangeRequest, User,
};
use ring::rand::SecureRandom;

/// Helper: creates a user with a unique email.
fn create_user(harness: &common::TestHarness, tenant: &TenantId) -> User {
    harness
        .identity()
        .create_user(
            tenant,
            &CreateUserRequest {
                email: format!("oidc-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "OIDC Test User".to_string(),
            },
        )
        .expect("create user")
}

// ===== Scenario: Full auth code flow round-trip via embedded API =====

#[tokio::test]
async fn oidc_authorization_code_flow_roundtrip() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();
    let user = create_user(&harness, &tenant);

    // 1. Register an OAuth client
    let client = harness
        .identity()
        .register_client(
            &tenant,
            &RegisterClientRequest {
                client_name: "Integration Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
            },
        )
        .expect("register client");

    assert_eq!(client.client_name(), "Integration Test App");
    assert_eq!(client.redirect_uris().len(), 1);

    // 2. Authorize: generate authorization code
    let auth_response = harness
        .identity()
        .authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "integration-test-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
            },
        )
        .expect("authorize");

    assert!(!auth_response.code().is_empty());
    assert_eq!(auth_response.state(), "integration-test-state");

    // 3. Exchange: trade auth code for tokens
    let token_response = harness
        .identity()
        .exchange_authorization_code(
            &tenant,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
            },
        )
        .expect("exchange code");

    // 4. Verify tokens
    assert!(!token_response.access_token().is_empty());
    assert!(!token_response.id_token().is_empty());
    assert!(!token_response.refresh_token().is_empty());
    assert_eq!(token_response.token_type(), "Bearer");
    assert!(token_response.expires_in() > 0);

    // 5. Access token should be valid via session lookup
    let claims = harness
        .identity()
        .validate_token(&tenant, token_response.access_token())
        .expect("validate access token");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.tid, tenant.to_string());

    // 6. ID token should contain correct user info
    let id_claims = hearth::identity::decode_claims_unverified(token_response.id_token())
        .expect("decode ID token");
    assert_eq!(id_claims.sub, user.id().to_string());
    assert_eq!(id_claims.token_type, "id_token");

    // 7. Access token should be verifiable via JWKS
    let jwks = harness.identity().jwks();
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(&jwks.keys[0].x)
        .expect("decode JWKS public key");
    let verified_claims =
        hearth::identity::verify_token_signature(token_response.access_token(), &pub_bytes)
            .expect("cryptographic verification");
    assert_eq!(verified_claims.sub, user.id().to_string());

    // 8. Discovery document should have valid endpoints
    let doc = harness.identity().oidc_discovery();
    assert!(!doc.issuer.is_empty());
    assert!(!doc.authorization_endpoint.is_empty());
    assert!(!doc.token_endpoint.is_empty());
    assert!(!doc.jwks_uri.is_empty());
}

// ===== Scenario: PKCE (S256) flow =====

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn oidc_pkce_s256_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();
    let user = create_user(&harness, &tenant);

    let client = harness
        .identity()
        .register_client(
            &tenant,
            &RegisterClientRequest {
                client_name: "PKCE Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
            },
        )
        .expect("register client");

    // Generate a code verifier (random 32 bytes, base64url-encoded)
    let rng = ring::rand::SystemRandom::new();
    let mut verifier_bytes = [0u8; 32];
    rng.fill(&mut verifier_bytes).expect("fill random bytes");
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    // Compute S256 code challenge: BASE64URL(SHA256(code_verifier))
    let digest = ring::digest::digest(&ring::digest::SHA256, code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest.as_ref());

    // 1. Authorize with PKCE code challenge
    let auth_response = harness
        .identity()
        .authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "pkce-test-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(code_challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
            },
        )
        .expect("authorize with PKCE");

    // 2. Exchange WITHOUT verifier should fail
    let no_verifier_result = harness.identity().exchange_authorization_code(
        &tenant,
        &TokenExchangeRequest {
            client_id: client.client_id().clone(),
            code: auth_response.code().to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            code_verifier: None,
        },
    );
    assert!(
        no_verifier_result.is_err(),
        "exchange without verifier must fail when PKCE was used"
    );

    // The code is now used, so we need a new one
    let auth_response2 = harness
        .identity()
        .authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "pkce-test-state-2".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(URL_SAFE_NO_PAD.encode(digest.as_ref())),
                code_challenge_method: Some(CodeChallengeMethod::S256),
            },
        )
        .expect("authorize with PKCE again");

    // 3. Exchange with WRONG verifier should fail
    let wrong_verifier_result = harness.identity().exchange_authorization_code(
        &tenant,
        &TokenExchangeRequest {
            client_id: client.client_id().clone(),
            code: auth_response2.code().to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            code_verifier: Some("wrong-verifier-value".to_string()),
        },
    );
    assert!(
        wrong_verifier_result.is_err(),
        "exchange with wrong verifier must fail"
    );

    // New code needed since previous was consumed by failed PKCE
    let auth_response3 = harness
        .identity()
        .authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "pkce-test-state-3".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(URL_SAFE_NO_PAD.encode(digest.as_ref())),
                code_challenge_method: Some(CodeChallengeMethod::S256),
            },
        )
        .expect("authorize with PKCE third time");

    // 4. Exchange with CORRECT verifier should succeed
    let token_response = harness
        .identity()
        .exchange_authorization_code(
            &tenant,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response3.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(code_verifier),
            },
        )
        .expect("exchange with correct verifier");

    // Verify tokens are valid
    assert!(!token_response.access_token().is_empty());
    assert!(!token_response.id_token().is_empty());
    assert_eq!(token_response.token_type(), "Bearer");

    let claims = harness
        .identity()
        .validate_token(&tenant, token_response.access_token())
        .expect("validate access token");
    assert_eq!(claims.sub, user.id().to_string());
}
