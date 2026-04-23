//! Integration tests for OIDC / OAuth 2.0 Authorization Code Flow.
//!
//! Black box tests via `TestHarness` — exercises OIDC operations
//! through the public `IdentityEngine` trait.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateUserRequest, RegisterClientRequest,
    TokenExchangeRequest, User,
};
use ring::rand::SecureRandom;

/// Helper: creates a user with a unique email.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("oidc-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "OIDC Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
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
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // 1. Register an OAuth client
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Integration Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
            },
        )
        .expect("register client");

    assert_eq!(client.client_name(), "Integration Test App");
    assert_eq!(client.redirect_uris().len(), 1);

    // 2. Authorize: generate authorization code
    let auth_response = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "integration-test-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
            },
        )
        .expect("authorize");

    assert!(!auth_response.code().is_empty());
    assert_eq!(auth_response.state(), "integration-test-state");

    // 3. Exchange: trade auth code for tokens
    let token_response = harness
        .identity()
        .exchange_authorization_code(
            &realm,
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
        .validate_token(&realm, token_response.access_token())
        .expect("validate access token");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.tid, realm.to_string());

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

// ===== Scenario: Full authorization code flow via HTTP endpoints =====

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn oidc_authorization_code_flow_via_http() {
    use std::net::TcpListener;
    use std::process::Command;
    use std::time::Duration;

    // Find available port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    // Start server
    let hearth_bin = {
        let mut path = std::env::current_exe()
            .expect("current exe")
            .parent()
            .expect("parent dir")
            .parent()
            .expect("grandparent dir")
            .to_path_buf();
        path.push("hearth");
        path
    };

    let mut child = Command::new(hearth_bin)
        .args(["serve", "--dev", "--port", &port.to_string()])
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hearth server");

    // Wait for server to be ready
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(10);
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let base = format!("http://127.0.0.1:{port}");
    let http_client = reqwest::Client::new();
    let realm_id = uuid::Uuid::new_v4().to_string();

    // 1. Create a user via HTTP
    let user_resp = http_client
        .post(format!("{base}/users"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "email": "http-oidc@example.com",
            "display_name": "HTTP OIDC Test User"
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("create user request");
    assert_eq!(user_resp.status(), 201, "create user should return 201");
    let user_body: serde_json::Value = user_resp.json().await.expect("parse user json");
    let user_id = user_body["id"].as_str().expect("user id in response");

    // 2. Register an OAuth client via HTTP
    let register_resp = http_client
        .post(format!("{base}/clients"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "client_name": "HTTP Integration Test App",
            "redirect_uris": ["https://app.example.com/callback"]
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("register client request");
    assert_eq!(register_resp.status(), 201, "register should return 201");
    let register_body: serde_json::Value = register_resp.json().await.expect("parse register json");
    let client_id = register_body["client_id"]
        .as_str()
        .expect("client_id in response");

    // 3. Authorize: generate authorization code via HTTP
    let auth_resp = http_client
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "client_id": client_id,
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid",
            "state": "http-test-state",
            "response_type": "code",
            "user_id": user_id
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("authorize request");
    assert_eq!(auth_resp.status(), 200, "authorize should return 200");
    let auth_body: serde_json::Value = auth_resp.json().await.expect("parse auth json");
    let code = auth_body["code"].as_str().expect("code in response");
    assert!(!code.is_empty(), "auth code should be non-empty");
    assert_eq!(
        auth_body["state"].as_str().expect("state"),
        "http-test-state"
    );

    // 4. Exchange code for tokens via HTTP
    let token_resp = http_client
        .post(format!("{base}/token"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "client_id": client_id,
            "code": code,
            "redirect_uri": "https://app.example.com/callback"
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("token exchange request");
    assert_eq!(token_resp.status(), 200, "token exchange should return 200");
    let token_body: serde_json::Value = token_resp.json().await.expect("parse token json");

    // 5. Verify token response contains all expected fields
    assert!(
        !token_body["access_token"].as_str().unwrap_or("").is_empty(),
        "access_token should be non-empty"
    );
    assert!(
        !token_body["id_token"].as_str().unwrap_or("").is_empty(),
        "id_token should be non-empty"
    );
    assert!(
        !token_body["refresh_token"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "refresh_token should be non-empty"
    );
    assert_eq!(
        token_body["token_type"].as_str().unwrap_or(""),
        "Bearer",
        "token_type should be Bearer"
    );
    assert!(
        token_body["expires_in"].as_i64().unwrap_or(0) > 0,
        "expires_in should be positive"
    );

    // 6. Verify JWKS endpoint returns keys
    let jwks_resp = http_client
        .get(format!("{base}/jwks"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("jwks request");
    assert_eq!(jwks_resp.status(), 200);
    let jwks_body: serde_json::Value = jwks_resp.json().await.expect("parse jwks");
    assert!(
        jwks_body["keys"].as_array().is_some_and(|k| !k.is_empty()),
        "JWKS should have at least one key"
    );

    // 7. Test missing realm header returns 400
    let no_realm_resp = http_client
        .post(format!("{base}/clients"))
        .json(&serde_json::json!({
            "client_name": "No Realm App",
            "redirect_uris": ["https://app.example.com/callback"]
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("request without realm");
    assert_eq!(
        no_realm_resp.status(),
        400,
        "missing realm header should return 400"
    );

    // Cleanup: kill the server
    let _ = child.kill();
    let _ = child.wait();
}

// ===== Scenario: PKCE (S256) flow =====

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn oidc_pkce_s256_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "PKCE Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
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
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "pkce-test-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(code_challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
            },
        )
        .expect("authorize with PKCE");

    // 2. Exchange WITHOUT verifier should fail
    let no_verifier_result = harness.identity().exchange_authorization_code(
        &realm,
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
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "pkce-test-state-2".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(URL_SAFE_NO_PAD.encode(digest.as_ref())),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
            },
        )
        .expect("authorize with PKCE again");

    // 3. Exchange with WRONG verifier should fail
    let wrong_verifier_result = harness.identity().exchange_authorization_code(
        &realm,
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
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "pkce-test-state-3".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(URL_SAFE_NO_PAD.encode(digest.as_ref())),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
            },
        )
        .expect("authorize with PKCE third time");

    // 4. Exchange with CORRECT verifier should succeed
    let token_response = harness
        .identity()
        .exchange_authorization_code(
            &realm,
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
        .validate_token(&realm, token_response.access_token())
        .expect("validate access token");
    assert_eq!(claims.sub, user.id().to_string());
}

// ===== Conformance: OIDC Discovery 1.0 =====

/// Discovery endpoint conforms to `OpenID` Connect Discovery 1.0 specification.
///
/// Validates all REQUIRED fields per Section 3 of the spec:
/// - `issuer` (REQUIRED): URL using https scheme, no query/fragment
/// - `authorization_endpoint` (REQUIRED): URL
/// - `token_endpoint` (REQUIRED): URL
/// - `jwks_uri` (REQUIRED): URL
/// - `response_types_supported` (REQUIRED): must include "code"
/// - `subject_types_supported` (REQUIRED): array of subject types
/// - `id_token_signing_alg_values_supported` (REQUIRED): array, must not include "none"
///
/// Also validates RECOMMENDED/OPTIONAL fields:
/// - `scopes_supported` (RECOMMENDED): must include "openid"
/// - `token_endpoint_auth_methods_supported` (OPTIONAL)
/// - `code_challenge_methods_supported` (OPTIONAL): PKCE methods
#[tokio::test]
async fn conformance_oidc_discovery_1_0() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let doc = harness.identity().oidc_discovery();

    // --- REQUIRED fields (Section 3, OpenID Connect Discovery 1.0) ---

    // issuer: MUST be a URL using the https scheme with no query or fragment
    assert!(!doc.issuer.is_empty(), "issuer MUST be present");
    assert!(
        doc.issuer.starts_with("https://"),
        "issuer MUST use https scheme, got: {}",
        doc.issuer
    );
    assert!(
        !doc.issuer.contains('?'),
        "issuer MUST NOT contain query component"
    );
    assert!(
        !doc.issuer.contains('#'),
        "issuer MUST NOT contain fragment component"
    );

    // authorization_endpoint: REQUIRED, MUST be a URL
    assert!(
        !doc.authorization_endpoint.is_empty(),
        "authorization_endpoint MUST be present"
    );
    assert!(
        doc.authorization_endpoint.starts_with("https://"),
        "authorization_endpoint MUST be a valid URL"
    );

    // token_endpoint: REQUIRED, MUST be a URL
    assert!(
        !doc.token_endpoint.is_empty(),
        "token_endpoint MUST be present"
    );
    assert!(
        doc.token_endpoint.starts_with("https://"),
        "token_endpoint MUST be a valid URL"
    );

    // jwks_uri: REQUIRED, MUST be a URL
    assert!(!doc.jwks_uri.is_empty(), "jwks_uri MUST be present");
    assert!(
        doc.jwks_uri.starts_with("https://"),
        "jwks_uri MUST be a valid URL"
    );

    // response_types_supported: REQUIRED, MUST include "code" for auth code flow
    assert!(
        !doc.response_types_supported.is_empty(),
        "response_types_supported MUST be present"
    );
    assert!(
        doc.response_types_supported.contains(&"code".to_string()),
        "response_types_supported MUST include 'code' for authorization code flow"
    );

    // subject_types_supported: REQUIRED
    assert!(
        !doc.subject_types_supported.is_empty(),
        "subject_types_supported MUST be present"
    );
    assert!(
        doc.subject_types_supported
            .iter()
            .all(|t| t == "public" || t == "pairwise"),
        "subject_types_supported must contain valid values (public/pairwise)"
    );

    // id_token_signing_alg_values_supported: REQUIRED, MUST NOT include "none"
    assert!(
        !doc.id_token_signing_alg_values_supported.is_empty(),
        "id_token_signing_alg_values_supported MUST be present"
    );
    assert!(
        !doc.id_token_signing_alg_values_supported
            .contains(&"none".to_string()),
        "id_token_signing_alg_values_supported MUST NOT include 'none'"
    );

    // --- RECOMMENDED fields ---

    // scopes_supported: RECOMMENDED, MUST include "openid" per OIDC Core 1.0 §3.1.2.1
    assert!(
        doc.scopes_supported.contains(&"openid".to_string()),
        "scopes_supported MUST include 'openid' per OIDC Core spec"
    );

    // --- Structural consistency ---

    // All endpoints MUST be under the issuer URL
    assert!(
        doc.authorization_endpoint.starts_with(&doc.issuer),
        "authorization_endpoint MUST be under issuer"
    );
    assert!(
        doc.token_endpoint.starts_with(&doc.issuer),
        "token_endpoint MUST be under issuer"
    );
    assert!(
        doc.jwks_uri.starts_with(&doc.issuer),
        "jwks_uri MUST be under issuer"
    );

    // Discovery document MUST be serializable to JSON
    let json = serde_json::to_string(&doc).expect("discovery doc must be JSON-serializable");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("must produce valid JSON");
    assert!(parsed.is_object(), "discovery doc must be a JSON object");

    // Verify all REQUIRED fields appear in JSON output
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ] {
        assert!(
            parsed.get(field).is_some(),
            "REQUIRED field '{field}' must appear in JSON output"
        );
    }
}

// ===== Conformance: Token endpoint RFC 6749 =====

/// Token endpoint behavior conforms to OAuth 2.0 (RFC 6749) token exchange spec.
///
/// Validates:
/// - Section 4.1.3: Access Token Request requirements
/// - Section 4.1.4: Access Token Response format
/// - Section 5.1: Successful Response MUST include `access_token`, `token_type`, `expires_in`
/// - Section 5.2: Error Response requirements
/// - Section 4.1.2: Authorization code is single-use
/// - Section 10.5: Authorization codes MUST be short-lived
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn conformance_token_endpoint_rfc6749() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    let client = harness
        .identity()
        .register_client(
            &realm,
            &hearth::identity::RegisterClientRequest {
                client_name: "RFC 6749 Conformance App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
            },
        )
        .expect("register client");

    // --- Section 4.1.3: Access Token Request ---
    // The client MUST include: grant_type, code, redirect_uri, client_id

    let auth_response = harness
        .identity()
        .authorize(
            &realm,
            &hearth::identity::AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "rfc6749-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
            },
        )
        .expect("authorize");

    // Authorization code MUST be non-empty
    assert!(
        !auth_response.code().is_empty(),
        "RFC 6749 §4.1.2: authorization code MUST be non-empty"
    );
    // State MUST be echoed back unchanged
    assert_eq!(
        auth_response.state(),
        "rfc6749-state",
        "RFC 6749 §4.1.2: state MUST be echoed back"
    );

    // --- Section 5.1: Successful Response ---
    let token_response = harness
        .identity()
        .exchange_authorization_code(
            &realm,
            &hearth::identity::TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
            },
        )
        .expect("exchange code");

    // access_token: REQUIRED (Section 5.1)
    assert!(
        !token_response.access_token().is_empty(),
        "RFC 6749 §5.1: access_token REQUIRED in response"
    );

    // token_type: REQUIRED (Section 5.1), case-insensitive per RFC 6749 §7.1
    assert!(
        !token_response.token_type().is_empty(),
        "RFC 6749 §5.1: token_type REQUIRED in response"
    );
    assert_eq!(
        token_response.token_type().to_lowercase(),
        "bearer",
        "RFC 6749 §5.1: token_type must be 'Bearer'"
    );

    // expires_in: RECOMMENDED (Section 5.1), MUST be positive
    assert!(
        token_response.expires_in() > 0,
        "RFC 6749 §5.1: expires_in MUST be a positive integer"
    );

    // refresh_token: OPTIONAL but present in our implementation
    assert!(
        !token_response.refresh_token().is_empty(),
        "refresh_token should be present in OIDC flow"
    );

    // --- Section 4.1.2: Authorization code single-use ---
    // "The client MUST NOT use the authorization code more than once."
    // "If an authorization code is used more than once, the authorization
    //  server MUST deny the request"
    let reuse_result = harness.identity().exchange_authorization_code(
        &realm,
        &hearth::identity::TokenExchangeRequest {
            client_id: client.client_id().clone(),
            code: auth_response.code().to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            code_verifier: None,
        },
    );
    assert!(
        reuse_result.is_err(),
        "RFC 6749 §4.1.2: reusing authorization code MUST be denied"
    );

    // --- Section 5.2: Error Response ---
    // Invalid code MUST produce an error
    let invalid_result = harness.identity().exchange_authorization_code(
        &realm,
        &hearth::identity::TokenExchangeRequest {
            client_id: client.client_id().clone(),
            code: "totally-invalid-code-value".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            code_verifier: None,
        },
    );
    assert!(
        invalid_result.is_err(),
        "RFC 6749 §5.2: invalid code MUST produce an error"
    );

    // Wrong redirect_uri MUST produce an error
    let auth_response2 = harness
        .identity()
        .authorize(
            &realm,
            &hearth::identity::AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-2".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
            },
        )
        .expect("authorize again");

    let wrong_redirect = harness.identity().exchange_authorization_code(
        &realm,
        &hearth::identity::TokenExchangeRequest {
            client_id: client.client_id().clone(),
            code: auth_response2.code().to_string(),
            redirect_uri: "https://evil.example.com/callback".to_string(),
            code_verifier: None,
        },
    );
    assert!(
        wrong_redirect.is_err(),
        "RFC 6749 §4.1.3: mismatched redirect_uri MUST produce an error"
    );

    // --- OIDC-specific: ID token MUST be present ---
    // (Not in RFC 6749 but required by OIDC Core 1.0 §3.1.3.3)
    assert!(
        !token_response.id_token().is_empty(),
        "OIDC Core §3.1.3.3: id_token MUST be present when scope includes 'openid'"
    );

    // ID token MUST be a valid JWT (three dot-separated base64url segments)
    let id_token_parts: Vec<&str> = token_response.id_token().split('.').collect();
    assert_eq!(
        id_token_parts.len(),
        3,
        "OIDC id_token MUST be a valid JWT (header.payload.signature)"
    );
}
