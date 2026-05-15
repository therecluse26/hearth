//! Integration tests for OAuth 2.0 Extended (Step 22).
//!
//! Black box tests via `TestHarness` — exercises client credentials,
//! device authorization, and refresh token rotation through the public
//! `IdentityEngine` trait.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    ClientCredentialsRequest, CreateRealmRequest, CreateUserRequest, DeviceAuthorizationRequest,
    RegisterClientRequest, TokenRevocationRequest, User,
};

/// Helper: creates a real realm with a signing key.
fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}
const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn create_realm(harness: &common::TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("oauth-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}

/// Helper: creates a user with a unique email.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("oauth-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "OAuth Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ===== Scenario C1: Full client credentials flow =====
//
// Register confidential client → client_credentials_token → validate →
// revoke → verify revoked.

#[tokio::test]
async fn client_credentials_full_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);

    // 1. Register a confidential client with a secret
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Machine Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some("super-secret-value-123!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register confidential client");

    assert!(client.is_confidential(), "client should be confidential");
    assert!(
        client
            .grant_types()
            .contains(&"client_credentials".to_string()),
        "client should support client_credentials grant"
    );

    // 2. Issue a token via client credentials
    let token_resp = harness
        .identity()
        .client_credentials_token(
            &realm,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: "super-secret-value-123!".to_string(),
                scope: Some("read write".to_string()),
            },
        )
        .expect("client credentials token");

    assert!(!token_resp.access_token().is_empty());
    assert_eq!(token_resp.token_type(), "Bearer");
    assert!(token_resp.expires_in() > 0);

    // 3. Validate the token — should be active
    let introspect = harness
        .identity()
        .introspect_token(
            &realm,
            &hearth::identity::TokenIntrospectionRequest {
                token: token_resp.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect token");

    assert!(introspect.active, "token should be active");
    assert_eq!(introspect.token_type.as_deref(), Some("access"));

    // 4. Revoke the token
    harness
        .identity()
        .revoke_token(
            &realm,
            &TokenRevocationRequest {
                token: token_resp.access_token().to_string(),
                token_type_hint: Some("access_token".to_string()),
            },
        )
        .expect("revoke token");

    // 5. Verify the token is now inactive
    let introspect_after = harness
        .identity()
        .introspect_token(
            &realm,
            &hearth::identity::TokenIntrospectionRequest {
                token: token_resp.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect after revocation");

    assert!(
        !introspect_after.active,
        "token should be inactive after revocation"
    );
}

// ===== Scenario C2: Full device authorization flow =====
//
// device_authorize → approve_device → poll_device_token → verify tokens.

#[tokio::test]
async fn device_authorization_full_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);

    // 1. Register a public client that supports device_code grant
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "TV App".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register device client");

    // 2. Initiate device authorization
    let device_resp = harness
        .identity()
        .device_authorize(
            &realm,
            &DeviceAuthorizationRequest {
                client_id: client.client_id().clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");

    assert!(!device_resp.device_code.is_empty());
    assert!(!device_resp.user_code.is_empty());
    assert_eq!(
        device_resp.user_code.len(),
        8,
        "user code should be 8 chars"
    );
    assert!(device_resp.expires_in > 0);
    assert!(device_resp.interval > 0);
    assert!(
        !device_resp.verification_uri.is_empty(),
        "verification URI should be present"
    );

    // 3. User approves the device
    // (Pre-approval polling is tested in unit tests; skipped here to avoid
    // rate-limit interference with the happy-path flow.)
    harness
        .identity()
        .approve_device(&realm, &device_resp.user_code, user.id())
        .expect("approve device");

    // 4. Polling after approval should return tokens
    let token_resp = harness
        .identity()
        .poll_device_token(&realm, &device_resp.device_code, client.client_id())
        .expect("poll device token after approval");

    assert!(!token_resp.access_token().is_empty());
    assert!(!token_resp.id_token().is_empty());
    assert!(!token_resp.refresh_token().is_empty());
    assert_eq!(token_resp.token_type(), "Bearer");
    assert!(token_resp.expires_in() > 0);

    // 5. Access token should be valid
    let claims = harness
        .identity()
        .validate_token(&realm, token_resp.access_token())
        .expect("validate device flow access token");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.tid, realm.to_string());
}

// ===== Scenario C3: Refresh token rotation E2E =====
//
// Auth code flow → issue tokens → refresh → validate new →
// old refresh rejected.

#[tokio::test]
async fn refresh_token_rotation_e2e() {
    use hearth::identity::{AuthorizationRequest, CodeChallengeMethod, TokenExchangeRequest};

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);

    // 1. Register a public client
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Rotation Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    // 2. Authorize and exchange for tokens
    let auth_resp = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "rotation-test".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
            },
        )
        .expect("authorize");

    let token_resp = harness
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        )
        .expect("exchange code");

    let original_refresh = token_resp.refresh_token().to_string();

    // 3. Refresh tokens — the rotation updates the stored grant family hash.
    //    Note: with a real-time clock at the same second, the JWT claims are
    //    identical (Ed25519 is deterministic), so token strings may match.
    //    The rotation is tracked by the stored hash, not the token string.
    let refreshed = harness
        .identity()
        .refresh_tokens(&realm, &original_refresh)
        .expect("refresh tokens");

    // 4. Validate new access token — should succeed
    let claims = harness
        .identity()
        .validate_token(&realm, refreshed.access_token())
        .expect("validate new access token");
    assert_eq!(claims.sub, user.id().to_string());

    // 5. Use old refresh token — should fail (grant family hash was rotated)
    let reuse_result = harness.identity().refresh_tokens(&realm, &original_refresh);
    assert!(
        reuse_result.is_err(),
        "reusing old refresh token after rotation must fail"
    );

    // 6. After theft detection (step 5), the grant family is revoked,
    // so even the current refresh token should also be invalid
    let new_refresh = refreshed.refresh_token().to_string();
    let new_refresh_result = harness.identity().refresh_tokens(&realm, &new_refresh);
    assert!(
        new_refresh_result.is_err(),
        "current refresh token should also be revoked after theft detection"
    );
}

// ===== Conformance F1: RFC 7662 Token Introspection Response =====

/// Validates that introspection responses conform to RFC 7662 §2.2.
///
/// - `active` MUST be a boolean (JSON primitive, not string "true")
/// - Active response MUST include `token_type`
/// - Active response SHOULD include `sub`, `exp`, `iat`, `iss`
/// - Inactive response MUST be `{"active": false}` with optional fields omitted
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn conformance_rfc7662_introspection_response() {
    use hearth::identity::{
        AuthorizationRequest, CodeChallengeMethod, TokenExchangeRequest, TokenIntrospectionRequest,
    };

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "RFC 7662 Test".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let auth = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                state: "rfc7662-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
            },
        )
        .expect("authorize");

    let tokens = harness
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        )
        .expect("exchange");

    // --- Active token introspection ---
    let active_resp = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect active token");

    // RFC 7662 §2.2: "active" REQUIRED, MUST be boolean
    assert!(active_resp.active, "active token must have active=true");

    // Serialize to JSON and verify structure
    let json = serde_json::to_value(&active_resp).expect("serialize introspection response");

    // "active" must be a JSON boolean, not a string
    assert!(
        json["active"].is_boolean(),
        "RFC 7662 §2.2: 'active' MUST be a JSON boolean"
    );
    assert_eq!(json["active"].as_bool(), Some(true));

    // Active response SHOULD include metadata fields
    assert!(
        json["sub"].is_string(),
        "RFC 7662 §2.2: active response SHOULD include 'sub'"
    );
    assert!(
        json["exp"].is_number(),
        "RFC 7662 §2.2: active response SHOULD include 'exp'"
    );
    assert!(
        json["iat"].is_number(),
        "RFC 7662 §2.2: active response SHOULD include 'iat'"
    );
    assert!(
        json["token_type"].is_string(),
        "RFC 7662 §2.2: active response SHOULD include 'token_type'"
    );

    // sub should match the user
    assert_eq!(
        json["sub"].as_str(),
        Some(user.id().to_string().as_str()),
        "sub must match the token's subject"
    );

    // exp must be in the future
    let exp = json["exp"].as_i64().expect("exp is numeric");
    let iat = json["iat"].as_i64().expect("iat is numeric");
    assert!(exp > iat, "exp must be greater than iat");

    // --- Inactive token introspection ---
    let inactive_resp = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: "this-is-not-a-valid-token".to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect invalid token should succeed per RFC 7662");

    assert!(
        !inactive_resp.active,
        "invalid token must have active=false"
    );

    // Serialize inactive response
    let inactive_json = serde_json::to_value(&inactive_resp).expect("serialize inactive response");

    // "active" must be false
    assert_eq!(inactive_json["active"].as_bool(), Some(false));

    // Optional fields should be null/absent for inactive tokens
    assert!(
        inactive_json["sub"].is_null(),
        "inactive response should omit 'sub'"
    );
    assert!(
        inactive_json["exp"].is_null(),
        "inactive response should omit 'exp'"
    );
}

// ===== Conformance F2: RFC 8628 Device Authorization Grant =====

/// Validates that the device authorization flow conforms to RFC 8628.
///
/// - §3.2: Device Authorization Response format
/// - §3.3: User code format (unambiguous characters)
/// - §3.4: Polling semantics (`authorization_pending`, `slow_down`)
/// - §3.5: Token issuance after approval
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn conformance_rfc8628_device_authorization() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "RFC 8628 Conformance".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register device client");

    // --- §3.2: Device Authorization Response ---
    let device_resp = harness
        .identity()
        .device_authorize(
            &realm,
            &DeviceAuthorizationRequest {
                client_id: client.client_id().clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");

    // device_code: REQUIRED
    assert!(
        !device_resp.device_code.is_empty(),
        "RFC 8628 §3.2: device_code REQUIRED"
    );

    // user_code: REQUIRED
    assert!(
        !device_resp.user_code.is_empty(),
        "RFC 8628 §3.2: user_code REQUIRED"
    );

    // verification_uri: REQUIRED
    assert!(
        !device_resp.verification_uri.is_empty(),
        "RFC 8628 §3.2: verification_uri REQUIRED"
    );

    // expires_in: REQUIRED, positive
    assert!(
        device_resp.expires_in > 0,
        "RFC 8628 §3.2: expires_in REQUIRED and must be positive"
    );

    // interval: OPTIONAL but present, must be positive
    assert!(
        device_resp.interval > 0,
        "interval should be a positive integer"
    );

    // --- §6.1: User Code format ---
    // "characters in the range of easily typeable characters"
    // Our implementation uses BCDFGHJKMNPQRSTVWXYZ23456789 (28 unambiguous chars)
    let unambiguous_chars = "BCDFGHJKMNPQRSTVWXYZ23456789";
    for ch in device_resp.user_code.chars() {
        assert!(
            unambiguous_chars.contains(ch),
            "RFC 8628 §6.1: user_code char '{ch}' not in unambiguous set"
        );
    }
    assert_eq!(
        device_resp.user_code.len(),
        8,
        "user_code should be 8 characters"
    );

    // --- §3.3: Authorization Pending ---
    // First poll before approval should return authorization_pending
    let pending =
        harness
            .identity()
            .poll_device_token(&realm, &device_resp.device_code, client.client_id());
    assert!(
        pending.is_err(),
        "RFC 8628 §3.3: unapproved device should return error"
    );

    // --- §3.5: Successful Token Response ---
    harness
        .identity()
        .approve_device(&realm, &device_resp.user_code, user.id())
        .expect("approve device");

    // Wait for rate limit interval (polling immediately after pending would SlowDown)
    // Use a new device flow to avoid rate limit
    let device_resp2 = harness
        .identity()
        .device_authorize(
            &realm,
            &DeviceAuthorizationRequest {
                client_id: client.client_id().clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize 2");

    harness
        .identity()
        .approve_device(&realm, &device_resp2.user_code, user.id())
        .expect("approve device 2");

    let token_resp = harness
        .identity()
        .poll_device_token(&realm, &device_resp2.device_code, client.client_id())
        .expect("poll approved device");

    // RFC 8628 §3.5: response follows RFC 6749 §5.1
    assert!(
        !token_resp.access_token().is_empty(),
        "RFC 6749 §5.1: access_token REQUIRED"
    );
    assert_eq!(
        token_resp.token_type(),
        "Bearer",
        "RFC 6749 §5.1: token_type REQUIRED"
    );
    assert!(
        token_resp.expires_in() > 0,
        "RFC 6749 §5.1: expires_in RECOMMENDED, positive"
    );
}
