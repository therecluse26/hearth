//! Integration tests for JWT token issuance and validation.
//!
//! Black box tests via `TestHarness` — exercises token operations
//! through the public `IdentityEngine` trait.

mod common;

use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{verify_token_signature, CreateUserRequest, User};

/// Helper: creates a user with a unique email in the given realm.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ===== Scenario: Token issuance and validation round-trip via public API =====

#[tokio::test]
async fn token_issuance_and_validation_roundtrip() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Create a session
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Issue tokens
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Access token should be non-empty
    assert!(!pair.access_token().is_empty(), "access token should exist");
    assert!(
        !pair.refresh_token().is_empty(),
        "refresh token should exist"
    );

    // Validate access token via session lookup (internal hot path)
    let claims = harness
        .identity()
        .validate_token(&realm, pair.access_token())
        .expect("validate access token");

    // Claims should reference the correct user and session
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.sid, session.id().to_string());
    assert_eq!(claims.tid, realm.to_string());
    assert_eq!(claims.token_type, "access");

    // JWKS should contain the Ed25519 signing key that issued the token
    // (plus RS256/ES256 ecosystem-compat entries from HEA-51 — those are
    // verification-only and not the signer for this access token).
    let jwks = harness.identity().jwks();
    let jwk = jwks
        .keys
        .iter()
        .find(|j| j.alg == "EdDSA")
        .expect("JWKS should include the EdDSA signer");
    let x_b64 = jwk.x.as_deref().expect("Ed25519 JWK must include x");
    let pub_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .expect("decode JWKS public key");
    let verified_claims = verify_token_signature(pair.access_token(), &pub_bytes)
        .expect("cryptographic verification should succeed");
    assert_eq!(verified_claims, claims);
}

// ===== Scenario: Token refresh flow end-to-end =====

#[tokio::test]
async fn token_refresh_flow_end_to_end() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Create session and initial tokens
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let original_pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Validate original access token works
    let original_claims = harness
        .identity()
        .validate_token(&realm, original_pair.access_token())
        .expect("validate original");
    assert_eq!(original_claims.token_type, "access");

    // Refresh using the refresh token
    let refreshed_pair = harness
        .identity()
        .refresh_tokens(&realm, original_pair.refresh_token())
        .expect("refresh tokens");

    // New access token should be valid and bound to same user/session
    let refreshed_claims = harness
        .identity()
        .validate_token(&realm, refreshed_pair.access_token())
        .expect("validate refreshed access token");
    assert_eq!(refreshed_claims.sub, user.id().to_string());
    assert_eq!(refreshed_claims.sid, session.id().to_string());
    assert_eq!(refreshed_claims.token_type, "access");

    // New refresh token should also be valid
    let refreshed_refresh_claims =
        hearth::identity::decode_claims_unverified(refreshed_pair.refresh_token())
            .expect("decode refreshed refresh token");
    assert_eq!(refreshed_refresh_claims.token_type, "refresh");
    assert_eq!(refreshed_refresh_claims.sub, user.id().to_string());

    // Attempt to use access token as refresh token should fail
    let bad_refresh = harness
        .identity()
        .refresh_tokens(&realm, original_pair.access_token());
    assert!(
        bad_refresh.is_err(),
        "using access token as refresh should fail"
    );
}

// ===== Scenario: Token validation fails for revoked session =====

#[tokio::test]
async fn token_invalid_after_session_revoked() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Token works before revocation
    assert!(
        harness
            .identity()
            .validate_token(&realm, pair.access_token())
            .is_ok(),
        "token should be valid before revocation"
    );

    // Revoke the session
    harness
        .identity()
        .revoke_session(&realm, session.id())
        .expect("revoke session");

    // Token should now fail validation (session lookup fails)
    let result = harness
        .identity()
        .validate_token(&realm, pair.access_token());
    assert!(
        result.is_err(),
        "token should be invalid after session revocation"
    );
}

// ===== Scenario: Token validation fails for wrong realm =====

#[tokio::test]
async fn token_invalid_for_different_realm() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();
    let user = create_user(&harness, &realm_a);

    let session = harness
        .identity()
        .create_session(
            &realm_a,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&realm_a, user.id(), session.id())
        .expect("issue tokens");

    // Validate with wrong realm should fail
    let result = harness
        .identity()
        .validate_token(&realm_b, pair.access_token());
    assert!(
        result.is_err(),
        "token should be invalid for different realm"
    );
}

// ===== Scenario: Issue tokens fails for nonexistent user =====

#[tokio::test]
async fn issue_tokens_fails_nonexistent_user() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Delete the user
    harness
        .identity()
        .delete_user(&realm, user.id())
        .expect("delete user");

    // Issue tokens should fail
    let result = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id());
    assert!(result.is_err(), "issue tokens should fail for deleted user");
}
