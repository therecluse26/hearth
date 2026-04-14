//! Integration tests for JWT token issuance and validation.
//!
//! Black box tests via `TestHarness` — exercises token operations
//! through the public `IdentityEngine` trait.

mod common;

use base64::Engine as _;
use hearth::core::TenantId;
use hearth::identity::{verify_token_signature, CreateUserRequest, User};

/// Helper: creates a user with a unique email in the given tenant.
fn create_user(harness: &common::TestHarness, tenant: &TenantId) -> User {
    harness
        .identity()
        .create_user(
            tenant,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
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
    let tenant = TenantId::generate();
    let user = create_user(&harness, &tenant);

    // Create a session
    let session = harness
        .identity()
        .create_session(&tenant, user.id())
        .expect("create session");

    // Issue tokens
    let pair = harness
        .identity()
        .issue_tokens(&tenant, user.id(), session.id())
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
        .validate_token(&tenant, pair.access_token())
        .expect("validate access token");

    // Claims should reference the correct user and session
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.sid, session.id().to_string());
    assert_eq!(claims.tid, tenant.to_string());
    assert_eq!(claims.token_type, "access");

    // JWKS should have the key that signed the token
    let jwks = harness.identity().jwks();
    assert_eq!(jwks.keys.len(), 1, "JWKS should have one key");

    // Verify the token cryptographically using JWKS public key
    let jwk = &jwks.keys[0];
    let pub_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&jwk.x)
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
    let tenant = TenantId::generate();
    let user = create_user(&harness, &tenant);

    // Create session and initial tokens
    let session = harness
        .identity()
        .create_session(&tenant, user.id())
        .expect("create session");
    let original_pair = harness
        .identity()
        .issue_tokens(&tenant, user.id(), session.id())
        .expect("issue tokens");

    // Validate original access token works
    let original_claims = harness
        .identity()
        .validate_token(&tenant, original_pair.access_token())
        .expect("validate original");
    assert_eq!(original_claims.token_type, "access");

    // Refresh using the refresh token
    let refreshed_pair = harness
        .identity()
        .refresh_tokens(&tenant, original_pair.refresh_token())
        .expect("refresh tokens");

    // New access token should be valid and bound to same user/session
    let refreshed_claims = harness
        .identity()
        .validate_token(&tenant, refreshed_pair.access_token())
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
        .refresh_tokens(&tenant, original_pair.access_token());
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
    let tenant = TenantId::generate();
    let user = create_user(&harness, &tenant);

    let session = harness
        .identity()
        .create_session(&tenant, user.id())
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&tenant, user.id(), session.id())
        .expect("issue tokens");

    // Token works before revocation
    assert!(
        harness
            .identity()
            .validate_token(&tenant, pair.access_token())
            .is_ok(),
        "token should be valid before revocation"
    );

    // Revoke the session
    harness
        .identity()
        .revoke_session(&tenant, session.id())
        .expect("revoke session");

    // Token should now fail validation (session lookup fails)
    let result = harness
        .identity()
        .validate_token(&tenant, pair.access_token());
    assert!(
        result.is_err(),
        "token should be invalid after session revocation"
    );
}

// ===== Scenario: Token validation fails for wrong tenant =====

#[tokio::test]
async fn token_invalid_for_different_tenant() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    let user = create_user(&harness, &tenant_a);

    let session = harness
        .identity()
        .create_session(&tenant_a, user.id())
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&tenant_a, user.id(), session.id())
        .expect("issue tokens");

    // Validate with wrong tenant should fail
    let result = harness
        .identity()
        .validate_token(&tenant_b, pair.access_token());
    assert!(
        result.is_err(),
        "token should be invalid for different tenant"
    );
}

// ===== Scenario: Issue tokens fails for nonexistent user =====

#[tokio::test]
async fn issue_tokens_fails_nonexistent_user() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();
    let user = create_user(&harness, &tenant);

    let session = harness
        .identity()
        .create_session(&tenant, user.id())
        .expect("create session");

    // Delete the user
    harness
        .identity()
        .delete_user(&tenant, user.id())
        .expect("delete user");

    // Issue tokens should fail
    let result = harness
        .identity()
        .issue_tokens(&tenant, user.id(), session.id());
    assert!(result.is_err(), "issue tokens should fail for deleted user");
}
