//! Integration and adversarial tests for Magic Link / Passwordless (Step 25).
//!
//! Black box tests via `TestHarness` — exercises magic link request,
//! validation, account creation, rate limiting, and enumeration resistance
//! through the public `IdentityEngine` trait.

mod common;

use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, CreateUserRequest, User};

/// Helper: creates a real realm with a signing key.
fn create_realm(harness: &common::TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ml-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}

/// Helper: creates a user with a unique email.
fn create_user_with_email(harness: &common::TestHarness, realm: &RealmId, email: &str) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Magic Link Test User".to_string(),
            },
        )
        .expect("create user")
}

// ===== Scenario E: Full passwordless flow (P0) =====
//
// create realm → create user with email → request magic link →
// validate token → verify returned user_id → use user_id to create session

#[tokio::test]
async fn magic_link_full_passwordless_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let email = format!("magic-{}@example.com", uuid::Uuid::new_v4());
    let user = create_user_with_email(&harness, &realm, &email);

    // Request magic link
    let response = harness
        .identity()
        .request_magic_link(&realm, &email)
        .expect("request_magic_link");
    assert!(!response.token().is_empty(), "token should be non-empty");

    // Validate token
    let returned_user_id = harness
        .identity()
        .validate_magic_link(&realm, response.token())
        .expect("validate_magic_link");

    // Verify correct user
    assert_eq!(
        returned_user_id.as_uuid(),
        user.id().as_uuid(),
        "returned user ID should match the existing user"
    );

    // Use user_id to create a session (proves the user is authenticated)
    let session = harness
        .identity()
        .create_session(
            &realm,
            &returned_user_id,
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session after magic link auth");

    assert!(
        harness
            .identity()
            .get_session(&realm, session.id())
            .expect("get session")
            .is_some(),
        "session should be valid after magic link authentication"
    );
}

// ===== Scenario F: Magic link with new email triggers account creation (P1) =====
//
// create realm (no user) → request magic link for unknown email →
// validate token → verify new user created → get_user_by_email returns user

#[tokio::test]
async fn magic_link_creates_account_for_unknown_email() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let unknown_email = format!("newuser-{}@example.com", uuid::Uuid::new_v4());

    // Email should not exist yet
    assert!(
        harness
            .identity()
            .get_user_by_email(&realm, &unknown_email)
            .expect("get_user_by_email")
            .is_none(),
        "email should not exist before magic link"
    );

    // Request magic link for unknown email (should succeed — enumeration resistance)
    let response = harness
        .identity()
        .request_magic_link(&realm, &unknown_email)
        .expect("request_magic_link for unknown email");

    // Validate token — should create a new user
    let new_user_id = harness
        .identity()
        .validate_magic_link(&realm, response.token())
        .expect("validate_magic_link should create user");

    // Verify the user now exists
    let user = harness
        .identity()
        .get_user(&realm, &new_user_id)
        .expect("get_user")
        .expect("user should exist after magic link validation");
    assert_eq!(
        user.email(),
        &unknown_email.to_lowercase(),
        "created user should have the magic link email"
    );

    // Also verify via get_user_by_email
    let user_by_email = harness
        .identity()
        .get_user_by_email(&realm, &unknown_email)
        .expect("get_user_by_email")
        .expect("user should be findable by email");
    assert_eq!(
        user_by_email.id().as_uuid(),
        new_user_id.as_uuid(),
        "user found by email should match"
    );
}

// ===== Scenario G: Rate limiting (Adversarial) =====
//
// Request 3 magic links for same email → all succeed
// Request 4th → fails with RateLimited

#[tokio::test]
async fn magic_link_rate_limiting() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let email = format!("ratelimit-{}@example.com", uuid::Uuid::new_v4());
    let _user = create_user_with_email(&harness, &realm, &email);

    // First 3 requests should succeed
    for i in 0..3 {
        harness
            .identity()
            .request_magic_link(&realm, &email)
            .unwrap_or_else(|e| panic!("request {i} should succeed: {e:?}"));
    }

    // 4th request should be rate-limited
    let err = harness
        .identity()
        .request_magic_link(&realm, &email)
        .expect_err("4th request should be rate-limited");
    assert!(
        matches!(err, hearth::identity::IdentityError::RateLimited),
        "should be RateLimited, got: {err:?}"
    );
}

// ===== Scenario H: Enumeration resistance (Adversarial) =====
//
// Request magic link for existing email → succeeds (returns token)
// Request magic link for nonexistent email → also succeeds (returns token)
// Both return MagicLinkResponse — caller cannot distinguish

#[tokio::test]
async fn magic_link_enumeration_resistance() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);

    // Create a user with a known email
    let existing_email = format!("existing-{}@example.com", uuid::Uuid::new_v4());
    let _user = create_user_with_email(&harness, &realm, &existing_email);

    // Nonexistent email
    let nonexistent_email = format!("ghost-{}@example.com", uuid::Uuid::new_v4());

    // Both should succeed
    let resp_existing = harness
        .identity()
        .request_magic_link(&realm, &existing_email)
        .expect("request for existing email should succeed");
    let resp_nonexistent = harness
        .identity()
        .request_magic_link(&realm, &nonexistent_email)
        .expect("request for nonexistent email should also succeed");

    // Both should return non-empty tokens
    assert!(
        !resp_existing.token().is_empty(),
        "existing email token should be non-empty"
    );
    assert!(
        !resp_nonexistent.token().is_empty(),
        "nonexistent email token should be non-empty"
    );

    // The tokens should be different (they're random), but both are valid
    assert_ne!(
        resp_existing.token(),
        resp_nonexistent.token(),
        "tokens should be distinct"
    );
}
