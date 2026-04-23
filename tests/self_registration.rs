//! Integration and adversarial tests for self-service registration (Gap #1).
//!
//! Black box tests via `TestHarness` — exercises `register_user`, registration
//! policy enforcement, email verification, rate limiting, and enumeration
//! resistance through the public `IdentityEngine` trait.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, IdentityError, RealmConfig, RegisterUserRequest,
    RegistrationPolicy, SessionContext, UserStatus,
};

/// Creates a realm with the given registration policy.
fn create_realm_with_policy(
    harness: &common::TestHarness,
    policy: Option<RegistrationPolicy>,
) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("reg-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: policy,
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    realm.id().clone()
}

fn default_request(email: &str) -> RegisterUserRequest {
    RegisterUserRequest {
        email: email.to_string(),
        display_name: email.to_string(),
        first_name: String::new(),
        last_name: String::new(),
        password: CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
        client_ip: Some("203.0.113.1".to_string()),
        invitation_token: None,
    }
}

// ===== Scenario 1: full signup → verify → login =====

#[tokio::test]
async fn full_signup_verify_login_flow() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(&harness, Some(RegistrationPolicy::Open));

    let email = format!("alice-{}@example.com", uuid::Uuid::new_v4());
    let resp = harness
        .identity()
        .register_user(&realm, &default_request(&email))
        .expect("register_user");
    assert!(
        !resp.verification_token.is_empty(),
        "token must be returned"
    );

    // User is created but pending verification.
    let user = harness
        .identity()
        .get_user(&realm, &resp.user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(user.status(), UserStatus::PendingVerification);

    // Unverified user cannot create a session.
    let pre_verify =
        harness
            .identity()
            .create_session(&realm, user.id(), &SessionContext::default());
    assert!(
        matches!(pre_verify, Err(IdentityError::UserNotVerified)),
        "unverified user must not be able to log in, got: {pre_verify:?}"
    );

    // Verify the email.
    let verified_user_id = harness
        .identity()
        .verify_email_token(&realm, &resp.verification_token)
        .expect("verify token");
    assert_eq!(verified_user_id, resp.user_id);

    // Now the user is Active and can authenticate.
    let user = harness
        .identity()
        .get_user(&realm, &resp.user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(user.status(), UserStatus::Active);

    let verified = harness
        .identity()
        .verify_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
        )
        .expect("verify_password");
    assert!(verified, "password must verify after registration");
}

// ===== Scenario 2: Disabled policy (default) rejects registration =====

#[tokio::test]
async fn signup_rejected_when_policy_disabled() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    // None → Disabled (safe default).
    let realm = create_realm_with_policy(&harness, None);

    let email = format!("blocked-{}@example.com", uuid::Uuid::new_v4());
    let result = harness
        .identity()
        .register_user(&realm, &default_request(&email));
    assert!(
        matches!(result, Err(IdentityError::RegistrationDisabled)),
        "expected RegistrationDisabled, got: {result:?}"
    );
}

// ===== Scenario 3: Domain-restricted policy =====

#[tokio::test]
async fn signup_domain_restricted_accepts_allowed_domain() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(
        &harness,
        Some(RegistrationPolicy::DomainRestricted(vec![
            "example.com".to_string()
        ])),
    );

    let email = format!("ok-{}@example.com", uuid::Uuid::new_v4());
    harness
        .identity()
        .register_user(&realm, &default_request(&email))
        .expect("allowed domain should register");
}

#[tokio::test]
async fn signup_domain_restricted_rejects_other_domain() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(
        &harness,
        Some(RegistrationPolicy::DomainRestricted(vec![
            "example.com".to_string()
        ])),
    );

    let email = format!("nope-{}@gmail.com", uuid::Uuid::new_v4());
    let result = harness
        .identity()
        .register_user(&realm, &default_request(&email));
    assert!(
        matches!(
            result,
            Err(IdentityError::RegistrationDomainNotAllowed { .. })
        ),
        "expected RegistrationDomainNotAllowed, got: {result:?}"
    );
}

// ===== Scenario 4: Enumeration resistance on duplicate email =====

#[tokio::test]
async fn signup_duplicate_email_returns_generic_success() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(&harness, Some(RegistrationPolicy::Open));

    let email = format!("dup-{}@example.com", uuid::Uuid::new_v4());
    let first = harness
        .identity()
        .register_user(&realm, &default_request(&email))
        .expect("first register");

    // Second request for the same email must return success (non-empty token)
    // without leaking whether the email already exists.
    let second = harness
        .identity()
        .register_user(&realm, &default_request(&email))
        .expect("second register must not error");
    assert!(!second.verification_token.is_empty());
    // The real user's verification token MUST NOT be usable via the
    // duplicate-email response path (the fake token should fail verification).
    let verify_fake = harness
        .identity()
        .verify_email_token(&realm, &second.verification_token);
    assert!(
        matches!(verify_fake, Err(IdentityError::VerificationTokenInvalid)),
        "fake token from duplicate signup must not verify, got: {verify_fake:?}"
    );
    // Sanity: first token still works.
    let verified = harness
        .identity()
        .verify_email_token(&realm, &first.verification_token)
        .expect("first token must verify");
    assert_eq!(verified, first.user_id);
}

// ===== Scenario 5: Verification token is single-use =====

#[tokio::test]
async fn verification_link_single_use() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(&harness, Some(RegistrationPolicy::Open));
    let email = format!("once-{}@example.com", uuid::Uuid::new_v4());
    let resp = harness
        .identity()
        .register_user(&realm, &default_request(&email))
        .expect("register");

    // First consumption succeeds.
    harness
        .identity()
        .verify_email_token(&realm, &resp.verification_token)
        .expect("first verify");

    // Second attempt must fail.
    let second = harness
        .identity()
        .verify_email_token(&realm, &resp.verification_token);
    assert!(
        matches!(second, Err(IdentityError::VerificationTokenInvalid)),
        "second verify must fail, got: {second:?}"
    );
}

// ===== Scenario 6: Per-email rate limiting =====

#[tokio::test]
async fn signup_rate_limited_per_email() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(&harness, Some(RegistrationPolicy::Open));

    let email = format!("burst-{}@example.com", uuid::Uuid::new_v4());
    // 3 registration attempts for the same email in an hour are allowed;
    // the 4th must be rate-limited (same bucket as magic-link: 3/hr).
    for attempt in 0..3 {
        let _ = harness
            .identity()
            .register_user(&realm, &default_request(&email))
            .unwrap_or_else(|e| panic!("attempt {attempt} failed: {e:?}"));
    }
    let fourth = harness
        .identity()
        .register_user(&realm, &default_request(&email));
    assert!(
        matches!(fourth, Err(IdentityError::RateLimited)),
        "4th attempt must be rate-limited, got: {fourth:?}"
    );
}

// ===== Scenario 7: Per-IP rate limiting =====

#[tokio::test]
async fn signup_rate_limited_per_ip() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_policy(&harness, Some(RegistrationPolicy::Open));

    let ip = "198.51.100.42".to_string();
    // IP bucket is 10/hr; 11th must be rate-limited across distinct emails.
    for attempt in 0..10 {
        let email = format!("ip-{attempt}-{}@example.com", uuid::Uuid::new_v4());
        let mut req = default_request(&email);
        req.client_ip = Some(ip.clone());
        harness
            .identity()
            .register_user(&realm, &req)
            .unwrap_or_else(|e| panic!("attempt {attempt} failed: {e:?}"));
    }
    let email = format!("ip-overflow-{}@example.com", uuid::Uuid::new_v4());
    let mut req = default_request(&email);
    req.client_ip = Some(ip);
    let overflow = harness.identity().register_user(&realm, &req);
    assert!(
        matches!(overflow, Err(IdentityError::RateLimited)),
        "11th attempt from same IP must be rate-limited, got: {overflow:?}"
    );
}

// ===== Scenario 8: Password policy enforced at registration =====

#[tokio::test]
async fn signup_enforces_realm_password_policy() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_obj = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("reg-pw-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                password_policy: Some(hearth::identity::PasswordPolicy {
                    min_length: Some(12),
                    require_uppercase: Some(true),
                    require_number: Some(true),
                    require_special: None,
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let realm = realm_obj.id().clone();

    let email = format!("weak-{}@example.com", uuid::Uuid::new_v4());
    let mut req = default_request(&email);
    req.password = CleartextPassword::from_string("short".to_string());
    let result = harness.identity().register_user(&realm, &req);
    assert!(
        matches!(result, Err(IdentityError::InvalidInput { .. })),
        "weak password must be rejected, got: {result:?}"
    );
}
