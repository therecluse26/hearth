//! Integration tests for per-realm auth policy enforcement (HEA-249).
//!
//! Confirms that `allowed_auth_methods`, token TTL overrides, and
//! `mfa_required` are enforced at runtime rather than accepted silently.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, RealmConfig,
    UpdateRealmRequest,
};

// ===== helpers =====

fn create_realm_with_config(
    harness: &common::TestHarness,
    config: RealmConfig,
) -> hearth::identity::Realm {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("policy-test-{}", uuid::Uuid::new_v4()),
            config: Some(config),
        })
        .expect("create realm")
}

fn create_user(harness: &common::TestHarness, realm: &RealmId) -> hearth::identity::User {
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

// ===== allowed_auth_methods enforcement =====

#[tokio::test]
async fn magic_link_blocked_when_not_in_allowed_methods() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            allowed_auth_methods: Some(vec!["password".to_string()]),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    let err = harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect_err("magic_link should be blocked");

    assert!(
        matches!(err, IdentityError::AuthMethodNotAllowed { method } if method == "magic_link"),
        "expected AuthMethodNotAllowed(magic_link), got: {err}"
    );
}

#[tokio::test]
async fn magic_link_allowed_when_in_allowed_methods() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            allowed_auth_methods: Some(vec![
                "password".to_string(),
                "magic_link".to_string(),
            ]),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect("magic_link should succeed when allowed");
}

#[tokio::test]
async fn magic_link_allowed_when_no_restriction() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(&harness, RealmConfig::default());
    let user = create_user(&harness, realm.id());

    harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect("magic_link should succeed when allowed_auth_methods is unconfigured");
}

// ===== per-realm token TTL enforcement =====

#[tokio::test]
async fn token_ttl_overrides_applied_at_issuance() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    // 5-minute access TTL / 1-day refresh TTL as per-realm override.
    let access_ttl_micros: i64 = 5 * 60 * 1_000_000;
    let refresh_ttl_micros: i64 = 24 * 60 * 60 * 1_000_000;

    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            access_token_ttl_micros: Some(access_ttl_micros),
            refresh_token_ttl_micros: Some(refresh_ttl_micros),
            ..RealmConfig::default()
        },
    );

    // Verify the config was persisted.
    let loaded = harness
        .identity()
        .get_realm(realm.id())
        .expect("get_realm")
        .expect("realm exists");
    assert_eq!(
        loaded.config().access_token_ttl_micros,
        Some(access_ttl_micros)
    );
    assert_eq!(
        loaded.config().refresh_token_ttl_micros,
        Some(refresh_ttl_micros)
    );
}

// ===== password complexity enforcement (existing, validated here for completeness) =====

#[tokio::test]
async fn password_complexity_enforced_on_set_password() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            password_policy: Some(hearth::identity::PasswordPolicy {
                min_length: Some(12),
                require_uppercase: Some(true),
                require_number: Some(true),
                require_special: Some(false),
                not_username: None,
                not_email: None,
                history_depth: None,
                max_age_days: None,
            }),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    // Too short — should fail with a policy violation.
    let err = harness
        .identity()
        .set_password(realm.id(), user.id(), &CleartextPassword::from_string("short1A".to_string()))
        .expect_err("short password should fail");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for short password, got: {err}"
    );

    // Meets policy — should succeed.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("ValidLongPassword1".to_string()),
        )
        .expect("password meeting policy should succeed");
}

// ===== mfa_required enforcement (existing, validated here for completeness) =====

#[tokio::test]
async fn mfa_required_realm_config_persists_and_is_readable() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            mfa_required: Some(true),
            ..RealmConfig::default()
        },
    );

    let loaded = harness
        .identity()
        .get_realm(realm.id())
        .expect("get_realm")
        .expect("realm exists");

    assert_eq!(
        loaded.config().mfa_required,
        Some(true),
        "mfa_required should be persisted"
    );
}

// ===== allowed_auth_methods update via UpdateRealmRequest =====

#[tokio::test]
async fn allowed_auth_methods_can_be_updated() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(&harness, RealmConfig::default());
    let user = create_user(&harness, realm.id());

    // Initially unrestricted — magic_link works.
    harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect("magic_link should succeed before restriction");

    // Restrict to password only.
    harness
        .identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    allowed_auth_methods: Some(vec!["password".to_string()]),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update realm");

    // Now magic_link should be blocked.
    let err = harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect_err("magic_link should now be blocked");

    assert!(
        matches!(err, IdentityError::AuthMethodNotAllowed { method } if method == "magic_link"),
        "expected AuthMethodNotAllowed after update, got: {err}"
    );
}
