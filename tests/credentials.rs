//! Integration tests for credential storage.
//!
//! Black box tests via `TestHarness` — exercises the credential operations
//! through the public `IdentityEngine` trait.

mod common;

use hearth::core::RealmId;
use hearth::identity::{CleartextPassword, CreateUserRequest, User};

/// Helper: creates a user with a unique email in the given realm.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
            },
        )
        .expect("create user")
}

// ===== Scenario 5: Full credential lifecycle =====

#[tokio::test]
async fn credential_lifecycle_set_verify_change() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // 1. No credential initially — returns generic error (enumeration resistance)
    let pw = CleartextPassword::from_string("initial-password".to_string());
    let err = harness
        .identity()
        .verify_password(&realm, user.id(), &pw)
        .expect_err("should fail — no credential");
    assert!(
        format!("{err}").contains("credential"),
        "should indicate credential failure: {err}"
    );

    // 2. Set password
    let pw = CleartextPassword::from_string("initial-password".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &pw)
        .expect("set password");

    // 3. Verify correct password
    let pw = CleartextPassword::from_string("initial-password".to_string());
    let result = harness
        .identity()
        .verify_password(&realm, user.id(), &pw)
        .expect("verify");
    assert!(result, "correct password should verify");

    // 4. Verify wrong password
    let wrong = CleartextPassword::from_string("wrong-password".to_string());
    let result = harness
        .identity()
        .verify_password(&realm, user.id(), &wrong)
        .expect("verify");
    assert!(!result, "wrong password should not verify");

    // 5. Overwrite password with set_password
    let new_pw = CleartextPassword::from_string("replaced-password".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &new_pw)
        .expect("overwrite password");

    // 6. Old password should no longer work
    let old = CleartextPassword::from_string("initial-password".to_string());
    let result = harness
        .identity()
        .verify_password(&realm, user.id(), &old)
        .expect("verify old");
    assert!(!result, "old password should no longer verify");

    // 7. New password should work
    let new_check = CleartextPassword::from_string("replaced-password".to_string());
    let result = harness
        .identity()
        .verify_password(&realm, user.id(), &new_check)
        .expect("verify new");
    assert!(result, "new password should verify");
}

// ===== Scenario 6: Authenticate → change → re-authenticate =====

#[tokio::test]
async fn change_password_flow() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Set initial password
    let pw = CleartextPassword::from_string("original-pw".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &pw)
        .expect("set password");

    // Authenticate with original
    let pw = CleartextPassword::from_string("original-pw".to_string());
    let ok = harness
        .identity()
        .verify_password(&realm, user.id(), &pw)
        .expect("verify");
    assert!(ok, "original password should authenticate");

    // Change password
    let old = CleartextPassword::from_string("original-pw".to_string());
    let new = CleartextPassword::from_string("updated-pw".to_string());
    harness
        .identity()
        .change_password(&realm, user.id(), &old, &new)
        .expect("change password");

    // Re-authenticate with new password
    let new_check = CleartextPassword::from_string("updated-pw".to_string());
    let ok = harness
        .identity()
        .verify_password(&realm, user.id(), &new_check)
        .expect("verify new");
    assert!(ok, "new password should authenticate");

    // Old password should fail
    let old_check = CleartextPassword::from_string("original-pw".to_string());
    let ok = harness
        .identity()
        .verify_password(&realm, user.id(), &old_check)
        .expect("verify old");
    assert!(!ok, "old password should no longer authenticate");

    // Wrong old password should fail on change
    let wrong_old = CleartextPassword::from_string("not-the-password".to_string());
    let bad_new = CleartextPassword::from_string("doesnt-matter".to_string());
    let err = harness
        .identity()
        .change_password(&realm, user.id(), &wrong_old, &bad_new)
        .expect_err("should fail");
    assert!(
        format!("{err}").contains("invalid credential"),
        "should indicate invalid credential: {err}"
    );
}

// ===== Cross-realm credential isolation =====

#[tokio::test]
async fn credentials_are_realm_isolated() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let user_a = create_user(&harness, &realm_a);

    // Set password for user in realm A
    let pw = CleartextPassword::from_string("realm-a-password".to_string());
    harness
        .identity()
        .set_password(&realm_a, user_a.id(), &pw)
        .expect("set password");

    // Cannot verify from realm B (user doesn't exist there)
    // Returns generic credential error for enumeration resistance
    let pw = CleartextPassword::from_string("realm-a-password".to_string());
    let err = harness
        .identity()
        .verify_password(&realm_b, user_a.id(), &pw)
        .expect_err("should fail");
    assert!(
        format!("{err}").contains("credential"),
        "should indicate credential failure in different realm: {err}"
    );
}

// ===== Delete cascade =====

#[tokio::test]
async fn delete_user_removes_credential() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Set password
    let pw = CleartextPassword::from_string("delete-me".to_string());
    harness
        .identity()
        .set_password(&realm, user.id(), &pw)
        .expect("set password");

    // Delete user
    harness
        .identity()
        .delete_user(&realm, user.id())
        .expect("delete user");

    // Verify should fail (user gone) — returns generic credential error
    let pw = CleartextPassword::from_string("delete-me".to_string());
    let err = harness
        .identity()
        .verify_password(&realm, user.id(), &pw)
        .expect_err("should fail");
    assert!(
        format!("{err}").contains("credential"),
        "should indicate credential failure after deletion: {err}"
    );
}
