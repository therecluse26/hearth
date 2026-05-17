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
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

/// Helper: loads the raw stored credential JSON for a user.
fn load_stored_credential(
    harness: &common::TestHarness,
    realm: &RealmId,
    user_id: &hearth::core::UserId,
) -> serde_json::Value {
    let key = format!("cred:user:{}", user_id.as_uuid());
    let bytes = harness
        .storage()
        .get(realm, key.as_bytes())
        .expect("load credential bytes")
        .expect("credential exists");
    serde_json::from_slice(&bytes).expect("credential json")
}

// ===== Scenario 5: Full credential lifecycle =====

#[tokio::test]
async fn credential_lifecycle_set_verify_change() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();
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
    let realm = harness.create_realm();
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
    let realm_a = harness.create_realm();
    let realm_b = harness.create_realm();

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

// ===== Password policy: not_username =====

#[tokio::test]
async fn not_username_policy_rejected() {
    use hearth::identity::{
        CreateRealmRequest, PasswordPolicy, RealmConfig, RegisterUserRequest, RegistrationPolicy,
    };

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("not-uname-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                password_policy: Some(PasswordPolicy {
                    not_username: Some(true),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    // Password contains display name "Alice" — rejected
    let err = harness
        .identity()
        .register_user(
            realm.id(),
            &RegisterUserRequest {
                email: format!("alice-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Alice".to_string(),
                first_name: "Alice".to_string(),
                last_name: String::new(),
                password: CleartextPassword::from_string("my-alice-password".to_string()),
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect_err("should reject password containing username");
    assert!(
        format!("{err}").contains("username"),
        "error should mention username: {err}"
    );

    // Clean password (does not contain display name) — accepted
    harness
        .identity()
        .register_user(
            realm.id(),
            &RegisterUserRequest {
                email: format!("bob-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Alice".to_string(),
                first_name: "Alice".to_string(),
                last_name: String::new(),
                password: CleartextPassword::from_string("unrelated-passphrase-42".to_string()),
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect("clean password should pass not_username policy");
}

// ===== Password policy: not_email =====

#[tokio::test]
async fn not_email_policy_rejected() {
    use hearth::identity::{
        CreateRealmRequest, PasswordPolicy, RealmConfig, RegisterUserRequest, RegistrationPolicy,
    };

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("not-email-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                password_policy: Some(PasswordPolicy {
                    not_email: Some(true),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let email = format!("carol-{}@example.com", uuid::Uuid::new_v4());

    // Password contains full email address — rejected
    let bad_pw = CleartextPassword::from_string(format!("prefix-{email}-suffix"));
    let err = harness
        .identity()
        .register_user(
            realm.id(),
            &RegisterUserRequest {
                email: email.clone(),
                display_name: "Carol".to_string(),
                first_name: "Carol".to_string(),
                last_name: String::new(),
                password: bad_pw,
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect_err("should reject password containing email");
    assert!(
        format!("{err}").contains("email"),
        "error should mention email: {err}"
    );

    // Clean password — accepted
    harness
        .identity()
        .register_user(
            realm.id(),
            &RegisterUserRequest {
                email: format!("carol2-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Carol".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                password: CleartextPassword::from_string("completely-unrelated-42".to_string()),
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect("clean password should pass not_email policy");
}

// ===== Password policy: history_depth =====

#[tokio::test]
async fn history_depth_prevents_reuse() {
    use hearth::identity::{
        CreateRealmRequest, IdentityError, PasswordPolicy, RealmConfig, RegistrationPolicy,
    };

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hist-realm-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                password_policy: Some(PasswordPolicy {
                    history_depth: Some(2),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("hist-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "History Tester".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let pw_alpha = || CleartextPassword::from_string("password-alpha".to_string());
    let pw_beta = || CleartextPassword::from_string("password-beta".to_string());
    let pw_gamma = || CleartextPassword::from_string("password-gamma".to_string());
    let pw_delta = || CleartextPassword::from_string("password-delta".to_string());

    // Set first two passwords; history now contains pw_alpha
    harness
        .identity()
        .set_password(realm.id(), user.id(), &pw_alpha())
        .expect("set alpha");
    harness
        .identity()
        .set_password(realm.id(), user.id(), &pw_beta())
        .expect("set beta");

    // pw_alpha is in the history window (depth=2) — rejected
    let err = harness
        .identity()
        .set_password(realm.id(), user.id(), &pw_alpha())
        .expect_err("should reject reuse of pw_alpha");
    assert!(
        matches!(err, IdentityError::PasswordReused),
        "expected PasswordReused, got: {err}"
    );

    // Advance the window: history = [pw_gamma, pw_beta]; pw_alpha rotates out
    harness
        .identity()
        .set_password(realm.id(), user.id(), &pw_gamma())
        .expect("set gamma");
    harness
        .identity()
        .set_password(realm.id(), user.id(), &pw_delta())
        .expect("set delta");

    // pw_alpha is no longer in the 2-deep history — allowed again
    harness
        .identity()
        .set_password(realm.id(), user.id(), &pw_alpha())
        .expect("pw_alpha should be reusable once rotated out of history");
}

// ===== Password policy: max_age_days (expiry) =====

#[tokio::test]
async fn password_expiry_enforced() {
    use hearth::audit::EmbeddedAuditEngine;
    use hearth::core::{FakeClock, Timestamp};
    use hearth::identity::{
        CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
        IdentityEngine, IdentityError, PasswordPolicy, RealmConfig, RegistrationPolicy,
    };
    use hearth::rbac::EmbeddedRbacEngine;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp_dir.path().to_path_buf()))
            .expect("open storage"),
    );
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        Arc::clone(&rbac) as Arc<dyn hearth::rbac::RbacEngine>,
        Arc::clone(&audit) as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine creation");

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("expiry-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                password_policy: Some(PasswordPolicy {
                    max_age_days: Some(30),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = engine
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("expiry-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Expiry Tester".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let pw = CleartextPassword::from_string("not-yet-expired".to_string());
    engine
        .set_password(realm.id(), user.id(), &pw)
        .expect("set password");

    // Within the 30-day window — verify succeeds
    let ok = engine
        .verify_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("not-yet-expired".to_string()),
        )
        .expect("verify within window");
    assert!(ok, "correct password should verify before expiry");

    // Advance past the 30-day limit (31 days in microseconds)
    clock.advance(31_i64 * 24 * 60 * 60 * 1_000_000);

    // Same correct password — now expired
    let err = engine
        .verify_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("not-yet-expired".to_string()),
        )
        .expect_err("should fail after expiry");
    assert!(
        matches!(err, IdentityError::PasswordExpired),
        "expected PasswordExpired, got: {err}"
    );
}

// ===== Per-realm hashing config =====

#[tokio::test]
async fn set_password_uses_realm_argon2_parameters() {
    use hearth::identity::{CreateRealmRequest, RealmConfig};

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hash-params-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_memory_cost: Some(1024),
                password_time_cost: Some(3),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = create_user(&harness, realm.id());
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("RealmAwarePassword123!".to_string()),
        )
        .expect("set password");

    let stored = load_stored_credential(&harness, realm.id(), user.id());
    let hash = stored["hash"].as_str().expect("hash string");
    assert!(
        hash.starts_with("$argon2id$"),
        "expected argon2id hash, got: {hash}"
    );
    assert!(
        hash.contains("m=1024"),
        "expected realm memory cost in hash params, got: {hash}"
    );
    assert!(
        hash.contains("t=3"),
        "expected realm time cost in hash params, got: {hash}"
    );
}

#[tokio::test]
async fn legacy_verify_rehash_uses_realm_argon2_parameters_and_keeps_age() {
    use hearth::identity::{
        CreateRealmRequest, ImportUserRequest, RawCredential, RealmConfig, UserStatus,
    };
    use std::collections::BTreeMap;

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("legacy-rehash-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_memory_cost: Some(1536),
                password_time_cost: Some(2),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let legacy_hash =
        bcrypt::hash("legacy-password", 4).expect("create bcrypt hash for import fixture");
    let imported_created_at = 1_700_000_000_000_000_i64;

    let user = harness
        .identity()
        .import_user(
            realm.id(),
            &ImportUserRequest {
                id: None,
                email: format!("legacy-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Legacy User".to_string(),
                first_name: "Legacy".to_string(),
                last_name: "User".to_string(),
                status: UserStatus::Active,
                credential: Some(RawCredential {
                    phc_string: legacy_hash,
                    created_at_micros: Some(imported_created_at),
                }),
                attributes: BTreeMap::new(),
            },
        )
        .expect("import user");

    let ok = harness
        .identity()
        .verify_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("legacy-password".to_string()),
        )
        .expect("verify imported legacy credential");
    assert!(ok, "legacy credential should verify");

    let stored = load_stored_credential(&harness, realm.id(), user.id());
    let hash = stored["hash"].as_str().expect("hash string");
    assert!(
        hash.starts_with("$argon2id$"),
        "expected upgrade to argon2id after verify, got: {hash}"
    );
    assert!(
        hash.contains("m=1536"),
        "expected realm memory override in upgraded hash, got: {hash}"
    );
    assert!(
        hash.contains("t=2"),
        "expected realm time override in upgraded hash, got: {hash}"
    );
    assert_eq!(
        stored["created_at"].as_i64(),
        Some(imported_created_at),
        "rehash should preserve original credential age for expiry policy"
    );
}

// ===== Policy enforcement on non-registration write paths =====

#[tokio::test]
async fn change_and_reset_paths_enforce_realm_password_policy() {
    use hearth::identity::{
        CreateRealmRequest, IdentityError, PasswordPolicy, RealmConfig, RegistrationPolicy,
    };

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("policy-paths-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                password_policy: Some(PasswordPolicy {
                    min_length: Some(12),
                    require_uppercase: Some(true),
                    require_number: Some(true),
                    not_email: Some(true),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = create_user(&harness, realm.id());
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("InitialStrongPass1!".to_string()),
        )
        .expect("set initial password");

    // 1) Change-password path should enforce policy.
    let change_err = harness
        .identity()
        .change_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("InitialStrongPass1!".to_string()),
            &CleartextPassword::from_string("weak".to_string()),
        )
        .expect_err("weak replacement password should be rejected");
    assert!(
        matches!(change_err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput on weak change_password, got: {change_err}"
    );

    // 2) Reset-password path should enforce policy.
    let reset_token = harness
        .identity()
        .request_password_reset(realm.id(), user.email())
        .expect("request reset")
        .expect("known user should produce token");
    let reset_err = harness
        .identity()
        .reset_password_with_token(
            realm.id(),
            &reset_token,
            &CleartextPassword::from_string("short1A".to_string()),
        )
        .expect_err("weak reset password should be rejected");
    assert!(
        matches!(reset_err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput on weak reset_password_with_token, got: {reset_err}"
    );
}

// ===== Delete cascade =====

#[tokio::test]
async fn delete_user_removes_credential() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();
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

#[tokio::test]
async fn argon2_param_change_triggers_lazy_rehash_on_login() {
    use hearth::identity::{CreateRealmRequest, RealmConfig, UpdateRealmRequest};

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    // Create realm with low memory cost so hashing is fast in tests.
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("argon2-rehash-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_memory_cost: Some(512),
                password_time_cost: Some(1),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = create_user(&harness, realm.id());
    let password = CleartextPassword::from_string("Rehash!Password1".to_string());
    harness
        .identity()
        .set_password(realm.id(), user.id(), &password)
        .expect("set password");

    // Verify the stored hash reflects the original params.
    let stored = load_stored_credential(&harness, realm.id(), user.id());
    let original_hash = stored["hash"].as_str().expect("hash").to_string();
    let original_created_at = stored["created_at"].as_i64().expect("created_at");
    assert!(
        original_hash.contains("m=512"),
        "expected m=512 in hash, got: {original_hash}"
    );

    // Update realm config to higher memory cost — simulates operator tuning.
    harness
        .identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                name: None,
                config: Some(RealmConfig {
                    password_memory_cost: Some(1024),
                    password_time_cost: Some(2),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update realm config");

    // Login with the same password — should succeed and trigger lazy rehash.
    let password2 = CleartextPassword::from_string("Rehash!Password1".to_string());
    let ok = harness
        .identity()
        .verify_password(realm.id(), user.id(), &password2)
        .expect("verify after config change");
    assert!(ok, "login should succeed with unchanged password");

    // Stored hash should now use the new params.
    let stored_after = load_stored_credential(&harness, realm.id(), user.id());
    let new_hash = stored_after["hash"].as_str().expect("hash after rehash");
    assert!(
        new_hash.contains("m=1024"),
        "expected m=1024 after lazy rehash, got: {new_hash}"
    );
    assert!(
        new_hash.contains("t=2"),
        "expected t=2 after lazy rehash, got: {new_hash}"
    );
    assert_eq!(
        stored_after["created_at"].as_i64(),
        Some(original_created_at),
        "lazy rehash must preserve original credential age"
    );

    // Subsequent login should still work using the new hash.
    let password3 = CleartextPassword::from_string("Rehash!Password1".to_string());
    let ok2 = harness
        .identity()
        .verify_password(realm.id(), user.id(), &password3)
        .expect("verify after rehash");
    assert!(ok2, "login should succeed after lazy rehash");
}
