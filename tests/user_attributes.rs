//! Integration tests for `update_user` attribute validation.
//!
//! Exercises the `validate_user_attributes` guard inside the identity engine
//! (empty key, key > 64 chars, invalid key chars, value > 1 KiB, total > 16 KiB).

mod common;

use std::collections::BTreeMap;

use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, IdentityError, UpdateUserRequest};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a user in the given realm and returns its ID.
async fn create_user(h: &common::TestHarness, realm: &RealmId) -> hearth::core::UserId {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: "Test".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    user.id().clone()
}

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_user_valid_attributes_accepted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[
                ("department", "engineering"),
                ("cost.center", "CC-42"),
                ("employee_id", "EMP001"),
            ])),
            ..Default::default()
        },
    );

    assert!(
        result.is_ok(),
        "valid attributes must be accepted; got: {result:?}"
    );
    let updated = result.expect("update");
    let attrs = updated.attributes();
    assert_eq!(
        attrs.get("department").map(String::as_str),
        Some("engineering")
    );
    assert_eq!(attrs.get("cost.center").map(String::as_str), Some("CC-42"));
}

#[tokio::test]
async fn update_user_empty_key_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[("", "value")])),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "empty key must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_key_too_long_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    // Exactly 65 characters (limit is 64).
    let long_key: String = "a".repeat(65);
    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[(&long_key, "v")])),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "65-char key must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_value_too_large_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    // Value of 1025 bytes (limit is 1024).
    let big_value: String = "x".repeat(1025);
    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[("key", &big_value)])),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "value > 1024 bytes must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_total_size_exceeded_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    // Build a map whose total key+value size exceeds 16 KiB (16 384 bytes).
    // Each entry: key "kXX" (3 bytes) + value 1000 bytes = 1003 bytes per entry.
    // 17 entries = 17 051 bytes > 16 384.
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let big_value: String = "v".repeat(1000);
    for i in 0..17u32 {
        map.insert(format!("k{i:02}"), big_value.clone());
    }

    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(map),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "total size > 16 KiB must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_invalid_chars_in_key_space_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[("invalid key", "value")])),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "key with space must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_invalid_chars_in_key_at_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[("invalid@key", "value")])),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "key with '@' must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_key_exactly_64_chars_accepted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    // Exactly at the 64-char limit — should pass.
    let exact_key: String = "a".repeat(64);
    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[(&exact_key, "v")])),
            ..Default::default()
        },
    );

    assert!(
        result.is_ok(),
        "64-char key must be accepted; got: {result:?}"
    );
}

#[tokio::test]
async fn update_user_value_exactly_1024_bytes_accepted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user_id = create_user(&h, &realm).await;

    let exactly_1024: String = "x".repeat(1024);
    let result = h.identity().update_user(
        &realm,
        &user_id,
        &UpdateUserRequest {
            attributes: Some(attrs(&[("key", &exactly_1024)])),
            ..Default::default()
        },
    );

    assert!(
        result.is_ok(),
        "value of exactly 1024 bytes must be accepted; got: {result:?}"
    );
}
