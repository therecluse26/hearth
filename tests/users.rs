//! Integration tests for user CRUD operations.
//!
//! Black box tests via `TestHarness` — exercises the identity engine
//! through the public `IdentityEngine` trait.

mod common;

use hearth::core::TenantId;
use hearth::identity::{CreateUserRequest, UpdateUserRequest, UserStatus};

// ===== P0 fast: Full CRUD lifecycle =====

#[tokio::test]
async fn create_and_read_user_by_id() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();

    let created = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Smith".to_string(),
            },
        )
        .expect("create");

    let fetched = harness
        .identity()
        .get_user(&tenant, created.id())
        .expect("get")
        .expect("should exist");

    assert_eq!(fetched.email(), "alice@example.com");
    assert_eq!(fetched.display_name(), "Alice Smith");
    assert_eq!(fetched.status(), UserStatus::Active);
}

#[tokio::test]
async fn create_and_read_user_by_email() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();

    let created = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "Bob@Example.COM".to_string(),
                display_name: "Bob".to_string(),
            },
        )
        .expect("create");

    // Lookup by original casing — should still find via normalization
    let fetched = harness
        .identity()
        .get_user_by_email(&tenant, "BOB@EXAMPLE.COM")
        .expect("get")
        .expect("should exist");

    assert_eq!(fetched.id(), created.id());
    assert_eq!(fetched.email(), "bob@example.com");
}

#[tokio::test]
async fn update_user_fields() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();

    let created = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create");

    let updated = harness
        .identity()
        .update_user(
            &tenant,
            created.id(),
            &UpdateUserRequest {
                display_name: Some("Alice Smith".to_string()),
                status: Some(UserStatus::Disabled),
                ..UpdateUserRequest::default()
            },
        )
        .expect("update");

    assert_eq!(updated.display_name(), "Alice Smith");
    assert_eq!(updated.status(), UserStatus::Disabled);
    assert_eq!(updated.email(), "alice@example.com"); // unchanged
    assert!(updated.updated_at() >= created.updated_at());
}

#[tokio::test]
async fn delete_user_removes_from_both_indexes() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();

    let created = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create");

    harness
        .identity()
        .delete_user(&tenant, created.id())
        .expect("delete");

    assert!(harness
        .identity()
        .get_user(&tenant, created.id())
        .expect("get")
        .is_none());
    assert!(harness
        .identity()
        .get_user_by_email(&tenant, "alice@example.com")
        .expect("get")
        .is_none());
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();

    harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("first create");

    let err = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "Alice@Example.COM".to_string(),
                display_name: "Other".to_string(),
            },
        )
        .expect_err("should fail");

    assert!(
        format!("{err}").contains("already exists"),
        "error should indicate duplicate: {err}"
    );
}

// ===== P0 fast: Delete cascade (partial — user only) =====

#[tokio::test]
async fn delete_frees_email_for_reuse() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = TenantId::generate();

    let first = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice 1".to_string(),
            },
        )
        .expect("create");

    harness
        .identity()
        .delete_user(&tenant, first.id())
        .expect("delete");

    // Should be able to re-create with same email
    let second = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice 2".to_string(),
            },
        )
        .expect("re-create should succeed");

    assert_ne!(first.id(), second.id());
}

// ===== Cross-tenant isolation =====

#[tokio::test]
async fn cross_tenant_isolation() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();

    let alice_a = harness
        .identity()
        .create_user(
            &tenant_a,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice A".to_string(),
            },
        )
        .expect("create in tenant A");

    // Same email in different tenant should succeed
    let alice_b = harness
        .identity()
        .create_user(
            &tenant_b,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice B".to_string(),
            },
        )
        .expect("create in tenant B should succeed");

    assert_ne!(alice_a.id(), alice_b.id());

    // Can't see tenant A's user from tenant B
    assert!(harness
        .identity()
        .get_user(&tenant_b, alice_a.id())
        .expect("get")
        .is_none());
}

// ===== P1: Server HTTP mode (ignored until protocol layer) =====

#[tokio::test]
#[ignore = "HTTP protocol layer not yet implemented"]
async fn server_mode_crud() {
    let _harness = common::TestHarness::server()
        .await
        .expect("server harness setup");
    // Will test the same CRUD operations through HTTP when available
}
