//! Integration tests for user search and realm name index.

mod common;

use hearth::identity::{CreateRealmRequest, CreateUserRequest, IdentityEngine, RealmStatus};

/// Helper: creates a realm and returns its ID.
fn setup_realm(identity: &dyn IdentityEngine) -> hearth::core::RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: "search-test-realm".to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

// ===== search_users tests =====

#[tokio::test]
async fn search_users_by_email_prefix() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let tid = setup_realm(identity);

    identity
        .create_user(
            &tid,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Smith".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create alice");
    identity
        .create_user(
            &tid,
            &CreateUserRequest {
                email: "bob@example.com".to_string(),
                display_name: "Bob Jones".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create bob");

    let results = identity
        .search_users(&tid, "alice", 10)
        .expect("search alice");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].email(), "alice@example.com");
}

#[tokio::test]
async fn search_users_by_display_name() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let tid = setup_realm(identity);

    identity
        .create_user(
            &tid,
            &CreateUserRequest {
                email: "user1@test.com".to_string(),
                display_name: "Charlie Brown".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let results = identity
        .search_users(&tid, "charlie", 10)
        .expect("search by name");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].display_name(), "Charlie Brown");
}

#[tokio::test]
async fn search_users_case_insensitive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let tid = setup_realm(identity);

    identity
        .create_user(
            &tid,
            &CreateUserRequest {
                email: "Alice@Example.COM".to_string(),
                display_name: "ALICE SMITH".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Search with different case
    let results = identity
        .search_users(&tid, "alice", 10)
        .expect("search lowercase");
    assert_eq!(results.len(), 1);

    let results = identity
        .search_users(&tid, "ALICE", 10)
        .expect("search uppercase");
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn search_users_respects_limit() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let tid = setup_realm(identity);

    for i in 0..5 {
        identity
            .create_user(
                &tid,
                &CreateUserRequest {
                    email: format!("user{i}@example.com"),
                    display_name: format!("User {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                },
            )
            .expect("create user");
    }

    let results = identity
        .search_users(&tid, "user", 3)
        .expect("search with limit");
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn search_users_empty_query_returns_empty() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let tid = setup_realm(identity);

    identity
        .create_user(
            &tid,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Empty or too-short query returns nothing (min 2 chars)
    let results = identity.search_users(&tid, "", 10).expect("empty query");
    assert!(results.is_empty());

    let results = identity.search_users(&tid, "a", 10).expect("1-char query");
    assert!(results.is_empty());
}

#[tokio::test]
async fn search_users_no_matches_returns_empty() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let tid = setup_realm(identity);

    identity
        .create_user(
            &tid,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let results = identity
        .search_users(&tid, "zzzzz", 10)
        .expect("no match query");
    assert!(results.is_empty());
}

// ===== get_realm_by_name tests =====

#[tokio::test]
async fn get_realm_by_name_found() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let created = identity
        .create_realm(&CreateRealmRequest {
            name: "my-realm".to_string(),
            config: None,
        })
        .expect("create");

    let found = identity
        .get_realm_by_name("my-realm")
        .expect("lookup")
        .expect("should find realm");
    assert_eq!(found.id(), created.id());
    assert_eq!(found.name(), "my-realm");
}

#[tokio::test]
async fn get_realm_by_name_not_found() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let result = identity.get_realm_by_name("nonexistent").expect("lookup");
    assert!(result.is_none());
}

#[tokio::test]
async fn realm_name_index_survives_rename() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "original-name".to_string(),
            config: None,
        })
        .expect("create");

    identity
        .update_realm(
            realm.id(),
            &hearth::identity::UpdateRealmRequest {
                name: Some("new-name".to_string()),
                ..Default::default()
            },
        )
        .expect("rename");

    // Old name should not resolve
    assert!(identity
        .get_realm_by_name("original-name")
        .expect("lookup old")
        .is_none());

    // New name should resolve
    let found = identity
        .get_realm_by_name("new-name")
        .expect("lookup new")
        .expect("should find renamed realm");
    assert_eq!(found.id(), realm.id());
}

#[tokio::test]
async fn realm_name_index_cleaned_on_delete() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "to-delete".to_string(),
            config: None,
        })
        .expect("create");

    identity.delete_realm(realm.id()).expect("delete");

    // Name should not resolve after deletion
    assert!(identity
        .get_realm_by_name("to-delete")
        .expect("lookup")
        .is_none());
}

#[tokio::test]
async fn realm_archived_status_persists() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "archive-test".to_string(),
            config: None,
        })
        .expect("create");

    let updated = identity
        .update_realm(
            realm.id(),
            &hearth::identity::UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive");

    assert_eq!(updated.status(), RealmStatus::Archived);

    // Fetch again to verify persistence
    let fetched = identity
        .get_realm(realm.id())
        .expect("get")
        .expect("should exist");
    assert_eq!(fetched.status(), RealmStatus::Archived);
}
