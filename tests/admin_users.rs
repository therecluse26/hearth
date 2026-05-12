//! Integration tests for the admin user management REST API.
//!
//! Covers search (`?search=`), bulk import (`POST /admin/api/users/import`),
//! and bulk export (`GET /admin/api/users/export`), all of which sit on top
//! of the existing CRUD endpoints introduced in Step 27.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== Test helpers =====

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn admin_token(harness: &common::TestHarness, realm: &RealmId) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@test.example".into(),
                display_name: "Admin User".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

    let role = harness
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin seeded");
    harness
        .rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

async fn resp_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("parse JSON")
}

async fn resp_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("UTF-8")
}

// ===== Search tests =====

#[tokio::test]
async fn search_users_returns_matching_results() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    // Create two users; search should only return the alice match.
    for (email, name) in &[
        ("alice@example.com", "Alice Smith"),
        ("bob@example.com", "Bob Jones"),
    ] {
        h.identity()
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: (*email).into(),
                    display_name: (*name).into(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
    }

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users?search=alice")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1, "expected one match");
    assert_eq!(items[0]["email"], "alice@example.com");
}

#[tokio::test]
async fn search_users_short_query_returns_empty() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users?search=a")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 0, "single-char search must return empty");
}

#[tokio::test]
async fn list_users_without_search_returns_paginated_results() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    h.identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "user@example.com".into(),
                display_name: "Test User".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    // Should include at least the newly created user and the admin user.
    assert!(
        body["items"].as_array().expect("items").len() >= 1,
        "at least one user"
    );
}

// ===== Import tests =====

#[tokio::test]
async fn import_users_creates_all_valid_entries() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let payload = serde_json::json!({
        "users": [
            {
                "email": "import1@example.com",
                "display_name": "Import One",
                "first_name": "Import",
                "last_name": "One",
                "status": "active"
            },
            {
                "email": "import2@example.com",
                "display_name": "Import Two",
                "status": "disabled",
                "attributes": {"plan": "enterprise"}
            }
        ]
    });

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["imported"], 2, "both users should be imported");
    assert_eq!(body["failed"], 0, "no failures expected");
    assert_eq!(body["total"], 2);

    // Verify the users actually exist in storage.
    let u1 = h
        .identity()
        .get_user_by_email(&realm, "import1@example.com")
        .expect("lookup")
        .expect("import1 must exist");
    assert_eq!(u1.display_name(), "Import One");

    let u2 = h
        .identity()
        .get_user_by_email(&realm, "import2@example.com")
        .expect("lookup")
        .expect("import2 must exist");
    assert_eq!(u2.status(), hearth::identity::UserStatus::Disabled);
}

#[tokio::test]
async fn import_users_reports_per_item_errors() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    // First create a user that will collide with the import.
    h.identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "existing@example.com".into(),
                display_name: "Existing User".into(),
                first_name: "Existing".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create existing user");

    let payload = serde_json::json!({
        "users": [
            {"email": "new@example.com", "display_name": "New User"},
            {"email": "existing@example.com", "display_name": "Existing User"}
        ]
    });

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["imported"], 1);
    assert_eq!(body["failed"], 1);

    let results = body["results"].as_array().expect("results array");
    let failed = results
        .iter()
        .find(|r| !r["error"].is_null())
        .expect("one failed result");
    assert_eq!(failed["email"], "existing@example.com");
}

#[tokio::test]
async fn import_users_invalid_status_returns_per_item_error() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let payload = serde_json::json!({
        "users": [
            {"email": "good@example.com", "display_name": "Good User", "status": "active"},
            {"email": "bad@example.com", "display_name": "Bad User", "status": "bogus_status"}
        ]
    });

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["imported"], 1);
    assert_eq!(body["failed"], 1);
}

#[tokio::test]
async fn import_users_empty_array_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"users":[]}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===== Export tests =====

#[tokio::test]
async fn export_users_returns_all_users_as_json() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    for i in 0..3u32 {
        h.identity()
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("user{i}@example.com"),
                    display_name: format!("User {i}"),
                    first_name: format!("User{i}"),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
    }

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users/export")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    // 3 regular users + the admin user created in admin_token().
    assert_eq!(
        body["count"],
        serde_json::json!(4),
        "expected 4 users in export"
    );
    let users = body["users"].as_array().expect("users array");
    for u in users {
        assert!(u["email"].is_string(), "email must be present");
        assert!(u["id"].is_string(), "id must be present");
        assert!(u["status"].is_string(), "status must be present");
    }
}

#[tokio::test]
async fn export_users_includes_attributes() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    // Import a user with attributes, then export and verify they appear.
    h.identity()
        .import_user(
            &realm,
            &hearth::identity::ImportUserRequest {
                id: None,
                email: "tagged@example.com".into(),
                display_name: "Tagged User".into(),
                first_name: "Tagged".into(),
                last_name: "User".into(),
                status: hearth::identity::UserStatus::Active,
                credential: None,
                attributes: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("tier".into(), "gold".into());
                    m
                },
            },
        )
        .expect("import user with attributes");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users/export")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    let users = body["users"].as_array().expect("users");
    let tagged = users
        .iter()
        .find(|u| u["email"] == "tagged@example.com")
        .expect("tagged user must appear in export");
    assert_eq!(tagged["attributes"]["tier"], "gold");
}

#[tokio::test]
async fn export_users_ndjson_format() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    h.identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "ndjson@example.com".into(),
                display_name: "NDJSON User".into(),
                first_name: "NDJSON".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users/export?format=ndjson")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/x-ndjson"),
        "content-type must be ndjson"
    );

    let text = resp_text(resp).await;
    // Each non-empty line must be valid JSON.
    for line in text.lines() {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line is not valid JSON: {e}\nLine: {line}"));
    }
    // At least two lines: the admin user + the ndjson user.
    assert!(
        text.lines().count() >= 2,
        "at least two NDJSON lines, got: {text}"
    );
}

#[tokio::test]
async fn export_requires_admin_token() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users/export")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn import_requires_admin_token() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"users":[{"email":"x@example.com","display_name":"X"}]}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
