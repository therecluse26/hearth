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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
        !body["items"].as_array().expect("items").is_empty(),
        "at least one user"
    );
}

// ===== Import tests =====

#[tokio::test]
async fn import_users_creates_all_valid_entries() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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
    let realm = h.create_realm();
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

// ===== CRUD happy-path tests =====

#[tokio::test]
async fn create_user_returns_201_with_user_body() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"email":"newuser@example.com","display_name":"New User"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp_json(resp).await;
    assert_eq!(body["email"], "newuser@example.com");
    assert!(body["id"].is_string(), "response must include user id");
}

#[tokio::test]
async fn get_user_by_id_returns_correct_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let app = build_app(&h).await;

    // Create via domain layer so we have a known ID.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "getme@example.com".into(),
                display_name: "Get Me".into(),
                first_name: "Get".into(),
                last_name: "Me".into(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users/{}", user.id().as_uuid()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["email"], "getme@example.com");
    assert_eq!(body["id"], user.id().as_uuid().to_string());
}

#[tokio::test]
async fn get_user_unknown_id_returns_404() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users/00000000-0000-0000-0000-000000000001")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_user_invalid_id_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users/not-a-uuid")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_returns_updated_display_name() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "updateme@example.com".into(),
                display_name: "Before".into(),
                first_name: "Before".into(),
                last_name: "Name".into(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/users/{}", user.id().as_uuid()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"display_name":"After"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["display_name"], "After");
}

#[tokio::test]
async fn delete_user_returns_204_and_user_gone() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "deleteme@example.com".into(),
                display_name: "Delete Me".into(),
                first_name: "Delete".into(),
                last_name: "Me".into(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    let app = build_app(&h).await;
    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{}", user.id().as_uuid()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    // Confirm the user is no longer reachable.
    let get_resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users/{}", user.id().as_uuid()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

// ===== Realm isolation regression =====

#[tokio::test]
async fn cross_realm_token_denied_on_list() {
    let h = common::TestHarness::embedded().await.expect("harness");

    // realm_a has an admin token; realm_b is a different tenant.
    let realm_a = h.create_realm();
    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed a");
    h.rbac().seed_realm(&realm_b).expect("seed b");

    // Mint a token scoped to realm_a.
    let token_a = admin_token(&h, &realm_a).await;
    let app = build_app(&h).await;

    // Send realm_a token with X-Realm-ID pointing to realm_b.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users")
                .header("X-Realm-ID", realm_b.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token_a}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    // Must be rejected — realm_a token must not access realm_b data.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===== Import idempotency =====

#[tokio::test]
async fn import_duplicate_email_reported_as_per_item_error() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let payload = r#"{"users":[{"email":"dup@example.com","display_name":"Dup"}]}"#;

    let app = build_app(&h).await;

    // First import succeeds.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(payload))
                .expect("request"),
        )
        .await
        .expect("response");
    let b1 = resp_json(resp1).await;
    assert_eq!(b1["imported"], 1);
    assert_eq!(b1["failed"], 0);

    // Second import with same email: implementation returns DuplicateEmail as
    // a per-item error (not idempotent upsert). This test documents current
    // behavior; callers must deduplicate before import.
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(payload))
                .expect("request"),
        )
        .await
        .expect("response");
    let b2 = resp_json(resp2).await;
    assert_eq!(b2["imported"], 0);
    assert_eq!(b2["failed"], 1);
    assert!(
        b2["results"][0]["error"].as_str().is_some(),
        "duplicate import must surface per-item error"
    );
}

// ===== HTTP method correctness =====

#[tokio::test]
async fn update_user_put_returns_405() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "puttest@example.com".into(),
                display_name: "Put Test".into(),
                first_name: "Put".into(),
                last_name: "Test".into(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/admin/users/{}", user.id().as_uuid()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"display_name":"New Name"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ===== Field filter tests =====

#[tokio::test]
async fn filter_users_by_email_returns_exact_match() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    for (email, name) in &[
        ("filter-alice@example.com", "Alice Filter"),
        ("filter-bob@example.com", "Bob Filter"),
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
                .uri("/admin/users?email=filter-alice@example.com")
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
    assert_eq!(items.len(), 1, "expected exactly one match");
    assert_eq!(items[0]["email"], "filter-alice@example.com");
}

#[tokio::test]
async fn filter_users_by_username_returns_substring_matches() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    for (email, name) in &[
        ("un1@example.com", "Alice Wonder"),
        ("un2@example.com", "Bob Stone"),
        ("un3@example.com", "Alice Cooper"),
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
                .uri("/admin/users?username=Alice")
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
    assert_eq!(items.len(), 2, "expected two Alice matches");
    let emails: Vec<&str> = items
        .iter()
        .map(|u| u["email"].as_str().expect("email string"))
        .collect();
    assert!(emails.contains(&"un1@example.com"));
    assert!(emails.contains(&"un3@example.com"));
}

#[tokio::test]
async fn filter_users_by_status_returns_only_matching_status() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    // Import one active and one disabled user so we have known statuses.
    h.identity()
        .import_user(
            &realm,
            &hearth::identity::ImportUserRequest {
                id: None,
                email: "status-active@example.com".into(),
                display_name: "Active User".into(),
                first_name: String::new(),
                last_name: String::new(),
                status: hearth::identity::UserStatus::Active,
                credential: None,
                attributes: Default::default(),
            },
        )
        .expect("import active user");

    h.identity()
        .import_user(
            &realm,
            &hearth::identity::ImportUserRequest {
                id: None,
                email: "status-disabled@example.com".into(),
                display_name: "Disabled User".into(),
                first_name: String::new(),
                last_name: String::new(),
                status: hearth::identity::UserStatus::Disabled,
                credential: None,
                attributes: Default::default(),
            },
        )
        .expect("import disabled user");

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users?status=disabled")
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
    assert!(
        items
            .iter()
            .all(|u| { u["email"].as_str() != Some("status-active@example.com") }),
        "active user must not appear in disabled filter results"
    );
    assert!(
        items
            .iter()
            .any(|u| u["email"] == "status-disabled@example.com"),
        "disabled user must appear in results"
    );
}

#[tokio::test]
async fn filter_users_invalid_status_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let app = build_app(&h).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users?status=bogus")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
