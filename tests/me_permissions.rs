//! Integration tests for `GET /v1/me/permissions`.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — `me_permissions:returns_live_set`,
//! `unauthenticated_401`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
use tower::ServiceExt as _;

fn build_router(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

#[tokio::test]
async fn returns_live_set_reflecting_post_issuance_changes() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "u@example.com".into(),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("sess");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    // Assign a role AFTER the token was issued.
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.viewer".into(),
                description: None,
                permissions: vec![Permission::new("docs.view").expect("valid")],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");

    let app = build_router(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me/permissions")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let perms: Vec<&str> = body["permissions"]
        .as_array()
        .expect("permissions array")
        .iter()
        .map(|v| v.as_str().expect("str"))
        .collect();
    assert!(
        perms.contains(&"docs.view"),
        "/v1/me/permissions must resolve freshly after assignment"
    );
}

#[tokio::test]
async fn unauthenticated_returns_401() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let app = build_router(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me/permissions")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
