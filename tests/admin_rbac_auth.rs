//! Integration tests for admin HTTP auth (permission-gated via `hearth.admin`).
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — `admin_rbac_auth`.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn issue_token_for(
    harness: &common::TestHarness,
    realm: &RealmId,
    email: &str,
    with_admin: bool,
) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    if with_admin {
        let role = harness
            .rbac()
            .get_role_by_name(realm, "realm.admin")
            .expect("lookup")
            .expect("seeded");
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
            .expect("assign admin");
    }

    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

#[tokio::test]
async fn permission_gated_allows_hearth_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token_for(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn permission_gated_denies_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token_for(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_returns_401() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
