//! Integration tests for admin HTTP role assignment CRUD.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — admin_assignments_rbac:crud,
//! assign_unknown_role_404.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext, User};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
use serde_json::json;
use tower::ServiceExt as _;

struct Ctx {
    h: common::TestHarness,
    realm: RealmId,
    token: String,
    subject_user: User,
}

async fn ctx() -> Ctx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let admin = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("a-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "A".into(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("admin");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seed");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(admin.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("admin assign");
    let session = h
        .identity()
        .create_session(&realm, admin.id(), &SessionContext::default())
        .expect("sess");
    let token = h
        .identity()
        .issue_tokens(&realm, admin.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    // A separate user to target with assignments.
    let target = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("t-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("target");

    Ctx {
        h,
        realm,
        token,
        subject_user: target,
    }
}

async fn send(
    c: &Ctx,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let app = router(Arc::new(AppState::new(
        c.h.identity_arc(),
        c.h.rbac_arc(),
        c.h.audit_arc(),
    )));
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {}", c.token))
        .header("X-Realm-ID", c.realm.as_uuid().to_string());
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    let b = body.map_or(Body::empty(), |v| Body::from(v.to_string()));
    let resp = app.oneshot(req.body(b).expect("req")).await.expect("resp");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1_000_000)
        .await
        .expect("body bytes");
    let json: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

#[tokio::test]
async fn assignment_crud_happy_path() {
    let c = ctx().await;

    // Create a custom role.
    let docs =
        c.h.rbac()
            .create_role(
                &c.realm,
                &CreateRoleRequest {
                    name: "docs.viewer".into(),
                    description: None,
                    permissions: vec![Permission::new("docs.view").expect("valid")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("role");

    // Assign to the target user via HTTP.
    let (status, body) = send(
        &c,
        "POST",
        &format!("/admin/users/{}/roles", c.subject_user.id()),
        Some(json!({"role_id": docs.id.to_string(), "org_id": null})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let assignment_id = body["id"].as_str().expect("id").to_string();

    // List.
    let (status, body) = send(
        &c,
        "GET",
        &format!("/admin/users/{}/roles", c.subject_user.id()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items");
    assert!(!items.is_empty());

    // Delete.
    let (status, _) = send(
        &c,
        "DELETE",
        &format!("/admin/assignments/{assignment_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn assign_unknown_role_returns_404() {
    let c = ctx().await;
    let missing = hearth::rbac::RoleId::generate();
    let (status, body) = send(
        &c,
        "POST",
        &format!("/admin/users/{}/roles", c.subject_user.id()),
        Some(json!({"role_id": missing.to_string(), "org_id": null})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn invalid_org_id_returns_400() {
    let c = ctx().await;
    let role =
        c.h.rbac()
            .create_role(
                &c.realm,
                &CreateRoleRequest {
                    name: "x".into(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("role");
    let (status, _) = send(
        &c,
        "POST",
        &format!("/admin/users/{}/roles", c.subject_user.id()),
        Some(json!({"role_id": role.id.to_string(), "org_id": "not-a-uuid"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
