//! Integration tests for admin HTTP group CRUD + membership.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — admin_groups_rbac:crud_and_members,
//! duplicate_name_rejected, cycle_on_nesting_rejected.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext, User};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::json;
use tower::ServiceExt as _;

struct Ctx {
    h: common::TestHarness,
    realm: RealmId,
    token: String,
    admin_user: User,
}

async fn ctx() -> Ctx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("a-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "A".into(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("user");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seed");
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
    Ctx {
        h,
        realm,
        token,
        admin_user: user,
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
async fn group_crud_and_member_management() {
    let c = ctx().await;

    // Create group A.
    let (status, body) = send(
        &c,
        "POST",
        "/admin/groups",
        Some(json!({"name": "Engineers", "slug": "eng", "description": null})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let gid = body["id"].as_str().expect("id").to_string();

    // Add admin user as a member.
    let (status, _) = send(
        &c,
        "POST",
        &format!("/admin/groups/{gid}/members"),
        Some(json!({"type": "user", "id": c.admin_user.id().to_string()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // List members.
    let (status, body) = send(&c, "GET", &format!("/admin/groups/{gid}/members"), None).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);

    // Delete group.
    let (status, _) = send(&c, "DELETE", &format!("/admin/groups/{gid}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn duplicate_group_slug_rejected() {
    let c = ctx().await;
    let body = json!({"name": "Dupe", "slug": "dupe", "description": null});
    let (status, _) = send(&c, "POST", "/admin/groups", Some(body.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(&c, "POST", "/admin/groups", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "already_exists");
}

#[tokio::test]
async fn nested_group_cycle_rejected() {
    let c = ctx().await;
    let (_, a) = send(
        &c,
        "POST",
        "/admin/groups",
        Some(json!({"name": "A", "slug": "a", "description": null})),
    )
    .await;
    let a_id = a["id"].as_str().expect("id").to_string();
    let (_, b) = send(
        &c,
        "POST",
        "/admin/groups",
        Some(json!({"name": "B", "slug": "b", "description": null})),
    )
    .await;
    let b_id = b["id"].as_str().expect("id").to_string();

    // b ⊂ a ok.
    let (s, _) = send(
        &c,
        "POST",
        &format!("/admin/groups/{a_id}/members"),
        Some(json!({"type": "group", "id": b_id.clone()})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    // a ⊂ b would cycle.
    let (s, body) = send(
        &c,
        "POST",
        &format!("/admin/groups/{b_id}/members"),
        Some(json!({"type": "group", "id": a_id})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "cycle_detected");
}
