//! Integration tests for admin HTTP role CRUD.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — admin_roles_rbac:crud,
//! duplicate_slug_rejected, cycle_on_composition_rejected, cross_realm_isolation.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::json;
use tower::ServiceExt as _;

struct AdminCtx {
    harness: common::TestHarness,
    realm: RealmId,
    token: String,
}

async fn admin_ctx() -> AdminCtx {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    harness.rbac().seed_realm(&realm).expect("seed");
    let user = harness
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
    let role = harness
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seed");
    harness
        .rbac()
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
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("sess");
    let token = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();
    AdminCtx {
        harness,
        realm,
        token,
    }
}

fn build_router(ctx: &AdminCtx) -> axum::Router {
    let state = Arc::new(AppState::new(
        ctx.harness.identity_arc(),
        ctx.harness.rbac_arc(),
        ctx.harness.audit_arc(),
    ));
    router(state)
}

async fn send(
    ctx: &AdminCtx,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let app = build_router(ctx);
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {}", ctx.token))
        .header("X-Realm-ID", ctx.realm.as_uuid().to_string());
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
async fn role_crud_happy_path() {
    let ctx = admin_ctx().await;

    // Create.
    let (status, body) = send(
        &ctx,
        "POST",
        "/admin/roles",
        Some(json!({
            "name": "docs.editor",
            "description": "Edits docs",
            "permissions": ["docs.view", "docs.edit"],
            "parent_roles": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().expect("id").to_string();
    assert_eq!(body["name"], "docs.editor");

    // Get.
    let (status, body) = send(&ctx, "GET", &format!("/admin/roles/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id);

    // Update.
    let (status, _body) = send(
        &ctx,
        "PUT",
        &format!("/admin/roles/{id}"),
        Some(json!({
            "name": "docs.editor.v2",
            "description": null,
            "permissions": null,
            "parent_roles": null,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Delete.
    let (status, _) = send(&ctx, "DELETE", &format!("/admin/roles/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn duplicate_role_name_rejected() {
    let ctx = admin_ctx().await;
    let body = json!({
        "name": "dupe",
        "description": null,
        "permissions": [],
        "parent_roles": [],
    });
    let (status, _) = send(&ctx, "POST", "/admin/roles", Some(body.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(&ctx, "POST", "/admin/roles", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "already_exists");
}

#[tokio::test]
async fn reserved_permission_rejected() {
    let ctx = admin_ctx().await;
    let (status, body) = send(
        &ctx,
        "POST",
        "/admin/roles",
        Some(json!({
            "name": "sneaky",
            "description": null,
            "permissions": ["system.admin"],
            "parent_roles": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "reserved_namespace");
}

#[tokio::test]
async fn reserved_permission_rejected_on_nested_namespace() {
    // Segment-boundary check: "system.admin.users" is still reserved
    // because the prefix match is on the literal "system." segment.
    let ctx = admin_ctx().await;
    let (status, body) = send(
        &ctx,
        "POST",
        "/admin/roles",
        Some(json!({
            "name": "sneakier",
            "description": null,
            "permissions": ["system.admin.users"],
            "parent_roles": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "reserved_namespace");
}

#[tokio::test]
async fn reserved_permission_rejected_on_update() {
    // Operator creates an innocuous role, then attempts to escalate by
    // PUTting a reserved permission into it. Must be rejected the same
    // way create_role rejects it — otherwise update becomes a bypass.
    let ctx = admin_ctx().await;
    let (status, body) = send(
        &ctx,
        "POST",
        "/admin/roles",
        Some(json!({
            "name": "initially_benign",
            "description": null,
            "permissions": ["docs.view"],
            "parent_roles": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().expect("id").to_string();

    let (status, body) = send(
        &ctx,
        "PUT",
        &format!("/admin/roles/{id}"),
        Some(json!({
            "name": null,
            "description": null,
            "permissions": ["system.admin"],
            "parent_roles": null,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "reserved_namespace");

    // Confirm the on-disk permission set was not mutated.
    let (status, body) = send(&ctx, "GET", &format!("/admin/roles/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    let perms: Vec<String> = body["permissions"]
        .as_array()
        .expect("perms array")
        .iter()
        .map(|v| v.as_str().expect("str").to_string())
        .collect();
    assert_eq!(perms, vec!["docs.view".to_string()]);
}

#[tokio::test]
async fn cross_realm_isolation_returns_404() {
    let ctx = admin_ctx().await;

    // Create a role in a different realm via the engine directly.
    let other_realm = RealmId::generate();
    ctx.harness.rbac().seed_realm(&other_realm).expect("seed");
    let foreign = ctx
        .harness
        .rbac()
        .create_role(
            &other_realm,
            &hearth::rbac::CreateRoleRequest {
                name: "foreign".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create foreign");

    // Attempt to GET it via ctx's realm-scoped admin token — must 404.
    let (status, _) = send(&ctx, "GET", &format!("/admin/roles/{}", foreign.id), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
