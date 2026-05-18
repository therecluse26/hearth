//! Integration tests for `GET /admin/users/{id}/effective-permissions`.
//!
//! Covers AUTHZ §8.2 — admin effective-permissions endpoint.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
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
) -> (String, String) {
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
    let user_id = user.id().as_uuid().to_string();

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
    let token = harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    (token, user_id)
}

#[tokio::test]
async fn happy_path_returns_effective_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    // Create a target user and assign them a role with some permissions.
    let target_user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "target@example.com".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");
    let doc_perm = Permission::new("docs.view").expect("valid perm");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.viewer".into(),
                description: None,
                permissions: vec![doc_perm.clone()],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(target_user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let (admin_token, _) = issue_token_for(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;
    let uri = format!(
        "/admin/users/{}/effective-permissions",
        target_user.id().as_uuid()
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    let roles: Vec<&str> = body["roles"]
        .as_array()
        .expect("roles array")
        .iter()
        .map(|v| v.as_str().expect("str"))
        .collect();
    let perms: Vec<&str> = body["permissions"]
        .as_array()
        .expect("permissions array")
        .iter()
        .map(|v| v.as_str().expect("str"))
        .collect();

    assert!(
        roles.contains(&"docs.viewer"),
        "must include assigned role name"
    );
    assert!(
        perms.contains(&"docs.view"),
        "must include docs.view permission"
    );
}

#[tokio::test]
async fn non_admin_token_returns_403() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let (non_admin_token, _) = issue_token_for(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    // Use a synthetic UUID for the target — we should get 403 before
    // the handler even reaches user lookup.
    let dummy_id = "00000000-0000-0000-0000-000000000000";
    let uri = format!("/admin/users/{dummy_id}/effective-permissions");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("Authorization", format!("Bearer {non_admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_user_returns_404() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let (admin_token, _) = issue_token_for(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;

    // Use a UUID that does not correspond to any existing user.
    let nonexistent_id = "ffffffff-ffff-ffff-ffff-ffffffffffff";
    let uri = format!("/admin/users/{nonexistent_id}/effective-permissions");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bad_org_id_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    // Create a target user so we pass the precheck.
    let target_user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "target@example.com".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    let (admin_token, _) = issue_token_for(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;
    let uri = format!(
        "/admin/users/{}/effective-permissions?org_id=not-a-uuid",
        target_user.id().as_uuid()
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed org_id must return 400"
    );
}

#[tokio::test]
async fn scope_narrowing_filters_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let target_user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "target@example.com".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    // Role with two permissions.
    let doc_read = Permission::new("docs.read").expect("valid");
    let doc_write = Permission::new("docs.write").expect("valid");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.editor".into(),
                description: None,
                permissions: vec![doc_read.clone(), doc_write.clone()],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(target_user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    // Create and reconcile a scope that only maps to docs.read.
    h.rbac()
        .reconcile_scopes(
            &realm,
            &[hearth::rbac::ScopeSpec {
                name: "docs_read_only".into(),
                permissions: Some(vec!["docs.read".to_string()]),
            }],
        )
        .expect("reconcile scopes");

    let (admin_token, _) = issue_token_for(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;
    let uri = format!(
        "/admin/users/{}/effective-permissions?scope=docs_read_only",
        target_user.id().as_uuid()
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("Authorization", format!("Bearer {admin_token}"))
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
        perms.contains(&"docs.read"),
        "scope-narrowed permissions must include docs.read"
    );
    assert!(
        !perms.contains(&"docs.write"),
        "scope-narrowed permissions must exclude docs.write"
    );
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let app = build_app(&h).await;
    let dummy_id = "00000000-0000-0000-0000-000000000000";
    let uri = format!("/admin/users/{dummy_id}/effective-permissions");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("Authorization", "Bearer not-a-valid-token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
