//! Integration tests for the HTTP authz surface.
//!
//! Drives `hearth::protocol::http::router` via `tower::ServiceExt::oneshot`
//! against the same wiring as production. Covers `POST /v1/authz/check`
//! and `GET /v1/me/capabilities`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite,
};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::protocol::http::{router, AppState, CapabilityPage, CapabilityPageEntry};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use serde_json::json;
use tower::ServiceExt;

/// Full test rig: temp storage + engines + router + a pre-issued bearer token
/// for a created user, so tests can make authenticated requests directly.
struct Rig {
    app: axum::Router,
    realm_id: RealmId,
    user_id: UserId,
    access_token: String,
    authz: Arc<EmbeddedAuthzEngine>,
    _temp_dir: tempfile::TempDir,
}

fn build_rig() -> Rig {
    build_rig_with_pages(std::collections::HashMap::new())
}

fn build_rig_with_pages(pages: std::collections::HashMap<String, CapabilityPage>) -> Rig {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(temp_dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let identity_engine = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
        )
        .expect("identity engine"),
    );
    let authz_engine = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    ));
    let audit_engine = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        clock,
    ));

    let realm = identity_engine
        .create_realm(&CreateRealmRequest {
            name: format!("authz-http-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let user = identity_engine
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("authz-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Authz User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let session = identity_engine
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("create session");
    let tokens = identity_engine
        .issue_tokens(realm.id(), user.id(), session.id())
        .expect("issue tokens");

    let mut state = AppState::new(
        identity_engine as Arc<dyn IdentityEngine>,
        Arc::clone(&authz_engine) as Arc<dyn hearth::authz::AuthorizationEngine>,
        audit_engine,
    );
    state.capability_pages = Arc::new(pages);
    let app = router(Arc::new(state));

    Rig {
        app,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        access_token: tokens.access_token().to_string(),
        authz: authz_engine,
        _temp_dir: temp_dir,
    }
}

/// Writes a direct `user:<uuid>` → `relation` → `object_type:object_id` tuple.
fn grant(rig: &Rig, object_type: &str, object_id: &str, relation: &str) {
    let tuple = RelationshipTuple::new(
        ObjectRef::new(object_type, object_id).expect("object"),
        relation,
        SubjectRef::direct("user", &rig.user_id.as_uuid().to_string()).expect("subject"),
    )
    .expect("tuple");
    rig.authz
        .write_tuples(&rig.realm_id, &[TupleWrite::Touch(tuple)])
        .expect("write_tuples");
}

async fn json_response(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let v: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    };
    (status, v)
}

// Scenario 1 — single check, allowed.

#[tokio::test]
async fn check_single_allowed() {
    let rig = build_rig();
    grant(&rig, "doc", "readme", "viewer");

    let body = json!({
        "checks": [
            { "object": "doc:readme", "relation": "viewer" }
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let (status, v) = json_response(rig.app.clone().oneshot(req).await.expect("oneshot")).await;
    assert_eq!(status, StatusCode::OK, "response body: {v}");
    assert_eq!(v["results"][0]["allowed"], json!(true));
    assert!(v.get("token").is_some(), "response must include zookie");
}

// Scenario 2 — single check, denied (no tuple).

#[tokio::test]
async fn check_single_denied_without_tuple() {
    let rig = build_rig();

    let body = json!({
        "checks": [
            { "object": "doc:nope", "relation": "viewer" }
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let (status, v) = json_response(rig.app.clone().oneshot(req).await.expect("oneshot")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["results"][0]["allowed"], json!(false));
}

// Scenario 3 — batch preserves order: mixed allowed/denied.

#[tokio::test]
async fn check_batch_preserves_order() {
    let rig = build_rig();
    grant(&rig, "doc", "readme", "viewer");
    grant(&rig, "org", "acme", "member");

    let body = json!({
        "checks": [
            { "object": "doc:readme", "relation": "viewer" },
            { "object": "doc:readme", "relation": "editor" },
            { "object": "org:acme", "relation": "member" }
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let (status, v) = json_response(rig.app.clone().oneshot(req).await.expect("oneshot")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["results"][0]["allowed"], json!(true));
    assert_eq!(v["results"][1]["allowed"], json!(false));
    assert_eq!(v["results"][2]["allowed"], json!(true));
}

// Scenario 4 — subject is taken from the token, never from the body.
// (The request body carries no `subject` field; the handler must use
// `user:<sub>` from the validated claims.)

#[tokio::test]
async fn check_uses_token_subject_not_body() {
    let rig = build_rig();
    grant(&rig, "doc", "readme", "viewer");

    // Even without providing a subject, the grant above (made to the
    // token's user) must resolve to allowed.
    let body = json!({
        "checks": [{ "object": "doc:readme", "relation": "viewer" }]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let (status, v) = json_response(rig.app.clone().oneshot(req).await.expect("oneshot")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["results"][0]["allowed"], json!(true));
}

// Scenario 5 — missing Authorization header → 401.

#[tokio::test]
async fn check_missing_token_returns_401() {
    let rig = build_rig();
    let body = json!({ "checks": [{ "object": "doc:1", "relation": "viewer" }] });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .body(Body::from(body.to_string()))
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// Scenario 6 — malformed object reference → 400.

#[tokio::test]
async fn check_malformed_object_returns_400() {
    let rig = build_rig();
    let body = json!({
        "checks": [{ "object": "not-an-object-ref", "relation": "viewer" }]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// Scenario 7 — batch over the 64-check cap → 400.

#[tokio::test]
async fn check_batch_over_cap_returns_400() {
    let rig = build_rig();
    let checks: Vec<_> = (0..65)
        .map(|i| json!({ "object": format!("doc:{i}"), "relation": "viewer" }))
        .collect();
    let body = json!({ "checks": checks });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// Scenario 8 — empty checks array → 400 (no meaningful work).

#[tokio::test]
async fn check_empty_batch_returns_400() {
    let rig = build_rig();
    let body = json!({ "checks": [] });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authz/check")
        .header("content-type", "application/json")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::from(body.to_string()))
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// /v1/me/capabilities
// ============================================================================

fn org_settings_page() -> std::collections::HashMap<String, CapabilityPage> {
    let mut pages = std::collections::HashMap::new();
    pages.insert(
        "org.settings".to_string(),
        CapabilityPage {
            entries: vec![CapabilityPageEntry {
                object_template: "org:{org_id}".to_string(),
                relations: vec!["member".to_string(), "admin".to_string()],
            }],
        },
    );
    pages
}

// Scenario 9 — capability page returns resolved checks in a map.

#[tokio::test]
async fn capabilities_returns_bundle_for_known_page() {
    let rig = build_rig_with_pages(org_settings_page());
    grant(&rig, "org", "acme", "member");

    let req = Request::builder()
        .method("GET")
        .uri("/v1/me/capabilities?page=org.settings&org_id=acme")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::empty())
        .expect("request");

    let (status, v) = json_response(rig.app.clone().oneshot(req).await.expect("oneshot")).await;
    assert_eq!(status, StatusCode::OK, "response body: {v}");
    assert_eq!(v["capabilities"]["org:acme#member"], json!(true));
    assert_eq!(v["capabilities"]["org:acme#admin"], json!(false));
    assert!(v.get("token").is_some());
}

// Scenario 10 — unknown page key → 404.

#[tokio::test]
async fn capabilities_unknown_page_returns_404() {
    let rig = build_rig_with_pages(org_settings_page());

    let req = Request::builder()
        .method("GET")
        .uri("/v1/me/capabilities?page=nonexistent")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::empty())
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// Scenario 11 — missing template variable → 400.

#[tokio::test]
async fn capabilities_missing_template_var_returns_400() {
    let rig = build_rig_with_pages(org_settings_page());

    // Missing `org_id` query param.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/me/capabilities?page=org.settings")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::empty())
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// Scenario 12 — missing page query param → 400.

#[tokio::test]
async fn capabilities_missing_page_param_returns_400() {
    let rig = build_rig_with_pages(org_settings_page());

    let req = Request::builder()
        .method("GET")
        .uri("/v1/me/capabilities")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", rig.access_token))
        .body(Body::empty())
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// Scenario 13 — missing authorization → 401.

#[tokio::test]
async fn capabilities_missing_auth_returns_401() {
    let rig = build_rig_with_pages(org_settings_page());

    let req = Request::builder()
        .method("GET")
        .uri("/v1/me/capabilities?page=org.settings&org_id=acme")
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .body(Body::empty())
        .expect("request");

    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// Avoid "unused field" warning on SessionId in the common module.
#[allow(dead_code)]
fn _session_id_type_hint(_: SessionId) {}
