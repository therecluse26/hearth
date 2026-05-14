#![allow(clippy::unwrap_used)]
//! SCIM 2.0 integration tests — drive the HTTP router via `tower::ServiceExt`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use serde_json::{json, Value};
use tower::ServiceExt;

/// The rig holds the router plus a handle to each engine so tests can
/// reach in to verify side effects, seed admin tuples, etc.
struct Rig {
    app: axum::Router,
    identity: Arc<EmbeddedIdentityEngine>,
    authz: Arc<EmbeddedRbacEngine>,
    _storage: Arc<EmbeddedStorageEngine>,
    // Keep the tempdir alive so mmap-backed storage stays valid.
    _dir: tempfile::TempDir,
}

fn build_rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    );
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let state = Arc::new(AppState::new(identity.clone(), authz.clone(), audit));
    Rig {
        app: router(state),
        identity,
        authz,
        _storage: engine,
        _dir: dir,
    }
}

fn setup_admin(rig: &Rig) -> (RealmId, String) {
    let realm = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "scim-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = rig
        .identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "admin@scim.test".to_string(),
                display_name: "Admin".to_string(),
                first_name: "Admin".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

    // Grant admin role via RBAC assignment.
    use hearth::identity::IdentityEngine;
    rig.authz.seed_realm(realm.id()).expect("seed");
    let admin_role = rig
        .authz
        .get_role_by_name(realm.id(), "realm.admin")
        .expect("lookup")
        .expect("seed role");
    rig.authz
        .assign_role(
            realm.id(),
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let session = rig
        .identity
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("session");
    let tokens = rig
        .identity
        .issue_tokens(realm.id(), user.id(), session.id())
        .expect("tokens");
    (realm.id().clone(), tokens.access_token().to_string())
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let value: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };
    (status, value)
}

fn scim_request(
    method: &str,
    path: &str,
    realm: &RealmId,
    token: &str,
) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {token}"))
}

// ===== Discovery =====

#[tokio::test]
async fn discovery_service_provider_config_returns_expected_shape() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let req = scim_request("GET", "/scim/v2/ServiceProviderConfig", &realm, &token)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&rig.app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["patch"]["supported"], json!(true));
    assert_eq!(body["filter"]["supported"], json!(true));
    assert_eq!(body["bulk"]["supported"], json!(false));
}

#[tokio::test]
async fn discovery_schemas_lists_user_and_group() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let req = scim_request("GET", "/scim/v2/Schemas", &realm, &token)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&rig.app, req).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array");
    let ids: Vec<&str> = arr.iter().filter_map(|v| v["id"].as_str()).collect();
    assert!(ids.contains(&"urn:ietf:params:scim:schemas:core:2.0:User"));
    assert!(ids.contains(&"urn:ietf:params:scim:schemas:core:2.0:Group"));
}

// ===== Users CRUD =====

#[tokio::test]
async fn users_post_creates_with_location_header_and_etag() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice@example.com",
        "externalId": "okta-alice",
        "name": {"givenName": "Alice", "familyName": "Example"},
        "emails": [{"value": "alice@example.com", "primary": true}],
        "active": true
    });
    let req = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(payload.to_string()))
        .unwrap();
    let resp = rig.app.clone().oneshot(req).await.expect("req");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let location = resp
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with("/scim/v2/Users/"));
    assert!(resp.headers().get("etag").is_some());
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["externalId"], "okta-alice");
    assert_eq!(json["userName"], "alice@example.com");
}

#[tokio::test]
async fn users_post_duplicate_external_id_is_conflict() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice@example.com",
        "externalId": "okta-dup",
        "name": {"givenName": "Alice", "familyName": "Example"}
    });
    let first = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(payload.to_string()))
        .unwrap();
    let (status1, _) = send(&rig.app, first).await;
    assert_eq!(status1, StatusCode::CREATED);

    let second = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "bob@example.com",
                "externalId": "okta-dup",
                "name": {"givenName": "Bob", "familyName": "Example"}
            })
            .to_string(),
        ))
        .unwrap();
    let (status2, body2) = send(&rig.app, second).await;
    assert_eq!(status2, StatusCode::CONFLICT);
    assert_eq!(body2["scimType"], "uniqueness");
    assert_eq!(
        body2["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
}

#[tokio::test]
async fn users_get_by_id_roundtrips() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let post = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "alice@example.com",
                "name": {"givenName": "Alice", "familyName": "Example"}
            })
            .to_string(),
        ))
        .unwrap();
    let (_, created) = send(&rig.app, post).await;
    let id = created["id"].as_str().unwrap();

    let get = scim_request("GET", &format!("/scim/v2/Users/{id}"), &realm, &token)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&rig.app, get).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["userName"], "alice@example.com");
    assert_eq!(body["id"], id);
}

#[tokio::test]
async fn users_patch_active_flips_to_disabled() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let post = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "alice@example.com",
                "name": {"givenName": "Alice", "familyName": "Example"},
                "active": true
            })
            .to_string(),
        ))
        .unwrap();
    let (_, created) = send(&rig.app, post).await;
    let id = created["id"].as_str().unwrap();

    let patch = scim_request("PATCH", &format!("/scim/v2/Users/{id}"), &realm, &token)
        .body(Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": false}]
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&rig.app, patch).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], false);
}

#[tokio::test]
async fn users_delete_cascades_and_returns_204() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let post = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "alice@example.com",
                "externalId": "okta-delete",
                "name": {"givenName": "Alice", "familyName": "Example"}
            })
            .to_string(),
        ))
        .unwrap();
    let (_, created) = send(&rig.app, post).await;
    let id = created["id"].as_str().unwrap();

    let del = scim_request("DELETE", &format!("/scim/v2/Users/{id}"), &realm, &token)
        .body(Body::empty())
        .unwrap();
    let resp = rig.app.clone().oneshot(del).await.expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Re-provision with the same externalId must succeed (cascade).
    let repost = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "alice2@example.com",
                "externalId": "okta-delete",
                "name": {"givenName": "Alice", "familyName": "Example"}
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = send(&rig.app, repost).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn users_list_supports_filter_and_pagination() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    for i in 0..5 {
        let post = scim_request("POST", "/scim/v2/Users", &realm, &token)
            .body(Body::from(
                json!({
                    "userName": format!("u{i}@example.com"),
                    "name": {"givenName": "U", "familyName": format!("{i}")}
                })
                .to_string(),
            ))
            .unwrap();
        let (status, _) = send(&rig.app, post).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    // Filter by userName exact match.
    let filter: String =
        form_urlencoded::byte_serialize(r#"userName eq "u2@example.com""#.as_bytes()).collect();
    let get = scim_request(
        "GET",
        &format!("/scim/v2/Users?filter={filter}"),
        &realm,
        &token,
    )
    .body(Body::empty())
    .unwrap();
    let (status, body) = send(&rig.app, get).await;
    assert_eq!(status, StatusCode::OK);
    let resources = body["Resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["userName"], "u2@example.com");
}

// ===== Groups =====

#[tokio::test]
async fn groups_post_creates_organization_and_members() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);

    // Provision a user first so we have something to reference.
    let user_post = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "m@example.com",
                "name": {"givenName": "M", "familyName": "One"}
            })
            .to_string(),
        ))
        .unwrap();
    let (_, created_user) = send(&rig.app, user_post).await;
    let user_id = created_user["id"].as_str().unwrap().to_string();

    let gpost = scim_request("POST", "/scim/v2/Groups", &realm, &token)
        .body(Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineering",
                "externalId": "okta-eng",
                "members": [{"value": user_id}]
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&rig.app, gpost).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["displayName"], "Engineering");
    assert_eq!(body["externalId"], "okta-eng");
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["value"], user_id);
}

// ===== Groups PATCH =====

#[tokio::test]
async fn groups_patch_renames_group_and_adds_member() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);

    // Provision two users.
    let u1_post = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "first@example.com",
                "name": {"givenName": "First", "familyName": "User"}
            })
            .to_string(),
        ))
        .unwrap();
    let (_, u1) = send(&rig.app, u1_post).await;
    let u1_id = u1["id"].as_str().unwrap().to_string();

    let u2_post = scim_request("POST", "/scim/v2/Users", &realm, &token)
        .body(Body::from(
            json!({
                "userName": "second@example.com",
                "name": {"givenName": "Second", "familyName": "User"}
            })
            .to_string(),
        ))
        .unwrap();
    let (_, u2) = send(&rig.app, u2_post).await;
    let u2_id = u2["id"].as_str().unwrap().to_string();

    // Create group with only the first user.
    let gpost = scim_request("POST", "/scim/v2/Groups", &realm, &token)
        .body(Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "OldName",
                "members": [{"value": u1_id}]
            })
            .to_string(),
        ))
        .unwrap();
    let (status, gbody) = send(&rig.app, gpost).await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = gbody["id"].as_str().unwrap().to_string();

    // PATCH: rename the group and add the second user.
    let patch = scim_request("PATCH", &format!("/scim/v2/Groups/{group_id}"), &realm, &token)
        .body(Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "displayName", "value": "NewName"},
                    {"op": "add", "path": "members", "value": [{"value": u2_id}]}
                ]
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&rig.app, patch).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["displayName"], "NewName");
    let member_ids: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["value"].as_str())
        .collect();
    assert!(member_ids.contains(&u1_id.as_str()), "original member retained");
    assert!(member_ids.contains(&u2_id.as_str()), "new member added");
}

// ===== Auth =====

#[tokio::test]
async fn missing_bearer_returns_scim_401() {
    let rig = build_rig();
    let realm = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "no-bearer".to_string(),
            config: None,
        })
        .expect("create");
    let req = Request::builder()
        .method("GET")
        .uri("/scim/v2/Users")
        .header("x-realm-id", realm.id().as_uuid().to_string())
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&rig.app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
}

#[tokio::test]
async fn invalid_filter_returns_scim_400_with_scim_type() {
    let rig = build_rig();
    let (realm, token) = setup_admin(&rig);
    let filter: String =
        form_urlencoded::byte_serialize(r#"emails[type eq "work"].value eq "x""#.as_bytes())
            .collect();
    let req = scim_request(
        "GET",
        &format!("/scim/v2/Users?filter={filter}"),
        &realm,
        &token,
    )
    .body(Body::empty())
    .unwrap();
    let (status, body) = send(&rig.app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidFilter");
}
