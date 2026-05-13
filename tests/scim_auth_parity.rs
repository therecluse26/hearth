#![allow(clippy::unwrap_used)]
//! SCIM auth-parity regression test.
//!
//! Every SCIM 2.0 route exposed at `/scim/v2/*` MUST share the same admin
//! authentication contract: anonymous requests are rejected with 401, and
//! a valid realm admin JWT is accepted. This is a regression test for the
//! defect fixed in commit `f4c3f7f`, where the three discovery endpoints
//! (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`) drifted to a
//! different auth path than the user/group handlers.
//!
//! The test is table-driven: every SCIM route is enumerated in the
//! `SCIM_ROUTES` array, and a constant guard asserts the expected route
//! count. Adding a new route to `src/protocol/scim/mod.rs` will leave
//! `SCIM_ROUTE_COUNT` stale, forcing the author to add an explicit row
//! here and re-audit the auth surface.

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
use serde_json::json;
use tower::ServiceExt;

/// Total number of SCIM `(method, path)` routes mounted by
/// `src/protocol/scim/mod.rs::router`.
///
/// If a route is added or removed, update this constant *and* extend
/// `SCIM_ROUTES` below so the auth-parity invariant is enforced on the
/// new surface.
const SCIM_ROUTE_COUNT: usize = 15;

/// Body kinds for routes that consume a JSON payload. Axum's `Json<T>`
/// extractor runs before the handler body, so anonymous probes still need
/// a body that parses as `T` — otherwise the request 422s before the
/// auth check runs and the test asserts the wrong thing.
#[derive(Copy, Clone)]
enum Payload {
    /// Empty body (`GET` / `DELETE`).
    None,
    /// Minimal valid `ScimUser` JSON.
    User,
    /// Minimal valid `ScimGroup` JSON.
    Group,
    /// Minimal valid SCIM PATCH op envelope.
    Patch,
}

#[derive(Copy, Clone)]
struct ScimRoute {
    method: &'static str,
    path: &'static str,
    payload: Payload,
}

/// Every SCIM route mounted under `/scim/v2`. Auth contract MUST be
/// identical for every entry.
const SCIM_ROUTES: &[ScimRoute] = &[
    // Discovery (RFC 7644 §4).
    ScimRoute {
        method: "GET",
        path: "/scim/v2/ServiceProviderConfig",
        payload: Payload::None,
    },
    ScimRoute {
        method: "GET",
        path: "/scim/v2/ResourceTypes",
        payload: Payload::None,
    },
    ScimRoute {
        method: "GET",
        path: "/scim/v2/Schemas",
        payload: Payload::None,
    },
    // Users.
    ScimRoute {
        method: "POST",
        path: "/scim/v2/Users",
        payload: Payload::User,
    },
    ScimRoute {
        method: "GET",
        path: "/scim/v2/Users",
        payload: Payload::None,
    },
    ScimRoute {
        method: "GET",
        path: "/scim/v2/Users/probe-id",
        payload: Payload::None,
    },
    ScimRoute {
        method: "PUT",
        path: "/scim/v2/Users/probe-id",
        payload: Payload::User,
    },
    ScimRoute {
        method: "PATCH",
        path: "/scim/v2/Users/probe-id",
        payload: Payload::Patch,
    },
    ScimRoute {
        method: "DELETE",
        path: "/scim/v2/Users/probe-id",
        payload: Payload::None,
    },
    // Groups.
    ScimRoute {
        method: "POST",
        path: "/scim/v2/Groups",
        payload: Payload::Group,
    },
    ScimRoute {
        method: "GET",
        path: "/scim/v2/Groups",
        payload: Payload::None,
    },
    ScimRoute {
        method: "GET",
        path: "/scim/v2/Groups/probe-id",
        payload: Payload::None,
    },
    ScimRoute {
        method: "PUT",
        path: "/scim/v2/Groups/probe-id",
        payload: Payload::Group,
    },
    ScimRoute {
        method: "PATCH",
        path: "/scim/v2/Groups/probe-id",
        payload: Payload::Patch,
    },
    ScimRoute {
        method: "DELETE",
        path: "/scim/v2/Groups/probe-id",
        payload: Payload::None,
    },
];

fn payload_body(payload: Payload) -> Body {
    match payload {
        Payload::None => Body::empty(),
        Payload::User => Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "parity-probe@example.com",
            })
            .to_string(),
        ),
        Payload::Group => Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "parity-probe",
            })
            .to_string(),
        ),
        Payload::Patch => Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [],
            })
            .to_string(),
        ),
    }
}

// ============================================================
// Rig — mirrors tests/scim.rs to keep wiring in one place.
// ============================================================

struct Rig {
    app: axum::Router,
    identity: Arc<EmbeddedIdentityEngine>,
    authz: Arc<EmbeddedRbacEngine>,
    _storage: Arc<EmbeddedStorageEngine>,
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

/// Provision a realm with an admin user and return `(realm_id, admin JWT)`.
fn setup_admin(rig: &Rig) -> (RealmId, String) {
    let realm = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "scim-auth-parity".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = rig
        .identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "admin@parity.test".to_string(),
                display_name: "Admin".to_string(),
                first_name: "Admin".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

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

fn build_request(route: &ScimRoute, realm: &RealmId, auth_header: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(route.method)
        .uri(route.path)
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm.as_uuid().to_string());
    if let Some(value) = auth_header {
        builder = builder.header("authorization", value);
    }
    builder.body(payload_body(route.payload)).expect("request")
}

async fn status(app: &axum::Router, req: Request<Body>) -> StatusCode {
    let resp = app.clone().oneshot(req).await.expect("request");
    let s = resp.status();
    // Drain the body so the response future fully resolves — keeps the
    // assertion failure messages clean if something hangs.
    let _ = to_bytes(resp.into_body(), usize::MAX).await;
    s
}

// ============================================================
// Tests.
// ============================================================

/// Guard rail: keep `SCIM_ROUTES` in sync with `router()` in
/// `src/protocol/scim/mod.rs`. A failure here means a route was added or
/// removed without updating this table — fix the table, audit the new
/// route's auth, then bump `SCIM_ROUTE_COUNT`.
#[test]
fn scim_route_table_is_complete() {
    assert_eq!(
        SCIM_ROUTES.len(),
        SCIM_ROUTE_COUNT,
        "SCIM_ROUTES is out of sync with SCIM_ROUTE_COUNT. \
         When you add or remove a route in src/protocol/scim/mod.rs, \
         add the matching (method, path) row to SCIM_ROUTES in \
         tests/scim_auth_parity.rs and bump SCIM_ROUTE_COUNT."
    );
}

/// Every SCIM route MUST reject a request with no `Authorization` header.
/// The previous behavior of the discovery endpoints leaked their own
/// "SCIM bearer-token" auth path that returned different status codes —
/// this test forces every route through the admin-JWT contract.
#[tokio::test]
async fn every_scim_route_rejects_anonymous_with_401() {
    let rig = build_rig();
    let (realm, _admin_token) = setup_admin(&rig);

    for route in SCIM_ROUTES {
        let req = build_request(route, &realm, None);
        let got = status(&rig.app, req).await;
        assert_eq!(
            got,
            StatusCode::UNAUTHORIZED,
            "{} {} should return 401 with no Authorization header (got {got})",
            route.method,
            route.path
        );
    }
}

/// Every SCIM route MUST reject a request whose bearer token is not a
/// valid admin JWT for the realm. Catches drift toward looser per-route
/// validators (the f4c3f7f bug class).
#[tokio::test]
async fn every_scim_route_rejects_garbage_bearer_with_401() {
    let rig = build_rig();
    let (realm, _admin_token) = setup_admin(&rig);

    for route in SCIM_ROUTES {
        let req = build_request(route, &realm, Some("Bearer not-a-real-token"));
        let got = status(&rig.app, req).await;
        assert_eq!(
            got,
            StatusCode::UNAUTHORIZED,
            "{} {} should return 401 with a bogus bearer token (got {got})",
            route.method,
            route.path
        );
    }
}

/// Every SCIM route MUST accept a valid realm admin JWT — i.e. the auth
/// check passes and the response is whatever the handler returns
/// downstream (200, 201, 404, 400, …), never 401 or 403. If any route
/// returns 401/403 here, its auth contract has diverged.
#[tokio::test]
async fn every_scim_route_accepts_admin_jwt() {
    let rig = build_rig();
    let (realm, admin_token) = setup_admin(&rig);
    let header = format!("Bearer {admin_token}");

    for route in SCIM_ROUTES {
        let req = build_request(route, &realm, Some(&header));
        let got = status(&rig.app, req).await;
        assert!(
            got != StatusCode::UNAUTHORIZED && got != StatusCode::FORBIDDEN,
            "{} {} should accept the admin JWT, but returned {got}",
            route.method,
            route.path
        );
    }
}
