//! Integration tests for the `/ui/admin/*` management surface.
//!
//! Drives the axum router via `tower::ServiceExt::oneshot`. Covers:
//!
//! * Non-admin user on `/ui/admin/users` → 403.
//! * Admin user list, create, detail, edit, delete.
//! * CSRF rejection on admin mutations.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite,
};
use hearth::core::Clock;
use hearth::core::SystemClock;
use hearth::core::{RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RegisterClientRequest,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// Builds a no-op email service for tests that don't exercise email delivery.
fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];

struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    #[allow(dead_code)]
    authz: Arc<dyn AuthorizationEngine>,
    realm_id: RealmId,
    #[allow(dead_code)]
    admin_user_id: hearth::core::UserId,
    admin_session_id: SessionId,
    non_admin_user_id: hearth::core::UserId,
    non_admin_session_id: SessionId,
}

#[allow(clippy::too_many_lines)]
fn build_rig() -> TestRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    )) as Arc<dyn AuthorizationEngine>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "Acme".to_string(),
            config: None,
        })
        .expect("create realm");

    // Admin user.
    let admin_user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "admin@acme.test".to_string(),
                display_name: "Admin".to_string(),
            },
        )
        .expect("create admin user");
    let pw = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(realm.id(), admin_user.id(), &pw)
        .expect("set admin password");
    identity
        .update_user(
            realm.id(),
            admin_user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
            },
        )
        .expect("activate admin");
    let admin_session = identity
        .create_session(
            realm.id(),
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create admin session");

    // Write admin Zanzibar tuple.
    let obj = ObjectRef::new("hearth", "admin").expect("obj");
    let sub = SubjectRef::direct("user", &admin_user.id().as_uuid().to_string()).expect("sub");
    let tuple = RelationshipTuple::new(obj, "admin", sub).expect("tuple");
    authz
        .write_tuples(realm.id(), &[TupleWrite::Touch(tuple)])
        .expect("write admin tuple");

    // Non-admin user.
    let non_admin_user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "bob@acme.test".to_string(),
                display_name: "Bob".to_string(),
            },
        )
        .expect("create non-admin user");
    let pw2 = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(realm.id(), non_admin_user.id(), &pw2)
        .expect("set non-admin password");
    identity
        .update_user(
            realm.id(),
            non_admin_user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
            },
        )
        .expect("activate non-admin");
    let non_admin_session = identity
        .create_session(
            realm.id(),
            non_admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create non-admin session");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    TestRig {
        app,
        identity,
        authz,
        realm_id: realm.id().clone(),
        admin_user_id: admin_user.id().clone(),
        admin_session_id: admin_session.id().clone(),
        non_admin_user_id: non_admin_user.id().clone(),
        non_admin_session_id: non_admin_session.id().clone(),
    }
}

fn auth_cookie(session_id: &SessionId, realm_id: &RealmId, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        session_id.as_uuid(),
        realm_id.as_uuid(),
        tag,
        csrf,
    )
}

fn admin_cookie(rig: &TestRig, csrf: &str) -> String {
    auth_cookie(&rig.admin_session_id, &rig.realm_id, csrf)
}

fn non_admin_cookie(rig: &TestRig, csrf: &str) -> String {
    auth_cookie(&rig.non_admin_session_id, &rig.realm_id, csrf)
}

// ---------------------------------------------------------------------------
// Authorization tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_admin_user_gets_403_on_admin_pages() {
    let rig = build_rig();
    let cookie = non_admin_cookie(&rig, "csrf-nonadmin");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_user_redirects_to_login() {
    let rig = build_rig();

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/users")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

// ---------------------------------------------------------------------------
// User list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_user_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-list");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("admin@acme.test"), "should list admin user");
    assert!(body.contains("bob@acme.test"), "should list non-admin user");
    assert!(body.contains("Create user"));
}

// ---------------------------------------------------------------------------
// Create user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_create_user_form_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-new");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/users/new")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Create user"));
    assert!(body.contains("name=\"email\""));
    assert!(body.contains("name=\"password\""));
}

#[tokio::test]
async fn admin_create_user_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-create";
    let cookie = admin_cookie(&rig, csrf);

    let form = format!(
        "email=charlie%40acme.test&display_name=Charlie&password=super-secret-password-12&_csrf={csrf}"
    );
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/users/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/ui/admin/users/"),
        "expected redirect to user detail, got: {location}"
    );
}

#[tokio::test]
async fn admin_create_user_duplicate_email_shows_error() {
    let rig = build_rig();
    let csrf = "csrf-dup";
    let cookie = admin_cookie(&rig, csrf);

    let form = format!(
        "email=admin%40acme.test&display_name=Clone&password=super-secret-password-12&_csrf={csrf}"
    );
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/users/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("already exists"),
        "expected dup error, got: {body}"
    );
}

#[tokio::test]
async fn admin_create_user_without_csrf_returns_403() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-ok");

    let form = "email=x%40acme.test&display_name=X&password=super-secret-password-12&_csrf=wrong";
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/users/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// User detail
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_user_detail_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-detail");

    let uri = format!("/ui/admin/users/{}", rig.non_admin_user_id.as_uuid());
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Bob"));
    assert!(body.contains("bob@acme.test"));
    assert!(body.contains("Delete user"));
}

#[tokio::test]
async fn admin_user_detail_returns_404_for_unknown() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-404");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/users/00000000-0000-0000-0000-000000000099")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Edit user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_edit_user_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-edit";
    let cookie = admin_cookie(&rig, csrf);

    let uid = rig.non_admin_user_id.as_uuid();
    let form =
        format!("email=bob-new%40acme.test&display_name=Robert&status=Disabled&_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/users/{uid}/edit"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Verify the changes persisted.
    let updated = rig
        .identity
        .get_user(&rig.realm_id, &rig.non_admin_user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(updated.email(), "bob-new@acme.test");
    assert_eq!(updated.display_name(), "Robert");
    assert_eq!(updated.status(), UserStatus::Disabled);
}

// ---------------------------------------------------------------------------
// Delete user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_delete_user_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-del";
    let cookie = admin_cookie(&rig, csrf);

    let uid = rig.non_admin_user_id.as_uuid();
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/users/{uid}/delete"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/users"),
    );

    // User no longer exists.
    assert!(rig
        .identity
        .get_user(&rig.realm_id, &rig.non_admin_user_id)
        .expect("get_user")
        .is_none());
}

// ===========================================================================
// Realm tests
// ===========================================================================

#[tokio::test]
async fn admin_realm_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-tlist");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Acme"), "should list the realm");
    assert!(
        body.contains("hearth.yaml"),
        "should show YAML config notice"
    );
}

// NOTE: admin_create_realm_succeeds removed — realms are now managed
// via hearth.yaml; the /admin/realms/new route no longer exists.

#[tokio::test]
async fn admin_realm_detail_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-tdetail");

    let uri = format!("/ui/admin/realms/{}", rig.realm_id.as_uuid());
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Acme"));
    assert!(body.contains("Active"));
}

// NOTE: admin_edit_realm_succeeds removed — realms are now managed
// via hearth.yaml; the /admin/realms/{id}/edit route no longer exists.

#[tokio::test]
async fn admin_delete_realm_requires_archived_status() {
    let rig = build_rig();
    let csrf = "csrf-tdel";
    let cookie = admin_cookie(&rig, csrf);

    // Create a second realm for deletion.
    let extra = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "Doomed".to_string(),
            config: None,
        })
        .expect("create doomed realm");

    // Deleting an Active realm should be rejected (400).
    let tid = extra.id().as_uuid();
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{tid}/delete"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "should reject deletion of non-archived realm"
    );

    // Archive the realm first (simulating what YAML reconciliation does).
    rig.identity
        .update_realm(
            extra.id(),
            &hearth::identity::UpdateRealmRequest {
                status: Some(hearth::identity::RealmStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive realm");

    // Now deletion should succeed.
    let form2 = format!("_csrf={csrf}");
    let response2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{tid}/delete"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form2))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response2.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response2
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/realms"),
    );

    assert!(rig
        .identity
        .get_realm(extra.id())
        .expect("get_realm")
        .is_none());
}

// ===========================================================================
// Application tests
// ===========================================================================

#[tokio::test]
async fn admin_app_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-alist");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/applications")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Managed via hearth.yaml"));
}

#[tokio::test]
async fn admin_app_detail_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-adetail");

    // Create a client via the engine.
    let client = rig
        .identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "DetailApp".to_string(),
                redirect_uris: vec!["https://example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
            },
        )
        .expect("register_client");

    let cid = client.client_id().as_uuid();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ui/admin/applications/{cid}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("DetailApp"));
    assert!(body.contains("https://example.com/cb"));
}

// ===========================================================================
// Session tests
// ===========================================================================

#[tokio::test]
async fn admin_sessions_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-slist");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/sessions")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    // At least the admin's own session should be listed.
    assert!(
        body.contains("admin@acme.test"),
        "should show admin session"
    );
}

#[tokio::test]
async fn admin_revoke_session_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-srevoke";
    let cookie = admin_cookie(&rig, csrf);

    // Create a throwaway session to revoke.
    let extra_session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.non_admin_user_id,
            &hearth::identity::SessionContext::default(),
        )
        .expect("create extra session");

    let sid = extra_session.id().as_uuid();
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/sessions/{sid}/revoke"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/sessions"),
    );

    // Session should be gone (revoked → get_session returns None).
    assert!(rig
        .identity
        .get_session(&rig.realm_id, extra_session.id())
        .expect("get_session")
        .is_none());
}

// ===========================================================================
// Audit tests
// ===========================================================================

#[tokio::test]
async fn admin_audit_page_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-audit");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/audit")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Audit log"));
}

#[tokio::test]
async fn admin_audit_page_shows_events_after_user_create() {
    let rig = build_rig();
    let csrf = "csrf-auditcr";
    let cookie = admin_cookie(&rig, csrf);

    // Create a user via the admin UI to generate an audit event.
    let form = format!(
        "email=auditee%40acme.test&display_name=Auditee&password=super-secret-password-12&_csrf={csrf}"
    );
    let _create_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/users/new")
                .header(header::COOKIE, admin_cookie(&rig, csrf))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    // Now load the audit page filtered by action=user_created.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/audit?action=user_created")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("user_created"),
        "expected user_created event in audit log"
    );
}
