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
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
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
    authz: Arc<dyn RbacEngine>,
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
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");

    // Admin user lives in the system realm (nil UUID) — this matches
    // the invariant enforced by `RequireAdmin`. Tests that exercise
    // admin routes target the application realm ("acme") via the
    // path-based `TargetRealm` extractor (`/ui/admin/realms/acme/...`).
    let admin_realm_id = hearth::core::RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@acme.test".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user");
    let pw = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(&admin_realm_id, admin_user.id(), &pw)
        .expect("set admin password");
    identity
        .update_user(
            &admin_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate admin");
    let admin_session = identity
        .create_session(
            &admin_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create admin session");

    // Grant admin realm role: seed the system realm's defaults and assign
    // the `realm.admin` role (which carries `hearth.admin`) to our admin user.
    authz
        .seed_realm(&admin_realm_id)
        .expect("seed system realm");
    let admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup role")
        .expect("seed role present");
    authz
        .assign_role(
            &admin_realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(admin_user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    // Non-admin user.
    let non_admin_user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "bob@acme.test".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
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
                first_name: None,
                last_name: None,
                ..Default::default()
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
    // Admin sessions are bound to the system realm (nil UUID), not the
    // application realm (`rig.realm_id`).
    let admin_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    auth_cookie(&rig.admin_session_id, &admin_realm, csrf)
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
                .uri("/ui/admin/realms/acme/users")
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
                .uri("/ui/admin/realms/acme/users")
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
                .uri("/ui/admin/realms/acme/users")
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
    // The acme tenant realm contains only `bob@acme.test`; the admin
    // lives in the system realm so they don't appear here.
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
                .uri("/ui/admin/realms/acme/users/new")
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
                .uri("/ui/admin/realms/acme/users/new")
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
        location.starts_with("/ui/admin/realms/acme/users/"),
        "expected redirect to user detail, got: {location}"
    );
}

#[tokio::test]
async fn admin_create_user_duplicate_email_shows_error() {
    let rig = build_rig();
    let csrf = "csrf-dup";
    let cookie = admin_cookie(&rig, csrf);

    // `bob@acme.test` is the non-admin test user seeded in the Acme
    // realm by `build_rig`. The admin account lives in the system
    // realm and doesn't collide with Acme users by design.
    let form = format!(
        "email=bob%40acme.test&display_name=Clone&password=super-secret-password-12&_csrf={csrf}"
    );
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/users/new")
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
                .uri("/ui/admin/realms/acme/users/new")
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

    let uri = format!(
        "/ui/admin/realms/acme/users/{}",
        rig.non_admin_user_id.as_uuid()
    );
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

/// `/ui/admin/realms/acme/sessions` renders the per-realm view (no
/// Realm column, scoped heading). The previous global / cross-realm view
/// was deleted alongside the path-based routing migration — every
/// realm-scoped page now lives under `/ui/admin/realms/{name}/...`.
#[tokio::test]
async fn admin_sessions_realm_scoped_view_omits_realm_column() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-sessions-acme");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions")
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
        !body.contains("Realm</th>"),
        "scoped view must not show a Realm column"
    );
    assert!(body.contains("bob@acme.test"));
    // Match by session UUID rather than email — the admin's email also
    // appears in the page chrome (topbar, sign-out menu) so a string
    // search would always find it. Counting "session-<uuid>" row IDs is
    // unambiguous: exactly one tenant session, zero system sessions.
    let admin_session_marker = format!("session-{}", rig.admin_session_id.as_uuid());
    let tenant_session_marker = format!("session-{}", rig.non_admin_session_id.as_uuid());
    assert!(
        body.contains(&tenant_session_marker),
        "scoped view must include the tenant session row"
    );
    assert!(
        !body.contains(&admin_session_marker),
        "scoped view must not leak the system admin's session into the Acme realm"
    );
}

/// `/ui/admin/users` renders the search input wired with HTMX live-search
/// attributes (hx-get, hx-trigger, hx-target). Resolves REQ-044.
#[tokio::test]
async fn admin_users_list_renders_htmx_live_search_attrs() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-htmx");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
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
        body.contains(r#"hx-get="/ui/admin/realms/acme/users""#),
        "search form must point hx-get at the list URL"
    );
    assert!(
        body.contains(r#"hx-trigger="input changed delay:200ms"#),
        "search form must debounce input by 200ms"
    );
    assert!(
        body.contains(r##"hx-target="#users-tbody""##),
        "search form must target the rows tbody"
    );
    assert!(
        body.contains(r#"<tbody id="users-tbody">"#),
        "the tbody must carry the id the search form targets"
    );
}

/// `GET /ui/admin/users` with `HX-Request: true` returns ONLY the rows
/// partial — no DOCTYPE / html / page chrome. Pins the live-search
/// payload size and prevents accidental nested-`<html>` regressions.
#[tokio::test]
async fn admin_users_list_returns_rows_partial_for_htmx_request() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-htmx-partial");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .header("HX-Request", "true")
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
        !body.to_ascii_lowercase().contains("<!doctype html"),
        "HTMX response must not include the page <!DOCTYPE>"
    );
    assert!(
        !body.contains("<html"),
        "HTMX response must not include a <html> tag"
    );
    // Should still contain at least one user row marker (the seeded bob).
    assert!(
        body.contains("bob@acme.test"),
        "rows partial must include the seeded user rows"
    );
}

/// `/ui/admin/sessions` renders the Active/Expired/All filter pills
/// and defaults to the Active view. Resolves REQ-050 in the gap doc.
#[tokio::test]
async fn admin_sessions_list_renders_status_filter_pills() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-sessions-pills");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions")
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

    // All three pills present, with their query strings.
    assert!(body.contains("?status=active"), "Active pill must be wired");
    assert!(
        body.contains("?status=expired"),
        "Expired pill must be wired"
    );
    assert!(body.contains("?status=all"), "All pill must be wired");

    // Default is Active — only the Active pill carries aria-selected="true".
    let active_marker = r#"href="/ui/admin/realms/acme/sessions?status=active"
     role="tab"
     aria-selected="true""#;
    assert!(
        body.contains(active_marker),
        "Active pill must be the default selected tab"
    );
}

/// `/ui/admin/sessions?status=expired` returns the empty-state row when
/// no sessions are past expiry. Pins the filter wires through end-to-end.
#[tokio::test]
async fn admin_sessions_list_expired_filter_empty_when_all_active() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-sessions-expired");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions?status=expired")
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

    // Both seeded sessions are fresh — Expired view is empty.
    assert!(
        body.contains("No sessions match the current filter"),
        "expired view should render the empty-state row when all sessions are active"
    );
    // Expired pill is the selected one.
    let expired_marker = r#"href="/ui/admin/realms/acme/sessions?status=expired"
     role="tab"
     aria-selected="true""#;
    assert!(
        body.contains(expired_marker),
        "Expired pill must be the selected tab when ?status=expired"
    );
}

/// Regression: a 404 from inside the admin shell renders **with**
/// chrome (sidebar, user pill, dark theme), not as a stand-alone
/// unstyled white page. The 2026-04-29 audit caught the legacy
/// behaviour leaving an authenticated admin staring at a bare
/// "Not Found" line with no nav to recover.
#[tokio::test]
async fn admin_user_detail_404_renders_inside_admin_shell() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-404-chrome");

    // Hit a UUID that doesn't exist in the acme tenant realm.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users/00000000-0000-0000-0000-0000ffff0001")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    assert!(body.contains("Not Found"));
    // Sidebar nav links — confirm the admin chrome is intact.
    assert!(
        body.contains("/ui/admin/realms"),
        "404 inside admin shell must keep the sidebar (Realms link)"
    );
    assert!(
        body.contains("/ui/logout"),
        "404 inside admin shell must keep the user pill / sign-out"
    );
    assert!(
        body.contains("admin@acme.test"),
        "404 inside admin shell must show the signed-in user's email"
    );
}

/// `GET /ui/admin/users` (no realm) returns 404 — the path-based routing
/// migration deleted the cookie / `?realm=` fallbacks that used to
/// silently resolve a tenant realm. Pins R-5 from `UI_ROUTING.md`.
#[tokio::test]
async fn admin_user_list_without_realm_path_returns_404() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-no-realm");

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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
                .uri("/ui/admin/realms/acme/users/00000000-0000-0000-0000-000000000099")
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
                .uri(format!("/ui/admin/realms/acme/users/{uid}/edit"))
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
                .uri(format!("/ui/admin/realms/acme/users/{uid}/delete"))
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
        Some("/ui/admin/realms/acme/users"),
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
    assert!(body.contains("acme"), "should list the realm");
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

    let uri = "/ui/admin/realms/acme".to_string();
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
    assert!(body.contains("acme"));
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
            name: "doomed".to_string(),
            config: None,
        })
        .expect("create doomed realm");

    // Deleting an Active realm should be rejected (400).
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/doomed/delete")
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
                .uri("/ui/admin/realms/doomed/delete")
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
                .uri("/ui/admin/realms/acme/applications")
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
    // The legacy "Managed via hearth.yaml" badge was replaced by an
    // "Edit in Config Editor" CTA in PR3 — operators have a working
    // path to the editor now, not a dead-end note. See the 2026-04-29
    // UX audit, finding #8.
    assert!(
        body.contains("Edit in Config Editor"),
        "applications list must surface a CTA to the config editor"
    );
    assert!(
        body.contains("/ui/admin/settings/editor?section=oidc"),
        "applications CTA must deep-link to the OIDC section"
    );
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
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
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
                .uri(format!("/ui/admin/realms/acme/applications/{cid}"))
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
                .uri("/ui/admin/realms/acme/sessions")
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
    // The acme realm contains bob's session.
    assert!(
        body.contains("bob@acme.test"),
        "should show non-admin session"
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
                .uri(format!("/ui/admin/realms/acme/sessions/{sid}/revoke"))
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
        Some("/ui/admin/realms/acme/sessions"),
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
                .uri("/ui/admin/realms/acme/audit")
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
                .uri("/ui/admin/realms/acme/users/new")
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
                .uri("/ui/admin/realms/acme/audit?action=user_created")
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

// ---------------------------------------------------------------------------
// Realm-aware redirects + admin-users surface
// ---------------------------------------------------------------------------

fn location_of(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn set_cookie_with(resp: &axum::http::Response<Body>, prefix: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(prefix))
        .map(str::to_string)
}

#[tokio::test]
async fn unauthenticated_admin_path_redirects_to_admin_login() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let loc = location_of(&response);
    assert!(
        loc.starts_with("/ui/admin/login"),
        "admin-path unauthenticated redirect must target /ui/admin/login, got {loc}"
    );
}

#[tokio::test]
async fn unauthenticated_last_realm_cookie_targets_tenant_login() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account")
                .header(header::COOKIE, "hearth_ui_last_realm=acme")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let loc = location_of(&response);
    assert!(
        loc.starts_with("/ui/realms/acme/login"),
        "last-realm cookie should drive realm-scoped login redirect, got {loc}"
    );
}

#[tokio::test]
async fn admin_logout_redirects_to_admin_login_and_sets_last_realm() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-logout");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header(header::COOKIE, &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("_csrf=csrf-logout"))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert!(
        response.status().is_redirection(),
        "logout should redirect, got {}",
        response.status()
    );
    let loc = location_of(&response);
    assert!(
        loc.starts_with("/ui/admin/login"),
        "admin logout must return to admin login, got {loc}"
    );
    let last_realm = set_cookie_with(&response, "hearth_ui_last_realm=").unwrap_or_default();
    assert!(
        last_realm.contains("hearth_ui_last_realm=__system__"),
        "admin logout must set last-realm sentinel, got {last_realm}"
    );
}

#[tokio::test]
async fn tenant_logout_redirects_to_realm_login() {
    let rig = build_rig();
    let cookie = non_admin_cookie(&rig, "csrf-tenant-logout");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header(header::COOKIE, &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("_csrf=csrf-tenant-logout"))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert!(response.status().is_redirection());
    let loc = location_of(&response);
    let realm_name = rig
        .identity
        .get_realm(&rig.realm_id)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string();
    assert_eq!(
        loc,
        format!("/ui/realms/{realm_name}/login"),
        "tenant logout must target the realm's login page"
    );
    let last_realm = set_cookie_with(&response, "hearth_ui_last_realm=").unwrap_or_default();
    assert!(
        last_realm.contains(&format!("hearth_ui_last_realm={realm_name}")),
        "tenant logout must set last-realm to realm name, got {last_realm}"
    );
}

#[tokio::test]
async fn admin_users_page_lists_only_system_realm_users() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-admin-users");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/admin-users")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(
        body.contains("admin@acme.test"),
        "admin-users page should list system-realm admin"
    );
    assert!(
        !body.contains("bob@acme.test"),
        "admin-users page must not leak tenant-realm users"
    );
    assert!(
        body.contains("Admin Users"),
        "admin-users page header must differ from tenant Users header"
    );
}

#[tokio::test]
async fn tenant_users_list_renders_realm_breadcrumb() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-tenant-users");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let body = String::from_utf8_lossy(&body_bytes);
    // Workspace breadcrumb: link to Realms list.
    assert!(
        body.contains("href=\"/ui/admin/realms\""),
        "tenant users list must link back to Realms"
    );
    // Tab bar must mark Users as the active page.
    assert!(
        body.contains("aria-current=\"page\""),
        "tenant users list must mark active tab"
    );
}
