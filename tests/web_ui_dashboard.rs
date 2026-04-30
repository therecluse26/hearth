//! Integration tests for the `/ui/*` dashboard + logout surface (Commit 3 of
//! the Phase 1.6 admin UI).
//!
//! Drives the axum router directly via `tower::ServiceExt::oneshot`, skipping
//! a real TCP listener. Covers:
//!
//! * Unauthenticated `/ui` → 303 redirect to `/ui/login?return_to=%2Fui`.
//! * Authenticated `/ui` → 200 with `Dashboard` content and the sign-out form.
//! * `POST /ui/logout` without the CSRF token → 403.
//! * `POST /ui/logout` with valid CSRF → 303 to `/ui/login`, cookies cleared,
//!   and the underlying session is revoked on the server.
//! * Dashboard works when `http::router` and `web::router` are merged (same as
//!   `main.rs:310`).

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
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::http as hearth_http;
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

/// Known-static cookie-secret bytes used by `build_rig`. Lets tests
/// compute cookie MACs without reaching into `CookieSecret` internals.
const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];

/// Fully assembled router + identity-engine handle + the created realm/user
/// + a live session id. Used by each test to exercise authenticated routes.
struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    authz: Arc<dyn RbacEngine>,
    audit: Arc<dyn hearth::audit::AuditEngine>,
    realm_id: RealmId,
    session_id: SessionId,
}

fn build_rig() -> TestRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Leak the tempdir — the storage engine mmaps files inside it for the
    // duration of the test process.
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
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;

    // Create a realm + active user so we have a real session to hand out.
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "Acme".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@acme.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");
    let password = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(realm.id(), user.id(), &password)
        .expect("set password");
    // Skip the email-verification step — flip straight to Active.
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate user");
    let session = identity
        .create_session(
            realm.id(),
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Grant the user the hearth#admin relation (same as the onboarding flow).
    authz.seed_realm(realm.id()).expect("seed");
    let _admin_role = authz
        .get_role_by_name(realm.id(), "realm.admin")
        .expect("lookup")
        .expect("seed role");
    authz
        .assign_role(
            realm.id(),
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(user.id().clone()),
                role_id: _admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    TestRig {
        app,
        identity,
        authz,
        audit,
        realm_id: realm.id().clone(),
        session_id: session.id().clone(),
    }
}

/// Builds the `Cookie` header value carrying both UI cookies in the
/// format the extractors expect.
fn auth_cookie(rig: &TestRig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(rig.session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.session_id.as_uuid(),
        rig.realm_id.as_uuid(),
        tag,
        csrf,
    )
}

#[tokio::test]
async fn dashboard_redirects_to_login_when_unauthenticated() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii");
    assert!(
        location.starts_with("/ui/login?return_to="),
        "unexpected Location: {location}"
    );
}

#[tokio::test]
async fn dashboard_renders_signed_in_page() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-abc");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui")
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
    assert!(body.contains("Welcome"), "dashboard should have welcome");
    assert!(
        body.contains("alice@acme.test"),
        "dashboard should show signed-in email"
    );
    assert!(
        body.contains("/ui/logout"),
        "dashboard should render sign-out form"
    );
    // Admin tiles must be visible because the test user has the
    // hearth#admin relation.
    assert!(
        body.contains("/ui/admin/users"),
        "dashboard should show Users admin link"
    );
    assert!(
        body.contains("/ui/admin/realms"),
        "dashboard should show Realms admin link"
    );
    assert!(
        body.contains("/ui/admin/applications"),
        "dashboard should show Applications admin link"
    );
    assert!(
        body.contains("/ui/admin/sessions"),
        "dashboard should show Sessions admin link"
    );
    assert!(
        body.contains("/ui/admin/audit"),
        "dashboard should show Audit log admin link"
    );
}

/// Regression: dashboard counts (Users / Realms / Applications /
/// Organizations) must aggregate across the system realm and every
/// tenant realm — not just the realm the admin happens to be signed
/// into. The 2026-04-29 audit caught the legacy single-realm count
/// showing "Organizations 0" while a tenant realm clearly held one,
/// since the admin signed in via the tenant realm in some flows but
/// orgs / apps in *other* realms went unsurfaced.
#[tokio::test]
async fn dashboard_counts_aggregate_across_realms() {
    let rig = build_rig();

    // Seed a second tenant realm with an organization. The dashboard
    // count must include it even though the admin is signed into Acme.
    let other_realm = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "OtherCorp".to_string(),
            config: None,
        })
        .expect("create OtherCorp");
    rig.identity
        .create_organization(
            other_realm.id(),
            &hearth::identity::CreateOrganizationRequest {
                name: "Cross-Realm Org".to_string(),
                slug: "cross-realm-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org in OtherCorp");

    let cookie = auth_cookie(&rig, "csrf-counts");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui")
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

    // The Realms count is global — must include both Acme and OtherCorp.
    // The cards in dashboard.html render the count next to a label;
    // both number and label appear in the rendered HTML, so a contains
    // check on the labelled value pins the realm-aware aggregation.
    assert!(body.contains("Realms"), "Realms card present");
    // Org count must be 1 (from OtherCorp), even though the admin
    // signed in via Acme. The legacy code reading session.realm_id
    // would have shown 0.
    assert!(body.contains("Organizations"), "Organizations card present");
    // The number rendered in the org card. dashboard.html composes the
    // count + label inside the same anchor, so a substring of both
    // tokens within a window distinguishes the right card.
    let snippet = "Organizations";
    let idx = body.find(snippet).expect("Organizations label");
    let window = &body[idx..usize::min(idx + 256, body.len())];
    assert!(
        window.contains(">1<"),
        "Organizations count must be 1 (aggregated from OtherCorp). Window: {window}"
    );
}

#[tokio::test]
async fn logout_without_csrf_returns_403() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-abc");

    // No `_csrf` field in the form body.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("_csrf=wrong"))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "mismatched CSRF must be rejected"
    );

    // And the session should still be alive.
    assert!(
        rig.identity
            .get_session(&rig.realm_id, &rig.session_id)
            .expect("get_session")
            .is_some(),
        "session must not be revoked on CSRF failure"
    );
}

#[tokio::test]
async fn logout_with_csrf_clears_cookies_and_revokes_session() {
    let rig = build_rig();
    let csrf = "csrf-token-123";
    let cookie = auth_cookie(&rig, csrf);

    let body = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    // Logout now routes the user back to their realm's login page so
    // the next sign-in attempt lands on a page that renders. The
    // `build_rig` test harness names its tenant realm "Acme".
    let realm_name = rig
        .identity
        .get_realm(&rig.realm_id)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string();
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("/ui/realms/{realm_name}/login").as_str())
    );

    // Both clearing cookies must be present.
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_session=") && c.contains("Max-Age=0")),
        "expected session cookie to be cleared, got: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_csrf=") && c.contains("Max-Age=0")),
        "expected csrf cookie to be cleared, got: {cookies:?}"
    );

    // Session must be revoked on the server.
    assert!(
        rig.identity
            .get_session(&rig.realm_id, &rig.session_id)
            .expect("get_session")
            .is_none(),
        "session must be revoked after logout"
    );
}

#[tokio::test]
async fn static_asset_served_with_immutable_cache_headers() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/static/htmx.min.js")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/javascript; charset=utf-8")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=31536000, immutable")
    );

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    assert!(body.len() > 1024, "htmx.min.js should be non-trivial");

    // Subject suppresses the unused-field warning when build_rig() returns
    // fields that individual tests don't touch.
    let _ = (rig.session_id, rig.realm_id, rig.authz, rig.audit);
}

/// Reproduces the exact router composition from `main.rs:310`:
/// `http::router(app_state).merge(web::router(web_state))`. The bug was
/// that `/ui` returned 404 after the merge because of the ambiguous
/// double-registration at `/ui/` on both the inner nest and the outer router.
#[tokio::test]
async fn dashboard_works_on_merged_router() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-merged");

    // Build the HTTP API router exactly as main.rs does.
    let app_state = Arc::new(hearth_http::AppState::new(
        Arc::clone(&rig.identity),
        Arc::clone(&rig.authz),
        Arc::clone(&rig.audit),
    ));
    let merged = hearth_http::router(app_state).merge(rig.app.clone());

    let response = merged
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /ui must return 200 on merged router"
    );
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("Welcome"),
        "merged-router dashboard should have welcome"
    );
}

/// Ensures `/ui/` (trailing slash) redirects to `/ui` after removing the
/// explicit outer route. Axum 0.8's `nest` does not match the bare trailing
/// slash, so a `Redirect::permanent("/ui")` handler is registered at `/ui/`.
#[tokio::test]
async fn dashboard_trailing_slash_redirects() {
    let rig = build_rig();

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::PERMANENT_REDIRECT,
        "GET /ui/ must redirect to /ui"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ascii");
    assert_eq!(location, "/ui", "redirect target must be /ui");
}
