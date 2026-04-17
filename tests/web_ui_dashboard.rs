//! Integration tests for the `/ui/*` dashboard + logout surface (Commit 3 of
//! the Phase 1.6 admin UI).
//!
//! Drives the axum router directly via `tower::ServiceExt::oneshot`, skipping
//! a real TCP listener. Covers:
//!
//! * Unauthenticated `/ui/` → 303 redirect to `/ui/login?return_to=%2Fui%2F`.
//! * Authenticated `/ui/` → 200 with `Dashboard` content and the sign-out form.
//! * `POST /ui/logout` without the CSRF token → 403.
//! * `POST /ui/logout` with valid CSRF → 303 to `/ui/login`, cookies cleared,
//!   and the underlying session is revoked on the server.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::authz::{AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine};
use hearth::core::Clock;
use hearth::core::SystemClock;
use hearth::core::{SessionId, TenantId};
use hearth::identity::email::EmailSender;
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateTenantRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// No-op email sender — onboarding isn't exercised by these tests but
/// `OnboardingService::new` still requires a sender handle.
struct NullEmailSender;

impl EmailSender for NullEmailSender {
    fn send_verification_email(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), hearth::identity::email::EmailError> {
        Ok(())
    }
    fn send_setup_notification(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), hearth::identity::email::EmailError> {
        Ok(())
    }
}

/// Known-static cookie-secret bytes used by `build_rig`. Lets tests
/// compute cookie MACs without reaching into `CookieSecret` internals.
const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];

/// Fully assembled router + identity-engine handle + the created tenant/user
/// + a live session id. Used by each test to exercise authenticated routes.
struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    tenant_id: TenantId,
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
    let authz = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    )) as Arc<dyn AuthorizationEngine>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;

    // Create a tenant + active user so we have a real session to hand out.
    let tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "Acme".to_string(),
            config: None,
        })
        .expect("create tenant");
    let user = identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "alice@acme.test".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create user");
    let password = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(tenant.id(), user.id(), &password)
        .expect("set password");
    // Skip the email-verification step — flip straight to Active.
    identity
        .update_user(
            tenant.id(),
            user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
            },
        )
        .expect("activate user");
    let session = identity
        .create_session(tenant.id(), user.id())
        .expect("create session");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::new(NullEmailSender) as Arc<dyn EmailSender>,
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
    );
    let app = web::router(state);

    TestRig {
        app,
        identity,
        tenant_id: tenant.id().clone(),
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
    mac.update(rig.tenant_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.session_id.as_uuid(),
        rig.tenant_id.as_uuid(),
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
                .uri("/ui/")
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
                .uri("/ui/")
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
            .get_session(&rig.tenant_id, &rig.session_id)
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
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/login")
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
            .get_session(&rig.tenant_id, &rig.session_id)
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
    let _ = (rig.session_id, rig.tenant_id);
}
