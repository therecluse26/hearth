#![allow(clippy::unwrap_used)]
//! Integration tests for the admin first-run onboarding wizard (HEA-487).
//!
//! Covers:
//! - Wizard renders on first run (no realms exist).
//! - Wizard redirects to dashboard when a realm already exists.
//! - Step 1 POST creates a realm and redirects to step 2.
//! - Step 2 POST creates an OAuth client and redirects to step 3.
//! - Step 3 POST creates a user and redirects to step 4.
//! - Test-email endpoint returns an HTMX fragment.
//! - Complete page renders with summary data.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, RealmId, SessionId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET_BYTES: [u8; 32] = [77u8; 32];
const CSRF: &str = "test-csrf-onboarding";

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

/// A minimal admin session + app, optionally with a pre-created realm.
struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
}

fn build_rig(pre_create_realm: bool) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Keep tempdir alive for the test duration.
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
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
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    // Admin lives in the system realm (nil UUID).
    let system_realm_id = RealmId::new(uuid::Uuid::nil());
    let admin = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@test.local".to_string(),
            display_name: "Admin".to_string(),
            ..Default::default()
        })
        .expect("create admin");
    identity
        .set_password(
            &system_realm_id,
            admin.id(),
            &CleartextPassword::from_string("hunter2".to_string()),
        )
        .expect("set password");
    identity
        .update_user(
            &system_realm_id,
            admin.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate admin");

    // Grant realm.admin role so RequireAdmin passes.
    rbac.seed_realm(&system_realm_id)
        .expect("seed system realm");
    let admin_role = rbac
        .get_role_by_name(&system_realm_id, "realm.admin")
        .expect("lookup role")
        .expect("role exists");
    rbac.assign_role(
        &system_realm_id,
        &hearth::rbac::AssignRoleRequest {
            subject: hearth::rbac::Subject::User(admin.id().clone()),
            role_id: admin_role.id,
            scope: hearth::rbac::Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign role");

    let admin_session = identity
        .create_session(
            &system_realm_id,
            admin.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    if pre_create_realm {
        identity
            .create_realm(&CreateRealmRequest {
                name: "existing-realm".to_string(),
                config: None,
            })
            .expect("pre-create realm");
    }

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        Some(null_email_service()),
    );
    let app = web::router(state);

    Rig {
        app,
        admin_session_id: admin_session.id().clone(),
    }
}

fn admin_cookie(session_id: &SessionId) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let system_realm = RealmId::new(uuid::Uuid::nil());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(system_realm.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        session_id.as_uuid(),
        system_realm.as_uuid(),
        tag,
        CSRF,
    )
}

fn csrf_body(extra: &str) -> String {
    format!("_csrf={CSRF}&{extra}")
}

// ---------------------------------------------------------------------------
// Wizard rendering / redirect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wizard_renders_on_first_run() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/onboarding")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("test");
    let html = std::str::from_utf8(&body).expect("test");
    assert!(
        html.contains("Create your first realm"),
        "wizard step 1 heading"
    );
}

#[tokio::test]
async fn wizard_skips_when_realm_exists() {
    let rig = build_rig(true);
    let cookie = admin_cookie(&rig.admin_session_id);

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/onboarding")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("test"),
        )
        .await
        .expect("test");

    // Redirects to dashboard because a realm already exists.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get("location").expect("test"), "/ui");
}

// ---------------------------------------------------------------------------
// Step 1 — realm creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn step1_creates_realm_and_redirects() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let body = csrf_body("display_name=Acme+Corp&realm_name=acme&theme=ember");

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/realm")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .expect("test")
        .to_str()
        .expect("test");
    assert!(
        loc.starts_with("/ui/admin/onboarding/app"),
        "redirects to step 2: {loc}"
    );
    assert!(loc.contains("realm=acme"), "realm param present: {loc}");
}

#[tokio::test]
async fn step1_rejects_duplicate_realm_name() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let body = csrf_body("display_name=Acme&realm_name=acme&theme=ember");

    // First creation — succeeds.
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/realm")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.clone()))
                .expect("test"),
        )
        .await
        .expect("test");

    // Second creation with same name — shows error form.
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/realm")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::OK);
    let html = std::str::from_utf8(&to_bytes(resp.into_body(), 1 << 20).await.expect("test"))
        .expect("test")
        .to_string();
    assert!(html.contains("already exists"), "error shown: {html}");
}

// ---------------------------------------------------------------------------
// Step 2 — OAuth app
// ---------------------------------------------------------------------------

#[tokio::test]
async fn step2_app_get_renders() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/onboarding/app?realm=acme")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::OK);
    let html = std::str::from_utf8(&to_bytes(resp.into_body(), 1 << 20).await.expect("test"))
        .expect("test")
        .to_string();
    assert!(html.contains("Register an application"), "step 2 heading");
}

#[tokio::test]
async fn step2_creates_app_and_redirects() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    // Pre-create realm so register_client can find it.
    // (In a real wizard flow step 1 creates it; here we need to set up state.)
    // We POST step 1 first.
    let step1_body = csrf_body("display_name=Acme&realm_name=acme&theme=ember");
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/realm")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(step1_body))
                .expect("test"),
        )
        .await
        .expect("test");

    let step2_body = csrf_body(
        "realm=acme&app_name=My+App&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&grant_authorization_code=1",
    );
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/app")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(step2_body))
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .expect("test")
        .to_str()
        .expect("test");
    assert!(
        loc.starts_with("/ui/admin/onboarding/invite"),
        "redirects to step 3: {loc}"
    );
}

// ---------------------------------------------------------------------------
// Step 3 — Invite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn step3_invite_get_renders() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/onboarding/invite?realm=acme")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::OK);
    let html = std::str::from_utf8(&to_bytes(resp.into_body(), 1 << 20).await.expect("test"))
        .expect("test")
        .to_string();
    assert!(html.contains("Invite a team member"), "step 3 heading");
}

#[tokio::test]
async fn step3_creates_user_and_redirects() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    // Create realm first.
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/realm")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(csrf_body(
                    "display_name=Acme&realm_name=acme&theme=ember",
                )))
                .expect("test"),
        )
        .await
        .expect("test");

    let step3_body = csrf_body("realm=acme&email=newuser%40example.com&role=admin");
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/invite")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(step3_body))
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .expect("test")
        .to_str()
        .expect("test");
    assert!(
        loc.starts_with("/ui/admin/onboarding/email"),
        "redirects to step 4: {loc}"
    );
    assert!(loc.contains("invited="), "invited param present: {loc}");
}

// ---------------------------------------------------------------------------
// Test-email HTMX endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_email_returns_htmx_fragment() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let body = csrf_body("recipient=test%40example.com");
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/onboarding/email/test")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::OK);
    let html = std::str::from_utf8(&to_bytes(resp.into_body(), 1 << 20).await.expect("test"))
        .expect("test")
        .to_string();
    // Log transport succeeds; result div is present.
    assert!(
        html.contains("email-test-result"),
        "HTMX fragment contains result div: {html}"
    );
}

// ---------------------------------------------------------------------------
// Complete page
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_page_renders_with_realm() {
    let rig = build_rig(false);
    let cookie = admin_cookie(&rig.admin_session_id);

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/onboarding/complete?realm=acme&app=My+App&client_id=abc123&invited=user%40example.com")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("test"),
        )
        .await
        .expect("test");

    assert_eq!(resp.status(), StatusCode::OK);
    let html = std::str::from_utf8(&to_bytes(resp.into_body(), 1 << 20).await.expect("test"))
        .expect("test")
        .to_string();
    assert!(html.contains("You're all set"), "completion heading");
    assert!(html.contains("acme"), "realm name present");
}
