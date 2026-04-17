//! Integration tests for the `/ui/account/*` self-service surface.
//!
//! Drives the axum router via `tower::ServiceExt::oneshot`. Covers:
//!
//! * Unauthenticated `/ui/account` → 303 redirect to `/ui/login`.
//! * Authenticated `/ui/account` → 200 with the password form.
//! * `POST /ui/account/password` — rejects CSRF mismatch (403), rejects
//!   wrong current password (200 with inline error), rejects new/confirm
//!   mismatch (200 with inline error), succeeds when all inputs valid
//!   (200 with success flash + verified via password round-trip).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::authz::{AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine};
use hearth::core::Clock;
use hearth::core::SystemClock;
use hearth::core::{SessionId, TenantId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateTenantRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// Builds a no-op email service for tests that don't exercise email delivery.
fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            EmailBranding::default(),
            None,
        )
        .expect("email service"),
    )
}

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];
const OLD_PASSWORD: &str = "correct-horse-battery-staple";
const NEW_PASSWORD: &str = "new-horse-battery-staple-12345";

struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    tenant_id: TenantId,
    user_id: hearth::core::UserId,
    session_id: SessionId,
}

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
    let password = CleartextPassword::from_string(OLD_PASSWORD.to_string());
    identity
        .set_password(tenant.id(), user.id(), &password)
        .expect("set password");
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
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    TestRig {
        app,
        identity,
        tenant_id: tenant.id().clone(),
        user_id: user.id().clone(),
        session_id: session.id().clone(),
    }
}

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
async fn account_index_redirects_when_unauthenticated() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn account_index_renders_for_signed_in_user() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-abc");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account")
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
    assert!(body.contains("Change password"));
    assert!(body.contains("alice@acme.test"));
    assert!(body.contains("name=\"current_password\""));
    assert!(body.contains("name=\"new_password\""));
    assert!(body.contains("name=\"_csrf\""));

    let _ = rig.user_id;
}

#[tokio::test]
async fn change_password_without_csrf_returns_403() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-abc");

    let body = format!(
        "current_password={OLD_PASSWORD}&new_password={NEW_PASSWORD}&confirm_password={NEW_PASSWORD}&_csrf=wrong"
    );

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/password")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Password must still be the OLD one.
    let check = CleartextPassword::from_string(OLD_PASSWORD.to_string());
    assert!(rig
        .identity
        .verify_password(&rig.tenant_id, &rig.user_id, &check)
        .expect("verify"));
}

#[tokio::test]
async fn change_password_with_wrong_current_shows_inline_error() {
    let rig = build_rig();
    let csrf = "csrf-inline";
    let cookie = auth_cookie(&rig, csrf);

    let body = format!(
        "current_password=not-the-password&new_password={NEW_PASSWORD}&confirm_password={NEW_PASSWORD}&_csrf={csrf}"
    );

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/password")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
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
        body.contains("Current password is incorrect"),
        "expected inline error, got: {body}"
    );

    // Password must still be the OLD one.
    let check = CleartextPassword::from_string(OLD_PASSWORD.to_string());
    assert!(rig
        .identity
        .verify_password(&rig.tenant_id, &rig.user_id, &check)
        .expect("verify"));
}

#[tokio::test]
async fn change_password_with_mismatched_confirmation_shows_error() {
    let rig = build_rig();
    let csrf = "csrf-mismatch";
    let cookie = auth_cookie(&rig, csrf);

    let body = format!(
        "current_password={OLD_PASSWORD}&new_password={NEW_PASSWORD}&confirm_password=something-different&_csrf={csrf}"
    );

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/password")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
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
        body.contains("do not match"),
        "expected mismatch error, got: {body}"
    );
}

#[tokio::test]
async fn change_password_success_updates_credential() {
    let rig = build_rig();
    let csrf = "csrf-success";
    let cookie = auth_cookie(&rig, csrf);

    let body = format!(
        "current_password={OLD_PASSWORD}&new_password={NEW_PASSWORD}&confirm_password={NEW_PASSWORD}&_csrf={csrf}"
    );

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/password")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
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
        body.contains("Password changed"),
        "expected success flash, got: {body}"
    );

    // New password verifies; old one does not.
    let new = CleartextPassword::from_string(NEW_PASSWORD.to_string());
    assert!(rig
        .identity
        .verify_password(&rig.tenant_id, &rig.user_id, &new)
        .expect("verify new"));
    let old = CleartextPassword::from_string(OLD_PASSWORD.to_string());
    assert!(!rig
        .identity
        .verify_password(&rig.tenant_id, &rig.user_id, &old)
        .expect("verify old"));
}

// ---------------------------------------------------------------------------
// TOTP / MFA
// ---------------------------------------------------------------------------

/// Inline TOTP computation — mirrors `src/identity/totp.rs::compute_totp`.
/// Used to prove that the UI's activation POST drives the same code path
/// the engine's `verify_totp_enrollment` expects.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let msg = step.to_be_bytes();
    let tag = ring::hmac::sign(&key, &msg);
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let otp = binary % 1_000_000;
    format!("{otp:06}")
}

/// Scrapes the pending base32 secret out of the rendered enrolment page.
/// The template wraps it in `<code class="hearth-secret">SECRET</code>`.
fn scrape_secret(body: &str) -> String {
    let open = body
        .find("hearth-secret\">")
        .expect("secret wrapper not found");
    let rest = &body[open + "hearth-secret\">".len()..];
    let end = rest.find("</code>").expect("secret close tag not found");
    rest[..end].to_string()
}

#[tokio::test]
async fn totp_enroll_page_renders_qr_and_recovery_codes() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-totp");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/totp")
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
    assert!(body.contains("Enrol a new authenticator"));
    assert!(body.contains("hearth-secret"));
    assert!(body.contains("otpauth://"));
    assert!(body.contains("name=\"code\""));
    assert!(body.contains("name=\"_csrf\""));
}

#[tokio::test]
async fn totp_activate_enables_mfa_with_valid_code() {
    let rig = build_rig();
    let csrf = "csrf-activate";
    let cookie = auth_cookie(&rig, csrf);

    // GET to seed a pending secret and scrape it from the response.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/totp")
                .header(header::COOKIE, cookie.clone())
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
    let secret = scrape_secret(body);

    // Compute the code the user would see in their authenticator app.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&secret, now_secs);

    // POST to activate.
    let form = format!("code={code}&_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/totp/activate")
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
        Some("/ui/account"),
    );
    assert!(rig
        .identity
        .mfa_enabled(&rig.tenant_id, &rig.user_id)
        .expect("mfa_enabled"));
}

#[tokio::test]
async fn totp_activate_with_bad_code_shows_inline_error() {
    let rig = build_rig();
    let csrf = "csrf-activate-bad";
    let cookie = auth_cookie(&rig, csrf);

    // Seed pending enrolment.
    let _ = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/totp")
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let form = format!("code=000000&_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/totp/activate")
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
        body.contains("Invalid authentication code"),
        "expected inline error, got: {body}"
    );
    assert!(!rig
        .identity
        .mfa_enabled(&rig.tenant_id, &rig.user_id)
        .expect("mfa_enabled"));
}

#[tokio::test]
async fn totp_activate_without_csrf_returns_403() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig, "csrf-ok");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/totp/activate")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("code=000000&_csrf=wrong"))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn totp_enroll_page_shows_disable_form_when_already_enabled() {
    let rig = build_rig();
    let csrf = "csrf-already-on";
    let cookie = auth_cookie(&rig, csrf);

    // Enrol MFA directly through the engine before hitting the page.
    let enrollment = rig
        .identity
        .enroll_totp(&rig.tenant_id, &rig.user_id)
        .expect("enroll");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    rig.identity
        .verify_totp_enrollment(&rig.tenant_id, &rig.user_id, &code)
        .expect("verify enrollment");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/totp")
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
    assert!(body.contains("MFA is enabled"));
    assert!(body.contains("Disable MFA"));
    assert!(body.contains("action=\"/ui/account/totp/disable\""));
}

#[tokio::test]
async fn totp_disable_turns_mfa_off() {
    let rig = build_rig();
    let csrf = "csrf-disable";
    let cookie = auth_cookie(&rig, csrf);

    // Enrol and activate through the engine first.
    let enrollment = rig
        .identity
        .enroll_totp(&rig.tenant_id, &rig.user_id)
        .expect("enroll");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    rig.identity
        .verify_totp_enrollment(&rig.tenant_id, &rig.user_id, &code)
        .expect("verify enrollment");
    assert!(rig
        .identity
        .mfa_enabled(&rig.tenant_id, &rig.user_id)
        .expect("mfa_enabled"));

    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/totp/disable")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(!rig
        .identity
        .mfa_enabled(&rig.tenant_id, &rig.user_id)
        .expect("mfa_enabled"));
}
