//! Integration tests for the two-phase MFA login flow.
//!
//! Drives the axum router via `tower::ServiceExt::oneshot`. Covers:
//!
//! * Login without MFA → immediate session (unchanged behaviour).
//! * Login with MFA → 303 `/ui/mfa-challenge` + pending cookie.
//! * `GET /ui/mfa-challenge` without pending cookie → 303 `/ui/login`.
//! * `GET /ui/mfa-challenge` with valid pending → 200 with challenge form.
//! * `POST /ui/mfa-challenge` with valid TOTP → session created.
//! * `POST /ui/mfa-challenge` with invalid code → 401 error.
//! * `POST /ui/mfa-challenge` with expired cookie → 401 "expired".
//! * `POST /ui/mfa-challenge` with recovery code → session created.
//! * Login with `return_to` propagated through MFA challenge.
//! * `POST /ui/mfa-challenge` with tampered cookie → rejected.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::authz::{AuthzConfig, EmbeddedAuthzEngine};
use hearth::core::{Clock, SystemClock, TenantId, UserId};
use hearth::identity::email::EmailSender;
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateTenantRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

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

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];
const PASSWORD: &str = "correct-horse-battery-staple";

struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    tenant_id: TenantId,
    user_id: UserId,
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
    ));
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));

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
    let password = CleartextPassword::from_string(PASSWORD.to_string());
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

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        authz.clone() as Arc<dyn hearth::authz::AuthorizationEngine>,
        Arc::new(NullEmailSender) as Arc<dyn EmailSender>,
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz as Arc<dyn hearth::authz::AuthorizationEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
    );
    let app = web::router(state);

    TestRig {
        app,
        identity,
        tenant_id: tenant.id().clone(),
        user_id: user.id().clone(),
    }
}

/// Enrolls and activates TOTP for the test user. Returns the base32 secret.
fn enroll_mfa(rig: &TestRig) -> String {
    let enrollment = rig
        .identity
        .enroll_totp(&rig.tenant_id, &rig.user_id)
        .expect("enroll_totp");
    let secret_b32 = enrollment.secret_base32.clone();

    // Generate a valid TOTP code for the current time and verify enrollment.
    let code = compute_totp_code(&secret_b32, current_unix_secs());
    rig.identity
        .verify_totp_enrollment(&rig.tenant_id, &rig.user_id, &code)
        .expect("verify_totp_enrollment");
    secret_b32
}

/// Inline TOTP computation — mirrors `src/identity/totp.rs::compute_totp`.
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

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs()
}

/// Submits the login form and returns the response.
async fn post_login(app: axum::Router, email: &str, password: &str, return_to: Option<&str>) -> axum::response::Response {
    let mut body = format!("email={email}&password={password}");
    if let Some(r) = return_to {
        body.push_str(&format!("&return_to={r}"));
    }
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/ui/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("build request"),
    )
    .await
    .expect("oneshot")
}

/// Extracts all Set-Cookie values from a response.
fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

/// Finds a cookie value in the Set-Cookie headers by name prefix.
fn find_cookie_value<'a>(cookies: &'a [String], name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    for c in cookies {
        if let Some(rest) = c.strip_prefix(&prefix) {
            return Some(rest.split(';').next().unwrap_or(""));
        }
    }
    None
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn login_without_mfa_creates_session_immediately() {
    let rig = build_rig();
    // No TOTP enrolled — should create session directly.
    let response = post_login(rig.app, "alice@acme.test", PASSWORD, None).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header");
    assert_eq!(location, "/ui");

    let cookies = set_cookies(&response);
    assert!(
        cookies.iter().any(|c| c.starts_with("hearth_ui_session=")),
        "session cookie must be set: {cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.starts_with("hearth_ui_mfa_pending=")),
        "MFA pending cookie must NOT be set: {cookies:?}"
    );
}

#[tokio::test]
async fn login_with_mfa_redirects_to_challenge() {
    let rig = build_rig();
    enroll_mfa(&rig);

    let response = post_login(rig.app, "alice@acme.test", PASSWORD, None).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header");
    assert_eq!(location, "/ui/mfa-challenge");

    let cookies = set_cookies(&response);
    assert!(
        cookies.iter().any(|c| c.starts_with("hearth_ui_mfa_pending=")),
        "MFA pending cookie must be set: {cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.starts_with("hearth_ui_session=") && !c.contains("Max-Age=0")),
        "session cookie must NOT be set: {cookies:?}"
    );
}

#[tokio::test]
async fn mfa_challenge_get_without_pending_redirects() {
    let rig = build_rig();

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/mfa-challenge")
                .body(Body::empty())
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
}

#[tokio::test]
async fn mfa_challenge_get_with_valid_pending_renders_form() {
    let rig = build_rig();
    enroll_mfa(&rig);

    // First log in to get the pending cookie.
    let login_resp = post_login(rig.app.clone(), "alice@acme.test", PASSWORD, None).await;
    let cookies = set_cookies(&login_resp);
    let pending_value = find_cookie_value(&cookies, "hearth_ui_mfa_pending")
        .expect("pending cookie must be set");

    // GET /ui/mfa-challenge with the pending cookie.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/mfa-challenge")
                .header(header::COOKIE, format!("hearth_ui_mfa_pending={pending_value}"))
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
        body.contains("Two-factor"),
        "challenge page should contain 'Two-factor': got {body}"
    );
}

#[tokio::test]
async fn mfa_challenge_post_valid_totp_creates_session() {
    let rig = build_rig();
    let secret = enroll_mfa(&rig);

    // Login to get pending cookie.
    let login_resp = post_login(rig.app.clone(), "alice@acme.test", PASSWORD, None).await;
    let cookies = set_cookies(&login_resp);
    let pending_value = find_cookie_value(&cookies, "hearth_ui_mfa_pending")
        .expect("pending cookie must be set");

    // Compute a valid TOTP code for the *next* time step.  Enrollment already
    // consumed the current step, so using `current_unix_secs()` would hit replay
    // protection.  The next step is within the ±1 tolerance window.
    let code = compute_totp_code(&secret, current_unix_secs() + 30);

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ui_mfa_pending={pending_value}"))
                .body(Body::from(format!("code={code}")))
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
        Some("/ui")
    );

    let resp_cookies = set_cookies(&response);
    assert!(
        resp_cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_session=") && !c.contains("Max-Age=0")),
        "session cookie must be set: {resp_cookies:?}"
    );
    // Pending cookie must be cleared.
    assert!(
        resp_cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_mfa_pending=") && c.contains("Max-Age=0")),
        "pending cookie must be cleared: {resp_cookies:?}"
    );
}

#[tokio::test]
async fn mfa_challenge_post_invalid_totp_shows_error() {
    let rig = build_rig();
    enroll_mfa(&rig);

    let login_resp = post_login(rig.app.clone(), "alice@acme.test", PASSWORD, None).await;
    let cookies = set_cookies(&login_resp);
    let pending_value = find_cookie_value(&cookies, "hearth_ui_mfa_pending")
        .expect("pending cookie must be set");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ui_mfa_pending={pending_value}"))
                .body(Body::from("code=000000"))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("Invalid code"),
        "error message should contain 'Invalid code': got {body}"
    );
}

#[tokio::test]
async fn mfa_challenge_post_expired_cookie_shows_expired() {
    let rig = build_rig();
    enroll_mfa(&rig);

    // Craft an expired pending cookie manually.
    let now = current_unix_secs();
    let expired = now.saturating_sub(10);
    let return_to_b64 = "";
    // Compute MAC matching the expired timestamp.
    let mac = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
        m.update(rig.user_id.as_uuid().as_bytes());
        m.update(b"|");
        m.update(rig.tenant_id.as_uuid().as_bytes());
        m.update(b"|");
        m.update(expired.to_string().as_bytes());
        m.update(b"|");
        m.update(return_to_b64.as_bytes());
        data_encoding::BASE64URL_NOPAD.encode(&m.finalize().into_bytes())
    };
    let expired_cookie = format!(
        "{}.{}.{expired}.{return_to_b64}.{mac}",
        rig.user_id.as_uuid(),
        rig.tenant_id.as_uuid(),
    );

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("hearth_ui_mfa_pending={expired_cookie}"),
                )
                .body(Body::from("code=123456"))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("expired"),
        "error message should contain 'expired': got {body}"
    );
}

#[tokio::test]
async fn mfa_challenge_post_recovery_code_creates_session() {
    let rig = build_rig();

    // Enroll MFA and capture recovery codes.
    let enrollment = rig
        .identity
        .enroll_totp(&rig.tenant_id, &rig.user_id)
        .expect("enroll_totp");
    let recovery_codes: Vec<String> = enrollment.recovery_codes.as_slice().to_vec();
    let secret_b32 = enrollment.secret_base32.clone();

    // Verify enrollment with a valid TOTP code.
    let code = compute_totp_code(&secret_b32, current_unix_secs());
    rig.identity
        .verify_totp_enrollment(&rig.tenant_id, &rig.user_id, &code)
        .expect("verify_totp_enrollment");

    // Login to get pending cookie.
    let login_resp = post_login(rig.app.clone(), "alice@acme.test", PASSWORD, None).await;
    let cookies = set_cookies(&login_resp);
    let pending_value = find_cookie_value(&cookies, "hearth_ui_mfa_pending")
        .expect("pending cookie must be set");

    // Submit a recovery code instead of TOTP.
    let recovery = &recovery_codes[0];
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ui_mfa_pending={pending_value}"))
                .body(Body::from(format!("code={recovery}")))
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
        Some("/ui")
    );

    let resp_cookies = set_cookies(&response);
    assert!(
        resp_cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_session=") && !c.contains("Max-Age=0")),
        "session cookie must be set: {resp_cookies:?}"
    );
}

#[tokio::test]
async fn mfa_challenge_preserves_return_to() {
    let rig = build_rig();
    let secret = enroll_mfa(&rig);

    // Login with return_to.
    let login_resp = post_login(
        rig.app.clone(),
        "alice@acme.test",
        PASSWORD,
        Some("/ui/admin/users"),
    )
    .await;
    let cookies = set_cookies(&login_resp);
    let pending_value = find_cookie_value(&cookies, "hearth_ui_mfa_pending")
        .expect("pending cookie must be set");

    // Submit valid TOTP for the next step (current step was consumed by enrollment).
    let code = compute_totp_code(&secret, current_unix_secs() + 30);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ui_mfa_pending={pending_value}"))
                .body(Body::from(format!("code={code}")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header");
    assert_eq!(
        location, "/ui/admin/users",
        "MFA success should redirect to original return_to"
    );
}

#[tokio::test]
async fn mfa_challenge_post_tampered_cookie_rejected() {
    let rig = build_rig();
    enroll_mfa(&rig);

    // Login to get a real pending cookie.
    let login_resp = post_login(rig.app.clone(), "alice@acme.test", PASSWORD, None).await;
    let cookies = set_cookies(&login_resp);
    let pending_value = find_cookie_value(&cookies, "hearth_ui_mfa_pending")
        .expect("pending cookie must be set");

    // Tamper with the cookie: replace the first char of the MAC (last segment).
    let mut parts: Vec<&str> = pending_value.splitn(5, '.').collect();
    assert_eq!(parts.len(), 5, "cookie should have 5 parts");
    let mac = parts[4].to_string();
    let tampered_mac = if mac.starts_with('A') {
        format!("B{}", &mac[1..])
    } else {
        format!("A{}", &mac[1..])
    };
    parts[4] = &tampered_mac;
    let tampered = parts.join(".");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("hearth_ui_mfa_pending={tampered}"),
                )
                .body(Body::from("code=123456"))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    // Tampered cookie → expired/invalid → 401.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("expired") || body.contains("sign in again"),
        "tampered cookie should be treated as expired: got {body}"
    );
}
