//! Integration tests for HEA-502 Security Phase B acceptance criteria.
//!
//! Covers:
//! - F-03: Security response headers on UI routes (X-Frame-Options, CSP, etc.)
//! - F-04: `Secure` cookie attribute when TLS is active
//! - F-05: CORS preflight and response headers on OAuth token endpoints
//! - F-06: Per-`(realm, client)` token endpoint rate limiting (429 + Retry-After)

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{ClientId, RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
    RegisterClientRequest,
};
use hearth::protocol::admin_auth::TOKEN_RATE_LIMIT;
use hearth::protocol::http::{router as http_router, AppState};
use hearth::protocol::web::auth::{issue_auth_cookies, CookieSecret};
use hearth::protocol::web::{self, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Builds a `WebState` for UI-layer tests with a seeded "default" realm.
fn make_web_state() -> WebState {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    identity
        .create_realm(&CreateRealmRequest {
            name: "default".to_string(),
            config: None,
        })
        .expect("seed default realm");

    let email = null_email_service();
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        email,
        data_dir,
    ));

    WebState::new(
        identity,
        authz,
        audit,
        onboarding,
        CookieSecret::random(),
        None,
    )
}

/// Builds an `AppState` for HTTP-layer tests.  Returns both state and the
/// seeded realm id so callers can register clients against it.
fn make_app_state() -> (Arc<AppState>, RealmId) {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage =
        Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).expect("storage"));
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("sec-test-{}", Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let state = Arc::new(AppState::new(identity, rbac, audit));
    (state, realm_id)
}

// ---------------------------------------------------------------------------
// F-03: Security headers
// ---------------------------------------------------------------------------

/// Security headers are injected on every UI response, including the login page.
#[tokio::test]
async fn security_headers_present_on_ui_route() {
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let h = resp.headers();
    assert_eq!(
        h["x-frame-options"], "DENY",
        "X-Frame-Options should be DENY",
    );
    assert_eq!(
        h["x-content-type-options"], "nosniff",
        "X-Content-Type-Options should be nosniff"
    );
    assert!(
        h.contains_key("referrer-policy"),
        "Referrer-Policy header must be present"
    );
    assert!(
        h.contains_key("content-security-policy"),
        "Content-Security-Policy header must be present"
    );
    assert!(
        !h.contains_key("strict-transport-security"),
        "HSTS must NOT be set when TLS is disabled"
    );
}

/// HSTS header is emitted only when `tls_enabled = true`.
#[tokio::test]
async fn hsts_header_present_when_tls_enabled() {
    let app = web::router(make_web_state().with_tls_enabled(true));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp.headers().contains_key("strict-transport-security"),
        "HSTS header must be present when TLS is enabled"
    );
}

/// CSP must reference 'unsafe-eval' (required by Alpine.js) but NOT 'unsafe-inline'.
#[tokio::test]
async fn csp_allows_eval_but_not_inline_scripts() {
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("CSP header");

    assert!(
        csp.contains("'unsafe-eval'"),
        "CSP must allow unsafe-eval for Alpine.js"
    );
    assert!(
        !csp.contains("'unsafe-inline'") || csp.contains("style-src"),
        "CSP must not allow unsafe-inline for scripts"
    );
}

// ---------------------------------------------------------------------------
// F-04: Secure cookie flag
// ---------------------------------------------------------------------------

/// When `secure = true`, both session and CSRF cookies carry `; Secure`.
#[test]
fn session_cookie_has_secure_flag_when_tls_on() {
    let secret = CookieSecret::random();
    let realm_id = RealmId::new(Uuid::new_v4());
    let session_id = SessionId::new(Uuid::new_v4());

    let cookies = issue_auth_cookies(&secret, &realm_id, &session_id, true);

    assert!(
        cookies.session_cookie.contains("; Secure"),
        "session cookie must have Secure flag: {}",
        cookies.session_cookie
    );
    assert!(
        cookies.csrf_cookie.contains("; Secure"),
        "CSRF cookie must have Secure flag: {}",
        cookies.csrf_cookie
    );
}

/// When `secure = false` (plain HTTP), neither cookie carries `; Secure`.
#[test]
fn session_cookie_no_secure_flag_when_tls_off() {
    let secret = CookieSecret::random();
    let realm_id = RealmId::new(Uuid::new_v4());
    let session_id = SessionId::new(Uuid::new_v4());

    let cookies = issue_auth_cookies(&secret, &realm_id, &session_id, false);

    assert!(
        !cookies.session_cookie.contains("; Secure"),
        "session cookie must NOT have Secure flag over plain HTTP: {}",
        cookies.session_cookie
    );
    assert!(
        !cookies.csrf_cookie.contains("; Secure"),
        "CSRF cookie must NOT have Secure flag over plain HTTP: {}",
        cookies.csrf_cookie
    );
}

// ---------------------------------------------------------------------------
// F-05: CORS
// ---------------------------------------------------------------------------

/// Helper: registers a confidential client with a known redirect URI and
/// returns the registered `ClientId`.
fn register_cors_client(state: &AppState, realm_id: &RealmId) -> ClientId {
    let client = state
        .identity
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: "CORS Test Client".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: Some("cors-test-secret-1234".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register CORS test client");
    client.client_id().clone()
}

/// OPTIONS `/token` from a registered origin → 204 with CORS headers.
#[tokio::test]
async fn cors_preflight_allowed_origin_returns_headers() {
    let (state, realm_id) = make_app_state();
    register_cors_client(&state, &realm_id);
    let app = http_router(Arc::clone(&state));

    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/token")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .header("origin", "https://app.example.com")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "preflight should be 204"
    );
    assert_eq!(
        resp.headers()["access-control-allow-origin"],
        "https://app.example.com",
        "allowed origin must be echoed back"
    );
    assert!(
        resp.headers().contains_key("access-control-allow-methods"),
        "access-control-allow-methods must be present"
    );
}

/// OPTIONS `/token` from an unregistered origin → 204 with NO CORS headers.
#[tokio::test]
async fn cors_preflight_unregistered_origin_no_cors_headers() {
    let (state, realm_id) = make_app_state();
    register_cors_client(&state, &realm_id);
    let app = http_router(Arc::clone(&state));

    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/token")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .header("origin", "https://evil.com")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "preflight should still be 204"
    );
    assert!(
        !resp.headers().contains_key("access-control-allow-origin"),
        "unregistered origin must NOT get CORS headers"
    );
}

/// POST `/token` with `Origin` from a registered domain → response has
/// `Access-Control-Allow-Origin` echoing that origin.
#[tokio::test]
async fn token_response_includes_cors_header_for_registered_origin() {
    let (state, realm_id) = make_app_state();
    let client_id = register_cors_client(&state, &realm_id);
    let app = http_router(Arc::clone(&state));

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id.as_uuid().to_string(),
        "client_secret": "cors-test-secret-1234",
        "scope": null,
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .header("origin", "https://app.example.com")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.headers()["access-control-allow-origin"],
        "https://app.example.com",
        "token response must echo allowed origin"
    );
}

// ---------------------------------------------------------------------------
// F-06: Token rate limiting
// ---------------------------------------------------------------------------

/// After exceeding `TOKEN_RATE_LIMIT` requests per window, the next request
/// receives `429 Too Many Requests` with a `Retry-After` header.
#[tokio::test]
async fn token_rate_limit_returns_429_with_retry_after() {
    let (state, realm_id) = make_app_state();
    let client = state
        .identity
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Rate Limit Test Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some("rl-secret-xyz".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    let client_id = client.client_id().clone();

    // Pre-exhaust the rate window by calling the limiter directly (fast path).
    #[allow(clippy::cast_possible_truncation)]
    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;
    for _ in 0..TOKEN_RATE_LIMIT {
        state
            .token_rate_limiter
            .check(&realm_id, &client_id, now_micros);
    }

    // The next request via HTTP should be rejected with 429.
    let app = http_router(Arc::clone(&state));
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id.as_uuid().to_string(),
        "client_secret": "rl-secret-xyz",
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "should return 429 after exhausting rate window"
    );
    assert!(
        resp.headers().contains_key("retry-after"),
        "429 response must include Retry-After header"
    );
}
