//! Integration tests for explicit realm routing in the `/ui/*` surface.
//!
//! Covers the three resolution regimes:
//!
//! * Single-realm — bare `/ui/*` resolves implicitly, no config needed.
//! * Multi-realm with `default_realm` — bare `/ui/*` resolves to the
//!   declared default; the explicit `/ui/realms/<name>/...` path also
//!   works.
//! * Multi-realm without `default_realm` — bare GETs render the picker;
//!   bare POSTs return 400; explicit path still works.
//!
//! The resolver has no "walk all realms" fallback, so tests also pin
//! that cross-realm token/email leaks do not happen.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::authz::{AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{CleartextPassword, RealmConfig};
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RegisterUserRequest, RegistrationPolicy,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [7u8; 32];

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

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
}

fn build_rig(realm_names: &[&str], default_realm: Option<&str>) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Keep the tempdir alive for the lifetime of the process — tests
    // are short and independent.
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

    for name in realm_names {
        identity
            .create_realm(&CreateRealmRequest {
                name: (*name).to_string(),
                config: Some(RealmConfig {
                    registration_policy: Some(RegistrationPolicy::Open),
                    ..RealmConfig::default()
                }),
            })
            .expect("create realm");
    }

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
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_default_realm(default_realm.map(str::to_string));
    let app = web::router(state);

    Rig { app, identity }
}

async fn get(app: &axum::Router, path: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("build GET request"),
        )
        .await
        .expect("send request");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_form(app: &axum::Router, path: &str, body: &str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("build POST request"),
        )
        .await
        .expect("send request");
    resp.status()
}

// ============================================================================
// Single-realm deployment
// ============================================================================

#[tokio::test]
async fn bare_login_resolves_to_sole_realm() {
    let rig = build_rig(&["solo"], None);
    let (status, body) = get(&rig.app, "/ui/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Sign in"), "login form should render: {body}");
}

#[tokio::test]
async fn bare_register_resolves_to_sole_realm() {
    let rig = build_rig(&["solo"], None);
    let (status, body) = get(&rig.app, "/ui/register").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Create your account"),
        "register form should render on the sole realm (has RegistrationPolicy::Open): {}",
        &body[..body.len().min(500)]
    );
    assert!(
        !body.contains("Registration unavailable"),
        "sole realm has Open policy; must not show disabled banner"
    );
}

#[tokio::test]
async fn path_scoped_login_resolves_to_named_realm() {
    let rig = build_rig(&["public", "staff"], None);
    let (status, body) = get(&rig.app, "/ui/realms/public/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Sign in"));
}

#[tokio::test]
async fn path_scoped_unknown_realm_returns_404() {
    let rig = build_rig(&["default"], None);
    let (status, _) = get(&rig.app, "/ui/realms/does-not-exist/login").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================================
// Multi-realm with default
// ============================================================================

#[tokio::test]
async fn bare_login_resolves_to_default_when_configured() {
    let rig = build_rig(&["public", "staff"], Some("public"));
    let (status, body) = get(&rig.app, "/ui/login").await;
    assert_eq!(status, StatusCode::OK);
    // Form action should include the resolved realm so a subsequent POST
    // binds to the same realm rather than re-walking.
    assert!(
        body.contains("/ui/realms/public/login") || body.contains("action=\"/ui/login\""),
        "login form should target the resolved default realm: {}",
        &body[..body.len().min(400)]
    );
}

#[tokio::test]
async fn bare_register_resolves_to_default_when_configured() {
    let rig = build_rig(&["public", "staff"], Some("staff"));
    let (status, body) = get(&rig.app, "/ui/register").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Create your account"));
}

// ============================================================================
// Multi-realm without default → picker
// ============================================================================

#[tokio::test]
async fn bare_login_without_default_returns_terse_error() {
    // Multi-realm + no default_realm → the bare URL MUST NOT enumerate
    // realms. A "pick a tenant" list is a tenant-inventory leak; the
    // correct response is a terse 400 telling the user to ask their
    // admin for the correct URL.
    let rig = build_rig(&["alpha", "beta"], None);
    let (status, body) = get(&rig.app, "/ui/login").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("Sign-in URL required") || body.contains("explicit realm"),
        "terse error page should render: {}",
        &body[..body.len().min(400)]
    );
    assert!(
        !body.contains("alpha") && !body.contains("beta"),
        "body must not enumerate realm names: {}",
        &body[..body.len().min(600)]
    );
}

#[tokio::test]
async fn bare_post_rejects_without_default() {
    let rig = build_rig(&["alpha", "beta"], None);
    let status = post_form(&rig.app, "/ui/login", "email=nobody@example.com&password=x").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "bare POST without default_realm must 400 (no realm to bind to)"
    );
}

// ============================================================================
// Regression: no walk-all-realms
// ============================================================================

#[tokio::test]
async fn login_does_not_walk_realms() {
    // User exists only in `beta`, but bare `/ui/login` resolves to `alpha`
    // via default_realm. The login POST must fail (user not in alpha) rather
    // than silently succeeding by walking to beta.
    let rig = build_rig(&["alpha", "beta"], Some("alpha"));
    let beta = rig
        .identity
        .get_realm_by_name("beta")
        .expect("lookup")
        .expect("beta exists");

    let user = rig
        .identity
        .register_user(
            beta.id(),
            &RegisterUserRequest {
                email: "u@example.com".to_string(),
                display_name: "U".to_string(),
                password: CleartextPassword::from_string(
                    "correct-horse-battery-staple".to_string(),
                ),
                client_ip: None,
                invitation_token: None,
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("register_user");
    // Activate (skip email verification for this test).
    rig.identity
        .verify_email_token(beta.id(), &user.verification_token)
        .expect("verify");

    let status = post_form(
        &rig.app,
        "/ui/login",
        "email=u%40example.com&password=correct-horse-battery-staple",
    )
    .await;
    // Either an explicit 401 or a re-rendered form — anything *except*
    // a 303 redirect (which would mean the walk silently crossed realms).
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "bare /ui/login with default=alpha must NOT succeed when the user lives only in beta"
    );
    assert_ne!(status, StatusCode::FOUND);
}

#[tokio::test]
async fn verify_email_respects_path_realm() {
    let rig = build_rig(&["alpha", "beta"], Some("alpha"));
    let alpha = rig
        .identity
        .get_realm_by_name("alpha")
        .expect("lookup")
        .expect("alpha exists");

    // Issue a verification token in alpha.
    let resp = rig
        .identity
        .register_user(
            alpha.id(),
            &RegisterUserRequest {
                email: "verify@example.com".to_string(),
                display_name: "V".to_string(),
                password: CleartextPassword::from_string(
                    "correct-horse-battery-staple".to_string(),
                ),
                client_ip: None,
                invitation_token: None,
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("register_user");

    // Hitting the token under realm `beta` must NOT succeed — no walk.
    let beta_url = format!(
        "/ui/realms/beta/verify-email?token={}",
        resp.verification_token
    );
    let (status, _) = get(&rig.app, &beta_url).await;
    assert!(
        status == StatusCode::GONE || status == StatusCode::NOT_FOUND,
        "wrong-realm verify must not succeed, got {status}"
    );

    // Hitting it under realm `alpha` succeeds.
    let alpha_url = format!(
        "/ui/realms/alpha/verify-email?token={}",
        resp.verification_token
    );
    let (status, _) = get(&rig.app, &alpha_url).await;
    assert_eq!(status, StatusCode::OK, "alpha verify should succeed");
}
