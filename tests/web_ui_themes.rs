//! Integration tests for `/ui/static/theme.css` and
//! `/ui/static/realm-theme/{id}` — the dynamic CSS serving routes.
//!
//! Drives the axum router via `tower::ServiceExt::oneshot`. Covers:
//!
//! * Default (no custom CSS) returns 200 with empty body.
//! * Custom CSS set via `with_theme_css` appears in the response body.
//! * Two requests with the same state return the same `ETag`.
//! * A request carrying `If-None-Match: <etag>` receives `304 Not Modified`.
//! * Different CSS produces a different `ETag`.
//! * Unknown realm-theme id returns 404.
//! * Known realm-theme id returns 200 with the correct CSS.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::RealmId;
use hearth::core::SystemClock;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
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

/// Builds a minimal `WebState` suitable for static-asset and pre-auth
/// route tests. A single `"default"` realm is created so the realm
/// resolver's sole-realm shortcut applies — matching what `reconcile::
/// reconcile_realms` does on first startup of a real deployment.
fn minimal_web_state() -> WebState {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Keep the temp dir alive for the duration of the test via `forget`.
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
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

/// Reads the raw body bytes of an axum `Response` up to `limit` bytes.
async fn body_bytes(resp: axum::response::Response, limit: usize) -> axum::body::Bytes {
    to_bytes(resp.into_body(), limit).await.expect("body bytes")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Default state (no custom CSS) → 200 with effectively empty body.
#[tokio::test]
async fn theme_css_empty_returns_200() {
    let app = web::router(minimal_web_state());
    let req = Request::builder()
        .uri("/ui/static/theme.css")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

/// CSS set via `with_theme_css` appears verbatim in the 200 body.
#[tokio::test]
async fn theme_css_custom_css_in_response() {
    let state = minimal_web_state().with_theme_css("body { color: red; }".to_string());
    let app = web::router(state);
    let req = Request::builder()
        .uri("/ui/static/theme.css")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_bytes(resp, 4096).await;
    assert!(
        body.windows(b"color: red".len())
            .any(|w| w == b"color: red"),
        "expected CSS content not found in response body"
    );
}

/// Two requests with identical state return the same `ETag` header value.
#[tokio::test]
async fn theme_css_etag_is_stable() {
    let css = ":root { --ht-content-brand: 255 0 0; }".to_string();
    let state = minimal_web_state().with_theme_css(css);

    // First request.
    let app1 = web::router(state.clone());
    let resp1 = app1
        .oneshot(
            Request::builder()
                .uri("/ui/static/theme.css")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("first request");
    let etag1 = resp1
        .headers()
        .get(header::ETAG)
        .expect("ETag header on first response")
        .to_str()
        .expect("ETag is ASCII")
        .to_string();

    // Second request — must produce the same ETag.
    let app2 = web::router(state);
    let resp2 = app2
        .oneshot(
            Request::builder()
                .uri("/ui/static/theme.css")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("second request");
    let etag2 = resp2
        .headers()
        .get(header::ETAG)
        .expect("ETag header on second response")
        .to_str()
        .expect("ETag is ASCII")
        .to_string();

    assert_eq!(etag1, etag2, "ETag changed between identical requests");
}

/// A request carrying `If-None-Match: <current etag>` receives `304 Not Modified`.
#[tokio::test]
async fn theme_css_conditional_returns_304() {
    let css = ":root { --ht-brand-from: 255 100 0; }".to_string();
    let state = minimal_web_state().with_theme_css(css);

    // First: fetch to obtain the ETag.
    let app = web::router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/static/theme.css")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("initial request");
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get(header::ETAG)
        .expect("ETag on initial response")
        .to_str()
        .expect("ASCII")
        .to_string();

    // Second: conditional request — should get 304.
    let app2 = web::router(state);
    let resp2 = app2
        .oneshot(
            Request::builder()
                .uri("/ui/static/theme.css")
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("conditional request");
    assert_eq!(
        resp2.status(),
        StatusCode::NOT_MODIFIED,
        "expected 304 with matching ETag"
    );
}

/// Different CSS content produces a different `ETag`.
#[tokio::test]
async fn theme_css_etag_changes_when_content_changes() {
    let state_a =
        minimal_web_state().with_theme_css(":root { --ht-brand-from: 0 0 255; }".to_string());
    let state_b =
        minimal_web_state().with_theme_css(":root { --ht-brand-from: 255 0 0; }".to_string());

    let get_etag = |state: WebState| async move {
        let app = web::router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ui/static/theme.css")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("request");
        resp.headers()
            .get(header::ETAG)
            .expect("ETag")
            .to_str()
            .expect("ASCII")
            .to_string()
    };

    let etag_a = get_etag(state_a).await;
    let etag_b = get_etag(state_b).await;
    assert_ne!(etag_a, etag_b, "ETags should differ for different CSS");
}

/// Unknown realm id at `/ui/static/realm-theme/{id}` returns 404.
#[tokio::test]
async fn realm_theme_not_found_returns_404() {
    let app = web::router(minimal_web_state());
    let req = Request::builder()
        .uri("/ui/static/realm-theme/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Theme CSS set via `with_theme_css` appears inlined in a `<style>` tag
/// in the rendered login page HTML — NOT as an external `<link>`.
#[tokio::test]
async fn theme_css_inlined_in_html_page() {
    let css = ":root { --ht-content-brand: 0 200 100; }".to_string();
    let state = minimal_web_state().with_theme_css(css.clone());
    let app = web::router(state);

    let req = Request::builder()
        .uri("/ui/login")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_bytes(resp, 64 * 1024).await;
    let html = std::str::from_utf8(&body).expect("UTF-8 html");

    // The CSS MUST appear inside a <style> tag, not as a <link> to theme.css
    assert!(
        html.contains("<style>:root { --ht-content-brand: 0 200 100; }</style>"),
        "theme CSS not found inline in HTML.\n\
         Looking for: <style>{css}</style>\n\
         Head section:\n{}",
        &html[..html.find("</head>").unwrap_or(500.min(html.len()))]
    );
    assert!(
        !html.contains(r#"href="/ui/static/theme.css""#),
        "theme.css should NOT be loaded via <link> tag anymore"
    );
}

/// Known realm id returns 200 with the correct CSS content.
#[tokio::test]
async fn realm_theme_found_returns_css() {
    let realm_id = RealmId::new(Uuid::new_v4());
    let id_str = realm_id.as_uuid().to_string();
    let css = ":root { --ht-content-brand: 0 200 100; }".to_string();

    let mut map = HashMap::new();
    map.insert(id_str.clone(), css.clone());

    let state = minimal_web_state().with_realm_themes(map);
    let app = web::router(state);

    let req = Request::builder()
        .uri(format!("/ui/static/realm-theme/{id_str}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_bytes(resp, 4096).await;
    let body_str = std::str::from_utf8(&body).expect("UTF-8");
    assert!(
        body_str.contains("--ht-content-brand: 0 200 100"),
        "realm CSS not found in response: {body_str}"
    );
}
