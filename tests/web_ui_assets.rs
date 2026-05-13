//! Sentinel assertions for the admin UI CSS pipeline.
//!
//! The 2026-04-23 audit discovered the Tailwind build can silently drop the
//! Hearth theme layer — `.bg-ht-surface-raised`, `.btn-ember`, the `@layer
//! base { body { … } }` rule — and leave `/ui/static/app.css` as a bare
//! Tailwind base build. These tests exist to catch that regression class
//! at CI time rather than via Playwright. They check *structural* rules,
//! not specific color hexes, so customer-theming flexibility is preserved.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::SystemClock;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::protocol::web::{
    self, assert_app_css_sane, assert_bytes_sane, etag_for_bytes, CookieSecret, WebState,
    APP_CSS_FALLBACK, APP_CSS_MIN_BYTES, APP_CSS_SENTINEL,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

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

fn minimal_web_state() -> WebState {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
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

async fn body_str(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 1_048_576)
        .await
        .expect("body bytes");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The embedded `app.css` must contain the Hearth theme layer.
/// Mirrors the boot-time canary in `main.rs`.
#[test]
fn embedded_app_css_passes_sanity_check() {
    assert_app_css_sane().expect("app.css sanity check must pass in CI");
}

/// `GET /ui/static/app.css` returns the Hearth theme layer with
/// `var(--ht-surface-*)` references (not hardcoded hex), so that
/// `/ui/static/theme.css` can remain the single source of hex values
/// a customer can override.
#[tokio::test]
async fn app_css_route_serves_theme_layer_with_var_references() {
    let app = web::router(minimal_web_state());
    let req = Request::builder()
        .uri("/ui/static/app.css")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;

    assert!(
        body.contains(".bg-ht-surface-raised"),
        "app.css is missing .bg-ht-surface-raised — Tailwind purge regression"
    );
    assert!(
        body.contains(".btn-ember"),
        "app.css is missing .btn-ember — components layer dropped"
    );
    assert!(
        body.contains("var(--ht-surface-base)"),
        "app.css must reference var(--ht-surface-base), not a literal hex \
         (customer theming would break otherwise)"
    );
}

/// `GET /ui/static/theme.css` is never empty — it always emits a `:root { … }`
/// block with the full `--ht-*` palette even when no custom theme CSS is
/// configured. Regresses a subtle bug where an unconfigured deployment
/// served an empty body, leaving every semantic color unresolved until
/// `app.css` loaded.
#[tokio::test]
async fn theme_css_route_always_emits_root_block() {
    let state = minimal_web_state()
        .with_theme_css(hearth::protocol::web::themes::theme_css("ember").to_string());
    let app = web::router(state);
    let req = Request::builder()
        .uri("/ui/static/theme.css")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;

    assert!(
        body.contains(":root {"),
        "theme.css must include a :root block"
    );
    assert!(
        body.contains("--ht-surface-base"),
        "theme.css must define --ht-surface-base — customer overrides anchor here"
    );
}

/// `WebState::with_app_css` replaces the bytes served at `/ui/static/app.css`
/// without recompiling the binary. This is the contract that lets operators
/// rebuild Tailwind, restart the server, and pick up the new theme — the
/// reload mechanism the user surfaced as broken on 2026-04-29.
#[tokio::test]
async fn with_app_css_overrides_embedded_bytes() {
    // Build a sentinel-passing payload that's distinguishable from the
    // embedded fallback. We need at least APP_CSS_MIN_BYTES of content
    // and a substring matching APP_CSS_SENTINEL.
    let marker = b"/* RUNTIME_LOAD_MARKER */";
    let mut runtime_bytes = vec![b' '; APP_CSS_MIN_BYTES];
    runtime_bytes.extend_from_slice(marker);
    runtime_bytes.extend_from_slice(APP_CSS_SENTINEL);
    runtime_bytes.extend_from_slice(b"{display:none}");
    assert!(assert_bytes_sane(&runtime_bytes).is_ok());

    let state = minimal_web_state().with_app_css(runtime_bytes.clone());

    // The ETag must reflect the runtime bytes, not the embedded fallback.
    assert_eq!(state.app_css_etag, etag_for_bytes(&runtime_bytes));
    assert_ne!(
        state.app_css_etag,
        etag_for_bytes(APP_CSS_FALLBACK),
        "runtime ETag must differ from embedded fallback ETag"
    );

    // The route must hand back the runtime payload, not the embedded one.
    let app = web::router(state);
    let req = Request::builder()
        .uri("/ui/static/app.css")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(
        body.contains("RUNTIME_LOAD_MARKER"),
        "served bytes must come from with_app_css, not include_bytes!"
    );
}

/// Without `with_app_css`, the embedded fallback is served. Pins the
/// single-binary deploy story.
#[tokio::test]
async fn embedded_fallback_is_served_when_with_app_css_unset() {
    let state = minimal_web_state();
    assert_eq!(state.app_css_etag, etag_for_bytes(APP_CSS_FALLBACK));

    let app = web::router(state);
    let req = Request::builder()
        .uri("/ui/static/app.css")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains(".bg-ht-surface-raised"));
}

/// `/favicon.ico` and `/ui/static/favicon.svg` both serve the SVG mark.
/// Silences the 404 noise the audit flagged on every admin page load.
#[tokio::test]
async fn favicon_is_served_at_both_paths() {
    for path in ["/favicon.ico", "/favicon.svg", "/ui/static/favicon.svg"] {
        let app = web::router(minimal_web_state());
        let req = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "favicon at {path}");
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type present")
            .to_str()
            .expect("ASCII");
        assert!(
            ct.starts_with("image/svg+xml"),
            "favicon at {path} served as {ct}, expected image/svg+xml"
        );
    }
}
