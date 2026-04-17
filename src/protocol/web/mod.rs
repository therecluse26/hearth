//! Web UI protocol adapter.
//!
//! Serves the Hearth admin UI under `/ui/*`. Wire adapter only — every
//! state change flows through the identity, authorization, or audit
//! engines. Templates live under `templates/ui/`, compiled into the
//! binary by the askama derive macro; static assets
//! (`htmx.min.js`, `app.css`) are embedded via `include_bytes!`.
//!
//! # Submodules
//!
//! * [`auth`] — cookie-based session + CSRF extractors
//!   ([`auth::UiSession`], [`auth::RequireAdmin`], [`auth::CsrfToken`]).
//! * [`templates`] — askama rendering glue + the [`templates::Flash`]
//!   value type.
//! * [`handlers`] — public (pre-auth) handlers: setup, verify-email,
//!   login.
//! * [`handlers_common`] — generic error templates used across modules.
//!
//! # Security notes
//!
//! * The setup handler is gated on a one-time token generated at startup
//!   (Jenkins-style). The token is held in `<data_dir>/.setup_token` and
//!   compared in constant time via [`crate::identity::onboarding`].
//! * On login the server issues two cookies — `hearth_ui_session`
//!   (`HttpOnly`) and `hearth_ui_csrf` (readable by HTMX). Both are
//!   `Path=/ui; SameSite=Lax`. See [`auth`] for the cookie format.
//! * CSRF is a stateless double-submit token — every mutation must
//!   echo the cookie back via the `_csrf` form field or the
//!   `X-CSRF-Token` HTMX header.

use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::Path as AxumPath;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Router;

use crate::audit::AuditEngine;
use crate::authz::AuthorizationEngine;
use crate::core::TenantId;
use crate::identity::onboarding::OnboardingService;
use crate::identity::IdentityEngine;

pub mod auth;
pub mod handlers;
pub(crate) mod handlers_common;
pub(crate) mod templates;

pub use auth::CookieSecret;

/// Shared state for the `/ui/*` routes.
///
/// Every field is cheap to clone — engines are `Arc<dyn _>`,
/// [`CookieSecret`] wraps an `Arc<[u8; 32]>`, and `current_tenant`
/// wraps an `Arc<RwLock<...>>`.
#[derive(Clone)]
pub struct WebState {
    /// Identity engine for session creation, password verification,
    /// and email-verification token consumption.
    pub identity: Arc<dyn IdentityEngine>,
    /// Authorization engine — used by [`auth::RequireAdmin`] to check
    /// the `hearth#admin` relation.
    pub authz: Arc<dyn AuthorizationEngine>,
    /// Audit engine — used to record UI-originated mutations.
    pub audit: Arc<dyn AuditEngine>,
    /// First-run onboarding orchestration.
    pub onboarding: Arc<OnboardingService>,
    /// 32-byte random secret used to MAC session cookies.
    pub cookie_secret: CookieSecret,
    /// The tenant the UI is currently pinned to. Set by
    /// [`OnboardingService::complete_setup`] on first-run, and cached
    /// on successful login for subsequent requests. `None` at startup
    /// until a tenant is known.
    pub current_tenant: Arc<RwLock<Option<TenantId>>>,
}

impl WebState {
    /// Builds a new [`WebState`].
    #[must_use]
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        authz: Arc<dyn AuthorizationEngine>,
        audit: Arc<dyn AuditEngine>,
        onboarding: Arc<OnboardingService>,
        cookie_secret: CookieSecret,
    ) -> Self {
        Self {
            identity,
            authz,
            audit,
            onboarding,
            cookie_secret,
            current_tenant: Arc::new(RwLock::new(None)),
        }
    }

    /// Pins a tenant as the "current" one for this process. Called by
    /// onboarding and the login handler so subsequent requests skip
    /// the `list_tenants` walk.
    pub fn set_current_tenant(&self, tenant_id: TenantId) {
        if let Ok(mut guard) = self.current_tenant.write() {
            *guard = Some(tenant_id);
        }
    }

    /// Reads the currently-pinned tenant id, if any.
    #[must_use]
    pub fn current_tenant(&self) -> Option<TenantId> {
        self.current_tenant.read().ok().and_then(|g| g.clone())
    }
}

/// Builds the `/ui/*` axum router.
///
/// Routes:
///
/// | Path | Method | Description |
/// |---|---|---|
/// | `/ui/setup` | GET/POST | First-run setup form (token-gated) |
/// | `/ui/setup/sent` | GET | "Check your email" confirmation |
/// | `/ui/verify-email` | GET | Consume an email-verification token |
/// | `/ui/login` | GET/POST | Login form + submit |
/// | `/ui/` | GET | Placeholder dashboard |
/// | `/ui/static/{file}` | GET | Embedded static assets (htmx, css) |
pub fn router(state: WebState) -> Router {
    let ui_routes = Router::new()
        .route(
            "/setup",
            axum::routing::get(handlers::setup_form).post(handlers::setup_submit),
        )
        .route("/setup/sent", axum::routing::get(handlers::setup_sent))
        .route("/verify-email", axum::routing::get(handlers::verify_email))
        .route(
            "/login",
            axum::routing::get(handlers::login_form).post(handlers::login_submit),
        )
        .route("/", axum::routing::get(handlers::dashboard))
        .route("/static/{file}", axum::routing::get(serve_static))
        .with_state(Arc::new(state));

    Router::new().nest("/ui", ui_routes)
}

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

/// HTMX v1.9.12 — pinned, checksum recorded in `assets/CHECKSUMS.txt`.
const HTMX_JS: &[u8] = include_bytes!("assets/htmx.min.js");
/// Hand-rolled CSS for the admin UI.
const APP_CSS: &[u8] = include_bytes!("assets/app.css");

/// Serves embedded static assets with long-lived caching headers.
///
/// Files are compiled into the binary — there is no filesystem access.
/// The cache headers are safe because the assets are immutable for the
/// life of a given binary (redeploy to change).
async fn serve_static(AxumPath(file): AxumPath<String>) -> Response {
    let (bytes, content_type) = match file.as_str() {
        "htmx.min.js" => (HTMX_JS, "application/javascript; charset=utf-8"),
        "app.css" => (APP_CSS, "text/css; charset=utf-8"),
        _ => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("not found"))
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        )
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke-test that the router builder is object-safe in the sense
    // that `WebState::new` compiles with the current trait object types.
    // Full HTTP-level tests live in `tests/onboarding.rs`.
    #[allow(clippy::items_after_statements)]
    #[test]
    fn web_state_builder_is_clonable() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<WebState>();
    }

    #[test]
    fn static_assets_are_embedded() {
        // Compile-time embedded — check lengths so future drops to zero bytes
        // (e.g. a broken build.rs) surface as a test failure.
        assert!(HTMX_JS.len() > 1024, "htmx.min.js seems too small");
        assert!(APP_CSS.len() > 64, "app.css seems too small");
    }
}
