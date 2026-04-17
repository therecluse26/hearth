//! Web UI protocol adapter.
//!
//! Serves the Hearth admin UI under `/ui/*`. Wire adapter only — every
//! state change flows through the identity, authorization, or audit
//! engines. Templates live under `templates/ui/`, compiled into the
//! binary by the askama derive macro; static assets (`htmx.min.js`,
//! `app.css`) are embedded via `include_bytes!`. Alpine.js is loaded
//! from a CDN with an SRI integrity hash.
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
use axum::response::{Redirect, Response};
use axum::Router;

use crate::audit::AuditEngine;
use crate::authz::AuthorizationEngine;
use crate::core::TenantId;
use crate::identity::onboarding::OnboardingService;
use crate::identity::IdentityEngine;

pub mod account;
pub mod admin;
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
/// | `/ui` | GET | Signed-in dashboard (redirects to login when unauthenticated) |
/// | `/ui/logout` | POST | Revoke session + clear cookies |
/// | `/ui/account` | GET | My-account page (password, MFA status) |
/// | `/ui/account/password` | POST | Change password |
/// | `/ui/account/totp` | GET | MFA enrol / disable page |
/// | `/ui/account/totp/activate` | POST | Activate pending TOTP enrolment |
/// | `/ui/account/totp/disable` | POST | Disable MFA |
/// | `/ui/admin/users` | GET | Admin users list |
/// | `/ui/admin/users/new` | GET/POST | Create user |
/// | `/ui/admin/users/{id}` | GET | User detail |
/// | `/ui/admin/users/{id}/edit` | GET/POST | Edit user |
/// | `/ui/admin/users/{id}/delete` | POST | Delete user |
/// | `/ui/admin/tenants` | GET | Admin tenants list |
/// | `/ui/admin/tenants/new` | GET/POST | Create tenant |
/// | `/ui/admin/tenants/{id}` | GET | Tenant detail |
/// | `/ui/admin/tenants/{id}/edit` | GET/POST | Edit tenant |
/// | `/ui/admin/tenants/{id}/delete` | POST | Delete tenant |
/// | `/ui/admin/applications` | GET | Admin applications list |
/// | `/ui/admin/applications/new` | GET/POST | Register application |
/// | `/ui/admin/applications/{id}` | GET | Application detail |
/// | `/ui/admin/applications/{id}/edit` | GET/POST | Edit application |
/// | `/ui/admin/applications/{id}/delete` | POST | Delete application |
/// | `/ui/admin/sessions` | GET | Admin sessions list |
/// | `/ui/admin/sessions/{id}/revoke` | POST | Revoke session |
/// | `/ui/admin/audit` | GET | Audit log viewer |
/// | `/ui/static/{file}` | GET | Embedded static assets (htmx, css) |
#[allow(clippy::too_many_lines)]
pub fn router(state: WebState) -> Router {
    let shared = Arc::new(state);
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
        .route("/logout", axum::routing::post(handlers::logout_submit))
        .route("/account", axum::routing::get(account::account_index))
        .route(
            "/account/password",
            axum::routing::post(account::account_change_password),
        )
        .route(
            "/account/totp",
            axum::routing::get(account::totp_enroll_form),
        )
        .route(
            "/account/totp/activate",
            axum::routing::post(account::totp_activate),
        )
        .route(
            "/account/totp/disable",
            axum::routing::post(account::totp_disable),
        )
        .route("/admin/users", axum::routing::get(admin::admin_users_list))
        .route(
            "/admin/users/new",
            axum::routing::get(admin::admin_user_create_form).post(admin::admin_user_create_submit),
        )
        .route(
            "/admin/users/{id}",
            axum::routing::get(admin::admin_user_detail),
        )
        .route(
            "/admin/users/{id}/edit",
            axum::routing::get(admin::admin_user_edit_form).post(admin::admin_user_edit_submit),
        )
        .route(
            "/admin/users/{id}/delete",
            axum::routing::post(admin::admin_user_delete),
        )
        // --- Tenants ---
        .route(
            "/admin/tenants",
            axum::routing::get(admin::admin_tenants_list),
        )
        .route(
            "/admin/tenants/new",
            axum::routing::get(admin::admin_tenant_create_form)
                .post(admin::admin_tenant_create_submit),
        )
        .route(
            "/admin/tenants/{id}",
            axum::routing::get(admin::admin_tenant_detail),
        )
        .route(
            "/admin/tenants/{id}/edit",
            axum::routing::get(admin::admin_tenant_edit_form).post(admin::admin_tenant_edit_submit),
        )
        .route(
            "/admin/tenants/{id}/delete",
            axum::routing::post(admin::admin_tenant_delete),
        )
        // --- Applications ---
        .route(
            "/admin/applications",
            axum::routing::get(admin::admin_apps_list),
        )
        .route(
            "/admin/applications/new",
            axum::routing::get(admin::admin_app_create_form).post(admin::admin_app_create_submit),
        )
        .route(
            "/admin/applications/{id}",
            axum::routing::get(admin::admin_app_detail),
        )
        .route(
            "/admin/applications/{id}/edit",
            axum::routing::get(admin::admin_app_edit_form).post(admin::admin_app_edit_submit),
        )
        .route(
            "/admin/applications/{id}/delete",
            axum::routing::post(admin::admin_app_delete),
        )
        // --- Sessions ---
        .route(
            "/admin/sessions",
            axum::routing::get(admin::admin_sessions_list),
        )
        .route(
            "/admin/sessions/{id}/revoke",
            axum::routing::post(admin::admin_session_revoke),
        )
        // --- Audit ---
        .route("/admin/audit", axum::routing::get(admin::admin_audit_list))
        .route("/static/{file}", axum::routing::get(serve_static))
        .with_state(Arc::clone(&shared));

    // axum 0.8 nest does NOT match `/ui/` (trailing slash) — only `/ui`
    // and `/ui/*`. Add a permanent redirect so bookmarks and old links
    // still work.
    Router::new()
        .route(
            "/ui/",
            axum::routing::get(|| async { Redirect::permanent("/ui") }),
        )
        .nest("/ui", ui_routes)
        .with_state(shared)
}

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

/// HTMX v1.9.12 — pinned, checksum recorded in `assets/CHECKSUMS.txt`.
const HTMX_JS: &[u8] = include_bytes!("assets/htmx.min.js");
/// Tailwind-generated CSS for the admin UI.
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
