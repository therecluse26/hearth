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
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Redirect, Response};
use axum::Router;

use crate::audit::AuditEngine;
use crate::authz::AuthorizationEngine;
use crate::config::{Config, EnvVarWarning};
use crate::core::TenantId;
use crate::identity::onboarding::OnboardingService;
use crate::identity::{EmailService, IdentityEngine};

pub mod account;
pub mod admin;
pub mod auth;
pub mod handlers;
pub(crate) mod handlers_common;
pub(crate) mod templates;
pub mod themes;

pub use auth::CookieSecret;

/// Default logo URL served from the embedded static assets. Used when
/// no custom `branding.logo_url` is configured.
pub const DEFAULT_LOGO_URL: &str = "/ui/static/img/hearth-wide-web.svg";

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
    /// Email service for sending transactional emails (password reset, etc.).
    ///
    /// `None` when email is not configured (tests, minimal deployments).
    pub email: Option<Arc<EmailService>>,
    /// 32-byte random secret used to MAC session cookies.
    pub cookie_secret: CookieSecret,
    /// The tenant the UI is currently pinned to. Set by
    /// [`OnboardingService::complete_setup`] on first-run, and cached
    /// on successful login for subsequent requests. `None` at startup
    /// until a tenant is known.
    pub current_tenant: Arc<RwLock<Option<TenantId>>>,
    /// Configuration warnings (missing/empty env vars) surfaced on the
    /// admin dashboard.
    pub config_warnings: Vec<EnvVarWarning>,
    /// `true` when the email transport is `Log` (no real delivery).
    /// Used by the setup-sent page to show a "check your server logs"
    /// callout only when emails are not actually being sent.
    pub email_is_log_transport: bool,
    /// Product name injected into templates (logo alt text, page titles).
    /// Defaults to `"Hearth"` when no `branding.product_name` is configured.
    pub product_name: String,
    /// Logo URL injected into every template. Defaults to the built-in
    /// Hearth SVG when no `branding.logo_url` is configured.
    pub logo_url: String,
    /// When `branding.logo_url` is a local file path, the file bytes are
    /// loaded at startup and served via `/ui/static/custom-logo`. `None`
    /// when using the built-in logo or a remote URL.
    pub custom_logo: Option<CustomLogo>,
    /// Full server configuration, made available for the System Info page.
    /// `None` in test contexts where no config file is loaded.
    pub config: Option<Arc<Config>>,
    /// Global theme CSS (named theme CSS + optional custom CSS file).
    /// Served at `GET /ui/static/theme.css`. Empty string when no theme
    /// is configured (ember dark is the default, expressed only in `:root`).
    pub theme_css: String,
    /// Per-tenant CSS blocks keyed by `TenantId` lowercased hex string.
    /// Served at `GET /ui/static/tenant-theme/{id}`. Empty when no tenants
    /// have per-tenant themes configured.
    pub tenant_themes: std::collections::HashMap<String, String>,
}

/// A logo loaded from a local file path at startup.
///
/// Served by [`serve_static`] at the `custom-logo` path. The file is
/// read once and kept in memory for the lifetime of the process.
#[derive(Clone)]
pub struct CustomLogo {
    /// Raw file bytes (SVG, PNG, JPEG).
    pub bytes: Vec<u8>,
    /// MIME content type (e.g. `"image/svg+xml"`).
    pub content_type: &'static str,
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
        email: Option<Arc<EmailService>>,
    ) -> Self {
        Self {
            identity,
            authz,
            audit,
            onboarding,
            email,
            cookie_secret,
            current_tenant: Arc::new(RwLock::new(None)),
            config_warnings: Vec::new(),
            email_is_log_transport: false,
            product_name: "Hearth".to_string(),
            logo_url: DEFAULT_LOGO_URL.to_string(),
            custom_logo: None,
            config: None,
            theme_css: String::new(),
            tenant_themes: std::collections::HashMap::new(),
        }
    }

    /// Attaches configuration warnings to this state.
    #[must_use]
    pub fn with_config_warnings(mut self, warnings: Vec<EnvVarWarning>) -> Self {
        self.config_warnings = warnings;
        self
    }

    /// Marks whether the email transport is `Log` (no real delivery).
    #[must_use]
    pub fn with_email_log_transport(mut self, val: bool) -> Self {
        self.email_is_log_transport = val;
        self
    }

    /// Sets the product name (overriding the default `"Hearth"`).
    #[must_use]
    pub fn with_product_name(mut self, name: String) -> Self {
        self.product_name = name;
        self
    }

    /// Sets a custom logo URL (overriding the built-in default).
    #[must_use]
    pub fn with_logo_url(mut self, url: String) -> Self {
        self.logo_url = url;
        self
    }

    /// Attaches the full server configuration for display on the System Info
    /// page. When absent (the default), the page shows a brief notice.
    #[must_use]
    pub fn with_config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    /// Attaches a custom logo loaded from a local file path. When set,
    /// [`serve_static`] serves it at `/ui/static/custom-logo`.
    #[must_use]
    pub fn with_custom_logo(mut self, bytes: Vec<u8>, content_type: &'static str) -> Self {
        self.custom_logo = Some(CustomLogo {
            bytes,
            content_type,
        });
        self
    }

    /// Sets the global theme CSS (named theme + optional custom CSS).
    /// Served at `GET /ui/static/theme.css`.
    #[must_use]
    pub fn with_theme_css(mut self, css: String) -> Self {
        self.theme_css = css;
        self
    }

    /// Sets the per-tenant theme map (tenant hex id → composed CSS).
    #[must_use]
    pub fn with_tenant_themes(mut self, map: std::collections::HashMap<String, String>) -> Self {
        self.tenant_themes = map;
        self
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

    /// Returns the per-tenant theme URL for the currently-pinned tenant,
    /// or `None` if no per-tenant theme is configured.
    ///
    /// Used by all authenticated handlers to populate `tenant_theme_url`
    /// in template structs, enabling per-tenant CSS overrides.
    #[must_use]
    pub fn tenant_theme_url(&self) -> Option<String> {
        let tenant_id = self.current_tenant()?;
        let id = tenant_id.as_uuid().to_string();
        self.tenant_themes
            .contains_key(&id)
            .then(|| format!("/ui/static/tenant-theme/{id}"))
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
/// | `/ui/admin/tenants` | GET | Admin tenants list (read-only) |
/// | `/ui/admin/tenants/{id}` | GET | Tenant detail (read-only) |
/// | `/ui/admin/tenants/{id}/delete` | POST | Delete archived tenant |
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
        .route(
            "/mfa-challenge",
            axum::routing::get(handlers::mfa_challenge_form).post(handlers::mfa_challenge_submit),
        )
        .route(
            "/forgot-password",
            axum::routing::get(handlers::forgot_password_form)
                .post(handlers::forgot_password_submit),
        )
        .route(
            "/forgot-password/sent",
            axum::routing::get(handlers::forgot_password_sent),
        )
        .route(
            "/reset-password",
            axum::routing::get(handlers::reset_password_form).post(handlers::reset_password_submit),
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
        // --- Tenants (read-only; managed via hearth.yaml) ---
        .route(
            "/admin/tenants",
            axum::routing::get(admin::admin_tenants_list),
        )
        .route(
            "/admin/tenants/{id}",
            axum::routing::get(admin::admin_tenant_detail),
        )
        .route(
            "/admin/tenants/{id}/delete",
            axum::routing::post(admin::admin_tenant_delete),
        )
        // --- Organizations ---
        .route(
            "/admin/organizations",
            axum::routing::get(admin::admin_orgs_list),
        )
        .route(
            "/admin/organizations/new",
            axum::routing::get(admin::admin_org_create_form).post(admin::admin_org_create_submit),
        )
        .route(
            "/admin/organizations/{id}",
            axum::routing::get(admin::admin_org_detail),
        )
        .route(
            "/admin/organizations/{id}/edit",
            axum::routing::get(admin::admin_org_edit_form).post(admin::admin_org_edit_submit),
        )
        .route(
            "/admin/organizations/{id}/delete",
            axum::routing::post(admin::admin_org_delete),
        )
        .route(
            "/admin/organizations/{id}/members",
            axum::routing::post(admin::admin_org_add_member),
        )
        .route(
            "/admin/organizations/{id}/members/{uid}/remove",
            axum::routing::post(admin::admin_org_remove_member),
        )
        .route(
            "/admin/organizations/{id}/members/{uid}/role",
            axum::routing::post(admin::admin_org_update_role),
        )
        .route(
            "/admin/organizations/{id}/invite",
            axum::routing::post(admin::admin_org_invite),
        )
        .route(
            "/admin/organizations/{id}/invitations/{iid}/revoke",
            axum::routing::post(admin::admin_org_revoke_invite),
        )
        // --- User search API (HTMX) ---
        .route(
            "/admin/api/users/search",
            axum::routing::get(admin::admin_api_user_search),
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
        .route(
            "/admin/settings",
            axum::routing::get(admin::admin_system_info),
        )
        .route(
            "/admin/test-email",
            axum::routing::post(admin::admin_test_email),
        )
        .route("/static/{*file}", axum::routing::get(serve_static))
        .route(
            "/static/theme.css",
            axum::routing::get(serve_theme_css),
        )
        .route(
            "/static/tenant-theme/{id}",
            axum::routing::get(serve_tenant_theme),
        )
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
/// Hearth wide logo (SVG). Public so `main.rs` can pass the SVG content
/// to the email service for inline rendering.
pub const HEARTH_WIDE_SVG: &[u8] = include_bytes!("assets/hearth-wide-web.svg");
/// Hearth icon (SVG).
const HEARTH_ICON_SVG: &[u8] = include_bytes!("assets/hearth-icon.svg");

/// Serves embedded static assets with long-lived caching headers.
///
/// Files are compiled into the binary — there is no filesystem access,
/// except for `custom-logo` which is loaded from disk at startup when
/// `branding.logo_url` points to a local file.
///
/// The cache headers are safe because the assets are immutable for the
/// life of a given binary (redeploy to change).
async fn serve_static(
    State(state): State<Arc<WebState>>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    // Try embedded assets first.
    let embedded: Option<(&[u8], &str)> = match file.as_str() {
        "htmx.min.js" => Some((HTMX_JS, "application/javascript; charset=utf-8")),
        "app.css" => Some((APP_CSS, "text/css; charset=utf-8")),
        "img/hearth-wide-web.svg" => Some((HEARTH_WIDE_SVG, "image/svg+xml")),
        "img/hearth-icon.svg" => Some((HEARTH_ICON_SVG, "image/svg+xml")),
        _ => None,
    };

    if let Some((bytes, content_type)) = embedded {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            )
            .body(Body::from(bytes))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // Runtime-loaded custom logo (from local file path at startup).
    if file == "custom-logo" {
        if let Some(logo) = &state.custom_logo {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, logo.content_type)
                .header(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=3600"),
                )
                .body(Body::from(logo.bytes.clone()))
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("not found"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Serves the global theme CSS at `/ui/static/theme.css`.
///
/// Contains the named theme overrides and any operator custom CSS. Empty
/// when the default ember theme is active and no custom CSS is set.
async fn serve_theme_css(State(state): State<Arc<WebState>>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
        .header(
            header::CACHE_CONTROL,
            // Revalidate on each request — operators can change themes.
            HeaderValue::from_static("no-cache"),
        )
        .body(Body::from(state.theme_css.clone()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Serves a per-tenant theme CSS at `/ui/static/tenant-theme/{id}`.
///
/// Returns `404 Not Found` when no per-tenant theme is configured for
/// the given tenant id.
async fn serve_tenant_theme(
    State(state): State<Arc<WebState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Some(css) = state.tenant_themes.get(&id) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
            .header(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache"),
            )
            .body(Body::from(css.clone()))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("not found"))
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
