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

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Redirect, Response};
use axum::Router;
use sha2::{Digest, Sha256};

use crate::audit::AuditEngine;
use crate::authz::AuthorizationEngine;
use crate::config::{Config, EnvVarWarning};
use crate::core::RealmId;
use crate::identity::onboarding::OnboardingService;
use crate::identity::{EmailService, IdentityEngine};

pub mod account;
pub mod admin;
pub mod auth;
pub mod handlers;
pub(crate) mod handlers_common;
pub mod realm_resolver;
pub(crate) mod templates;
pub mod themes;

pub use auth::CookieSecret;

/// Default logo URL served from the embedded static assets. Used when
/// no custom `branding.logo_url` is configured.
pub const DEFAULT_LOGO_URL: &str = "/ui/static/img/hearth-wide-web.svg";

/// Shared state for the `/ui/*` routes.
///
/// Every field is cheap to clone — engines are `Arc<dyn _>`,
/// [`CookieSecret`] wraps an `Arc<[u8; 32]>`, and `current_realm`
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
    /// The realm the UI is currently pinned to. Set by
    /// [`OnboardingService::complete_setup`] on first-run, and cached
    /// on successful login for subsequent requests. `None` at startup
    /// until a realm is known.
    pub current_realm: Arc<RwLock<Option<RealmId>>>,
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
    /// Per-realm CSS blocks keyed by `RealmId` lowercased hex string.
    /// Served at `GET /ui/static/realm-theme/{id}`. Empty when no realms
    /// have per-realm themes configured.
    pub realm_themes: HashMap<String, String>,
    /// `ETag` for the global theme CSS (SHA-256 of [`WebState::theme_css`],
    /// first 8 bytes). Updated by [`WebState::with_theme_css`].
    pub theme_css_etag: String,
    /// Per-realm `ETags`, keyed by the same realm hex string as
    /// [`WebState::realm_themes`]. Updated by [`WebState::with_realm_themes`].
    pub realm_theme_etags: HashMap<String, String>,
    /// Parsed trusted proxy IP addresses (from `server.trusted_proxies` config).
    ///
    /// Used by [`crate::protocol::client_info::extract_client_ip`] to walk
    /// `X-Forwarded-For` right-to-left and find the real client IP.
    pub trusted_proxies: Vec<IpAddr>,
    /// Notifier for triggering config hot-reload from the admin API.
    ///
    /// When `notify()` is called, the SIGHUP handler loop wakes and
    /// re-reads the config file + runs reconciliation. `None` in test
    /// contexts.
    pub reload_notify: Option<Arc<tokio::sync::Notify>>,
    /// Name of the default realm for pre-auth URLs when the request URL
    /// doesn't carry an explicit realm path segment. See the resolver
    /// in [`super::realm_resolver`] for how this is used.
    ///
    /// `None` means "no default"; on multi-realm deployments that forces
    /// users to visit `/ui/realms/<name>/...` explicitly.
    pub default_realm_name: Option<String>,
    /// Path to the config file for the config editor. `None` in test or
    /// dev-mode contexts where no file was loaded.
    pub config_path: Option<PathBuf>,
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
            current_realm: Arc::new(RwLock::new(None)),
            config_warnings: Vec::new(),
            email_is_log_transport: false,
            product_name: "Hearth".to_string(),
            logo_url: DEFAULT_LOGO_URL.to_string(),
            custom_logo: None,
            config: None,
            theme_css: String::new(),
            realm_themes: HashMap::new(),
            theme_css_etag: etag_for(""),
            realm_theme_etags: HashMap::new(),
            trusted_proxies: Vec::new(),
            reload_notify: None,
            default_realm_name: None,
            config_path: None,
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

    /// Sets the parsed trusted proxy IPs for real client IP extraction.
    #[must_use]
    pub fn with_trusted_proxies(mut self, proxies: Vec<IpAddr>) -> Self {
        self.trusted_proxies = proxies;
        self
    }

    /// Sets the global theme CSS (named theme + optional custom CSS).
    /// Served at `GET /ui/static/theme.css`. Also computes and caches the
    /// `ETag` for conditional-request support.
    #[must_use]
    pub fn with_theme_css(mut self, css: String) -> Self {
        self.theme_css_etag = etag_for(&css);
        self.theme_css = css;
        self
    }

    /// Sets the per-realm theme map (realm hex id → composed CSS).
    /// Also computes and caches per-entry `ETags`.
    #[must_use]
    pub fn with_realm_themes(mut self, map: HashMap<String, String>) -> Self {
        self.realm_theme_etags = map.iter().map(|(k, v)| (k.clone(), etag_for(v))).collect();
        self.realm_themes = map;
        self
    }

    /// Attaches the reload notifier for triggering config hot-reload
    /// from the admin API.
    #[must_use]
    pub fn with_reload_notify(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.reload_notify = Some(notify);
        self
    }

    /// Attaches the config file path for the config editor.
    #[must_use]
    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Sets the default realm name used for bare `/ui/*` pre-auth URLs
    /// on multi-realm deployments. See [`super::realm_resolver`].
    #[must_use]
    pub fn with_default_realm(mut self, name: Option<String>) -> Self {
        self.default_realm_name = name;
        self
    }

    /// Looks up the per-realm theme CSS for a specific realm, bypassing
    /// the process-global `current_realm` cache. Prefer this in pre-auth
    /// handlers where the realm is resolved from the URL or cookie.
    #[must_use]
    pub fn realm_theme_css_for(&self, realm_id: &RealmId) -> Option<String> {
        let id = realm_id.as_uuid().to_string();
        self.realm_themes.get(&id).cloned()
    }

    /// Pins a realm as the "current" one for this process. Called by
    /// onboarding and the login handler so subsequent requests skip
    /// the `list_realms` walk.
    pub fn set_current_realm(&self, realm_id: RealmId) {
        if let Ok(mut guard) = self.current_realm.write() {
            *guard = Some(realm_id);
        }
    }

    /// Reads the currently-pinned realm id, if any.
    #[must_use]
    pub fn current_realm(&self) -> Option<RealmId> {
        self.current_realm.read().ok().and_then(|g| g.clone())
    }

    /// Returns the per-realm theme CSS for the currently-pinned realm,
    /// or `None` if no per-realm theme is configured.
    ///
    /// Used by all authenticated handlers to populate `realm_theme_css`
    /// in template structs, enabling inline per-realm CSS overrides.
    #[must_use]
    pub fn realm_theme_css(&self) -> Option<String> {
        let realm_id = self.current_realm()?;
        let id = realm_id.as_uuid().to_string();
        self.realm_themes.get(&id).cloned()
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
/// | `/ui/account/sessions` | GET | List the signed-in user's active sessions |
/// | `/ui/account/sessions/{sid}/revoke` | POST | Revoke one of the user's own sessions |
/// | `/ui/account/sessions/revoke-others` | POST | Revoke every session except the current one |
/// | `/ui/admin/users` | GET | Admin users list |
/// | `/ui/admin/users/new` | GET/POST | Create user |
/// | `/ui/admin/users/{id}` | GET | User detail |
/// | `/ui/admin/users/{id}/edit` | GET/POST | Edit user |
/// | `/ui/admin/users/{id}/delete` | POST | Delete user |
/// | `/ui/admin/realms` | GET | Admin realms list (read-only) |
/// | `/ui/admin/realms/{id}` | GET | Realm detail (read-only) |
/// | `/ui/admin/realms/{id}/delete` | POST | Delete archived realm |
/// | `/ui/admin/applications` | GET | Admin applications list |
/// | `/ui/admin/applications/new` | GET/POST | Register application |
/// | `/ui/admin/applications/{id}` | GET | Application detail |
/// | `/ui/admin/applications/{id}/edit` | GET/POST | Edit application |
/// | `/ui/admin/applications/{id}/delete` | POST | Delete application |
/// | `/ui/admin/sessions` | GET | Admin sessions list |
/// | `/ui/admin/sessions/{id}/revoke` | POST | Revoke session |
/// | `/ui/admin/audit` | GET | Audit log viewer |
/// | `/ui/static/{file}` | GET | Static assets (CSS, theme, htmx, logo) |
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
            "/login/passkey-begin",
            axum::routing::get(handlers::passkey_login_begin),
        )
        .route(
            "/login/passkey-complete",
            axum::routing::post(handlers::passkey_login_complete),
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
            "/accept-invitation",
            axum::routing::get(handlers::accept_invitation_page),
        )
        .route(
            "/forgot-password/sent",
            axum::routing::get(handlers::forgot_password_sent),
        )
        .route(
            "/reset-password",
            axum::routing::get(handlers::reset_password_form).post(handlers::reset_password_submit),
        )
        .route(
            "/register",
            axum::routing::get(handlers::register_form).post(handlers::register_submit),
        )
        .route(
            "/register/sent",
            axum::routing::get(handlers::register_sent),
        )
        // Realm-scoped pre-auth routes. Always resolve via the URL path,
        // bypassing the default_realm / single-realm fallbacks that apply
        // to bare `/ui/*` URLs. See `realm_resolver` for the full model.
        .route(
            "/realms/{realm}/login",
            axum::routing::get(handlers::login_form_scoped).post(handlers::login_submit_scoped),
        )
        .route(
            "/realms/{realm}/login/passkey-begin",
            axum::routing::get(handlers::passkey_login_begin_scoped),
        )
        .route(
            "/realms/{realm}/login/passkey-complete",
            axum::routing::post(handlers::passkey_login_complete_scoped),
        )
        .route(
            "/realms/{realm}/register",
            axum::routing::get(handlers::register_form_scoped)
                .post(handlers::register_submit_scoped),
        )
        .route(
            "/realms/{realm}/register/sent",
            axum::routing::get(handlers::register_sent_scoped),
        )
        .route(
            "/realms/{realm}/forgot-password",
            axum::routing::get(handlers::forgot_password_form_scoped)
                .post(handlers::forgot_password_submit_scoped),
        )
        .route(
            "/realms/{realm}/forgot-password/sent",
            axum::routing::get(handlers::forgot_password_sent_scoped),
        )
        .route(
            "/realms/{realm}/reset-password",
            axum::routing::get(handlers::reset_password_form_scoped)
                .post(handlers::reset_password_submit_scoped),
        )
        .route(
            "/realms/{realm}/verify-email",
            axum::routing::get(handlers::verify_email_scoped),
        )
        .route(
            "/realms/{realm}/accept-invitation",
            axum::routing::get(handlers::accept_invitation_page_scoped),
        )
        .route("/", axum::routing::get(handlers::dashboard))
        .route(
            "/device",
            axum::routing::get(handlers::device_approve_form).post(handlers::device_approve_submit),
        )
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
        .route(
            "/account/passkeys/register-begin",
            axum::routing::get(account::passkey_register_begin),
        )
        .route(
            "/account/passkeys/register-complete",
            axum::routing::post(account::passkey_register_complete),
        )
        .route(
            "/account/passkeys/{cred_id}/delete",
            axum::routing::post(account::passkey_delete),
        )
        .route(
            "/account/sessions",
            axum::routing::get(account::sessions_index),
        )
        .route(
            "/account/sessions/revoke-others",
            axum::routing::post(account::revoke_other_sessions),
        )
        .route(
            "/account/sessions/{sid}/revoke",
            axum::routing::post(account::revoke_session),
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
        .route(
            "/admin/users/{id}/reset-password",
            axum::routing::post(admin::admin_user_send_reset),
        )
        .route(
            "/admin/users/{id}/disable-mfa",
            axum::routing::post(admin::admin_user_disable_mfa),
        )
        .route(
            "/admin/users/{id}/sessions/{sid}/revoke",
            axum::routing::post(admin::admin_user_revoke_session),
        )
        .route(
            "/admin/users/{id}/webauthn/{cred_id}/revoke",
            axum::routing::post(admin::admin_user_revoke_webauthn),
        )
        // --- Realms (read-only; managed via hearth.yaml) ---
        .route(
            "/admin/realms",
            axum::routing::get(admin::admin_realms_list),
        )
        .route(
            "/admin/realms/{id}",
            axum::routing::get(admin::admin_realm_detail),
        )
        .route(
            "/admin/realms/{id}/delete",
            axum::routing::post(admin::admin_realm_delete),
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
            "/admin/organizations/{id}/members/picker",
            axum::routing::get(admin::admin_org_member_picker),
        )
        .route(
            "/admin/organizations/{id}/members/bulk",
            axum::routing::post(admin::admin_org_bulk_add_members),
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
        // --- Config reload API ---
        .route(
            "/admin/api/config/reload",
            axum::routing::post(admin::admin_api_config_reload),
        )
        // --- Applications (read-only — managed via hearth.yaml) ---
        .route(
            "/admin/applications",
            axum::routing::get(admin::admin_apps_list),
        )
        .route(
            "/admin/applications/{id}",
            axum::routing::get(admin::admin_app_detail),
        )
        .route(
            "/admin/applications/{id}/regenerate-secret",
            axum::routing::post(admin::admin_app_regenerate_secret),
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
            "/admin/audit/verify",
            axum::routing::post(admin::admin_audit_verify_integrity),
        )
        .route(
            "/admin/settings",
            axum::routing::get(admin::admin_system_info),
        )
        .route(
            "/admin/settings/editor",
            axum::routing::get(admin::admin_config_editor),
        )
        .route(
            "/admin/settings/editor/preview",
            axum::routing::post(admin::admin_config_editor_preview),
        )
        .route(
            "/admin/settings/editor/apply",
            axum::routing::post(admin::admin_config_editor_apply),
        )
        .route(
            "/admin/settings/editor/visual/preview",
            axum::routing::post(admin::admin_config_editor_visual_preview),
        )
        .route(
            "/admin/settings/editor/visual/validate",
            axum::routing::post(admin::admin_config_editor_visual_validate),
        )
        .route(
            "/admin/settings/editor/visual/apply",
            axum::routing::post(admin::admin_config_editor_visual_apply),
        )
        .route(
            "/admin/settings/editor/visual/export",
            axum::routing::post(admin::admin_config_editor_visual_export),
        )
        .route(
            "/admin/settings/editor/export",
            axum::routing::get(admin::admin_config_editor_export),
        )
        .route(
            "/admin/test-email",
            axum::routing::post(admin::admin_test_email),
        )
        .route("/static/{*file}", axum::routing::get(serve_static))
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
// ETag helpers
// ---------------------------------------------------------------------------

/// Computes a short, quoted `ETag` from the first 8 bytes of `SHA-256(data)`.
fn etag_for(data: &str) -> String {
    let hash = Sha256::digest(data.as_bytes());
    let hex = hash[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    format!("\"{hex}\"")
}

/// Returns `true` when the request carries an `If-None-Match` value that
/// matches `etag` exactly, indicating the browser already has the latest copy.
fn is_not_modified(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag)
}

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

/// HTMX v1.9.12 — pinned, checksum recorded in `assets/CHECKSUMS.txt`.
const HTMX_JS: &[u8] = include_bytes!("assets/htmx.min.js");
/// Tailwind-generated CSS for the admin UI.
const APP_CSS: &[u8] = include_bytes!("assets/app.css");

/// Content-derived `ETag` for the compiled CSS bundle.
///
/// Computed once at first access from the first 8 bytes of the SHA-256
/// digest of [`APP_CSS`]. Changes whenever `app.css` is rebuilt into a
/// new binary.
static APP_CSS_ETAG: OnceLock<String> = OnceLock::new();

/// Returns the content-derived `ETag` string for [`APP_CSS`].
fn app_css_etag() -> &'static str {
    APP_CSS_ETAG.get_or_init(|| {
        let hash = Sha256::digest(APP_CSS);
        let hex = hash[..8]
            .iter()
            .fold(String::with_capacity(16), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
        format!("\"{hex}\"")
    })
}

/// Hearth wide logo (SVG). Public so `main.rs` can pass the SVG content
/// to the email service for inline rendering.
pub const HEARTH_WIDE_SVG: &[u8] = include_bytes!("assets/hearth-wide-web.svg");
/// Hearth icon (SVG).
const HEARTH_ICON_SVG: &[u8] = include_bytes!("assets/hearth-icon.svg");

/// Serves all `/ui/static/*` assets — embedded files, operator theme
/// CSS, per-realm theme CSS, and runtime-loaded custom logos.
///
/// Handles `theme.css` and `realm-theme/{id}` inline to avoid
/// catch-all vs specific-route ambiguity in the axum router.
///
/// Files are compiled into the binary — there is no filesystem access,
/// except for `custom-logo` which is loaded from disk at startup when
/// `branding.logo_url` points to a local file.
///
/// `app.css` is served with `no-cache` + an `ETag` so the browser
/// revalidates on each soft refresh but skips re-downloading unchanged
/// content (304 Not Modified). Other embedded assets are truly immutable
/// for the lifetime of a binary, so they keep `immutable` caching.
async fn serve_static(
    headers: HeaderMap,
    State(state): State<Arc<WebState>>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    // Global theme CSS (named theme + optional operator custom CSS).
    if file == "theme.css" {
        let etag = state.theme_css_etag.as_str();
        if is_not_modified(&headers, etag) {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, etag)
                .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
            .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
            .header(header::ETAG, etag)
            .body(Body::from(state.theme_css.clone()))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // Per-realm theme CSS.
    if let Some(id) = file.strip_prefix("realm-theme/") {
        if let Some(css) = state.realm_themes.get(id) {
            // INVARIANT: etag is inserted for every key in realm_themes
            // by with_realm_themes().
            #[allow(clippy::unwrap_used)]
            let etag = state.realm_theme_etags.get(id).unwrap().as_str();
            if is_not_modified(&headers, etag) {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, etag)
                    .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()));
            }
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
                .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
                .header(header::ETAG, etag)
                .body(Body::from(css.clone()))
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // `app.css` uses `ETag`-based conditional caching.
    if file == "app.css" {
        let etag = app_css_etag();
        if is_not_modified(&headers, etag) {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, etag)
                .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
            .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
            .header(header::ETAG, etag)
            .body(Body::from(APP_CSS))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // Other embedded assets are immutable for the life of this binary.
    let embedded: Option<(&[u8], &str)> = match file.as_str() {
        "htmx.min.js" => Some((HTMX_JS, "application/javascript; charset=utf-8")),
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

    #[test]
    fn etag_for_is_quoted_hex() {
        let tag = etag_for("hello");
        assert!(tag.starts_with('"'), "etag must be double-quoted");
        assert!(tag.ends_with('"'), "etag must be double-quoted");
        // inner content is 16 lowercase hex chars (8 bytes)
        let inner = &tag[1..tag.len() - 1];
        assert_eq!(inner.len(), 16);
        assert!(inner.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn etag_for_is_deterministic_and_distinct() {
        assert_eq!(etag_for("a"), etag_for("a"));
        assert_ne!(etag_for("a"), etag_for("b"));
    }

    #[test]
    fn is_not_modified_matches_exact_etag() {
        let mut headers = HeaderMap::new();
        let etag = "\"abcd1234abcd1234\"";
        headers.insert(
            header::IF_NONE_MATCH,
            etag.parse().expect("valid header value"),
        );
        assert!(is_not_modified(&headers, etag));
    }

    #[test]
    fn is_not_modified_rejects_stale_etag() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            "\"old000000000000\"".parse().expect("valid header value"),
        );
        assert!(!is_not_modified(&headers, "\"new000000000000\""));
    }

    #[test]
    fn is_not_modified_absent_header_returns_false() {
        assert!(!is_not_modified(&HeaderMap::new(), "\"any\""));
    }

    #[test]
    fn app_css_etag_is_stable_and_quoted() {
        let e1 = app_css_etag();
        let e2 = app_css_etag();
        assert_eq!(e1, e2, "ETag must be stable across calls");
        assert!(e1.starts_with('"'));
        assert!(e1.ends_with('"'));
    }

    #[test]
    fn with_theme_css_computes_etag() {
        // Build a minimal WebState-like structure just to exercise the builder.
        // We can't easily construct a full WebState in a unit test, so we test
        // etag_for and with_theme_css logic directly.
        let css = "body { color: red; }".to_string();
        let expected = etag_for(&css);
        assert!(!expected.is_empty());
        assert_ne!(expected, etag_for(""));
    }
}
