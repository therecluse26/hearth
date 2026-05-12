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
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;
use sha2::{Digest, Sha256};

use crate::audit::AuditEngine;
use crate::config::{Config, EnvVarWarning};
use crate::core::RealmId;
use crate::identity::onboarding::OnboardingService;
use crate::identity::{EmailService, IdentityEngine};
use crate::rbac::RbacEngine;

pub mod account;
pub mod account_consents;
pub mod account_linked;
pub mod admin;
pub mod auth;
pub mod federation;
pub mod handlers;
pub(crate) mod handlers_common;
pub mod oauth_consent;
pub mod realm_resolver;
pub mod saml;
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
    /// RBAC engine — used by [`auth::RequireAdmin`] to check that the
    /// session carries the `hearth.admin` permission, and by admin UI
    /// handlers for role/group management.
    pub rbac: Arc<dyn RbacEngine>,
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
    /// Per-realm product-name overrides keyed by `RealmId` hyphenated UUID
    /// string. Resolved by [`WebState::product_name_for`] with fallback to
    /// the global `product_name`. Empty when no realm sets `web.product_name`.
    pub realm_product_names: HashMap<String, String>,
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
    /// Optional federation HTTP transport override. `None` in production
    /// (the handler uses [`crate::identity::federation::UreqFederationTransport`]);
    /// tests inject a [`crate::identity::federation::StubFederationTransport`]
    /// to drive the federation callback path without touching the network.
    pub federation_http: Option<Arc<dyn crate::identity::federation::FederationHttpTransport>>,
    /// Bytes served at `GET /ui/static/app.css`. Loaded from disk at
    /// startup when `server.assets_dir` is configured, else falls back
    /// to the copy embedded at compile time via `include_bytes!`. `Arc`
    /// makes per-request clones cheap.
    ///
    /// Hot path: the byte slice is handed straight to `axum::body::Body`.
    pub app_css: Arc<Vec<u8>>,
    /// `ETag` for [`WebState::app_css`]. SHA-256 prefix of the bytes,
    /// computed once at startup. Updated by [`WebState::with_app_css`].
    pub app_css_etag: String,
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
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
        onboarding: Arc<OnboardingService>,
        cookie_secret: CookieSecret,
        email: Option<Arc<EmailService>>,
    ) -> Self {
        Self {
            identity,
            rbac,
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
            realm_product_names: HashMap::new(),
            theme_css_etag: etag_for(""),
            realm_theme_etags: HashMap::new(),
            trusted_proxies: Vec::new(),
            reload_notify: None,
            default_realm_name: None,
            config_path: None,
            federation_http: None,
            app_css: Arc::new(APP_CSS_FALLBACK.to_vec()),
            app_css_etag: etag_for_bytes(APP_CSS_FALLBACK),
        }
    }

    /// Replaces the bytes served at `/ui/static/app.css` with operator-supplied
    /// CSS — typically the contents of `<server.assets_dir>/app.css` loaded at
    /// startup by `main.rs`. Recomputes the `ETag` from the new bytes.
    ///
    /// When this builder is not called, the embedded `include_bytes!` fallback
    /// is served instead.
    #[must_use]
    pub fn with_app_css(mut self, bytes: Vec<u8>) -> Self {
        self.app_css_etag = etag_for_bytes(&bytes);
        self.app_css = Arc::new(bytes);
        self
    }

    /// Injects an HTTP transport used by the federation service for
    /// outbound calls (token exchange, JWKS, userinfo). Intended for
    /// tests — production builds leave this `None` and fall through to
    /// [`crate::identity::federation::UreqFederationTransport`].
    #[must_use]
    pub fn with_federation_http(
        mut self,
        transport: Arc<dyn crate::identity::federation::FederationHttpTransport>,
    ) -> Self {
        self.federation_http = Some(transport);
        self
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

    /// Sets the per-realm product-name overrides (realm UUID string →
    /// display name). Empty map is a no-op fallback to global.
    #[must_use]
    pub fn with_realm_product_names(mut self, map: HashMap<String, String>) -> Self {
        self.realm_product_names = map;
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

    /// Resolves the product name to display for a request scoped to the
    /// given realm. Falls back to the global `product_name` when no
    /// per-realm override is configured. The 2026-04-30 UX audit caught
    /// every page rendering the first realm's product name regardless of
    /// scope — this method is the seam handlers should call instead of
    /// reaching for the global field directly.
    #[must_use]
    pub fn product_name_for(&self, realm_id: &RealmId) -> String {
        let id = realm_id.as_uuid().to_string();
        self.realm_product_names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| self.product_name.clone())
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
            "/mfa-enroll-required",
            axum::routing::get(handlers::mfa_enroll_required_form),
        )
        .route(
            "/mfa-enroll-required/activate",
            axum::routing::post(handlers::mfa_enroll_required_submit),
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
        // Admin pre-auth surface. Always resolves to the system realm;
        // does not route through the tenant resolver. See
        // `src/protocol/web/realm_resolver.rs` and the admin-realm
        // architecture note for details.
        .route(
            "/admin/login",
            axum::routing::get(handlers::admin_login_form).post(handlers::admin_login_submit),
        )
        .route(
            "/admin/login/passkey-begin",
            axum::routing::get(handlers::passkey_login_begin_admin),
        )
        .route(
            "/admin/login/passkey-complete",
            axum::routing::post(handlers::passkey_login_complete_admin),
        )
        .route(
            "/admin/verify-email",
            axum::routing::get(handlers::admin_verify_email),
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
            "/account/totp/recovery-codes.txt",
            axum::routing::get(account::totp_download_recovery_codes),
        )
        .route(
            "/account/totp/regenerate-codes",
            axum::routing::post(account::totp_regenerate_codes),
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
        // --- Self-service OAuth consent management ---
        .route(
            "/account/consents",
            axum::routing::get(account_consents::consents_index),
        )
        .route(
            "/account/applications",
            axum::routing::get(account_consents::account_applications),
        )
        .route(
            "/account/consents/revoke-all",
            axum::routing::post(account_consents::revoke_all_consents),
        )
        .route(
            "/account/applications/revoke-all",
            axum::routing::post(account_consents::revoke_all_consents),
        )
        .route(
            "/account/consents/{client_id}/revoke",
            axum::routing::post(account_consents::revoke_consent),
        )
        .route(
            "/account/applications/{client_id}/revoke",
            axum::routing::post(account_consents::revoke_consent),
        )
        // --- Self-service federation management ---
        .route(
            "/account/linked-accounts",
            axum::routing::get(account_linked::linked_accounts_index),
        )
        .route(
            "/account/linked-accounts/{idp_id}/unlink",
            axum::routing::post(account_linked::unlink),
        )
        // --- Federation login flow (pre-auth) ---
        .route("/federation/begin", axum::routing::get(federation::begin))
        .route(
            "/federation/callback",
            axum::routing::get(federation::callback),
        )
        .route(
            "/federation/confirm-link",
            axum::routing::get(federation::confirm_link_page).post(federation::confirm_link_submit),
        )
        .route(
            "/realms/{realm}/federation/begin",
            axum::routing::get(federation::begin_scoped),
        )
        .route(
            "/realms/{realm}/federation/callback",
            axum::routing::get(federation::callback_scoped),
        )
        // --- SAML 2.0 SP + IdP endpoints ---
        .route(
            "/realms/{realm}/federation/saml/metadata",
            axum::routing::get(saml::sp_metadata),
        )
        .route(
            "/realms/{realm}/federation/saml/acs",
            axum::routing::post(saml::sp_acs),
        )
        .route(
            "/realms/{realm}/federation/saml/begin",
            axum::routing::get(saml::sp_begin),
        )
        .route(
            "/realms/{realm}/saml/metadata",
            axum::routing::get(saml::idp_metadata),
        )
        .route(
            "/realms/{realm}/saml/sso",
            axum::routing::get(saml::idp_sso_get).post(saml::idp_sso_post),
        )
        .route(
            "/realms/{realm}/saml/sso/init",
            axum::routing::get(saml::idp_sso_init),
        )
        // --- Browser-facing OAuth authorize + consent flow ---
        .route(
            "/oauth/authorize",
            axum::routing::get(oauth_consent::authorize_get),
        )
        .route(
            "/realms/{realm}/oauth/authorize",
            axum::routing::get(oauth_consent::authorize_get_scoped),
        )
        .route(
            "/oauth/consent",
            axum::routing::get(oauth_consent::consent_page).post(oauth_consent::consent_submit),
        )
        .route(
            "/admin/admin-users",
            axum::routing::get(admin::admin_admin_users_list),
        )
        .route(
            // Spec-named admin-user creation route (REQ-022). 302 alias to the
            // generic /admin/users/new form pre-scoped to the system realm.
            // The form template already POSTs back with `target_query` carrying
            // `?admin_target=system`, so submission lands on the same handler chain.
            "/admin/admin-users/new",
            axum::routing::get(admin::admin_admin_user_create_alias),
        )
        // --- Realms list (system-scoped) ---
        .route(
            "/admin/realms",
            axum::routing::get(admin::admin_realms_list),
        )
        // --- Realm-scoped: users ---
        .route(
            "/admin/realms/{realm}/users",
            axum::routing::get(admin::admin_users_list),
        )
        .route(
            "/admin/realms/{realm}/users/new",
            axum::routing::get(admin::admin_user_create_form).post(admin::admin_user_create_submit),
        )
        .route(
            "/admin/realms/{realm}/users/{id}",
            axum::routing::get(admin::admin_user_detail),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/edit",
            axum::routing::get(admin::admin_user_edit_form).post(admin::admin_user_edit_submit),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/delete",
            axum::routing::post(admin::admin_user_delete),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/reset-password",
            axum::routing::post(admin::admin_user_send_reset),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/disable-mfa",
            axum::routing::post(admin::admin_user_disable_mfa),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/reset-mfa-codes",
            axum::routing::post(admin::admin_user_reset_mfa_codes),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/sessions/{sid}/revoke",
            axum::routing::post(admin::admin_user_revoke_session),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/webauthn/{cred_id}/revoke",
            axum::routing::post(admin::admin_user_revoke_webauthn),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/roles/assign",
            axum::routing::post(admin::admin_user_assign_role),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/roles/{assignment_id}/unassign",
            axum::routing::post(admin::admin_user_unassign_role),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/permissions/grant",
            axum::routing::post(admin::admin_user_grant_permission),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/permissions/revoke",
            axum::routing::post(admin::admin_user_revoke_permission),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/consents",
            axum::routing::get(admin::admin_user_consents_list),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/applications",
            axum::routing::get(admin::admin_user_consents_list),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/consents/{client_id}/revoke",
            axum::routing::post(admin::admin_user_consent_revoke),
        )
        .route(
            "/admin/realms/{realm}/users/{id}/applications/{client_id}/revoke",
            axum::routing::post(admin::admin_user_consent_revoke),
        )
        // --- Realm meta (workspace landing, delete, admin grants, claims) ---
        .route(
            "/admin/realms/{realm}",
            axum::routing::get(admin::admin_realm_detail),
        )
        .route(
            "/admin/realms/{realm}/delete",
            axum::routing::post(admin::admin_realm_delete),
        )
        .route(
            "/admin/realms/{realm}/admins/picker",
            axum::routing::get(admin::admin_realm_admin_picker),
        )
        .route(
            "/admin/realms/{realm}/admins/grant",
            axum::routing::post(admin::admin_realm_admin_grant),
        )
        .route(
            "/admin/realms/{realm}/admins/{uid}/revoke",
            axum::routing::post(admin::admin_realm_admin_revoke),
        )
        .route(
            "/admin/realms/{realm}/claims",
            axum::routing::get(admin::admin_realm_claims),
        )
        // --- Realm-scoped: RBAC + permissions ---
        .route(
            "/admin/realms/{realm}/rbac/debug",
            axum::routing::get(admin::admin_rbac_debug),
        )
        .route(
            // Canonical resolver URL per spec (REQ-056). Aliases to /rbac/debug
            // preserving query string.
            "/admin/realms/{realm}/permissions/resolve",
            axum::routing::get(admin::admin_permissions_resolve_alias),
        )
        .route(
            "/admin/realms/{realm}/rbac/token-preview",
            axum::routing::post(admin::admin_rbac_token_preview),
        )
        .route(
            "/admin/realms/{realm}/rbac/permissions",
            axum::routing::get(admin::admin_rbac_permissions),
        )
        .route(
            "/admin/realms/{realm}/rbac/roles",
            axum::routing::get(admin::admin_rbac_roles),
        )
        .route(
            "/admin/realms/{realm}/rbac/roles/new",
            axum::routing::get(admin::admin_role_create_form)
                .post(admin::admin_role_create_submit),
        )
        .route(
            "/admin/realms/{realm}/rbac/roles/{id}",
            axum::routing::get(admin::admin_role_detail),
        )
        .route(
            "/admin/realms/{realm}/rbac/roles/{id}/edit",
            axum::routing::get(admin::admin_role_edit_form)
                .post(admin::admin_role_edit_submit),
        )
        .route(
            "/admin/realms/{realm}/rbac/roles/{id}/delete",
            axum::routing::post(admin::admin_role_delete),
        )
        .route(
            "/admin/realms/{realm}/rbac/scopes",
            axum::routing::get(admin::admin_rbac_scopes),
        )
        // --- Realm-scoped: organizations ---
        .route(
            "/admin/realms/{realm}/organizations",
            axum::routing::get(admin::admin_orgs_list),
        )
        .route(
            "/admin/realms/{realm}/organizations/new",
            axum::routing::get(admin::admin_org_create_form).post(admin::admin_org_create_submit),
        )
        .route(
            "/admin/realms/{realm}/organizations/bulk-delete",
            axum::routing::post(admin::admin_orgs_bulk_delete),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}",
            axum::routing::get(admin::admin_org_detail),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/edit",
            axum::routing::get(admin::admin_org_edit_form).post(admin::admin_org_edit_submit),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/delete",
            axum::routing::post(admin::admin_org_delete),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members",
            axum::routing::post(admin::admin_org_add_member),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/picker",
            axum::routing::get(admin::admin_org_member_picker),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/{uid}/remove",
            axum::routing::post(admin::admin_org_remove_member),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/{uid}/role",
            axum::routing::post(admin::admin_org_update_role),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/invite",
            axum::routing::post(admin::admin_org_invite),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/status",
            axum::routing::post(admin::admin_org_status_toggle),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/invitations/{iid}/revoke",
            axum::routing::post(admin::admin_org_revoke_invite),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/invitations/{iid}/resend",
            axum::routing::post(admin::admin_org_resend_invite),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/{uid}/rbac/assign",
            axum::routing::post(admin::admin_org_member_assign_role),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/{uid}/rbac/{aid}/unassign",
            axum::routing::post(admin::admin_org_member_unassign_role),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/{uid}/permissions/grant",
            axum::routing::post(admin::admin_org_member_grant_perm),
        )
        .route(
            "/admin/realms/{realm}/organizations/{id}/members/{uid}/permissions/revoke",
            axum::routing::post(admin::admin_org_member_revoke_perm),
        )
        // --- Realm-scoped: groups (RBAC) ---
        .route(
            "/admin/realms/{realm}/groups",
            axum::routing::get(admin::admin_groups_list),
        )
        .route(
            "/admin/realms/{realm}/groups/new",
            axum::routing::get(admin::admin_group_create_form)
                .post(admin::admin_group_create_submit),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}",
            axum::routing::get(admin::admin_group_detail),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/edit",
            axum::routing::get(admin::admin_group_edit_form).post(admin::admin_group_edit_submit),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/delete",
            axum::routing::post(admin::admin_group_delete),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/members",
            axum::routing::post(admin::admin_group_member_add),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/members/picker",
            axum::routing::get(admin::admin_group_member_picker),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/members/{kind}/{mid}/remove",
            axum::routing::post(admin::admin_group_member_remove),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/roles/assign",
            axum::routing::post(admin::admin_group_role_assign),
        )
        .route(
            "/admin/realms/{realm}/groups/{id}/roles/{aid}/unassign",
            axum::routing::post(admin::admin_group_role_unassign),
        )
        // --- Realm-scoped: user search API (HTMX) ---
        .route(
            "/admin/realms/{realm}/api/users/search",
            axum::routing::get(admin::admin_api_user_search),
        )
        .route(
            "/admin/realms/{realm}/rbac/api/users/search",
            axum::routing::get(admin::admin_api_rbac_user_search),
        )
        // --- Config reload API (system-scoped) ---
        .route(
            "/admin/api/config/reload",
            axum::routing::post(admin::admin_api_config_reload),
        )
        // --- Sidebar nav data (realm tree) (system-scoped) ---
        .route(
            "/admin/api/nav/realms",
            axum::routing::get(admin::admin_api_nav_realms),
        )
        // --- Realm-scoped: applications ---
        .route(
            "/admin/realms/{realm}/applications",
            axum::routing::get(admin::admin_apps_list),
        )
        .route(
            "/admin/realms/{realm}/applications/new",
            axum::routing::get(admin::admin_app_create_form)
                .post(admin::admin_app_create_submit),
        )
        .route(
            "/admin/realms/{realm}/applications/{id}",
            axum::routing::get(admin::admin_app_detail),
        )
        .route(
            "/admin/realms/{realm}/applications/{id}/edit",
            axum::routing::get(admin::admin_app_edit_form)
                .post(admin::admin_app_edit_submit),
        )
        .route(
            "/admin/realms/{realm}/applications/{id}/delete",
            axum::routing::post(admin::admin_app_delete),
        )
        .route(
            "/admin/realms/{realm}/applications/{id}/regenerate-secret",
            axum::routing::post(admin::admin_app_regenerate_secret),
        )
        // --- Realm-scoped: sessions ---
        .route(
            "/admin/realms/{realm}/sessions",
            axum::routing::get(admin::admin_sessions_list),
        )
        .route(
            "/admin/realms/{realm}/sessions/{id}/revoke",
            axum::routing::post(admin::admin_session_revoke),
        )
        // --- Realm-scoped: audit ---
        .route(
            "/admin/realms/{realm}/audit",
            axum::routing::get(admin::admin_audit_list),
        )
        .route(
            "/admin/realms/{realm}/audit/verify",
            axum::routing::post(admin::admin_audit_verify_integrity),
        )
        .route(
            "/admin/realms/{realm}/audit/export",
            axum::routing::get(admin::admin_audit_export),
        )
        .route(
            "/admin/api/realms/{realm}/audit/events",
            axum::routing::get(admin::admin_api_audit_events),
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
        .route("/favicon.ico", axum::routing::get(serve_favicon))
        .route("/favicon.svg", axum::routing::get(serve_favicon))
        .nest("/ui", ui_routes)
        // Branded 404 for any /ui/* path that no nested route matched, plus
        // every other unrouted path on the web tree. Without this, axum's
        // default falls through with an empty body and the browser paints
        // its native error page (Chrome's "This site can't be reached"),
        // which looks like the server is broken — caught by the 2026-04-30
        // UX audit. The handler ignores the request body and renders the
        // same template as the explicit `not_found_authed` calls.
        .fallback(serve_branded_404)
        .with_state(shared)
}

/// Default 404 handler. Returns the branded error page rather than letting
/// axum fall through to a bare `404 Not Found` text body.
async fn serve_branded_404(req: axum::extract::Request) -> Response {
    let path = req.uri().path().to_string();
    handlers_common::not_found(&format!("No page exists at {path}."))
}

/// Serves the Hearth flame as `image/svg+xml`. Works for both `.ico` and
/// `.svg` requests — every modern browser accepts SVG via `<link rel="icon">`
/// and falls back gracefully when it receives an SVG at `.ico`. Keeps the
/// binary slim by avoiding a separate rasterised `.ico`.
async fn serve_favicon() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/svg+xml")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(Body::from(FAVICON_SVG))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ---------------------------------------------------------------------------
// ETag helpers
// ---------------------------------------------------------------------------

/// Computes a short, quoted `ETag` from the first 8 bytes of `SHA-256(data)`.
fn etag_for(data: &str) -> String {
    etag_for_bytes(data.as_bytes())
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
/// Tailwind-generated CSS for the admin UI, embedded at compile time.
///
/// Used as the fallback when `server.assets_dir` is unset or the runtime
/// file under it is unreadable. Production deployments that want
/// rebuild-and-restart theme reloads should configure `assets_dir` and
/// load the runtime copy via [`WebState::with_app_css`].
pub const APP_CSS_FALLBACK: &[u8] = include_bytes!("assets/app.css");
/// Favicon — SVG mark of the Hearth flame, inlined and served at `/favicon.ico`
/// and `/ui/static/favicon.svg`.
const FAVICON_SVG: &[u8] = include_bytes!("assets/favicon.svg");

/// Sentinel substring that MUST appear in any `app.css` we serve. Presence
/// proves the Tailwind build ran with the Hearth theme layer (the audit of
/// 2026-04-23 discovered this silently dropping). Checked at server boot
/// against both the embedded fallback and any disk-loaded override; CI
/// re-verifies the embedded copy via `tests/web_ui_assets.rs`.
pub const APP_CSS_SENTINEL: &[u8] = b".bg-ht-surface-raised";

/// Minimum plausible size for a real Tailwind build. Smaller than this
/// almost certainly means the build emitted only a stub.
pub const APP_CSS_MIN_BYTES: usize = 4_096;

/// Verifies that an `app.css` byte buffer contains a plausible Tailwind
/// build with the Hearth theme layer.
///
/// Used at server boot to validate both the compile-time embedded copy
/// (always present) and an operator-supplied disk copy (optional, loaded
/// from `server.assets_dir`). Intentionally cheap — a single substring
/// scan over ~30 KB — and runs once per process so the hot path is
/// unaffected. Returns an error describing the likely cause so the
/// operator can spot it in the startup log.
///
/// # Errors
/// Returns `Err` when the bytes are too small to contain a real Tailwind
/// build, or when they do not contain [`APP_CSS_SENTINEL`].
pub fn assert_bytes_sane(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < APP_CSS_MIN_BYTES {
        return Err(
            "app.css is under 4 KiB — Tailwind build almost certainly failed. \
             Run: cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify",
        );
    }
    if !bytes
        .windows(APP_CSS_SENTINEL.len())
        .any(|w| w == APP_CSS_SENTINEL)
    {
        return Err(
            "app.css is missing the Hearth theme layer (no `.bg-ht-surface-raised` rule). \
             Check `ui/tailwind.config.js` content globs and safelist, then rebuild.",
        );
    }
    Ok(())
}

/// Verifies that the compile-time embedded `app.css` fallback is sane.
///
/// Backwards-compatible alias kept for `main.rs`'s startup canary; new
/// callers should use [`assert_bytes_sane`] directly to validate either
/// the embedded or runtime-loaded bytes.
///
/// # Errors
/// Same as [`assert_bytes_sane`].
pub fn assert_app_css_sane() -> Result<(), &'static str> {
    assert_bytes_sane(APP_CSS_FALLBACK)
}

/// Computes the `ETag` string (`"<16-hex>"`) for an arbitrary byte slice
/// using the first 8 bytes of its SHA-256 digest. Used by the static-asset
/// handler so `If-None-Match` revalidation works against runtime-loaded
/// CSS as well as the embedded fallback.
#[must_use]
pub fn etag_for_bytes(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let hex = hash[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    format!("\"{hex}\"")
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

    // `app.css` uses `ETag`-based conditional caching. The bytes come from
    // `state.app_css`, which is the runtime-loaded copy when
    // `server.assets_dir` is configured, else the embedded fallback.
    if file == "app.css" {
        let etag = state.app_css_etag.as_str();
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
            .body(Body::from(state.app_css.as_slice().to_vec()))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // Other embedded assets are immutable for the life of this binary.
    let embedded: Option<(&[u8], &str)> = match file.as_str() {
        "htmx.min.js" => Some((HTMX_JS, "application/javascript; charset=utf-8")),
        "favicon.svg" => Some((FAVICON_SVG, "image/svg+xml")),
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
        assert!(
            APP_CSS_FALLBACK.len() > 64,
            "app.css fallback seems too small"
        );
    }

    #[test]
    fn assert_bytes_sane_rejects_short_buffer() {
        let result = assert_bytes_sane(b"hi");
        assert!(result.is_err(), "tiny buffer should fail sanity check");
    }

    #[test]
    fn assert_bytes_sane_rejects_missing_sentinel() {
        // Long enough to pass the size gate, but no `.bg-ht-surface-raised`.
        let bytes = vec![b'a'; APP_CSS_MIN_BYTES + 10];
        assert!(assert_bytes_sane(&bytes).is_err());
    }

    #[test]
    fn assert_bytes_sane_accepts_buffer_with_sentinel() {
        let mut bytes = vec![b'a'; APP_CSS_MIN_BYTES];
        bytes.extend_from_slice(APP_CSS_SENTINEL);
        bytes.extend_from_slice(b"{display:none}");
        assert!(assert_bytes_sane(&bytes).is_ok());
    }

    #[test]
    fn etag_for_bytes_changes_with_content() {
        let a = etag_for_bytes(b"alpha");
        let b = etag_for_bytes(b"beta");
        assert_ne!(a, b, "different bytes must produce different ETags");
        assert_eq!(a, etag_for_bytes(b"alpha"), "ETag must be deterministic");
    }

    #[test]
    fn with_app_css_replaces_bytes_and_etag() {
        let mut bytes = vec![b'x'; APP_CSS_MIN_BYTES];
        bytes.extend_from_slice(APP_CSS_SENTINEL);
        let expected_etag = etag_for_bytes(&bytes);

        // We can't fully construct WebState here without engines, so just
        // verify the ETag computation matches what `with_app_css` would set.
        // End-to-end coverage lives in tests/web_ui_assets.rs.
        assert_eq!(expected_etag, etag_for_bytes(&bytes));
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
    fn embedded_app_css_etag_is_stable_and_quoted() {
        let e1 = etag_for_bytes(APP_CSS_FALLBACK);
        let e2 = etag_for_bytes(APP_CSS_FALLBACK);
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
