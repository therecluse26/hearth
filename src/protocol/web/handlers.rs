//! Axum handlers for the public `/ui/*` entry points.
//!
//! Wire adapter only — every state transition delegates to
//! `OnboardingService` or `IdentityEngine`. Templates live under
//! `templates/ui/` and are compiled into the binary by the askama
//! derive macro.
//!
//! See [`super`] module docs for the cookie and CSRF model.
//!
//! # Routes covered here
//!
//! This file owns the public (pre-auth) surface:
//!
//! * `GET  /ui/setup` — first-run setup form (token-gated).
//! * `POST /ui/setup` — submit setup form.
//! * `GET  /ui/setup/sent` — "check your email" confirmation.
//! * `GET  /ui/verify-email` — consume a verification token.
//! * `GET  /ui/login` — login form.
//! * `POST /ui/login` — submit login credentials.
//!
//! Post-auth routes (`/ui/`, `/ui/logout`, `/ui/account/*`,
//! `/ui/admin/*`) live alongside in dedicated modules.
//!
//! # Security notes
//!
//! * `login_submit` sets two cookies on success: `hearth_ui_session`
//!   (`HttpOnly` — server-only) and `hearth_ui_csrf` (readable by JS so
//!   the page can echo it via HTMX headers). Both are `Path=/ui` +
//!   `SameSite=Lax`.
//! * The session cookie value is `sid.tid.mac` (stateless binding of a
//!   session id to its tenant id via HMAC-SHA256). See [`super::auth`]
//!   for parsing.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::identity::onboarding::OnboardingError;
use crate::identity::{CleartextPassword, IdentityError};

use super::auth::{
    clear_mfa_pending_cookie, cookie_value_from_headers, issue_auth_cookies,
    issue_mfa_pending_cookie, parse_mfa_pending_cookie, sanitize_return_to, IssuedCookies,
    MFA_PENDING_COOKIE,
};
use super::templates::{render, render_status, Flash};
use super::WebState;

// ============================================================================
// Template structs
// ============================================================================

/// Setup form template — used for both initial render and error re-render.
#[derive(Template)]
#[template(path = "ui/setup.html")]
struct SetupTemplate {
    token: String,
    error: Option<String>,
    // Layout fields (nav disabled for public pages).
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl SetupTemplate {
    fn new(token: String, error: Option<String>, product_name: String, logo_url: String) -> Self {
        Self {
            token,
            error,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Simple "setup submitted" confirmation page.
#[derive(Template)]
#[template(path = "ui/setup_sent.html")]
#[allow(clippy::struct_excessive_bools)]
struct SetupSentTemplate {
    /// Whether to show the "Running without SMTP?" callout (true when
    /// the email transport is `Log`).
    show_log_fallback: bool,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl SetupSentTemplate {
    fn new(show_log_fallback: bool, product_name: String, logo_url: String) -> Self {
        Self {
            show_log_fallback,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Login form template.
#[derive(Template)]
#[template(path = "ui/login.html")]
struct LoginTemplate {
    error: Option<String>,
    return_to: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl LoginTemplate {
    fn new(
        error: Option<String>,
        return_to: Option<String>,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            error,
            return_to,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Successful email verification page.
#[derive(Template)]
#[template(path = "ui/verify_email_ok.html")]
struct VerifyOkTemplate {
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl VerifyOkTemplate {
    fn new(product_name: String, logo_url: String) -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Dashboard template with quick-link tiles for account management
/// and (for admins) the full management surface.
#[derive(Template)]
#[template(path = "ui/dashboard.html")]
struct DashboardTemplate {
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
    config_warnings: Vec<crate::config::EnvVarWarning>,
}

/// Invalid / expired / malformed verification link page.
#[derive(Template)]
#[template(path = "ui/verify_email_invalid.html")]
struct VerifyInvalidTemplate {
    heading: &'static str,
    message: &'static str,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl VerifyInvalidTemplate {
    fn new(
        heading: &'static str,
        message: &'static str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            heading,
            message,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// MFA challenge template — shown after password verification when MFA is
/// enabled. Accepts a TOTP code or recovery code.
#[derive(Template)]
#[template(path = "ui/mfa_challenge.html")]
struct MfaChallengeTemplate {
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl MfaChallengeTemplate {
    fn new(error: Option<String>, product_name: String, logo_url: String) -> Self {
        Self {
            error,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

// ============================================================================
// Setup form
// ============================================================================

/// Query parameters for the setup GET handler.
#[derive(Debug, Deserialize)]
pub struct SetupQuery {
    /// Setup token provided by the operator (from the startup log line).
    pub token: Option<String>,
}

/// Renders the first-run setup form.
///
/// Returns `404 Not Found` if:
/// - the `token` query parameter is missing,
/// - the token does not match the on-disk file, or
/// - Hearth is already configured (a tenant exists).
///
/// The 404 is deliberately generic so that a would-be attacker cannot
/// distinguish "wrong token" from "system already set up".
pub async fn setup_form(
    State(state): State<Arc<WebState>>,
    Query(query): Query<SetupQuery>,
) -> Response {
    let Some(token) = query.token.as_deref() else {
        return not_found_response("Setup page is not available.");
    };

    match state.onboarding.verify_setup_token(token) {
        Ok(()) => {}
        Err(OnboardingError::InvalidSetupToken | OnboardingError::AlreadyConfigured) => {
            return not_found_response("Setup page is not available.");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to verify setup token");
            return internal_error_response();
        }
    }

    let mut tmpl = SetupTemplate::new(
        token.to_string(),
        None,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Form body submitted by the setup page.
#[derive(Debug, Deserialize)]
pub struct SetupForm {
    /// Setup token echoed from the hidden input.
    pub token: String,
    /// Admin email address.
    pub admin_email: String,
    /// Admin display name.
    pub admin_display_name: String,
    /// Admin password.
    pub admin_password: String,
}

/// Handles setup form submission.
///
/// On success, redirects (303 See Other) to `/ui/setup/sent`. The setup
/// token is consumed by `OnboardingService::complete_setup`.
pub async fn setup_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    // Re-verify token as defence in depth — the GET validated it, but an
    // attacker could POST directly.
    match state.onboarding.verify_setup_token(&form.token) {
        Ok(()) => {}
        Err(OnboardingError::InvalidSetupToken | OnboardingError::AlreadyConfigured) => {
            return not_found_response("Setup page is not available.");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to verify setup token on submit");
            return internal_error_response();
        }
    }

    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let setup_err = |token: String, msg: String, status: StatusCode| {
        let mut tmpl = SetupTemplate::new(token, Some(msg), product_name.clone(), logo_url.clone());
        tmpl.theme_css.clone_from(&theme_css);
        render_status(&tmpl, status)
    };

    if let Err(msg) = validate_setup_form(&form) {
        return setup_err(form.token.clone(), msg, StatusCode::BAD_REQUEST);
    }

    let password = CleartextPassword::from_string(form.admin_password.clone());

    let base_url = derive_base_url(&headers);
    match state.onboarding.complete_setup(
        form.admin_email.trim(),
        form.admin_display_name.trim(),
        &password,
        &base_url,
    ) {
        Ok(outcome) => {
            // Pin the newly-created tenant as the "current" tenant for
            // future logins through this process. On restart the first
            // tenant is re-resolved at login time.
            state.set_current_tenant(outcome.tenant_id.clone());
            Redirect::to("/ui/setup/sent").into_response()
        }
        Err(OnboardingError::AlreadyConfigured) => {
            not_found_response("Setup page is not available.")
        }
        Err(OnboardingError::Identity(IdentityError::DuplicateEmail)) => setup_err(
            form.token.clone(),
            "An account with that email already exists in this system.".to_string(),
            StatusCode::CONFLICT,
        ),
        Err(OnboardingError::Identity(IdentityError::TenantNotFound)) => setup_err(
            form.token.clone(),
            "No tenant is configured. Add a tenant to hearth.yaml and restart.".to_string(),
            StatusCode::CONFLICT,
        ),
        Err(OnboardingError::Identity(IdentityError::InvalidInput { reason })) => setup_err(
            form.token.clone(),
            format!("Invalid input: {reason}"),
            StatusCode::BAD_REQUEST,
        ),
        Err(OnboardingError::Email(e)) => {
            tracing::error!(error = %e, "setup: failed to send verification email");
            setup_err(
                form.token.clone(),
                "The account was created but the verification email could not be sent. \
                Check the server logs for the verification link, or retry after fixing the email \
                transport."
                    .to_string(),
                StatusCode::BAD_GATEWAY,
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "setup: unexpected failure");
            internal_error_response()
        }
    }
}

/// Renders the "setup submitted" confirmation page.
///
/// Shows a "check your server logs" callout only when the email
/// transport is `Log` (i.e. no real email delivery).
pub async fn setup_sent(State(state): State<Arc<WebState>>) -> Response {
    let mut tmpl = SetupSentTemplate::new(
        state.email_is_log_transport,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

// ============================================================================
// Email verification
// ============================================================================

/// Query parameters for `/ui/verify-email`.
#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    /// Single-use email-verification token.
    pub token: Option<String>,
}

/// Handles email verification. On success the user transitions
/// `PendingVerification` → `Active` and can thereafter sign in.
pub async fn verify_email(
    State(state): State<Arc<WebState>>,
    Query(query): Query<VerifyQuery>,
) -> Response {
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();

    let Some(token) = query.token.as_deref() else {
        let mut tmpl = VerifyInvalidTemplate::new(
            "Invalid link",
            "This verification link is missing or malformed.",
            product_name,
            logo_url,
        );
        tmpl.theme_css.clone_from(&state.theme_css);
        return render_status(&tmpl, StatusCode::BAD_REQUEST);
    };

    // The token is not tenant-scoped in the URL. Walk the first page
    // of tenants and try each until one succeeds or we exhaust them.
    // Phase 1 deployments are almost always single-tenant; this stays
    // O(#tenants) and off the hot path.
    let tenants = match state.identity.list_tenants(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "verify-email: list_tenants failed");
            return internal_error_response();
        }
    };

    for tenant in &tenants {
        match state.identity.verify_email_token(tenant.id(), token) {
            Ok(_) => {
                let mut tmpl = VerifyOkTemplate::new(product_name, logo_url);
                tmpl.theme_css.clone_from(&state.theme_css);
                return render(&tmpl);
            }
            Err(IdentityError::VerificationTokenInvalid) => {}
            Err(e) => {
                tracing::error!(error = %e, "verify-email: unexpected failure");
                return internal_error_response();
            }
        }
    }

    let mut tmpl = VerifyInvalidTemplate::new(
        "Link expired or already used",
        "This verification link is no longer valid. Request a new verification email from \
        the sign-in page once it becomes available.",
        product_name,
        logo_url,
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    render_status(&tmpl, StatusCode::GONE)
}

// ============================================================================
// Login
// ============================================================================

/// Query parameters for the GET login form (optional `return_to`).
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Relative path to redirect back to after a successful sign-in.
    pub return_to: Option<String>,
}

/// Renders the login form.
pub async fn login_form(
    State(state): State<Arc<WebState>>,
    Query(query): Query<LoginQuery>,
) -> Response {
    let return_to = query.return_to.as_deref().and_then(sanitize_return_to);
    let mut tmpl = LoginTemplate::new(
        None,
        return_to,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Credentials submitted by the login form.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    /// Email address.
    pub email: String,
    /// Password.
    pub password: String,
    /// Optional `return_to` path submitted via hidden field.
    #[serde(default)]
    pub return_to: Option<String>,
}

/// Handles login submission.
///
/// On success: creates a session, issues the `hearth_ui_session` and
/// `hearth_ui_csrf` cookies, then redirects. When MFA is enabled for
/// the user, redirects to `/ui/mfa-challenge` with a pending cookie
/// instead of creating a session.
///
/// All authentication failures collapse into a single generic error
/// message (enumeration resistance).
pub async fn login_submit(
    State(state): State<Arc<WebState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let email = form.email.trim();
    let return_to = form.return_to.as_deref().and_then(sanitize_return_to);

    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let generic_error = || {
        let mut tmpl = LoginTemplate::new(
            Some("Sign-in failed. Check your credentials and try again.".to_string()),
            return_to.clone(),
            product_name.clone(),
            logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&theme_css);
        render_status(&tmpl, StatusCode::UNAUTHORIZED)
    };

    // Walk up to the first page of tenants (Phase 1 = usually one).
    let tenants = match state.identity.list_tenants(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "login: failed to list tenants");
            return internal_error_response();
        }
    };

    for tenant in &tenants {
        let Ok(Some(user)) = state.identity.get_user_by_email(tenant.id(), email) else {
            continue;
        };

        let password = CleartextPassword::from_string(form.password.clone());

        match state
            .identity
            .verify_password(tenant.id(), user.id(), &password)
        {
            Ok(true) => {}
            Ok(false) => return generic_error(),
            Err(e) => {
                tracing::warn!(error = %e, "login: password verification failed");
                return generic_error();
            }
        }

        // --- MFA gate ---
        // If the user has MFA enabled, issue a pending cookie and redirect
        // to the challenge page instead of creating a session.
        let mfa_on = state
            .identity
            .mfa_enabled(tenant.id(), user.id())
            .unwrap_or(false);
        if mfa_on {
            let cookie = issue_mfa_pending_cookie(
                &state.cookie_secret,
                tenant.id(),
                user.id(),
                return_to.as_deref(),
            );
            state.set_current_tenant(tenant.id().clone());
            let mut response = Redirect::to("/ui/mfa-challenge").into_response();
            append_cookie(&mut response, &cookie);
            return response;
        }

        match state.identity.create_session(tenant.id(), user.id()) {
            Ok(session) => {
                let IssuedCookies {
                    session_cookie,
                    csrf_cookie,
                } = issue_auth_cookies(&state.cookie_secret, tenant.id(), session.id());

                // Pin this tenant as the "current" one so subsequent logins from
                // this process resolve consistently.
                state.set_current_tenant(tenant.id().clone());

                let location = return_to.as_deref().unwrap_or("/ui");
                let mut response = Redirect::to(location).into_response();
                append_cookie(&mut response, &session_cookie);
                append_cookie(&mut response, &csrf_cookie);
                return response;
            }
            Err(IdentityError::UserNotVerified) => {
                let mut tmpl = LoginTemplate::new(
                    Some(
                        "Your email is not verified yet. Check your inbox (or the server \
                         logs) for the verification link and click it before signing in."
                            .to_string(),
                    ),
                    return_to.clone(),
                    state.product_name.clone(),
                    state.logo_url.clone(),
                );
                tmpl.theme_css.clone_from(&state.theme_css);
                return render_status(&tmpl, StatusCode::FORBIDDEN);
            }
            Err(e) => {
                tracing::warn!(error = %e, "login: create_session failed");
                return generic_error();
            }
        }
    }

    generic_error()
}

// ============================================================================
// MFA challenge
// ============================================================================

/// Form body submitted by the MFA challenge page.
#[derive(Debug, Deserialize)]
pub struct MfaChallengeForm {
    /// TOTP code or recovery code entered by the user.
    pub code: String,
}

/// Renders the MFA challenge form.
///
/// If the MFA pending cookie is missing or invalid, redirects to
/// `/ui/login` — the user must start the login flow again.
pub async fn mfa_challenge_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    if parse_mfa_pending_cookie(&state.cookie_secret, raw).is_none() {
        return Redirect::to("/ui/login").into_response();
    }

    let mut tmpl =
        MfaChallengeTemplate::new(None, state.product_name.clone(), state.logo_url.clone());
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Handles MFA challenge submission.
///
/// Validates the pending cookie, then tries `verify_totp()` (6-digit
/// numeric) or `verify_recovery_code()` (anything else). On success:
/// creates a session, issues cookies, clears the pending cookie, and
/// redirects to the original `return_to` or `/ui`.
pub async fn mfa_challenge_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<MfaChallengeForm>,
) -> Response {
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return mfa_expired_response(
            state.product_name.clone(),
            state.logo_url.clone(),
            &state.theme_css,
        );
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return mfa_expired_response(
            state.product_name.clone(),
            state.logo_url.clone(),
            &state.theme_css,
        );
    };

    let code = form.code.trim();

    // Dispatch: 6-digit all-numeric → TOTP; anything else → recovery code.
    let is_totp = code.len() == 6 && code.chars().all(|c| c.is_ascii_digit());
    let verify_result = if is_totp {
        state
            .identity
            .verify_totp(&pending.tenant_id, &pending.user_id, code)
    } else {
        state
            .identity
            .verify_recovery_code(&pending.tenant_id, &pending.user_id, code)
    };

    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let mfa_err = |msg: String, status: StatusCode| {
        let mut tmpl = MfaChallengeTemplate::new(Some(msg), product_name.clone(), logo_url.clone());
        tmpl.theme_css.clone_from(&theme_css);
        render_status(&tmpl, status)
    };

    match verify_result {
        Ok(()) => {}
        Err(IdentityError::RateLimited) => {
            return mfa_err(
                "Too many failed attempts. Please wait a few minutes and try again.".to_string(),
                StatusCode::TOO_MANY_REQUESTS,
            );
        }
        Err(IdentityError::InvalidMfaCode | IdentityError::MfaNotEnabled) => {
            return mfa_err(
                "Invalid code. Please try again.".to_string(),
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "mfa-challenge: verification failed");
            return mfa_err(
                "Invalid code. Please try again.".to_string(),
                StatusCode::UNAUTHORIZED,
            );
        }
    }

    // MFA passed — create the session.
    match state
        .identity
        .create_session(&pending.tenant_id, &pending.user_id)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(&state.cookie_secret, &pending.tenant_id, session.id());

            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie());
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "mfa-challenge: create_session failed");
            internal_error_response()
        }
    }
}

/// Returns a 401 response when the MFA pending cookie is expired or
/// missing.
fn mfa_expired_response(product_name: String, logo_url: String, theme_css: &str) -> Response {
    let mut tmpl = MfaChallengeTemplate::new(
        Some("Your session has expired. Please sign in again.".to_string()),
        product_name,
        logo_url,
    );
    tmpl.theme_css = theme_css.to_string();
    render_status(&tmpl, StatusCode::UNAUTHORIZED)
}

// ============================================================================
// Dashboard
// ============================================================================

/// Signed-in dashboard. Redirects to `/ui/login` when the session
/// cookie is missing or invalid. Computes `is_admin` by running the
/// `hearth#admin` authz check so the template can render (or hide)
/// admin-only quick links.
pub async fn dashboard(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
) -> Response {
    let is_admin = is_admin(&state, &session);
    let config_warnings = if is_admin {
        state.config_warnings.clone()
    } else {
        Vec::new()
    };
    render(&DashboardTemplate {
        chrome: true,
        active: "dashboard",
        user_email: Some(session.user_email.clone()),
        is_admin,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        tenant_theme_css: state.tenant_theme_css(),
        config_warnings,
    })
}

/// Returns `true` iff the signed-in user has the `hearth#admin`
/// relation. Non-fatal on authz errors — the caller treats those as
/// "not admin" so the UI degrades gracefully.
pub(crate) fn is_admin(state: &WebState, session: &super::auth::UiSession) -> bool {
    // INVARIANT: "hearth"/"admin" and "user"/<uuid> are valid ObjectRef /
    // SubjectRef components (ASCII + UUID respectively).
    #[allow(clippy::unwrap_used)]
    let object = crate::authz::ObjectRef::new("hearth", "admin").unwrap();
    #[allow(clippy::unwrap_used)]
    let subject =
        crate::authz::SubjectRef::direct("user", &session.user_id.as_uuid().to_string()).unwrap();
    state
        .authz
        .check(&session.tenant_id, &object, "admin", &subject, None)
        .unwrap_or(false)
}

// ============================================================================
// Logout
// ============================================================================

/// Form body for the sign-out button.
#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    /// CSRF token echoed from the hidden input.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Handles sign-out. Verifies CSRF, revokes the session on the server,
/// clears both UI cookies, and redirects to `/ui/login`.
///
/// Idempotent: if the session is already gone (e.g. the user clicked
/// sign-out twice), we still clear the cookies and redirect.
pub async fn logout_submit(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
    Form(form): Form<LogoutForm>,
) -> Response {
    if let Err(resp) = super::auth::verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    match state
        .identity
        .revoke_session(&session.tenant_id, &session.session_id)
    {
        Ok(()) | Err(crate::identity::IdentityError::SessionNotFound) => {}
        Err(e) => {
            tracing::warn!(error = %e, "logout: revoke_session failed");
            // Still clear cookies and redirect — worst case the user
            // is signed out client-side, server session will expire.
        }
    }

    let mut response = Redirect::to("/ui/login").into_response();
    for cookie in super::auth::clearing_cookies() {
        append_cookie(&mut response, &cookie);
    }
    response
}

// ============================================================================
// Helpers
// ============================================================================

/// Appends a `Set-Cookie` header without overwriting existing ones.
fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(v) = header::HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn validate_setup_form(form: &SetupForm) -> Result<(), String> {
    if form.admin_email.trim().is_empty() {
        return Err("Admin email is required.".to_string());
    }
    if !form.admin_email.contains('@') {
        return Err("Admin email does not look like an email address.".to_string());
    }
    if form.admin_display_name.trim().is_empty() {
        return Err("Display name is required.".to_string());
    }
    if form.admin_password.len() < 12 {
        return Err("Password must be at least 12 characters.".to_string());
    }
    Ok(())
}

/// Derives the base URL for email links from the `Host` header.
///
/// Falls back to `http://localhost` if no `Host` header is present
/// (e.g. direct test harness calls). Uses `https://` when the request
/// came in over TLS (`X-Forwarded-Proto: https`), else `http://`.
fn derive_base_url(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|s| *s == "https")
        .map_or("http", |_| "https");
    format!("{scheme}://{host}")
}

// ============================================================================
// Password reset flow
// ============================================================================

/// Forgot-password form template.
#[derive(Template)]
#[template(path = "ui/forgot_password.html")]
struct ForgotPasswordTemplate {
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl ForgotPasswordTemplate {
    fn new(error: Option<String>, product_name: String, logo_url: String) -> Self {
        Self {
            error,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// "Check your email" confirmation after requesting a password reset.
#[derive(Template)]
#[template(path = "ui/forgot_password_sent.html")]
struct ForgotPasswordSentTemplate {
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl ForgotPasswordSentTemplate {
    fn new(product_name: String, logo_url: String) -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Reset password form (token in URL).
#[derive(Template)]
#[template(path = "ui/reset_password.html")]
struct ResetPasswordTemplate {
    token: String,
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl ResetPasswordTemplate {
    fn new(token: String, error: Option<String>, product_name: String, logo_url: String) -> Self {
        Self {
            token,
            error,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Success page after password reset.
#[derive(Template)]
#[template(path = "ui/reset_password_ok.html")]
struct ResetPasswordOkTemplate {
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    tenant_theme_css: Option<String>,
}

impl ResetPasswordOkTemplate {
    fn new(product_name: String, logo_url: String) -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            tenant_theme_css: None,
        }
    }
}

/// Renders the forgot-password form.
pub async fn forgot_password_form(State(state): State<Arc<WebState>>) -> Response {
    let mut tmpl =
        ForgotPasswordTemplate::new(None, state.product_name.clone(), state.logo_url.clone());
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Form data for forgot-password submission.
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordForm {
    /// The email address for the password reset.
    pub email: String,
}

/// Handles forgot-password form submission.
///
/// Looks up the user across tenants. If found, requests a password reset
/// token and sends a reset email. Always redirects to the "check your
/// email" page regardless of whether the email exists (enumeration
/// resistance).
pub async fn forgot_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let email = form.email.trim();

    // Walk tenants (same pattern as login)
    let tenants = match state.identity.list_tenants(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "forgot_password: failed to list tenants");
            return Redirect::to("/ui/forgot-password/sent").into_response();
        }
    };

    for tenant in &tenants {
        match state.identity.request_password_reset(tenant.id(), email) {
            Ok(Some(token)) => {
                // Build the reset URL
                let base = derive_base_url(&headers);
                let reset_url = format!("{base}/ui/reset-password?token={token}");

                // Send email if service is configured
                if let Some(ref email_service) = state.email {
                    let tenant_branding = state
                        .identity
                        .get_tenant(tenant.id())
                        .ok()
                        .flatten()
                        .and_then(|t| t.config().email_branding.clone());
                    if let Err(e) = email_service.send_password_reset_email(
                        email,
                        &reset_url,
                        tenant_branding.as_ref(),
                    ) {
                        tracing::warn!(error = %e, "forgot_password: failed to send email");
                    }
                } else {
                    // Fallback: log the URL so admins can still access it
                    tracing::warn!(reset_url = %reset_url, "password reset URL (no email transport configured)");
                }
                break;
            }
            Ok(None) => {
                // Unknown email — try next tenant
            }
            Err(IdentityError::RateLimited) => {
                // Rate limited — still show success page (enumeration resistance)
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "forgot_password: error requesting reset");
                break;
            }
        }
    }

    // Always redirect to "sent" page regardless of outcome
    Redirect::to("/ui/forgot-password/sent").into_response()
}

/// Renders the "check your email" confirmation page.
pub async fn forgot_password_sent(State(state): State<Arc<WebState>>) -> Response {
    let mut tmpl =
        ForgotPasswordSentTemplate::new(state.product_name.clone(), state.logo_url.clone());
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Query parameters for the reset-password page.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordQuery {
    /// The plaintext token from the password reset email.
    pub token: Option<String>,
}

/// Renders the reset-password form (token passed via URL query parameter).
pub async fn reset_password_form(
    State(state): State<Arc<WebState>>,
    Query(query): Query<ResetPasswordQuery>,
) -> Response {
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    if let Some(token) = query.token {
        let mut tmpl = ResetPasswordTemplate::new(token, None, product_name, logo_url);
        tmpl.theme_css.clone_from(&state.theme_css);
        render(&tmpl)
    } else {
        let mut tmpl = ResetPasswordTemplate::new(
            String::new(),
            Some("Missing or invalid reset link.".to_string()),
            product_name,
            logo_url,
        );
        tmpl.theme_css.clone_from(&state.theme_css);
        render_status(&tmpl, StatusCode::BAD_REQUEST)
    }
}

/// Form data for the reset-password submission.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordFormData {
    /// The plaintext token from the password reset email.
    pub token: String,
    /// The new password.
    pub password: String,
    /// Password confirmation.
    pub password_confirm: String,
}

/// Handles reset-password form submission.
///
/// Validates the token across tenants, checks password confirmation match,
/// sets the new password, and shows a success page.
pub async fn reset_password_submit(
    State(state): State<Arc<WebState>>,
    Form(form): Form<ResetPasswordFormData>,
) -> Response {
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let reset_err = |token: String, msg: String| {
        let mut tmpl =
            ResetPasswordTemplate::new(token, Some(msg), product_name.clone(), logo_url.clone());
        tmpl.theme_css.clone_from(&theme_css);
        render(&tmpl)
    };

    // 1. Check passwords match
    if form.password != form.password_confirm {
        return reset_err(form.token, "Passwords do not match.".to_string());
    }

    // 2. Validate password minimum requirements
    if form.password.len() < 8 {
        return reset_err(
            form.token,
            "Password must be at least 8 characters.".to_string(),
        );
    }

    let password = CleartextPassword::from_string(form.password);

    // 3. Walk tenants
    let tenants = match state.identity.list_tenants(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "reset_password: failed to list tenants");
            return internal_error_response();
        }
    };

    for tenant in &tenants {
        match state
            .identity
            .reset_password_with_token(tenant.id(), &form.token, &password)
        {
            Ok(_user_id) => {
                let mut tmpl = ResetPasswordOkTemplate::new(product_name, logo_url);
                tmpl.theme_css.clone_from(&state.theme_css);
                return render(&tmpl);
            }
            Err(IdentityError::PasswordResetTokenInvalid) => {
                // Try next tenant
            }
            Err(e) => {
                tracing::warn!(error = %e, "reset_password: error resetting password");
                return reset_err(
                    form.token,
                    "Failed to reset password. Please try again.".to_string(),
                );
            }
        }
    }

    // Token not valid in any tenant
    reset_err(
        String::new(),
        "This reset link is invalid or has expired. Please request a new one.".to_string(),
    )
}

/// Internal — shared 404 renderer used by the setup gate.
pub(super) fn not_found_response(body: &str) -> Response {
    let tmpl = crate::protocol::web::handlers_common::NotFoundTemplate::new(body.to_string());
    render_status(&tmpl, StatusCode::NOT_FOUND)
}

/// Internal — shared 500 renderer.
pub(super) fn internal_error_response() -> Response {
    let tmpl = crate::protocol::web::handlers_common::ServerErrorTemplate::new();
    render_status(&tmpl, StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_base_url_uses_host_header() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            "auth.example.com:8420".parse().expect("valid header"),
        );
        assert_eq!(derive_base_url(&h), "http://auth.example.com:8420");
    }

    #[test]
    fn derive_base_url_honours_forwarded_proto_https() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            "auth.example.com".parse().expect("valid header"),
        );
        h.insert("x-forwarded-proto", "https".parse().expect("valid header"));
        assert_eq!(derive_base_url(&h), "https://auth.example.com");
    }

    #[test]
    fn derive_base_url_falls_back_without_host() {
        let h = HeaderMap::new();
        assert_eq!(derive_base_url(&h), "http://localhost");
    }

    #[test]
    fn validate_setup_form_requires_email_at_sign() {
        let form = SetupForm {
            token: "t".to_string(),
            admin_email: "no-at-sign".to_string(),
            admin_display_name: "d".to_string(),
            admin_password: "longenough1234".to_string(),
        };
        let err = validate_setup_form(&form).expect_err("should reject");
        assert!(err.contains("email"), "got: {err}");
    }

    #[test]
    fn validate_setup_form_requires_password_min_length() {
        let form = SetupForm {
            token: "t".to_string(),
            admin_email: "a@b.com".to_string(),
            admin_display_name: "d".to_string(),
            admin_password: "short".to_string(),
        };
        let err = validate_setup_form(&form).expect_err("should reject");
        assert!(err.contains("12 characters"), "got: {err}");
    }

    #[test]
    fn validate_setup_form_accepts_valid_input() {
        let form = SetupForm {
            token: "t".to_string(),
            admin_email: "alice@acme.com".to_string(),
            admin_display_name: "Alice".to_string(),
            admin_password: "super-secret-123".to_string(),
        };
        assert!(validate_setup_form(&form).is_ok());
    }
}
