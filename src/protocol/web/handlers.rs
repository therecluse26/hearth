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

use super::auth::{issue_auth_cookies, sanitize_return_to, IssuedCookies};
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
}

impl SetupTemplate {
    fn new(token: String, error: Option<String>) -> Self {
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
        }
    }
}

/// Simple "setup submitted" confirmation page.
#[derive(Template)]
#[template(path = "ui/setup_sent.html")]
struct SetupSentTemplate {
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
}

impl SetupSentTemplate {
    fn new() -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
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
}

impl LoginTemplate {
    fn new(error: Option<String>, return_to: Option<String>) -> Self {
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
}

impl VerifyOkTemplate {
    fn new() -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
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
}

impl VerifyInvalidTemplate {
    fn new(heading: &'static str, message: &'static str) -> Self {
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

    render(&SetupTemplate::new(token.to_string(), None))
}

/// Form body submitted by the setup page.
#[derive(Debug, Deserialize)]
pub struct SetupForm {
    /// Setup token echoed from the hidden input.
    pub token: String,
    /// Human-readable tenant name.
    pub tenant_name: String,
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

    if let Err(msg) = validate_setup_form(&form) {
        return render_status(
            &SetupTemplate::new(form.token.clone(), Some(msg)),
            StatusCode::BAD_REQUEST,
        );
    }

    let password = CleartextPassword::from_string(form.admin_password.clone());

    let base_url = derive_base_url(&headers);
    match state.onboarding.complete_setup(
        form.tenant_name.trim(),
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
        Err(OnboardingError::Identity(IdentityError::DuplicateEmail)) => {
            let msg = "An account with that email already exists in this system.".to_string();
            render_status(
                &SetupTemplate::new(form.token.clone(), Some(msg)),
                StatusCode::CONFLICT,
            )
        }
        Err(OnboardingError::Identity(IdentityError::DuplicateTenantName)) => {
            let msg =
                "A tenant with that name already exists. Retry with a different name.".to_string();
            render_status(
                &SetupTemplate::new(form.token.clone(), Some(msg)),
                StatusCode::CONFLICT,
            )
        }
        Err(OnboardingError::Identity(IdentityError::InvalidInput { reason })) => {
            let msg = format!("Invalid input: {reason}");
            render_status(
                &SetupTemplate::new(form.token.clone(), Some(msg)),
                StatusCode::BAD_REQUEST,
            )
        }
        Err(OnboardingError::Email(e)) => {
            tracing::error!(error = %e, "setup: failed to send verification email");
            let msg = "The account was created but the verification email could not be sent. \
                Check the server logs for the verification link, or retry after fixing the email \
                transport."
                .to_string();
            render_status(
                &SetupTemplate::new(form.token.clone(), Some(msg)),
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
pub async fn setup_sent() -> Response {
    render(&SetupSentTemplate::new())
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
    let Some(token) = query.token.as_deref() else {
        return render_status(
            &VerifyInvalidTemplate::new(
                "Invalid link",
                "This verification link is missing or malformed.",
            ),
            StatusCode::BAD_REQUEST,
        );
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
            Ok(_) => return render(&VerifyOkTemplate::new()),
            Err(IdentityError::VerificationTokenInvalid) => {}
            Err(e) => {
                tracing::error!(error = %e, "verify-email: unexpected failure");
                return internal_error_response();
            }
        }
    }

    render_status(
        &VerifyInvalidTemplate::new(
            "Link expired or already used",
            "This verification link is no longer valid. Request a new verification email from \
            the sign-in page once it becomes available.",
        ),
        StatusCode::GONE,
    )
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
pub async fn login_form(Query(query): Query<LoginQuery>) -> Response {
    let return_to = query.return_to.as_deref().and_then(sanitize_return_to);
    render(&LoginTemplate::new(None, return_to))
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
/// `hearth_ui_csrf` cookies, then redirects. All authentication
/// failures collapse into a single generic error message (enumeration
/// resistance).
pub async fn login_submit(
    State(state): State<Arc<WebState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let email = form.email.trim();
    let return_to = form.return_to.as_deref().and_then(sanitize_return_to);

    let generic_error = || {
        render_status(
            &LoginTemplate::new(
                Some("Sign-in failed. Check your credentials and try again.".to_string()),
                return_to.clone(),
            ),
            StatusCode::UNAUTHORIZED,
        )
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
                return render_status(
                    &LoginTemplate::new(
                        Some(
                            "Your email is not verified yet. Check your inbox (or the server \
                             logs) for the verification link and click it before signing in."
                                .to_string(),
                        ),
                        return_to.clone(),
                    ),
                    StatusCode::FORBIDDEN,
                );
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
    render(&DashboardTemplate {
        chrome: true,
        active: "dashboard",
        user_email: Some(session.user_email.clone()),
        is_admin,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
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
    if form.tenant_name.trim().is_empty() {
        return Err("Tenant name is required.".to_string());
    }
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
            tenant_name: "t".to_string(),
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
            tenant_name: "t".to_string(),
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
            tenant_name: "Acme".to_string(),
            admin_email: "alice@acme.com".to_string(),
            admin_display_name: "Alice".to_string(),
            admin_password: "super-secret-123".to_string(),
        };
        assert!(validate_setup_form(&form).is_ok());
    }
}
