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
//!   session id to its realm id via HMAC-SHA256). See [`super::auth`]
//!   for parsing.

use std::net::SocketAddr;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::identity::onboarding::OnboardingError;
use crate::identity::{
    AuthenticationOptions, CleartextPassword, CompleteAuthenticationParams, IdentityError,
    SessionContext,
};
use crate::protocol::client_info::build_session_context;

/// Default peer address used when `ConnectInfo` is not available
/// (e.g., in tests using `tower::oneshot` without `into_make_service_with_connect_info`).
const FALLBACK_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
    config_warnings: Vec<crate::config::EnvVarWarning>,
    /// Entity counts for the admin stats row.
    user_count: usize,
    realm_count: usize,
    app_count: usize,
    org_count: usize,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
/// - Hearth is already configured (a realm exists).
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
            // Pin the newly-created realm as the "current" realm for
            // future logins through this process. On restart the first
            // realm is re-resolved at login time.
            state.set_current_realm(outcome.realm_id.clone());
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
        Err(OnboardingError::Identity(IdentityError::RealmNotFound)) => setup_err(
            form.token.clone(),
            "No realm is configured. Add a realm to hearth.yaml and restart.".to_string(),
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

    // The token is not realm-scoped in the URL. Walk the first page
    // of realms and try each until one succeeds or we exhaust them.
    // Phase 1 deployments are almost always single-realm; this stays
    // O(#realms) and off the hot path.
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "verify-email: list_realms failed");
            return internal_error_response();
        }
    };

    for realm in &realms {
        match state.identity.verify_email_token(realm.id(), token) {
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
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let email = form.email.trim();
    let return_to = form.return_to.as_deref().and_then(sanitize_return_to);
    let session_ctx = build_session_context(&headers, FALLBACK_PEER, &state.trusted_proxies);

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

    // Walk up to the first page of realms (Phase 1 = usually one).
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "login: failed to list realms");
            return internal_error_response();
        }
    };

    for realm in &realms {
        let Ok(Some(user)) = state.identity.get_user_by_email(realm.id(), email) else {
            continue;
        };

        let password = CleartextPassword::from_string(form.password.clone());

        match state
            .identity
            .verify_password(realm.id(), user.id(), &password)
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
            .mfa_enabled(realm.id(), user.id())
            .unwrap_or(false);
        if mfa_on {
            let cookie = issue_mfa_pending_cookie(
                &state.cookie_secret,
                realm.id(),
                user.id(),
                return_to.as_deref(),
            );
            state.set_current_realm(realm.id().clone());
            let mut response = Redirect::to("/ui/mfa-challenge").into_response();
            append_cookie(&mut response, &cookie);
            return response;
        }

        match state
            .identity
            .create_session(realm.id(), user.id(), &session_ctx)
        {
            Ok(session) => {
                let IssuedCookies {
                    session_cookie,
                    csrf_cookie,
                } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id());

                // Pin this realm as the "current" one so subsequent logins from
                // this process resolve consistently.
                state.set_current_realm(realm.id().clone());

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
// Passkey (WebAuthn) login
// ============================================================================

/// `GET /ui/login/passkey-begin` — starts a discoverable credential
/// authentication ceremony and returns the challenge as JSON.
///
/// This is a pre-auth endpoint: no session is required. The challenge
/// is created per-realm (iterating all active realms) since we don't
/// know which realm the user belongs to yet.
pub async fn passkey_login_begin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    use base64::Engine as _;

    // Derive RP ID from Host header (strip port if present).
    let host_str = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let rp_id = host_str
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();

    let options = AuthenticationOptions {
        rp_id: rp_id.clone(),
    };

    // We only need ONE challenge — the challenge store is realm-agnostic
    // and `user_id=None` (discoverable flow) skips the per-realm user
    // existence check. Use the first realm just to satisfy the API.
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "passkey-login-begin: failed to list realms");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Unavailable").into_response();
        }
    };

    let Some(first_realm) = realms.first() else {
        return (StatusCode::BAD_REQUEST, "No realms configured").into_response();
    };

    let challenge = match state.identity.start_webauthn_authentication(
        first_realm.id(),
        None,
        &options,
    ) {
        Ok(c) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c),
        Err(e) => {
            tracing::error!(error = %e, "passkey-login-begin: start_webauthn_authentication failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Unavailable").into_response();
        }
    };

    let body = serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id,
        "userVerification": "preferred",
        "timeout": 300_000,
    });
    axum::Json(body).into_response()
}

/// JSON body from the browser passkey authentication completion.
#[derive(Debug, Deserialize)]
pub struct PasskeyLoginCompleteBody {
    /// Base64url-encoded credential ID from the authenticator.
    pub credential_id: String,
    /// Base64url-encoded `clientDataJSON`.
    pub client_data_json: String,
    /// Base64url-encoded authenticator data.
    pub authenticator_data: String,
    /// Base64url-encoded signature.
    pub signature: String,
    /// Base64url-encoded user handle (optional, for discoverable credentials).
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// `POST /ui/login/passkey-complete` — completes the discoverable
/// credential authentication ceremony and issues a session.
///
/// Iterates realms to find the one that owns the credential. On
/// success, creates a session and returns the redirect location as
/// JSON (the browser JS will navigate to it).
pub async fn passkey_login_complete(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    use base64::Engine as _;
    let session_ctx = build_session_context(&headers, FALLBACK_PEER, &state.trusted_proxies);

    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let Ok(credential_id) = b64.decode(&body.credential_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid credential_id").into_response();
    };
    let Ok(client_data_json) = b64.decode(&body.client_data_json) else {
        return (StatusCode::BAD_REQUEST, "Invalid client_data_json").into_response();
    };
    let Ok(authenticator_data) = b64.decode(&body.authenticator_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid authenticator_data").into_response();
    };
    let Ok(signature) = b64.decode(&body.signature) else {
        return (StatusCode::BAD_REQUEST, "Invalid signature").into_response();
    };
    let user_handle_bytes = body.user_handle.as_deref().and_then(|h| b64.decode(h).ok());

    // Derive origin from Host header.
    let host_str = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if host_str.starts_with("localhost") || host_str.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };
    let origin = format!("{scheme}://{host_str}");

    // For discoverable credentials the authenticator returns the user
    // handle (the user UUID we set during registration). Use it to
    // identify the correct realm BEFORE consuming the one-shot challenge.
    let Some(ref uh_bytes) = user_handle_bytes else {
        tracing::warn!("passkey-login-complete: no user_handle in assertion");
        return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    };
    let Ok(uh_str) = std::str::from_utf8(uh_bytes) else {
        // user_handle is raw UUID bytes (16 bytes), not a UTF-8 string.
        // Try parsing as raw UUID bytes.
        let Ok(uuid) = uuid::Uuid::from_slice(uh_bytes) else {
            tracing::warn!("passkey-login-complete: invalid user_handle bytes");
            return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
        };
        let user_id = crate::core::UserId::new(uuid);
        return passkey_complete_for_user(
            &state,
            &user_id,
            &credential_id,
            &client_data_json,
            &authenticator_data,
            &signature,
            user_handle_bytes.as_ref(),
            &origin,
            &session_ctx,
        );
    };
    // Try parsing as UUID string representation.
    let Ok(uuid) = uuid::Uuid::parse_str(uh_str) else {
        // Fall back to treating it as raw bytes.
        let Ok(uuid) = uuid::Uuid::from_slice(uh_bytes) else {
            tracing::warn!("passkey-login-complete: cannot parse user_handle as UUID");
            return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
        };
        let user_id = crate::core::UserId::new(uuid);
        return passkey_complete_for_user(
            &state,
            &user_id,
            &credential_id,
            &client_data_json,
            &authenticator_data,
            &signature,
            user_handle_bytes.as_ref(),
            &origin,
            &session_ctx,
        );
    };

    let user_id = crate::core::UserId::new(uuid);
    passkey_complete_for_user(
        &state,
        &user_id,
        &credential_id,
        &client_data_json,
        &authenticator_data,
        &signature,
        user_handle_bytes.as_ref(),
        &origin,
        &session_ctx,
    )
}

/// Resolves the realm that owns `user_id`, then completes the
/// `WebAuthn` authentication and creates a session.
///
/// This is extracted so the UUID-parsing branches in
/// `passkey_login_complete` can share the same completion logic.
#[allow(clippy::too_many_arguments)]
fn passkey_complete_for_user(
    state: &Arc<WebState>,
    user_id: &crate::core::UserId,
    credential_id: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    user_handle_bytes: Option<&Vec<u8>>,
    origin: &str,
    session_ctx: &SessionContext,
) -> Response {
    // Find which realm owns this user.
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "passkey-login-complete: failed to list realms");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Unavailable").into_response();
        }
    };

    let realm = realms.iter().find(|t| {
        state
            .identity
            .get_user(t.id(), user_id)
            .ok()
            .flatten()
            .is_some()
    });

    let Some(realm) = realm else {
        tracing::warn!(user_id = %user_id, "passkey-login-complete: user not found in any realm");
        return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    };

    let params = CompleteAuthenticationParams {
        credential_id,
        client_data_json,
        authenticator_data,
        signature,
        user_handle: user_handle_bytes.map(Vec::as_slice),
        origin,
    };

    let auth_result = match state
        .identity
        .complete_webauthn_authentication(realm.id(), &params)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "passkey-login-complete: authentication failed");
            return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
        }
    };

    // Check realm policy: some regulated environments require TOTP
    // even after passkey auth despite its inherent multi-factor nature.
    let require_mfa_after_passkey = realm.config().passkey_requires_mfa.unwrap_or(false);

    if require_mfa_after_passkey {
        let mfa_on = state
            .identity
            .mfa_enabled(realm.id(), auth_result.user_id())
            .unwrap_or(false);
        if mfa_on {
            let cookie = issue_mfa_pending_cookie(
                &state.cookie_secret,
                realm.id(),
                auth_result.user_id(),
                None, // no return_to for passkey flow
            );
            state.set_current_realm(realm.id().clone());
            let response_json = axum::Json(serde_json::json!({
                "redirect": "/ui/mfa-challenge",
            }));
            let mut response = response_json.into_response();
            append_cookie(&mut response, &cookie);
            return response;
        }
    }

    // Passkey authentication bypasses the TOTP gate — a passkey
    // is inherently multi-factor (possession + biometric/PIN).
    // Only reached if passkey_requires_mfa is false or user has no MFA enrolled.
    match state
        .identity
        .create_session(realm.id(), auth_result.user_id(), session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id());

            state.set_current_realm(realm.id().clone());

            let mut response = axum::Json(serde_json::json!({
                "redirect": "/ui",
            }))
            .into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            response
        }
        Err(IdentityError::UserNotVerified) => axum::Json(serde_json::json!({
            "error": "Email not verified. Check your inbox for the verification link."
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "passkey-login: create_session failed");
            (StatusCode::UNAUTHORIZED, "Authentication failed").into_response()
        }
    }
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
    let session_ctx = build_session_context(&headers, FALLBACK_PEER, &state.trusted_proxies);
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
            .verify_totp(&pending.realm_id, &pending.user_id, code)
    } else {
        state
            .identity
            .verify_recovery_code(&pending.realm_id, &pending.user_id, code)
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
        .create_session(&pending.realm_id, &pending.user_id, &session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(&state.cookie_secret, &pending.realm_id, session.id());

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

    // Count entities for admin stats. Non-fatal — defaults to 0.
    let (user_count, realm_count, app_count, org_count) = if is_admin {
        let uc = state
            .identity
            .list_users(&session.realm_id, None, 10_000)
            .map(|p| p.items.len())
            .unwrap_or(0);
        let tc = state
            .identity
            .list_realms(None, 10_000)
            .map(|p| p.items.len())
            .unwrap_or(0);
        let ac = state
            .identity
            .list_clients(&session.realm_id, None, 10_000)
            .map(|p| p.items.len())
            .unwrap_or(0);
        let oc = state
            .identity
            .list_organizations(&session.realm_id, None, 10_000)
            .map(|p| p.items.len())
            .unwrap_or(0);
        (uc, tc, ac, oc)
    } else {
        (0, 0, 0, 0)
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
        realm_theme_css: state.realm_theme_css(),
        config_warnings,
        user_count,
        realm_count,
        app_count,
        org_count,
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
        .check(&session.realm_id, &object, "admin", &subject, None)
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
        .revoke_session(&session.realm_id, &session.session_id)
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
    realm_theme_css: Option<String>,
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
            realm_theme_css: None,
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
/// Looks up the user across realms. If found, requests a password reset
/// token and sends a reset email. Always redirects to the "check your
/// email" page regardless of whether the email exists (enumeration
/// resistance).
pub async fn forgot_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let email = form.email.trim();

    // Walk realms (same pattern as login)
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "forgot_password: failed to list realms");
            return Redirect::to("/ui/forgot-password/sent").into_response();
        }
    };

    for realm in &realms {
        match state.identity.request_password_reset(realm.id(), email) {
            Ok(Some(token)) => {
                // Build the reset URL
                let base = derive_base_url(&headers);
                let reset_url = format!("{base}/ui/reset-password?token={token}");

                // Send email if service is configured
                if let Some(ref email_service) = state.email {
                    let realm_branding = state
                        .identity
                        .get_realm(realm.id())
                        .ok()
                        .flatten()
                        .and_then(|t| t.config().email_branding.clone());
                    if let Err(e) = email_service.send_password_reset_email(
                        email,
                        &reset_url,
                        realm_branding.as_ref(),
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
                // Unknown email — try next realm
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
/// Validates the token across realms, checks password confirmation match,
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

    // 3. Walk realms
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "reset_password: failed to list realms");
            return internal_error_response();
        }
    };

    for realm in &realms {
        match state
            .identity
            .reset_password_with_token(realm.id(), &form.token, &password)
        {
            Ok(_user_id) => {
                let mut tmpl = ResetPasswordOkTemplate::new(product_name, logo_url);
                tmpl.theme_css.clone_from(&state.theme_css);
                return render(&tmpl);
            }
            Err(IdentityError::PasswordResetTokenInvalid) => {
                // Try next realm
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

    // Token not valid in any realm
    reset_err(
        String::new(),
        "This reset link is invalid or has expired. Please request a new one.".to_string(),
    )
}

// ============================================================================
// Self-service registration
// ============================================================================

/// Registration form template.
#[derive(Template)]
#[template(path = "ui/register.html")]
#[allow(clippy::struct_excessive_bools)]
struct RegisterTemplate {
    disabled: bool,
    invite_only: bool,
    email_prefill: String,
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
    realm_theme_css: Option<String>,
}

impl RegisterTemplate {
    fn new(
        disabled: bool,
        invite_only: bool,
        email_prefill: String,
        error: Option<String>,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            disabled,
            invite_only,
            email_prefill,
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
            realm_theme_css: None,
        }
    }
}

/// Confirmation page after a successful signup submission.
#[derive(Template)]
#[template(path = "ui/register_sent.html")]
struct RegisterSentTemplate {
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
    realm_theme_css: Option<String>,
}

impl RegisterSentTemplate {
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
            realm_theme_css: None,
        }
    }
}

/// Form data for `POST /ui/register`.
#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    /// Email address.
    pub email: String,
    /// Display name.
    pub display_name: String,
    /// New password.
    pub password: String,
    /// Password confirmation.
    pub password_confirm: String,
    /// Optional invitation token (required when policy is invite-only).
    #[serde(default)]
    pub invitation_token: Option<String>,
}

/// Picks the single realm under which self-registration runs.
///
/// Phase 1 deployments are overwhelmingly single-realm; multi-realm signup
/// will eventually route via subdomain or `?realm=` but is out of scope
/// here. We pick the first active realm returned by the engine and fall
/// back to the first realm overall if none are Active (matches the
/// `forgot_password_submit` tolerance for mid-suspension edge cases).
fn pick_registration_realm(state: &WebState) -> Option<crate::identity::Realm> {
    let realms = state.identity.list_realms(None, 100).ok()?.items;
    realms
        .iter()
        .find(|r| r.status() == crate::identity::RealmStatus::Active)
        .cloned()
        .or_else(|| realms.into_iter().next())
}

/// Returns `(disabled, invite_only)` flags derived from the realm's
/// registration policy.
fn registration_policy_flags(realm: Option<&crate::identity::Realm>) -> (bool, bool) {
    match realm.and_then(|r| r.config().registration_policy.clone()) {
        None | Some(crate::identity::RegistrationPolicy::Disabled) => (true, false),
        Some(crate::identity::RegistrationPolicy::InviteOnly) => (false, true),
        Some(_) => (false, false),
    }
}

/// Renders the registration form.
pub async fn register_form(State(state): State<Arc<WebState>>) -> Response {
    let realm = pick_registration_realm(&state);
    let (disabled, invite_only) = registration_policy_flags(realm.as_ref());
    let mut tmpl = RegisterTemplate::new(
        disabled,
        invite_only,
        String::new(),
        None,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Maps `IdentityError` values from `register_user` to user-facing banner text.
fn register_error_message(err: &IdentityError) -> String {
    match err {
        IdentityError::InvalidInput { reason } => reason.clone(),
        IdentityError::RegistrationDomainNotAllowed { .. } => {
            "That email domain is not permitted for registration.".to_string()
        }
        IdentityError::RegistrationRequiresInvitation => {
            "A valid invitation is required to register in this realm.".to_string()
        }
        IdentityError::RegistrationDisabled => {
            "Registration is not enabled for this realm.".to_string()
        }
        IdentityError::RateLimited => {
            "Too many registration attempts. Please try again later.".to_string()
        }
        _ => "Registration failed. Please try again.".to_string(),
    }
}

/// Extracts the caller's IP from proxy-aware headers, if present.
fn register_client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Handles registration form submission.
///
/// On success, creates a `PendingVerification` user, issues a verification
/// token, emails it, and redirects to `/ui/register/sent`. On any policy or
/// validation error, re-renders the form with a banner. Duplicate emails
/// are handled at the engine layer with a fake-success response so we never
/// see an error on that path — that preserves enumeration resistance.
pub async fn register_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let realm = pick_registration_realm(&state);
    let (disabled, invite_only) = registration_policy_flags(realm.as_ref());

    let render_err = |msg: String, email: String| {
        let mut tmpl = RegisterTemplate::new(
            disabled,
            invite_only,
            email,
            Some(msg),
            product_name.clone(),
            logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&theme_css);
        render_status(&tmpl, StatusCode::BAD_REQUEST)
    };

    if disabled {
        return render_err(
            "Registration is not enabled for this realm.".to_string(),
            form.email,
        );
    }
    if form.password != form.password_confirm {
        return render_err("Passwords do not match.".to_string(), form.email);
    }
    if form.password.len() < 8 {
        return render_err(
            "Password must be at least 8 characters.".to_string(),
            form.email,
        );
    }

    let Some(realm) = realm else {
        tracing::error!("register_submit: no realm available for registration");
        return internal_error_response();
    };

    let request = crate::identity::RegisterUserRequest {
        email: form.email.clone(),
        display_name: form.display_name,
        password: CleartextPassword::from_string(form.password),
        client_ip: register_client_ip(&headers),
        invitation_token: form.invitation_token.clone(),
    };

    let response = match state.identity.register_user(realm.id(), &request) {
        Ok(r) => r,
        Err(e) => {
            if !matches!(
                e,
                IdentityError::InvalidInput { .. }
                    | IdentityError::RegistrationDomainNotAllowed { .. }
                    | IdentityError::RegistrationRequiresInvitation
                    | IdentityError::RegistrationDisabled
                    | IdentityError::RateLimited
            ) {
                tracing::warn!(error = %e, "register_submit: unexpected engine error");
            }
            return render_err(register_error_message(&e), form.email);
        }
    };

    if let Some(email_service) = state.email.as_ref() {
        let base = derive_base_url(&headers);
        let verify_url = format!(
            "{base}/ui/verify-email?token={}",
            response.verification_token
        );
        let branding = realm.config().email_branding.clone();
        if let Err(e) =
            email_service.send_verification_email(&form.email, &verify_url, branding.as_ref())
        {
            tracing::warn!(error = %e, "register_submit: failed to send verification email");
        }
    } else {
        tracing::warn!(
            "register_submit: no email transport configured; verification cannot be delivered"
        );
    }

    Redirect::to("/ui/register/sent").into_response()
}

/// Renders the post-submission confirmation page.
pub async fn register_sent(State(state): State<Arc<WebState>>) -> Response {
    let mut tmpl = RegisterSentTemplate::new(state.product_name.clone(), state.logo_url.clone());
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
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

// ============================================================================
// Invitation acceptance
// ============================================================================

/// Query params for the invitation acceptance page.
#[derive(Debug, Deserialize)]
pub struct AcceptInvitationParams {
    /// The plaintext invitation token from the email link.
    pub token: Option<String>,
}

/// Template for invitation acceptance result.
#[derive(Template)]
#[template(path = "ui/accept_invitation.html")]
#[allow(clippy::struct_excessive_bools)]
struct AcceptInvitationTemplate {
    success: bool,
    org_name: String,
    error_message: String,
    // Chrome fields.
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
    realm_theme_css: Option<String>,
}

/// `GET /ui/accept-invitation?token=...` — accepts an organization invitation.
///
/// Walks all realms, trying `accept_invitation` with the token.
/// On success, renders a welcome page; on failure, renders an error.
pub async fn accept_invitation_page(
    State(state): State<Arc<WebState>>,
    Query(params): Query<AcceptInvitationParams>,
) -> Response {
    let token = match &params.token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            return render(&AcceptInvitationTemplate {
                success: false,
                org_name: String::new(),
                error_message: "No invitation token provided.".to_string(),
                chrome: false,
                active: "",
                user_email: None,
                is_admin: false,
                flash: None,
                csrf: None,
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: None,
            });
        }
    };

    // Walk realms and try to accept the invitation
    let realms = match state.identity.list_realms(None, 100) {
        Ok(page) => page.items,
        Err(e) => {
            tracing::error!(error = %e, "accept_invitation: failed to list realms");
            return render(&AcceptInvitationTemplate {
                success: false,
                org_name: String::new(),
                error_message: "An internal error occurred.".to_string(),
                chrome: false,
                active: "",
                user_email: None,
                is_admin: false,
                flash: None,
                csrf: None,
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: None,
            });
        }
    };

    for realm in &realms {
        if let Ok(membership) = state.identity.accept_invitation(realm.id(), token) {
            // Resolve org name for display
            let org_name = state
                .identity
                .get_organization(realm.id(), membership.org_id())
                .ok()
                .flatten()
                .map_or_else(|| "the organization".to_string(), |o| o.name().to_string());

            return render(&AcceptInvitationTemplate {
                success: true,
                org_name,
                error_message: String::new(),
                chrome: false,
                active: "",
                user_email: None,
                is_admin: false,
                flash: None,
                csrf: None,
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: None,
            });
        }
    }

    // No realm accepted the token
    render(&AcceptInvitationTemplate {
        success: false,
        org_name: String::new(),
        error_message: "This invitation has expired or is invalid.".to_string(),
        chrome: false,
        active: "",
        user_email: None,
        is_admin: false,
        flash: None,
        csrf: None,
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: None,
    })
}

// ============================================================================
// Device Authorization Approval
// ============================================================================

/// Query / flash parameters for the device approval page.
#[derive(Debug, Deserialize)]
pub struct DeviceApproveParams {
    /// Flash key for success / error messages after POST redirect.
    pub flash: Option<String>,
}

/// Template for the device authorization approval page.
#[derive(Template)]
#[template(path = "ui/device_approve.html")]
#[allow(clippy::struct_excessive_bools)]
pub struct DeviceApproveTemplate {
    pub chrome: bool,
    pub active: &'static str,
    pub user_email: Option<String>,
    pub is_admin: bool,
    pub flash: Option<super::templates::Flash>,
    pub csrf: Option<String>,
    pub narrow: bool,
    pub product_name: String,
    pub logo_url: String,
    pub theme_css: String,
    pub realm_theme_css: Option<String>,
}

/// Form submitted when the user approves a device.
#[derive(Debug, Deserialize)]
pub struct DeviceApproveForm {
    /// The 8-character user code shown on the input-constrained device.
    pub user_code: String,
    /// CSRF token.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// GET `/ui/device` — renders the device approval form (requires auth).
pub async fn device_approve_form(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
    Query(params): Query<DeviceApproveParams>,
) -> Response {
    let admin = is_admin(&state, &session);
    let flash = match params.flash.as_deref() {
        Some("approved") => Some(super::templates::Flash {
            kind: "success",
            message: "Device approved successfully.".to_string(),
        }),
        Some("expired") => Some(super::templates::Flash {
            kind: "error",
            message: "That device code has expired.".to_string(),
        }),
        Some("invalid") => Some(super::templates::Flash {
            kind: "error",
            message: "Invalid device code. Please check and try again.".to_string(),
        }),
        _ => None,
    };

    render(&DeviceApproveTemplate {
        chrome: true,
        active: "",
        user_email: Some(session.user_email.clone()),
        is_admin: admin,
        flash,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

/// POST `/ui/device` — processes the device approval form.
pub async fn device_approve_submit(
    State(state): State<Arc<WebState>>,
    session: super::auth::UiSession,
    Form(form): Form<DeviceApproveForm>,
) -> Response {
    let code = form.user_code.trim().to_uppercase();

    if code.is_empty() || code.len() > 8 {
        return Redirect::to("/ui/device?flash=invalid").into_response();
    }

    match state
        .identity
        .approve_device(&session.realm_id, &code, &session.user_id)
    {
        Ok(()) => Redirect::to("/ui/device?flash=approved").into_response(),
        Err(IdentityError::DeviceCodeExpired) => {
            Redirect::to("/ui/device?flash=expired").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "device_approve: approve_device failed");
            Redirect::to("/ui/device?flash=invalid").into_response()
        }
    }
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
