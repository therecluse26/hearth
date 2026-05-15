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
use super::realm_resolver::{self, Resolved};
use super::templates::{render, render_status, Flash};
use super::WebState;
use crate::identity::Realm;

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

/// One federation sign-in button rendered on the login page.
pub(super) struct FederationButton {
    /// URL of the `/federation/begin?idp=...` endpoint.
    pub(super) begin_url: String,
    /// Human-readable label for the button ("Google", "GitHub", etc.).
    pub(super) display_name: String,
}

/// Login form template.
#[derive(Template)]
#[template(path = "ui/login.html")]
#[allow(clippy::struct_excessive_bools, dead_code)]
struct LoginTemplate {
    error: Option<String>,
    return_to: Option<String>,
    /// Submitted email, echoed back into the form on auth failure so the
    /// user doesn't have to retype it. Empty on the initial GET.
    /// Carries no enumeration risk: we always show the same generic error,
    /// so the field is preserved whether or not the address matches a user.
    email: String,
    /// URL the form POSTs to — empty for bare `/ui/login`, or
    /// `/ui/realms/<name>/login` for a realm-scoped form.
    form_action: String,
    /// URL of the forgot-password page (scope-matched).
    forgot_url: String,
    /// URL of the register page (scope-matched).
    register_url: String,
    /// When `false`, the "Create account" link is hidden — set from the
    /// realm's [`RegistrationPolicy`] so disabled realms don't advertise
    /// a dead registration URL.
    show_register: bool,
    /// Endpoint prefix for passkey AJAX calls, scope-matched.
    passkey_begin_url: String,
    passkey_complete_url: String,
    locale: String,
    heading_text: &'static str,
    email_label: &'static str,
    password_label: &'static str,
    submit_label: &'static str,
    or_continue_with_label: &'static str,
    or_label: &'static str,
    sign_in_with_label: &'static str,
    forgot_password_label: &'static str,
    create_account_label: &'static str,
    passkey_sign_in_label: &'static str,
    passkey_authenticating_label: &'static str,
    passkey_unavailable_error: &'static str,
    passkey_cancelled_error: &'static str,
    passkey_failed_error: &'static str,
    /// When `true`, the TOTP step is shown inline instead of email+password.
    /// Set by the handler when password is correct but MFA is required.
    show_totp: bool,
    /// URL the inline TOTP form POSTs to (scope-matched).
    totp_action: String,
    /// URL of the MFA recovery code page (scope-matched).
    recovery_code_url: String,
    /// Shown alongside error when email is unverified — "Resend verification email".
    resend_verification_url: Option<String>,
    /// Shown alongside error when a magic link is expired — "Request a new magic link".
    new_magic_link_url: Option<String>,
    /// Federation sign-in buttons, one per configured connector.
    federation_buttons: Vec<FederationButton>,
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
        action_prefix: &str,
        show_register: bool,
        locale: &str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        let text = login_locale_text(locale);
        Self {
            error,
            return_to,
            email: String::new(),
            form_action: format!("{action_prefix}/login"),
            forgot_url: with_locale_query(&format!("{action_prefix}/forgot-password"), locale),
            register_url: with_locale_query(&format!("{action_prefix}/register"), locale),
            show_register,
            passkey_begin_url: format!("{action_prefix}/login/passkey-begin"),
            passkey_complete_url: format!("{action_prefix}/login/passkey-complete"),
            locale: locale.to_string(),
            heading_text: text.heading_text,
            email_label: text.email_label,
            password_label: text.password_label,
            submit_label: text.submit_label,
            or_continue_with_label: text.or_continue_with_label,
            or_label: text.or_label,
            sign_in_with_label: text.sign_in_with_label,
            forgot_password_label: text.forgot_password_label,
            create_account_label: text.create_account_label,
            passkey_sign_in_label: text.passkey_sign_in_label,
            passkey_authenticating_label: text.passkey_authenticating_label,
            passkey_unavailable_error: text.passkey_unavailable_error,
            passkey_cancelled_error: text.passkey_cancelled_error,
            passkey_failed_error: text.passkey_failed_error,
            show_totp: false,
            totp_action: format!("{action_prefix}/mfa-challenge"),
            recovery_code_url: format!("{action_prefix}/mfa-recovery"),
            resend_verification_url: None,
            new_magic_link_url: None,
            federation_buttons: Vec::new(),
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
    /// URL the "Sign in" button links to. Scope-matched to the realm
    /// the verification happened in so a user coming through
    /// `/ui/realms/<name>/verify-email` doesn't fall back onto the
    /// bare `/ui/login` resolver.
    login_url: String,
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
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
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
    /// Friendly greeting name — first non-empty of display name, given
    /// name, or local part of the email. Surfaced in the "Welcome, X"
    /// heading so admins are not greeted by a raw email address.
    greeting_name: String,
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

/// Forced MFA enrollment template — shown when the realm requires MFA but the
/// user has not yet enrolled. Mirrors the account enrollment UI but uses the
/// narrow, chrome-free layout (no nav) because the user has no session yet.
#[derive(Template)]
#[template(path = "ui/mfa_enroll_required.html")]
struct MfaEnrollRequiredTemplate {
    error: Option<String>,
    secret_base32: String,
    provisioning_uri: String,
    qr_svg: String,
    recovery_codes: Vec<String>,
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

impl MfaEnrollRequiredTemplate {
    fn new(
        error: Option<String>,
        secret_base32: String,
        provisioning_uri: String,
        qr_svg: String,
        recovery_codes: Vec<String>,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            error,
            secret_base32,
            provisioning_uri,
            qr_svg,
            recovery_codes,
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
    /// URL the form POSTs to (scope-matched).
    form_action: String,
    /// URL of the MFA recovery code page (scope-matched).
    recovery_code_url: String,
    /// Carry through the post-login redirect.
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

impl MfaChallengeTemplate {
    fn new(
        error: Option<String>,
        product_name: String,
        logo_url: String,
        return_to: Option<String>,
    ) -> Self {
        Self {
            error,
            form_action: "/ui/mfa-challenge".to_string(),
            recovery_code_url: "/ui/mfa-recovery".to_string(),
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

    let base_url = derive_base_url(
        state
            .config
            .as_ref()
            .and_then(|c| c.onboarding.base_url.as_deref()),
        &headers,
    );
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

/// Handles email verification on the bare `/ui/verify-email?token=...` URL.
pub async fn verify_email(
    State(state): State<Arc<WebState>>,
    Query(query): Query<VerifyQuery>,
) -> Response {
    verify_email_impl(state, query, RealmSource::Path(None))
}

/// Handles email verification on `/ui/realms/<name>/verify-email?token=...`.
pub async fn verify_email_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    Query(query): Query<VerifyQuery>,
) -> Response {
    verify_email_impl(state, query, RealmSource::Path(Some(realm_name)))
}

/// Handles email verification on `/ui/admin/verify-email?token=...`.
///
/// This is the link admins receive in their setup confirmation email.
/// Resolves to the system realm regardless of application realm state.
pub async fn admin_verify_email(
    State(state): State<Arc<WebState>>,
    Query(query): Query<VerifyQuery>,
) -> Response {
    verify_email_impl(state, query, RealmSource::Admin)
}

/// Shared implementation. On success the user transitions
/// `PendingVerification` → `Active` and can thereafter sign in.
#[allow(clippy::needless_pass_by_value)]
fn verify_email_impl(state: Arc<WebState>, query: VerifyQuery, source: RealmSource) -> Response {
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

    let (realm, action_prefix) = match resolve_for_source(&state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };

    match state.identity.verify_email_token(realm.id(), token) {
        Ok(_) => {
            let login_url = format!("{action_prefix}/login");
            let mut tmpl = VerifyOkTemplate::new(login_url, product_name, logo_url);
            tmpl.theme_css.clone_from(&state.theme_css);
            tmpl.realm_theme_css = state.realm_theme_css_for(realm.id());
            render(&tmpl)
        }
        Err(IdentityError::VerificationTokenInvalid) => {
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
        Err(e) => {
            tracing::error!(error = %e, "verify-email: unexpected failure");
            internal_error_response()
        }
    }
}

// ============================================================================
// Login
// ============================================================================

/// Query parameters for the GET login form (optional `return_to`).
#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Relative path to redirect back to after a successful sign-in.
    pub return_to: Option<String>,
    /// Optional locale tag for login UI copy (for example: `en`, `es`).
    pub locale: Option<String>,
}

/// Renders the login form at the bare `/ui/login` URL.
pub async fn login_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    login_form_impl(state, headers, query, RealmSource::Path(None))
}

/// Renders the login form under `/ui/realms/<name>/login`.
pub async fn login_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    login_form_impl(state, headers, query, RealmSource::Path(Some(realm_name)))
}

/// Renders the admin login form at `/ui/admin/login`. The session
/// created by a successful submit is always bound to the system realm.
pub async fn admin_login_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    login_form_impl(state, headers, query, RealmSource::Admin)
}

#[allow(clippy::needless_pass_by_value)]
fn login_form_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    query: LoginQuery,
    source: RealmSource,
) -> Response {
    let return_to = query.return_to.as_deref().and_then(sanitize_return_to);
    let locale = resolve_login_locale(
        query.locale.as_deref(),
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    );
    let (realm, action_prefix) = match resolve_for_source(&state, source, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let product_name = state.product_name_for(realm.id());
    let show_register = registration_enabled(&realm);
    let mut tmpl = LoginTemplate::new(
        None,
        return_to,
        &action_prefix,
        show_register,
        locale,
        product_name,
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css_for(realm.id());
    tmpl.federation_buttons = federation_buttons_for(&state, realm.id(), &action_prefix);
    render(&tmpl)
}

/// Builds the list of federation sign-in buttons rendered on a login
/// page. Returns an empty vector when the realm has no connectors
/// registered or the engine errors (which we log and swallow — the
/// password form still works).
pub(super) fn federation_buttons_for(
    state: &WebState,
    realm_id: &crate::core::RealmId,
    action_prefix: &str,
) -> Vec<FederationButton> {
    let idps = match state.identity.list_idps(realm_id) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "list_idps for login page failed");
            return Vec::new();
        }
    };
    idps.into_iter()
        .map(|cfg| FederationButton {
            begin_url: format!(
                "{action_prefix}/federation/begin?idp={}",
                form_urlencoded::byte_serialize(cfg.name.as_bytes()).collect::<String>()
            ),
            display_name: cfg.display_name,
        })
        .collect()
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
    /// Optional locale submitted via hidden field.
    #[serde(default)]
    pub locale: Option<String>,
}

/// Handles login submission at the bare `/ui/login` URL.
pub async fn login_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    login_submit_impl(state, headers, form, RealmSource::Path(None))
}

/// Handles login submission at `/ui/realms/<name>/login`.
pub async fn login_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    login_submit_impl(state, headers, form, RealmSource::Path(Some(realm_name)))
}

/// Handles admin login submission at `/ui/admin/login`. On success,
/// issues a session cookie bound to the system realm.
pub async fn admin_login_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    login_submit_impl(state, headers, form, RealmSource::Admin)
}

/// Shared login submit. On success: creates a session, issues the
/// `hearth_ui_session` and `hearth_ui_csrf` cookies, then redirects.
/// When MFA is enabled, redirects to `/ui/mfa-challenge` with a
/// pending cookie instead. All auth failures collapse into a single
/// generic error (enumeration resistance).
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn login_submit_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: LoginForm,
    source: RealmSource,
) -> Response {
    let email = form.email.trim();
    let return_to = form.return_to.as_deref().and_then(sanitize_return_to);
    let locale = resolve_login_locale(
        form.locale.as_deref(),
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    );
    let session_ctx = build_session_context(&headers, FALLBACK_PEER, &state.trusted_proxies);

    let (realm, action_prefix) = match resolve_for_source(&state, source, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };

    let product_name = state.product_name_for(realm.id());
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let realm_theme = state.realm_theme_css_for(realm.id());
    let show_register = registration_enabled(&realm);
    // Extract the client IP once, after trusted-proxy stripping, for the
    // per-IP rate limiter. Empty string = no IP available (skipped by engine).
    let client_ip = session_ctx.ip_address.clone().unwrap_or_default();

    let generic_error = {
        let action_prefix = action_prefix.clone();
        let return_to = return_to.clone();
        let realm_theme = realm_theme.clone();
        let submitted_email = email.to_string();
        let product_name = product_name.clone();
        move || {
            let mut tmpl = LoginTemplate::new(
                Some("Sign-in failed. Check your credentials and try again.".to_string()),
                return_to.clone(),
                &action_prefix,
                show_register,
                locale,
                product_name.clone(),
                logo_url.clone(),
            );
            // Echo the submitted email back into the form so the user
            // doesn't have to retype it. The error message is constant
            // regardless of whether the address matches a real account
            // (enumeration resistance), so this leaks nothing.
            tmpl.email.clone_from(&submitted_email);
            tmpl.theme_css.clone_from(&theme_css);
            tmpl.realm_theme_css.clone_from(&realm_theme);
            render_status(&tmpl, StatusCode::UNAUTHORIZED)
        }
    };

    // Enforce realm policy: password auth must be in the allow-list.
    if let Some(ref methods) = realm.config().allowed_auth_methods {
        if !methods.iter().any(|m| m == "password") {
            tracing::warn!(realm = %realm.id(), "login: password auth blocked by realm policy");
            return generic_error();
        }
    }

    // Per-IP rate limit check. Must happen before user lookup so a blocked
    // IP cannot probe which email addresses exist.
    if state
        .identity
        .check_ip_login_rate_limit(realm.id(), &client_ip)
        .is_err()
    {
        tracing::warn!(ip = %client_ip, "login: IP rate limit exceeded");
        return generic_error();
    }

    // Resolved realm → single targeted lookup. No walk.
    let Ok(Some(user)) = state.identity.get_user_by_email(realm.id(), email) else {
        state
            .identity
            .record_ip_login_attempt(realm.id(), &client_ip);
        return generic_error();
    };

    let password = CleartextPassword::from_string(form.password.clone());
    match state
        .identity
        .verify_password(realm.id(), user.id(), &password)
    {
        Ok(true) => {}
        Ok(false) => {
            state
                .identity
                .record_ip_login_attempt(realm.id(), &client_ip);
            return generic_error();
        }
        Err(e) => {
            tracing::warn!(error = %e, "login: password verification failed");
            state
                .identity
                .record_ip_login_attempt(realm.id(), &client_ip);
            return generic_error();
        }
    }

    // --- MFA gate ---
    let mfa_on = state
        .identity
        .mfa_enabled(realm.id(), user.id())
        .unwrap_or(false);
    let realm_requires_mfa = realm.config().mfa_required.unwrap_or(false);
    let secure = state.is_secure_request(&headers);
    if mfa_on {
        let cookie = issue_mfa_pending_cookie(
            &state.cookie_secret,
            realm.id(),
            user.id(),
            return_to.as_deref(),
            secure,
        );
        state.set_current_realm(realm.id().clone());
        // Return the login page with the inline TOTP section visible rather than
        // redirecting to /ui/mfa-challenge. The pending cookie still grants the
        // challenge handler proof of password validation.
        let mut tmpl = LoginTemplate::new(
            None,
            return_to.clone(),
            &action_prefix,
            show_register,
            locale,
            product_name.clone(),
            state.logo_url.clone(),
        );
        tmpl.show_totp = true;
        tmpl.email = email.to_string();
        tmpl.theme_css = state.theme_css.clone();
        tmpl.realm_theme_css.clone_from(&realm_theme);
        let mut response = render(&tmpl);
        append_cookie(&mut response, &cookie);
        return response;
    } else if realm_requires_mfa {
        // Realm mandates MFA but this user has none enrolled. Issue the same
        // pending cookie (proves identity) and redirect to forced enrollment.
        let cookie = issue_mfa_pending_cookie(
            &state.cookie_secret,
            realm.id(),
            user.id(),
            return_to.as_deref(),
            secure,
        );
        state.set_current_realm(realm.id().clone());
        let mut response = Redirect::to("/ui/mfa-enroll-required").into_response();
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
            } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id(), secure);

            state.set_current_realm(realm.id().clone());

            let location = return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), realm.id()),
                    secure,
                ),
            );
            response
        }
        Err(IdentityError::UserNotVerified) => {
            let mut tmpl = LoginTemplate::new(
                Some(
                    "Your email is not verified yet. Check your inbox (or the server \
                     logs) for the verification link and click it before signing in."
                        .to_string(),
                ),
                return_to.clone(),
                &action_prefix,
                show_register,
                locale,
                product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.email = email.to_string();
            tmpl.theme_css.clone_from(&state.theme_css);
            tmpl.realm_theme_css = realm_theme;
            render_status(&tmpl, StatusCode::FORBIDDEN)
        }
        Err(e) => {
            tracing::warn!(error = %e, "login: create_session failed");
            generic_error()
        }
    }
}

// ============================================================================
// Passkey (WebAuthn) login
// ============================================================================

/// `GET /ui/login/passkey-begin` — bare variant.
pub async fn passkey_login_begin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    passkey_login_begin_impl(state, headers, None)
}

/// `GET /ui/realms/<name>/login/passkey-begin` — realm-scoped variant.
pub async fn passkey_login_begin_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    passkey_login_begin_impl(state, headers, Some(realm_name))
}

/// `GET /ui/admin/login/passkey-begin` — admin variant. Forces the system
/// realm so admin sign-ins don't leak into a tenant realm's credential
/// store on multi-realm deployments.
pub async fn passkey_login_begin_admin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let realm = match resolve_admin_realm(&state) {
        PreAuthRealm::Ok { realm, .. } => realm,
        PreAuthRealm::Handled(_) => {
            return (StatusCode::BAD_REQUEST, "System realm unavailable").into_response();
        }
    };
    passkey_login_begin_with_realm(state, headers, realm)
}

/// Starts a discoverable credential authentication ceremony. The
/// challenge is created in the resolved realm; the store is realm-scoped
/// but `user_id=None` (discoverable flow) skips per-realm user lookup.
#[allow(clippy::needless_pass_by_value)]
fn passkey_login_begin_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    path_realm: Option<String>,
) -> Response {
    let realm = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok { realm, .. } => realm,
        PreAuthRealm::Handled(_) => {
            // JSON endpoint: picker HTML is not useful. Return 400.
            return (StatusCode::BAD_REQUEST, "Realm not resolvable").into_response();
        }
    };
    passkey_login_begin_with_realm(state, headers, realm)
}

/// Shared body of every passkey-begin handler once the target realm has
/// been resolved. Split out so the admin variant can force the system
/// realm without re-running the bare realm resolver.
#[allow(clippy::needless_pass_by_value)]
fn passkey_login_begin_with_realm(
    state: Arc<WebState>,
    headers: HeaderMap,
    realm: Realm,
) -> Response {
    use base64::Engine as _;

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

    let challenge = match state
        .identity
        .start_webauthn_authentication(realm.id(), None, &options)
    {
        Ok(c) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c),
        Err(e) => {
            tracing::error!(error = %e, "passkey-login-begin: start failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Unavailable").into_response();
        }
    };

    let user_verification = realm
        .config()
        .webauthn_user_verification
        .as_deref()
        .unwrap_or("preferred");

    let body = serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id,
        "userVerification": user_verification,
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

/// `POST /ui/login/passkey-complete` — bare variant.
pub async fn passkey_login_complete(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    passkey_login_complete_impl(state, headers, body, None)
}

/// `POST /ui/realms/<name>/login/passkey-complete` — realm-scoped variant.
pub async fn passkey_login_complete_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    passkey_login_complete_impl(state, headers, body, Some(realm_name))
}

/// `POST /ui/admin/login/passkey-complete` — admin variant. Routes the
/// assertion through the system realm rather than the default/sole
/// tenant realm.
pub async fn passkey_login_complete_admin(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyLoginCompleteBody>,
) -> Response {
    let system_realm_name = match resolve_admin_realm(&state) {
        PreAuthRealm::Ok { realm, .. } => realm.name().to_string(),
        PreAuthRealm::Handled(_) => {
            return (StatusCode::BAD_REQUEST, "System realm unavailable").into_response();
        }
    };
    passkey_login_complete_impl(state, headers, body, Some(system_realm_name))
}

/// Completes the discoverable credential authentication ceremony.
/// The realm is resolved via the standard pre-auth resolver — no
/// cross-realm walk. The `user_handle` from the assertion identifies
/// the user within the resolved realm.
#[allow(clippy::needless_pass_by_value)]
fn passkey_login_complete_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    body: PasskeyLoginCompleteBody,
    path_realm: Option<String>,
) -> Response {
    use base64::Engine as _;
    let mut session_ctx = build_session_context(&headers, FALLBACK_PEER, &state.trusted_proxies);
    // Passkeys are inherently multi-factor (possession + biometric/PIN), so they
    // satisfy any realm-level mfa_required policy without a separate TOTP gate.
    session_ctx.satisfies_mfa_via_passkey = true;

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

    // Parse the user handle into a UserId.
    let Some(ref uh_bytes) = user_handle_bytes else {
        tracing::warn!("passkey-login-complete: no user_handle in assertion");
        return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    };
    let user_id_result = std::str::from_utf8(uh_bytes)
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .or_else(|| uuid::Uuid::from_slice(uh_bytes).ok());
    let Some(uuid) = user_id_result else {
        tracing::warn!("passkey-login-complete: cannot parse user_handle as UUID");
        return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    };
    let user_id = crate::core::UserId::new(uuid);

    // Resolve realm. JSON endpoint — picker/400 HTML isn't useful; return 400.
    let realm = match resolve_pre_auth_realm(&state, path_realm, true) {
        PreAuthRealm::Ok { realm, .. } => realm,
        PreAuthRealm::Handled(_) => {
            return (StatusCode::BAD_REQUEST, "Realm not resolvable").into_response();
        }
    };

    // Confirm the user actually exists in the resolved realm.
    let exists = state
        .identity
        .get_user(realm.id(), &user_id)
        .ok()
        .flatten()
        .is_some();
    if !exists {
        tracing::warn!(user_id = %user_id, "passkey-login-complete: user not in resolved realm");
        return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response();
    }

    passkey_complete_for_user(
        &state,
        &realm,
        &user_id,
        &credential_id,
        &client_data_json,
        &authenticator_data,
        &signature,
        user_handle_bytes.as_ref(),
        &origin,
        &session_ctx,
        state.is_secure_request(&headers),
    )
}

/// Completes the `WebAuthn` authentication against the resolved realm
/// and creates a session. Extracted so the bare and scoped variants
/// share the same completion logic.
#[allow(clippy::too_many_arguments)]
fn passkey_complete_for_user(
    state: &Arc<WebState>,
    realm: &Realm,
    user_id: &crate::core::UserId,
    credential_id: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    user_handle_bytes: Option<&Vec<u8>>,
    origin: &str,
    session_ctx: &SessionContext,
    secure: bool,
) -> Response {
    let _ = user_id;

    // Enforce realm policy: passkey auth must be in the allow-list.
    if let Some(ref methods) = realm.config().allowed_auth_methods {
        if !methods.iter().any(|m| m == "passkey") {
            tracing::warn!(realm = %realm.id(), "passkey-login: blocked by realm policy");
            return (StatusCode::FORBIDDEN, "Authentication method not permitted").into_response();
        }
    }

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
                secure,
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
            } = issue_auth_cookies(&state.cookie_secret, realm.id(), session.id(), secure);

            state.set_current_realm(realm.id().clone());

            let mut response = axum::Json(serde_json::json!({
                "redirect": "/ui",
            }))
            .into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), realm.id()),
                    secure,
                ),
            );
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
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };

    let mut tmpl = MfaChallengeTemplate::new(
        None,
        state.product_name.clone(),
        state.logo_url.clone(),
        pending.return_to,
    );
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
    let return_to = pending.return_to.clone();
    let mfa_err = |msg: String, status: StatusCode| {
        let mut tmpl = MfaChallengeTemplate::new(
            Some(msg),
            product_name.clone(),
            logo_url.clone(),
            return_to.clone(),
        );
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
            let secure = state.is_secure_request(&headers);
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(
                &state.cookie_secret,
                &pending.realm_id,
                session.id(),
                secure,
            );

            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), &pending.realm_id),
                    secure,
                ),
            );
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
        None,
    );
    tmpl.theme_css = theme_css.to_string();
    render_status(&tmpl, StatusCode::UNAUTHORIZED)
}

// ============================================================================
// Forced MFA enrollment (realm policy: mfa_required = true)
// ============================================================================

/// Renders the forced MFA enrollment page.
///
/// Reached when a realm's `mfa_required` policy is enabled and the user has
/// no TOTP enrolled. Requires a valid MFA pending cookie (proves password was
/// verified). Initiates a fresh enrollment ceremony and shows the QR code and
/// recovery codes.
pub async fn mfa_enroll_required_form(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };

    let realm_id = pending.realm_id.clone();
    let user_id = pending.user_id.clone();
    let identity = state.identity.clone();
    let enroll_result =
        tokio::task::spawn_blocking(move || identity.enroll_totp(&realm_id, &user_id)).await;

    let enroll_result = match enroll_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "forced enroll_totp spawn_blocking panicked");
            Err(IdentityError::Storage(Box::new(e)))
        }
    };

    match enroll_result {
        Ok(enrollment) => {
            use super::account::generate_qr_svg;
            let qr_svg = generate_qr_svg(&enrollment.provisioning_uri);
            let mut tmpl = MfaEnrollRequiredTemplate::new(
                None,
                enrollment.secret_base32,
                enrollment.provisioning_uri,
                qr_svg,
                enrollment.recovery_codes.as_slice().to_vec(),
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.theme_css.clone_from(&state.theme_css);
            render(&tmpl)
        }
        Err(IdentityError::MfaAlreadyEnabled) => {
            // User somehow got here with MFA already set up — send to challenge.
            Redirect::to("/ui/mfa-challenge").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "forced enroll_totp failed");
            let mut tmpl = MfaEnrollRequiredTemplate::new(
                Some("Unable to start MFA enrollment. Please try signing in again.".to_string()),
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.theme_css.clone_from(&state.theme_css);
            render_status(&tmpl, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Form body for `POST /ui/mfa-enroll-required/activate`.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollRequiredForm {
    #[serde(default)]
    pub code: String,
}

/// Verifies the TOTP code during forced enrollment and completes the login.
///
/// Reads the MFA pending cookie, confirms the enrollment code, enables MFA,
/// then issues full session + CSRF cookies (same as a successful MFA challenge).
pub async fn mfa_enroll_required_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<MfaEnrollRequiredForm>,
) -> Response {
    let session_ctx = build_session_context(&headers, FALLBACK_PEER, &state.trusted_proxies);
    let Some(raw) = cookie_value_from_headers(&headers, MFA_PENDING_COOKIE) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(pending) = parse_mfa_pending_cookie(&state.cookie_secret, raw) else {
        return Redirect::to("/ui/login").into_response();
    };

    let realm_id = pending.realm_id.clone();
    let user_id = pending.user_id.clone();
    let code = form.code.trim().to_string();
    let identity = state.identity.clone();
    let verify_result = tokio::task::spawn_blocking(move || {
        identity.verify_totp_enrollment(&realm_id, &user_id, &code)
    })
    .await;

    let verify_result = match verify_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "forced verify_totp_enrollment panicked");
            Err(IdentityError::Storage(Box::new(e)))
        }
    };

    let err_response = |msg: &str| {
        let mut tmpl = MfaEnrollRequiredTemplate::new(
            Some(msg.to_string()),
            String::new(),
            String::new(),
            String::new(),
            Vec::new(),
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&state.theme_css);
        render_status(&tmpl, StatusCode::UNPROCESSABLE_ENTITY)
    };

    match verify_result {
        Ok(()) => {}
        Err(IdentityError::InvalidMfaCode) => {
            return err_response("Invalid code. Please re-scan the QR code and try again.");
        }
        Err(IdentityError::MfaNotEnabled) => {
            return Redirect::to("/ui/mfa-enroll-required").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "forced verify_totp_enrollment failed");
            return err_response("Unable to activate MFA right now. Please try again.");
        }
    }

    // Enrollment confirmed — complete login.
    let secure = state.is_secure_request(&headers);
    match state
        .identity
        .create_session(&pending.realm_id, &pending.user_id, &session_ctx)
    {
        Ok(session) => {
            let IssuedCookies {
                session_cookie,
                csrf_cookie,
            } = issue_auth_cookies(
                &state.cookie_secret,
                &pending.realm_id,
                session.id(),
                secure,
            );

            let location = pending.return_to.as_deref().unwrap_or("/ui");
            let mut response = Redirect::to(location).into_response();
            append_cookie(&mut response, &session_cookie);
            append_cookie(&mut response, &csrf_cookie);
            append_cookie(&mut response, &clear_mfa_pending_cookie(secure));
            append_cookie(
                &mut response,
                &super::auth::last_realm_cookie(
                    &super::auth::last_realm_value(state.identity.as_ref(), &pending.realm_id),
                    secure,
                ),
            );
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "forced enrollment: create_session failed");
            internal_error_response()
        }
    }
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

    // Aggregate entity counts across the system realm + every tenant
    // realm so the dashboard cards reflect the operator's full scope —
    // not just the realm the admin happens to be signed into.
    //
    // The 2026-04-29 UX audit caught the legacy single-realm count
    // showing "Organizations 0" while a tenant realm clearly held one;
    // the cards are global by definition (they link to global list
    // pages), so the counts must be too. Failures fall through silently
    // — partial counts are better than a 500 on a stat card.
    let (user_count, realm_count, app_count, org_count) = if is_admin {
        let realm_count = state
            .identity
            .list_realms(None, 10_000)
            .map(|p| p.items.len())
            .unwrap_or(0);

        let system_id = crate::identity::keys::system_realm_id();
        let mut user_count = 0;
        let mut app_count = 0;
        let mut org_count = 0;

        // System realm — operators only.
        user_count += state
            .identity
            .list_users(&system_id, None, 10_000)
            .map(|p| p.items.len())
            .unwrap_or(0);

        // Tenant realms — sum users / clients / orgs from each.
        if let Ok(realms_page) = state.identity.list_realms(None, 10_000) {
            for realm in realms_page.items {
                user_count += state
                    .identity
                    .list_users(realm.id(), None, 10_000)
                    .map(|p| p.items.len())
                    .unwrap_or(0);
                app_count += state
                    .identity
                    .list_clients(realm.id(), None, 10_000)
                    .map(|p| p.items.len())
                    .unwrap_or(0);
                org_count += state
                    .identity
                    .list_organizations(realm.id(), None, 10_000)
                    .map(|p| p.items.len())
                    .unwrap_or(0);
            }
        }

        (user_count, realm_count, app_count, org_count)
    } else {
        (0, 0, 0, 0)
    };

    let greeting_name = greeting_name_for(&session);

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
        greeting_name,
    })
}

/// Picks the friendliest available name for the dashboard greeting:
/// a non-empty display name, otherwise the local part of the email.
/// Falls back to the literal email address when the local part is also
/// empty (which validation should prevent, but we are defensive).
fn greeting_name_for(session: &super::auth::UiSession) -> String {
    let display = session.user_display_name.trim();
    if !display.is_empty() && display != session.user_email {
        return display.to_string();
    }
    session
        .user_email
        .split_once('@')
        .map(|(local, _)| local)
        .filter(|s| !s.is_empty())
        .unwrap_or(&session.user_email)
        .to_string()
}

/// Returns `true` iff the signed-in user has the `hearth.admin` permission.
/// Non-fatal on RBAC errors — the caller treats those as "not admin" so
/// the UI degrades gracefully.
pub(crate) fn is_admin(state: &WebState, session: &super::auth::UiSession) -> bool {
    match state
        .rbac
        .resolve_permissions(&session.user_id, &session.realm_id, None, None)
    {
        Ok(resolved) => resolved
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin"),
        Err(_) => false,
    }
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
    headers: axum::http::HeaderMap,
    session: super::auth::UiSession,
    Form(form): Form<LogoutForm>,
) -> Response {
    if let Err(resp) = super::auth::verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let secure = state.is_secure_request(&headers);

    // Resolve the realm *before* revoking — the session record is about
    // to disappear. System-realm sessions route back to /ui/admin/login;
    // tenant sessions route back to /ui/realms/{name}/login.
    let redirect_realm: Option<String> =
        if session.realm_id == crate::identity::keys::system_realm_id() {
            Some(super::auth::SYSTEM_REALM_SENTINEL.to_string())
        } else {
            // Look up the realm name. If the lookup fails for any
            // reason (deleted mid-session, engine error) we fall back to
            // the last-realm cookie, which we refresh below.
            state
                .identity
                .get_realm(&session.realm_id)
                .ok()
                .flatten()
                .map(|r| r.name().to_string())
        };

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

    let login_url = super::auth::login_url_for_realm(redirect_realm.as_deref());
    let mut response = Redirect::to(&login_url).into_response();
    for cookie in super::auth::clearing_cookies(secure) {
        append_cookie(&mut response, &cookie);
    }
    // Refresh the last-realm cookie so the user returns here on the
    // next unauthenticated request even if they clear other cookies.
    if let Some(ref name) = redirect_realm {
        append_cookie(&mut response, &super::auth::last_realm_cookie(name, secure));
    }
    response
}

// ============================================================================
// Helpers
// ============================================================================

/// Appends a `Set-Cookie` header without overwriting existing ones.
pub(super) fn append_cookie(response: &mut Response, value: &str) {
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

/// Returns the base URL for security-sensitive email links.
///
/// Security invariant: this must not trust request-controlled headers
/// (`Host`, `X-Forwarded-Proto`, etc.), to prevent link poisoning.
/// Uses configured `onboarding.base_url` when present, otherwise the
/// local fallback `http://localhost`.
fn derive_base_url(configured_base_url: Option<&str>, _headers: &HeaderMap) -> String {
    configured_base_url
        .unwrap_or("http://localhost")
        .trim_end_matches('/')
        .to_string()
}

const DEFAULT_LOGIN_LOCALE: &str = "en";

#[derive(Clone, Copy)]
struct LoginLocaleText {
    heading_text: &'static str,
    email_label: &'static str,
    password_label: &'static str,
    submit_label: &'static str,
    or_continue_with_label: &'static str,
    or_label: &'static str,
    sign_in_with_label: &'static str,
    forgot_password_label: &'static str,
    create_account_label: &'static str,
    passkey_sign_in_label: &'static str,
    passkey_authenticating_label: &'static str,
    passkey_unavailable_error: &'static str,
    passkey_cancelled_error: &'static str,
    passkey_failed_error: &'static str,
}

const LOGIN_LOCALE_EN: LoginLocaleText = LoginLocaleText {
    heading_text: "Sign in to your account",
    email_label: "Email",
    password_label: "Password",
    submit_label: "Sign in",
    or_continue_with_label: "or continue with",
    or_label: "or",
    sign_in_with_label: "Sign in with",
    forgot_password_label: "Forgot password?",
    create_account_label: "Create account",
    passkey_sign_in_label: "Sign in with passkey",
    passkey_authenticating_label: "Authenticating…",
    passkey_unavailable_error: "Passkey authentication is not available.",
    passkey_cancelled_error: "Authentication was cancelled.",
    passkey_failed_error: "Passkey authentication failed.",
};

const LOGIN_LOCALE_ES: LoginLocaleText = LoginLocaleText {
    heading_text: "Inicia sesión en tu cuenta",
    email_label: "Correo electrónico",
    password_label: "Contraseña",
    submit_label: "Iniciar sesión",
    or_continue_with_label: "o continúa con",
    or_label: "o",
    sign_in_with_label: "Iniciar sesión con",
    forgot_password_label: "¿Olvidaste tu contraseña?",
    create_account_label: "Crear cuenta",
    passkey_sign_in_label: "Iniciar sesión con passkey",
    passkey_authenticating_label: "Autenticando…",
    passkey_unavailable_error: "La autenticación con passkey no está disponible.",
    passkey_cancelled_error: "La autenticación fue cancelada.",
    passkey_failed_error: "La autenticación con passkey falló.",
};

fn login_locale_text(locale: &str) -> LoginLocaleText {
    if locale == "es" {
        LOGIN_LOCALE_ES
    } else {
        LOGIN_LOCALE_EN
    }
}

fn resolve_login_locale(requested: Option<&str>, accept_language: Option<&str>) -> &'static str {
    if let Some(locale) = requested.and_then(normalize_login_locale) {
        return locale;
    }

    if let Some(header) = accept_language {
        for candidate in header.split(',') {
            if let Some(locale) = normalize_login_locale(candidate) {
                return locale;
            }
        }
    }

    DEFAULT_LOGIN_LOCALE
}

fn normalize_login_locale(input: &str) -> Option<&'static str> {
    let raw = input.trim().split(';').next()?.trim();
    if raw.is_empty() {
        return None;
    }

    let normalized = raw.to_ascii_lowercase().replace('_', "-");
    if normalized == "es" || normalized.starts_with("es-") {
        return Some("es");
    }
    if normalized == "en" || normalized.starts_with("en-") {
        return Some("en");
    }

    None
}

fn with_locale_query(path: &str, locale: &str) -> String {
    if locale == DEFAULT_LOGIN_LOCALE {
        return path.to_string();
    }
    let encoded = form_urlencoded::byte_serialize(locale.as_bytes()).collect::<String>();
    format!("{path}?locale={encoded}")
}

// ============================================================================
// Password reset flow
// ============================================================================

/// Forgot-password form template.
#[derive(Template)]
#[template(path = "ui/forgot_password.html")]
struct ForgotPasswordTemplate {
    error: Option<String>,
    form_action: String,
    login_url: String,
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
    fn new(
        error: Option<String>,
        action_prefix: &str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            error,
            form_action: format!("{action_prefix}/forgot-password"),
            login_url: format!("{action_prefix}/login"),
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
    login_url: String,
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
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
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
    form_action: String,
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
    fn new(
        token: String,
        error: Option<String>,
        action_prefix: &str,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            token,
            error,
            form_action: format!("{action_prefix}/reset-password"),
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
    login_url: String,
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
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
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

/// Renders the forgot-password form at the bare URL.
pub async fn forgot_password_form(State(state): State<Arc<WebState>>) -> Response {
    forgot_password_form_impl(state, None)
}

/// Renders the forgot-password form under `/ui/realms/<name>/forgot-password`.
pub async fn forgot_password_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    forgot_password_form_impl(state, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value)]
fn forgot_password_form_impl(state: Arc<WebState>, path_realm: Option<String>) -> Response {
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let mut tmpl = ForgotPasswordTemplate::new(
        None,
        &action_prefix,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css_for(realm.id());
    render(&tmpl)
}

/// Form data for forgot-password submission.
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordForm {
    /// The email address for the password reset.
    pub email: String,
}

/// Handles forgot-password form submission at the bare URL.
pub async fn forgot_password_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    forgot_password_submit_impl(state, headers, form, None)
}

/// Handles forgot-password form submission at `/ui/realms/<name>/forgot-password`.
pub async fn forgot_password_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    forgot_password_submit_impl(state, headers, form, Some(realm_name))
}

/// Shared implementation. Looks up the user in the resolved realm.
/// Always redirects to the "check your email" page regardless of outcome
/// (enumeration resistance).
#[allow(clippy::needless_pass_by_value)]
fn forgot_password_submit_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: ForgotPasswordForm,
    path_realm: Option<String>,
) -> Response {
    let email = form.email.trim();
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let sent_url = format!("{action_prefix}/forgot-password/sent");

    match state.identity.request_password_reset(realm.id(), email) {
        Ok(Some(token)) => {
            let base = derive_base_url(
                state
                    .config
                    .as_ref()
                    .and_then(|c| c.onboarding.base_url.as_deref()),
                &headers,
            );
            let reset_url = format!("{base}{action_prefix}/reset-password?token={token}");
            if let Some(ref email_service) = state.email {
                let realm_branding = realm.config().email_branding.clone();
                let stored = realm
                    .config()
                    .email_templates
                    .get("password_reset")
                    .cloned();
                if let Err(e) = email_service.send_password_reset_email(
                    email,
                    &reset_url,
                    realm_branding.as_ref(),
                    stored.as_ref(),
                    None,
                ) {
                    tracing::warn!(error = %e, "forgot_password: failed to send email");
                }
            } else {
                tracing::warn!(reset_url = %reset_url, "password reset URL (no email transport configured)");
            }
        }
        Ok(None) | Err(IdentityError::RateLimited) => {
            // Unknown email or rate-limited — silent success.
        }
        Err(e) => {
            tracing::warn!(error = %e, "forgot_password: error requesting reset");
        }
    }

    Redirect::to(&sent_url).into_response()
}

/// Renders the "check your email" confirmation page at the bare URL.
pub async fn forgot_password_sent(State(state): State<Arc<WebState>>) -> Response {
    forgot_password_sent_impl(state, None)
}

/// Realm-scoped variant of the forgot-password "sent" page.
pub async fn forgot_password_sent_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    forgot_password_sent_impl(state, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value)]
fn forgot_password_sent_impl(state: Arc<WebState>, path_realm: Option<String>) -> Response {
    let action_prefix = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok { action_prefix, .. } => action_prefix,
        PreAuthRealm::Handled(resp) => return resp,
    };
    let mut tmpl = ForgotPasswordSentTemplate::new(
        format!("{action_prefix}/login"),
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

/// Query parameters for the reset-password page.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordQuery {
    /// The plaintext token from the password reset email.
    pub token: Option<String>,
}

/// Renders the reset-password form at the bare URL.
pub async fn reset_password_form(
    State(state): State<Arc<WebState>>,
    Query(query): Query<ResetPasswordQuery>,
) -> Response {
    reset_password_form_impl(state, query, None)
}

/// Renders the reset-password form at `/ui/realms/<name>/reset-password`.
pub async fn reset_password_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    Query(query): Query<ResetPasswordQuery>,
) -> Response {
    reset_password_form_impl(state, query, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value)]
fn reset_password_form_impl(
    state: Arc<WebState>,
    query: ResetPasswordQuery,
    path_realm: Option<String>,
) -> Response {
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let realm_theme = state.realm_theme_css_for(realm.id());
    if let Some(token) = query.token {
        let mut tmpl =
            ResetPasswordTemplate::new(token, None, &action_prefix, product_name, logo_url);
        tmpl.theme_css.clone_from(&state.theme_css);
        tmpl.realm_theme_css = realm_theme;
        render(&tmpl)
    } else {
        let mut tmpl = ResetPasswordTemplate::new(
            String::new(),
            Some("Missing or invalid reset link.".to_string()),
            &action_prefix,
            product_name,
            logo_url,
        );
        tmpl.theme_css.clone_from(&state.theme_css);
        tmpl.realm_theme_css = realm_theme;
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

/// Handles reset-password form submission at the bare URL.
pub async fn reset_password_submit(
    State(state): State<Arc<WebState>>,
    Form(form): Form<ResetPasswordFormData>,
) -> Response {
    reset_password_submit_impl(state, form, None)
}

/// Handles reset-password form submission at `/ui/realms/<name>/reset-password`.
pub async fn reset_password_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    Form(form): Form<ResetPasswordFormData>,
) -> Response {
    reset_password_submit_impl(state, form, Some(realm_name))
}

/// Shared implementation — validates the token against the resolved
/// realm only, no walk.
#[allow(clippy::needless_pass_by_value)]
fn reset_password_submit_impl(
    state: Arc<WebState>,
    form: ResetPasswordFormData,
    path_realm: Option<String>,
) -> Response {
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let realm_theme = state.realm_theme_css_for(realm.id());

    let reset_err = |token: String, msg: String| {
        let mut tmpl = ResetPasswordTemplate::new(
            token,
            Some(msg),
            &action_prefix,
            product_name.clone(),
            logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&theme_css);
        tmpl.realm_theme_css.clone_from(&realm_theme);
        render(&tmpl)
    };

    if form.password != form.password_confirm {
        return reset_err(form.token, "Passwords do not match.".to_string());
    }

    if form.password.len() < 8 {
        return reset_err(
            form.token,
            "Password must be at least 8 characters.".to_string(),
        );
    }

    let password = CleartextPassword::from_string(form.password);

    match state
        .identity
        .reset_password_with_token(realm.id(), &form.token, &password)
    {
        Ok(_user_id) => {
            let login_url = format!("{action_prefix}/login");
            let mut tmpl = ResetPasswordOkTemplate::new(login_url, product_name, logo_url);
            tmpl.theme_css.clone_from(&state.theme_css);
            tmpl.realm_theme_css.clone_from(&realm_theme);
            render(&tmpl)
        }
        Err(IdentityError::PasswordResetTokenInvalid) => reset_err(
            String::new(),
            "This reset link is invalid or has expired. Please request a new one.".to_string(),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "reset_password: error resetting password");
            reset_err(
                form.token,
                "Failed to reset password. Please try again.".to_string(),
            )
        }
    }
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
    /// URL the form POSTs to — `/ui/register` for bare routes,
    /// `/ui/realms/<name>/register` for the realm-scoped route.
    form_action: String,
    /// URL for the "Sign in" link at the bottom of the form.
    login_url: String,
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
    #[allow(clippy::too_many_arguments)]
    fn new(
        disabled: bool,
        invite_only: bool,
        email_prefill: String,
        error: Option<String>,
        form_action: String,
        login_url: String,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            disabled,
            invite_only,
            email_prefill,
            error,
            form_action,
            login_url,
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
    login_url: String,
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
    fn new(login_url: String, product_name: String, logo_url: String) -> Self {
        Self {
            login_url,
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
    /// Display name (optional — synthesized from first/last if empty).
    #[serde(default)]
    pub display_name: String,
    /// First (given) name.
    #[serde(default)]
    pub first_name: String,
    /// Last (family) name.
    #[serde(default)]
    pub last_name: String,
    /// New password.
    pub password: String,
    /// Password confirmation.
    pub password_confirm: String,
    /// Optional invitation token (required when policy is invite-only).
    #[serde(default)]
    pub invitation_token: Option<String>,
}

/// Returns `(disabled, invite_only)` flags derived from the realm's
/// registration policy.
fn registration_policy_flags(realm: &Realm) -> (bool, bool) {
    match realm.config().registration_policy.clone() {
        None | Some(crate::identity::RegistrationPolicy::Disabled) => (true, false),
        Some(crate::identity::RegistrationPolicy::InviteOnly) => (false, true),
        Some(_) => (false, false),
    }
}

/// Returns `true` when self-registration is enabled for the realm, i.e.
/// the policy is anything other than `None` / `Disabled`. Used by the
/// login page to decide whether to show the "Create account" link at all
/// — hiding it on disabled realms avoids advertising a URL that would
/// only show "Registration unavailable".
fn registration_enabled(realm: &Realm) -> bool {
    !registration_policy_flags(realm).0
}

/// Renders the registration form for the bare `/ui/register` URL.
pub async fn register_form(State(state): State<Arc<WebState>>) -> Response {
    register_form_impl(state, None)
}

/// Renders the registration form under `/ui/realms/<name>/register`.
pub async fn register_form_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    register_form_impl(state, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value)]
fn register_form_impl(state: Arc<WebState>, path_realm: Option<String>) -> Response {
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let (disabled, invite_only) = registration_policy_flags(&realm);
    let form_action = format!("{action_prefix}/register");
    let login_url = format!("{action_prefix}/login");
    let mut tmpl = RegisterTemplate::new(
        disabled,
        invite_only,
        String::new(),
        None,
        form_action,
        login_url,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css_for(realm.id());
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

/// Handles registration form submission (bare `/ui/register`).
pub async fn register_submit(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    register_submit_impl(state, headers, form, None)
}

/// Handles registration form submission for `/ui/realms/<name>/register`.
pub async fn register_submit_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    register_submit_impl(state, headers, form, Some(realm_name))
}

/// Shared implementation for bare and realm-scoped register submits.
///
/// On success, creates a `PendingVerification` user, issues a verification
/// token, emails it, and redirects to the scope's `register/sent` page.
/// Duplicate emails are handled at the engine layer with a fake-success
/// response so we never see an error on that path — preserving
/// enumeration resistance.
#[allow(clippy::needless_pass_by_value)]
fn register_submit_impl(
    state: Arc<WebState>,
    headers: HeaderMap,
    form: RegisterForm,
    path_realm: Option<String>,
) -> Response {
    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, true) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };

    let product_name = state.product_name.clone();
    let logo_url = state.logo_url.clone();
    let theme_css = state.theme_css.clone();
    let realm_theme = state.realm_theme_css_for(realm.id());
    let (disabled, invite_only) = registration_policy_flags(&realm);
    let form_action = format!("{action_prefix}/register");
    let login_url = format!("{action_prefix}/login");
    let sent_url = format!("{action_prefix}/register/sent");

    let render_err = |msg: String, email: String| {
        let mut tmpl = RegisterTemplate::new(
            disabled,
            invite_only,
            email,
            Some(msg),
            form_action.clone(),
            login_url.clone(),
            product_name.clone(),
            logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&theme_css);
        tmpl.realm_theme_css.clone_from(&realm_theme);
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

    let request = crate::identity::RegisterUserRequest {
        email: form.email.clone(),
        display_name: form.display_name.clone(),
        first_name: form.first_name.clone(),
        last_name: form.last_name.clone(),
        password: CleartextPassword::from_string(form.password.clone()),
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
        let base = derive_base_url(
            state
                .config
                .as_ref()
                .and_then(|c| c.onboarding.base_url.as_deref()),
            &headers,
        );
        let verify_url = format!(
            "{base}{action_prefix}/verify-email?token={}",
            response.verification_token
        );
        let branding = realm.config().email_branding.clone();
        let stored_verification = realm.config().email_templates.get("verification").cloned();
        if let Err(e) = email_service.send_verification_email(
            &form.email,
            &verify_url,
            branding.as_ref(),
            stored_verification.as_ref(),
            None,
        ) {
            tracing::warn!(error = %e, "register_submit: failed to send verification email");
        }
    } else {
        tracing::warn!(
            "register_submit: no email transport configured; verification cannot be delivered"
        );
    }

    Redirect::to(&sent_url).into_response()
}

/// Renders the post-submission confirmation page for the bare URL.
pub async fn register_sent(State(state): State<Arc<WebState>>) -> Response {
    register_sent_impl(state, None)
}

/// Renders the post-submission confirmation page for a realm-scoped URL.
pub async fn register_sent_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
) -> Response {
    register_sent_impl(state, Some(realm_name))
}

#[allow(clippy::needless_pass_by_value)]
fn register_sent_impl(state: Arc<WebState>, path_realm: Option<String>) -> Response {
    let action_prefix = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok { action_prefix, .. } => action_prefix,
        PreAuthRealm::Handled(resp) => return resp,
    };
    let mut tmpl = RegisterSentTemplate::new(
        format!("{action_prefix}/login"),
        state.product_name.clone(),
        state.logo_url.clone(),
    );
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
// Pre-auth realm resolution wrapper
// ============================================================================

/// Terse 400 page shown when a bare `/ui/*` URL can't resolve a realm
/// on a multi-realm deployment with no `default_realm` configured.
///
/// Deliberately lists no realm names — presenting a picker would leak
/// the tenant inventory to anonymous visitors. Users who need to sign
/// in should be handed a specific `/ui/realms/<name>/...` URL by their
/// administrator (email, docs, internal portal).
#[derive(Template)]
#[template(path = "ui/realm_required.html")]
struct RealmRequiredTemplate {
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

impl RealmRequiredTemplate {
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

/// Which realm-resolution strategy a pre-auth handler should use.
///
/// Most handlers are shared between the bare `/ui/*` routes, the
/// path-scoped `/ui/realms/<name>/*` routes, AND the admin-surface
/// `/ui/admin/*` routes. This enum lets them dispatch without
/// duplicating the template-render and form-submit logic.
#[derive(Debug)]
pub(super) enum RealmSource {
    /// Bare or path-scoped tenant route. `Option<String>` is the
    /// realm name from the URL path, if any.
    Path(Option<String>),
    /// Admin surface (`/ui/admin/*`). Always resolves to the system
    /// realm with `action_prefix = "/ui/admin"`.
    Admin,
}

/// Unified entry point that dispatches to the right resolver based on
/// the `RealmSource`.
pub(super) fn resolve_for_source(
    state: &WebState,
    source: RealmSource,
    is_mutation: bool,
) -> PreAuthRealm {
    match source {
        RealmSource::Path(path_realm) => resolve_pre_auth_realm(state, path_realm, is_mutation),
        RealmSource::Admin => resolve_admin_realm(state),
    }
}

/// Outcome of [`resolve_pre_auth_realm`].
///
/// Size-difference lint suppressed: the `Ok` variant is the common case
/// and boxing it would add an indirection on every pre-auth request.
/// The `Handled` variant carries an `axum::Response` exactly once and
/// is returned directly; the outer size is dominated by it either way.
#[allow(clippy::large_enum_variant)]
pub(super) enum PreAuthRealm {
    /// Realm resolved. `action_prefix` is the URL prefix that form `action`
    /// attributes should use — either `/ui` for bare routes or
    /// `/ui/realms/<name>` for path-scoped ones.
    Ok { realm: Realm, action_prefix: String },
    /// A response has already been constructed (picker, 404, 400, 500).
    /// Callers return it directly without touching any realm-scoped state.
    Handled(Response),
}

/// Resolves the realm for a pre-auth request and produces either a
/// usable `Realm` or the complete response the caller should return.
///
/// * `path_realm` — `Some(<name>)` when the request came in under
///   `/ui/realms/<name>/...`; `None` for bare `/ui/...` URLs.
/// * `is_mutation` — POST/PUT/DELETE handlers set `true`; on an
///   unresolvable multi-realm request they return 400 (a picker would
///   lose the form state anyway).
#[allow(clippy::needless_pass_by_value)]
pub(super) fn resolve_pre_auth_realm(
    state: &WebState,
    path_realm: Option<String>,
    is_mutation: bool,
) -> PreAuthRealm {
    let path_realm_present = path_realm.is_some();
    match realm_resolver::resolve(state, path_realm.as_deref()) {
        Resolved::Realm(realm) => {
            // Form actions and sibling links always need a leading "/ui".
            // When the request came in with an explicit realm segment, we
            // preserve it; otherwise the bare `/ui` prefix lets callers
            // construct URLs like `{prefix}/login` and `{prefix}/register`
            // without special-casing the empty string.
            let action_prefix = if path_realm_present {
                format!("/ui/realms/{}", realm.name())
            } else {
                "/ui".to_string()
            };
            PreAuthRealm::Ok {
                realm,
                action_prefix,
            }
        }
        Resolved::NotFound => PreAuthRealm::Handled(not_found_response("Realm not found.")),
        Resolved::MustChoose(_realms) => {
            // Same terse 400 for GET and POST. Intentionally ignores
            // `is_mutation` and the realm list — enumerating realms to
            // anonymous callers is the bug we're avoiding.
            let _ = is_mutation;
            PreAuthRealm::Handled(realm_required_response(state))
        }
        Resolved::Storage => PreAuthRealm::Handled(internal_error_response()),
    }
}

/// Resolves the admin (system) realm for `/ui/admin/*` pre-auth
/// routes. The system realm is auto-seeded at engine construction, so
/// this should always succeed; a missing system realm indicates a
/// broken installation and we return 500.
///
/// Returns `PreAuthRealm::Ok { action_prefix: "/ui/admin" }` so all
/// admin-surface forms and sibling links stay on the admin URL space,
/// never leaking the reserved realm name or falling through to the
/// tenant resolver.
pub(super) fn resolve_admin_realm(state: &WebState) -> PreAuthRealm {
    let system = crate::identity::keys::system_realm_id();
    match state.identity.get_realm(&system) {
        Ok(Some(realm)) => PreAuthRealm::Ok {
            realm,
            action_prefix: "/ui/admin".to_string(),
        },
        Ok(None) => {
            tracing::error!(
                "admin realm missing from storage — system realm seeding failed at startup"
            );
            PreAuthRealm::Handled(internal_error_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "admin realm lookup failed");
            PreAuthRealm::Handled(internal_error_response())
        }
    }
}

/// Renders the terse "explicit realm URL required" 400 page. Lists no
/// realm names. Shown on multi-realm deployments when a bare `/ui/*`
/// URL is hit without `server.default_realm` configured.
fn realm_required_response(state: &WebState) -> Response {
    let mut tmpl = RealmRequiredTemplate::new(state.product_name.clone(), state.logo_url.clone());
    tmpl.theme_css.clone_from(&state.theme_css);
    render_status(&tmpl, StatusCode::BAD_REQUEST)
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
    login_url: String,
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

/// `GET /ui/accept-invitation?token=...` — bare URL variant.
pub async fn accept_invitation_page(
    State(state): State<Arc<WebState>>,
    Query(params): Query<AcceptInvitationParams>,
) -> Response {
    accept_invitation_page_impl(state, params, None)
}

/// `GET /ui/realms/<name>/accept-invitation?token=...` — realm-scoped variant.
pub async fn accept_invitation_page_scoped(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    Query(params): Query<AcceptInvitationParams>,
) -> Response {
    accept_invitation_page_impl(state, params, Some(realm_name))
}

/// Accepts an organization invitation against the resolved realm only.
#[allow(clippy::needless_pass_by_value)]
fn accept_invitation_page_impl(
    state: Arc<WebState>,
    params: AcceptInvitationParams,
    path_realm: Option<String>,
) -> Response {
    let render_result = |success: bool,
                         org_name: String,
                         error_message: String,
                         login_url: String,
                         realm_theme: Option<String>| {
        render(&AcceptInvitationTemplate {
            success,
            org_name,
            error_message,
            login_url,
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
            realm_theme_css: realm_theme,
        })
    };

    let (realm, action_prefix) = match resolve_pre_auth_realm(&state, path_realm, false) {
        PreAuthRealm::Ok {
            realm,
            action_prefix,
        } => (realm, action_prefix),
        PreAuthRealm::Handled(resp) => return resp,
    };
    let realm_theme = state.realm_theme_css_for(realm.id());
    let login_url = format!("{action_prefix}/login");

    let token = match &params.token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            return render_result(
                false,
                String::new(),
                "No invitation token provided.".to_string(),
                login_url,
                realm_theme,
            );
        }
    };

    match state.identity.accept_invitation(realm.id(), token) {
        Ok(membership) => {
            let org_name = state
                .identity
                .get_organization(realm.id(), membership.org_id())
                .ok()
                .flatten()
                .map_or_else(|| "the organization".to_string(), |o| o.name().to_string());
            render_result(true, org_name, String::new(), login_url, realm_theme)
        }
        Err(_) => render_result(
            false,
            String::new(),
            "This invitation has expired or is invalid.".to_string(),
            login_url,
            realm_theme,
        ),
    }
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
    fn derive_base_url_uses_configured_origin() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            "auth.example.com:8420".parse().expect("valid header"),
        );
        h.insert("x-forwarded-proto", "https".parse().expect("valid header"));
        assert_eq!(
            derive_base_url(Some("https://canonical.example.com"), &h),
            "https://canonical.example.com"
        );
    }

    #[test]
    fn derive_base_url_ignores_host_and_forwarded_proto_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            header::HOST,
            "attacker.example".parse().expect("valid header"),
        );
        h.insert("x-forwarded-proto", "https".parse().expect("valid header"));
        assert_eq!(
            derive_base_url(Some("https://auth.example.com"), &h),
            "https://auth.example.com"
        );
    }

    #[test]
    fn derive_base_url_falls_back_without_host() {
        let h = HeaderMap::new();
        assert_eq!(derive_base_url(None, &h), "http://localhost");
    }

    #[test]
    fn derive_base_url_trims_trailing_slash() {
        let h = HeaderMap::new();
        assert_eq!(
            derive_base_url(Some("https://auth.example.com/"), &h),
            "https://auth.example.com"
        );
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
