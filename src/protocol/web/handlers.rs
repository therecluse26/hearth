//! Axum handlers for the `/ui/*` routes.
//!
//! Inline HTML only — the real template layer lands in the Phase 1.6
//! Admin UI plan. Keep business logic out of this module; every state
//! transition must go through `OnboardingService` or `IdentityEngine`.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::identity::onboarding::OnboardingError;
use crate::identity::{CleartextPassword, IdentityError};

use super::WebState;

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

    Html(render_setup_form(token, None)).into_response()
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
        return Html(render_setup_form(&form.token, Some(&msg)))
            .into_response()
            .with_status(StatusCode::BAD_REQUEST);
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
        Ok(_) => Redirect::to("/ui/setup/sent").into_response(),
        Err(OnboardingError::AlreadyConfigured) => {
            not_found_response("Setup page is not available.")
        }
        Err(OnboardingError::Identity(IdentityError::DuplicateEmail)) => {
            let msg = "An account with that email already exists in this system.";
            Html(render_setup_form(&form.token, Some(msg)))
                .into_response()
                .with_status(StatusCode::CONFLICT)
        }
        Err(OnboardingError::Identity(IdentityError::DuplicateTenantName)) => {
            let msg = "A tenant with that name already exists. Retry with a different name.";
            Html(render_setup_form(&form.token, Some(msg)))
                .into_response()
                .with_status(StatusCode::CONFLICT)
        }
        Err(OnboardingError::Identity(IdentityError::InvalidInput { reason })) => {
            let msg = format!("Invalid input: {reason}");
            Html(render_setup_form(&form.token, Some(&msg)))
                .into_response()
                .with_status(StatusCode::BAD_REQUEST)
        }
        Err(OnboardingError::Email(e)) => {
            tracing::error!(error = %e, "setup: failed to send verification email");
            let msg =
                "The account was created but the verification email could not be sent. Check \
                the server logs for the verification link, or retry after fixing the email \
                transport.";
            Html(render_setup_form(&form.token, Some(msg)))
                .into_response()
                .with_status(StatusCode::BAD_GATEWAY)
        }
        Err(e) => {
            tracing::error!(error = %e, "setup: unexpected failure");
            internal_error_response()
        }
    }
}

/// Renders the "setup submitted" confirmation page.
pub async fn setup_sent() -> Html<String> {
    Html(wrap_page(
        "Check your email",
        r#"
        <h1>Almost done</h1>
        <p>We sent a verification link to the email address you just entered.
        Click the link to activate your account, then sign in.</p>
        <p><em>Running without an SMTP server?</em> The verification URL was written to
        the Hearth server logs at <code>WARN</code> level — look for a line containing
        <code>verification_url</code>.</p>
        <p><a href="/ui/login">Go to sign-in</a></p>
        "#,
    ))
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
        return Html(wrap_page(
            "Verification link invalid",
            "<h1>Invalid link</h1><p>This verification link is missing or malformed.</p>",
        ))
        .into_response()
        .with_status(StatusCode::BAD_REQUEST);
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
                return Html(wrap_page(
                    "Email verified",
                    r#"
                    <h1>Email verified</h1>
                    <p>Your account is now active. You can sign in.</p>
                    <p><a href="/ui/login">Sign in</a></p>
                    "#,
                ))
                .into_response();
            }
            Err(IdentityError::VerificationTokenInvalid) => {}
            Err(e) => {
                tracing::error!(error = %e, "verify-email: unexpected failure");
                return internal_error_response();
            }
        }
    }

    Html(wrap_page(
        "Verification link invalid",
        "
        <h1>Link expired or already used</h1>
        <p>This verification link is no longer valid. Request a new verification
        email from the sign-in page once it becomes available.</p>
        ",
    ))
    .into_response()
    .with_status(StatusCode::GONE)
}

// ============================================================================
// Login (placeholder — full UI arrives in Phase 1.6)
// ============================================================================

/// Renders the login form.
pub async fn login_form() -> Html<String> {
    Html(render_login_form(None))
}

/// Credentials submitted by the login form.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    /// Email address.
    pub email: String,
    /// Password.
    pub password: String,
}

/// Handles login submission.
///
/// On success: creates a session, sets a `hearth_ui_session` cookie
/// (`HttpOnly; Path=/ui; SameSite=Lax`), and redirects to `/ui/`.
/// All authentication failures collapse into a single generic error
/// message (enumeration resistance).
pub async fn login_submit(
    State(state): State<Arc<WebState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    // The Identity trait is tenant-scoped, but the web login form does
    // not know the tenant yet. For the placeholder flow we pick the
    // first tenant the email resolves to — multi-tenant login UX is a
    // Phase 1.6 concern. Any failure → generic 401.
    let email = form.email.trim();
    let generic_error = || {
        Html(render_login_form(Some(
            "Sign-in failed. Check your credentials and try again.",
        )))
        .into_response()
        .with_status(StatusCode::UNAUTHORIZED)
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
                let cookie = format!(
                    "hearth_ui_session={}; HttpOnly; Path=/ui; SameSite=Lax",
                    session.id().as_uuid()
                );
                let mut response = Redirect::to("/ui/").into_response();
                if let Ok(v) = header::HeaderValue::from_str(&cookie) {
                    response.headers_mut().insert(header::SET_COOKIE, v);
                }
                return response;
            }
            Err(IdentityError::UserNotVerified) => {
                return Html(render_login_form(Some(
                    "Your email is not verified yet. Check your inbox (or the server \
                    logs) for the verification link and click it before signing in.",
                )))
                .into_response()
                .with_status(StatusCode::FORBIDDEN);
            }
            Err(e) => {
                tracing::warn!(error = %e, "login: create_session failed");
                return generic_error();
            }
        }
    }

    generic_error()
}

/// Placeholder dashboard — the real management UI lands in Phase 1.6.
pub async fn dashboard() -> Html<String> {
    Html(wrap_page(
        "Hearth",
        "
        <h1>Welcome</h1>
        <p>You are signed in. The management dashboard is coming in a future release.
        For now, use the JSON admin API at <code>/admin/*</code>.</p>
        ",
    ))
}

// ============================================================================
// Helpers
// ============================================================================

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

fn not_found_response(body: &str) -> Response {
    Html(wrap_page(
        "Not Found",
        &format!("<h1>Not Found</h1><p>{}</p>", html_escape(body)),
    ))
    .into_response()
    .with_status(StatusCode::NOT_FOUND)
}

fn internal_error_response() -> Response {
    Html(wrap_page(
        "Server error",
        "<h1>Server error</h1><p>Something went wrong. Check the server logs.</p>",
    ))
    .into_response()
    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
}

fn render_setup_form(token: &str, error: Option<&str>) -> String {
    let token_esc = html_escape(token);
    let error_html = error.map_or(String::new(), |e| {
        format!(
            r#"<div class="error" role="alert">{}</div>"#,
            html_escape(e)
        )
    });
    wrap_page(
        "Hearth · First-run setup",
        &format!(
            r#"
            <h1>Welcome to Hearth</h1>
            <p>No tenant has been configured yet. Create your first tenant and admin
            account below.</p>
            {error_html}
            <form method="post" action="/ui/setup" autocomplete="off">
              <input type="hidden" name="token" value="{token_esc}">
              <label for="tenant_name">Tenant name</label>
              <input type="text" id="tenant_name" name="tenant_name" required>

              <label for="admin_display_name">Your display name</label>
              <input type="text" id="admin_display_name" name="admin_display_name" required>

              <label for="admin_email">Email</label>
              <input type="email" id="admin_email" name="admin_email" required
                     autocomplete="email">

              <label for="admin_password">Password (min 12 characters)</label>
              <input type="password" id="admin_password" name="admin_password" required
                     minlength="12" autocomplete="new-password">

              <button type="submit">Create admin account</button>
            </form>
            "#,
        ),
    )
}

fn render_login_form(error: Option<&str>) -> String {
    let error_html = error.map_or(String::new(), |e| {
        format!(
            r#"<div class="error" role="alert">{}</div>"#,
            html_escape(e)
        )
    });
    wrap_page(
        "Hearth · Sign in",
        &format!(
            r#"
            <h1>Sign in</h1>
            {error_html}
            <form method="post" action="/ui/login">
              <label for="email">Email</label>
              <input type="email" id="email" name="email" required autocomplete="email">

              <label for="password">Password</label>
              <input type="password" id="password" name="password" required
                     autocomplete="current-password">

              <button type="submit">Sign in</button>
            </form>
            "#,
        ),
    )
}

fn wrap_page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 32rem;
            margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }}
    h1 {{ margin-top: 0; }}
    label {{ display: block; margin-top: 1rem; font-weight: 600; }}
    input {{ display: block; width: 100%; padding: .5rem; margin-top: .25rem;
             box-sizing: border-box; font-size: 1rem; }}
    button {{ margin-top: 1.5rem; padding: .625rem 1rem; font-size: 1rem;
              cursor: pointer; }}
    .error {{ background: #fde8e8; color: #7a1a1a; padding: .75rem 1rem;
              border-radius: .25rem; margin-top: 1rem; }}
    code {{ background: rgba(127,127,127,0.15); padding: .1em .35em; border-radius: 3px; }}
  </style>
</head>
<body>
  {body}
</body>
</html>"#,
        title = html_escape(title),
        body = body,
    )
}

/// Minimal HTML escape for text interpolation.
///
/// We intentionally do not use a crate — the only text we interpolate
/// into HTML is (a) the setup token (base64url, already safe) and (b)
/// operator-supplied error messages we control.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Extension trait to override the status of a generated response.
trait ResponseStatusExt {
    /// Sets the HTTP status on an already-built response.
    fn with_status(self, status: StatusCode) -> Response;
}

impl ResponseStatusExt for Response {
    fn with_status(mut self, status: StatusCode) -> Response {
        *self.status_mut() = status;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_prevents_basic_injection() {
        let out = html_escape(r#"<script>"evil"</script>"#);
        assert!(!out.contains("<script>"), "got: {out}");
        assert!(out.contains("&lt;script&gt;"), "got: {out}");
    }

    #[test]
    fn wrap_page_contains_title_and_body() {
        let page = wrap_page("Title<x>", "<h1>Body</h1>");
        assert!(
            page.contains("<title>Title&lt;x&gt;</title>"),
            "got: {page}"
        );
        assert!(page.contains("<h1>Body</h1>"), "got: {page}");
    }

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
