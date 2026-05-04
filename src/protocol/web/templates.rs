//! Shared template scaffolding and small value types used by every
//! askama template rendered by the `/ui/*` routes.
//!
//! The [`Chrome`] struct captures the "chrome" parameters (nav,
//! flash banner, CSRF meta, active tab) that every page needs. All
//! page template structs embed a [`Chrome`] under a field named
//! `chrome` and the layout (`_layout.html`) accesses them via
//! flattened names (`active`, `user_email`, `is_admin`, `flash`,
//! `chrome` itself is not exposed).
//!
//! Rendering helper: [`render`] converts `Result<String, askama::Error>`
//! to an `axum` `Response` so handlers stay one-liners.
//!
//! The helpers here are *purely* presentation glue — no engine calls,
//! no storage, no business logic.
//!
//! # Why not `askama_axum`?
//!
//! `askama_axum 0.4` was published against axum 0.7 and is not yet
//! compatible with axum 0.8 at the version pinned in `Cargo.toml`.
//! Wrapping `template.render()` in `axum::response::Html` yields an
//! equivalent `IntoResponse` with one less dependency.
//!
//! # Alias shape used by page templates
//!
//! Page templates declare fields like `chrome: Chrome`, `error:
//! Option<String>`, etc., and the layout references `active`,
//! `user_email`, `is_admin`, `flash`, and `csrf` — those names come
//! from the `chrome` field via the `Template` derive's ability to look
//! through nested struct fields. To keep the lookup path short we
//! flatten them with a `#[allow(dead_code)]` helper: pages carry the
//! fields directly (not nested) which is what the layout expects.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use tracing::error;

/// Cookie name carrying a one-shot flash banner across a
/// post-redirect-get cycle.
///
/// Replaces the previous `?flash=…&flash_kind=…` query-string scheme,
/// which polluted shareable URLs, replayed on refresh, and exposed a
/// reflected-content surface. The cookie is HttpOnly + SameSite=Strict
/// + Path=/ui and lives at most [`FLASH_COOKIE_TTL_SECS`] seconds.
pub const FLASH_COOKIE: &str = "hearth_ui_flash";

/// Maximum lifetime of a flash cookie. Long enough to survive a 303
/// redirect + one render cycle, short enough that an unread flash
/// disappears before the next user action.
pub const FLASH_COOKIE_TTL_SECS: u64 = 10;

/// Builds a `Set-Cookie` value that stores a one-shot flash banner.
///
/// Encoding: `<base64url(message)>.<kind>`. The kind is restricted to
/// `success` or `error` at construction time so the cookie cannot be
/// used to inject arbitrary text into the rendered page beyond the
/// allowed CSS classes.
#[must_use]
pub fn set_flash_cookie(message: &str, kind: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    let kind = if kind == "error" { "error" } else { "success" };
    let encoded = BASE64URL_NOPAD.encode(message.as_bytes());
    format!(
        "{FLASH_COOKIE}={encoded}.{kind}; HttpOnly; Path=/ui; SameSite=Strict; Max-Age={FLASH_COOKIE_TTL_SECS}"
    )
}

/// Builds a `Set-Cookie` value that clears the flash cookie. Emitted
/// alongside the rendered page so the next refresh starts clean.
#[must_use]
pub fn clear_flash_cookie() -> String {
    format!("{FLASH_COOKIE}=; HttpOnly; Path=/ui; SameSite=Strict; Max-Age=0")
}

/// Reads a flash banner from the request cookies.
///
/// Returns `None` when the cookie is missing, malformed, or carries an
/// unrecognised kind. Callers should also emit [`clear_flash_cookie`]
/// in their response so the same flash does not show up on refresh.
#[must_use]
pub fn take_flash_cookie(headers: &HeaderMap) -> Option<Flash> {
    use data_encoding::BASE64URL_NOPAD;
    let raw = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())?;
    let value = raw.split(';').map(str::trim).find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == FLASH_COOKIE {
            Some(v)
        } else {
            None
        }
    })?;
    let (msg_b64, kind) = value.rsplit_once('.')?;
    let kind = match kind {
        "error" => "error",
        "success" => "success",
        _ => return None,
    };
    let bytes = BASE64URL_NOPAD.decode(msg_b64.as_bytes()).ok()?;
    let message = String::from_utf8(bytes).ok()?;
    Some(Flash { kind, message })
}

/// Returns a 303 redirect to `url` with a flash cookie set.
///
/// The redirect URL itself MUST NOT contain `?flash=` query params —
/// callers that compose URLs with realm context should keep only the
/// realm param.
#[must_use]
pub fn redirect_with_flash(url: &str, message: &str, kind: &str) -> Response {
    let mut response = Redirect::to(url).into_response();
    if let Ok(value) = HeaderValue::from_str(&set_flash_cookie(message, kind)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// A flash message shown at the top of the content area.
///
/// `kind` is used verbatim as the CSS class suffix: `error` or
/// `success`. The constructor helpers enforce those two variants
/// at source sites.
#[derive(Debug, Clone)]
pub struct Flash {
    /// CSS class suffix: `"error"` or `"success"`.
    pub kind: &'static str,
    /// The human-readable text shown in the flash banner.
    pub message: String,
}

#[allow(dead_code)] // used by forthcoming account/admin handler commits
impl Flash {
    /// Creates an error-style flash banner (red background).
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            kind: "error",
            message: message.into(),
        }
    }

    /// Creates a success-style flash banner (green background).
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            kind: "success",
            message: message.into(),
        }
    }
}

/// Renders an askama template to an HTTP response.
///
/// On success: returns `200 OK` with `Content-Type: text/html;
/// charset=utf-8` (axum's `Html` wrapper sets this header).
/// On rendering failure: logs the error and returns `500 Internal
/// Server Error` with a generic HTML body.
///
/// Callers that need a different status code should use
/// [`render_status`] instead.
pub fn render<T: askama::Template>(template: &T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(err) => {
            error!(error = %err, "template render failed");
            internal_error_fallback()
        }
    }
}

/// Renders an askama template with a caller-supplied status code.
pub fn render_status<T: askama::Template>(template: &T, status: StatusCode) -> Response {
    let mut response = render(template);
    *response.status_mut() = status;
    response
}

// ---------------------------------------------------------------------------
// HTMX detection
// ---------------------------------------------------------------------------

/// Extractor that detects whether the current request was made by HTMX.
///
/// HTMX sets the `HX-Request: true` header on every fetch it initiates.
/// Handlers can use this to decide between returning a full page or a
/// partial HTML fragment.
pub struct IsHtmx(pub bool);

impl<S> FromRequestParts<S> for IsHtmx
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let is_htmx = parts
            .headers
            .get("HX-Request")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "true");
        Ok(Self(is_htmx))
    }
}

// ---------------------------------------------------------------------------
// HTMX toast response
// ---------------------------------------------------------------------------

/// Returns a 200 response with an `HX-Trigger` header that tells the
/// client-side Alpine.js toast container to display a notification.
///
/// `kind` is typically `"success"` or `"error"`.
pub fn htmx_toast_response(message: &str, kind: &str) -> Response {
    let json = format!(
        r#"{{"showToast":{{"message":"{}","kind":"{}"}}}}"#,
        message.replace('"', r#"\""#),
        kind.replace('"', r#"\""#),
    );
    let mut response = Response::new(axum::body::Body::empty());
    if let Ok(val) = HeaderValue::from_str(&json) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("hx-trigger"), val);
    }
    response
}

/// Minimal fallback used when template rendering itself fails. We
/// avoid another template dispatch here to prevent recursion.
fn internal_error_fallback() -> Response {
    let body = "<!DOCTYPE html><title>Server error</title>\
        <h1>Server error</h1><p>Template rendering failed. See logs.</p>";
    let mut response = Html(body).into_response();
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}
