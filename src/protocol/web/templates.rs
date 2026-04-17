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
//! Page templates declare fields like:
//!
//! ```ignore
//! pub struct Page {
//!     pub chrome: Chrome,
//!     pub error: Option<String>,
//!     // ...
//! }
//! ```
//!
//! and the layout references `active`, `user_email`, `is_admin`,
//! `flash`, and `csrf` — those names come from the `chrome` field
//! via the `Template` derive's ability to look through nested
//! struct fields. To keep the lookup path short we flatten them
//! with a `#[allow(dead_code)]` helper: pages carry the fields
//! directly (not nested) which is what the layout expects.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use tracing::error;

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

/// Minimal fallback used when template rendering itself fails. We
/// avoid another template dispatch here to prevent recursion.
fn internal_error_fallback() -> Response {
    let body = "<!DOCTYPE html><title>Server error</title>\
        <h1>Server error</h1><p>Template rendering failed. See logs.</p>";
    let mut response = Html(body).into_response();
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}
