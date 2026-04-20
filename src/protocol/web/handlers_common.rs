//! Shared askama template structs used by multiple handler modules.
//!
//! Placing these here avoids a circular dependency between `handlers.rs`
//! and the account/admin modules, all of which need generic
//! `not_found` / `server_error` / `forbidden` pages.

use askama::Template;

use super::templates::Flash;

/// Generic "Not Found" HTML page.
#[derive(Template)]
#[template(path = "ui/errors/not_found.html")]
pub(crate) struct NotFoundTemplate {
    pub(crate) message: String,
    pub(crate) chrome: bool,
    pub(crate) active: &'static str,
    pub(crate) user_email: Option<String>,
    pub(crate) is_admin: bool,
    pub(crate) flash: Option<Flash>,
    pub(crate) csrf: Option<String>,
    pub(crate) narrow: bool,
    pub(crate) product_name: String,
    pub(crate) logo_url: String,
    pub(crate) theme_css: String,
    pub(crate) realm_theme_css: Option<String>,
}

impl NotFoundTemplate {
    pub(crate) fn new(message: String) -> Self {
        Self {
            message,
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name: "Hearth".to_string(),
            logo_url: super::DEFAULT_LOGO_URL.to_string(),
            theme_css: String::new(),
            realm_theme_css: None,
        }
    }
}

/// Generic "Forbidden" HTML page.
#[derive(Template)]
#[template(path = "ui/errors/forbidden.html")]
pub(crate) struct ForbiddenTemplate {
    pub(crate) chrome: bool,
    pub(crate) active: &'static str,
    pub(crate) user_email: Option<String>,
    pub(crate) is_admin: bool,
    pub(crate) flash: Option<Flash>,
    pub(crate) csrf: Option<String>,
    pub(crate) narrow: bool,
    pub(crate) product_name: String,
    pub(crate) logo_url: String,
    pub(crate) theme_css: String,
    pub(crate) realm_theme_css: Option<String>,
}

impl ForbiddenTemplate {
    pub(crate) fn new(user_email: Option<String>) -> Self {
        Self {
            chrome: true,
            active: "",
            user_email,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name: "Hearth".to_string(),
            logo_url: super::DEFAULT_LOGO_URL.to_string(),
            theme_css: String::new(),
            realm_theme_css: None,
        }
    }
}

/// Generic "Server error" HTML page.
#[derive(Template)]
#[template(path = "ui/errors/server_error.html")]
pub(crate) struct ServerErrorTemplate {
    pub(crate) chrome: bool,
    pub(crate) active: &'static str,
    pub(crate) user_email: Option<String>,
    pub(crate) is_admin: bool,
    pub(crate) flash: Option<Flash>,
    pub(crate) csrf: Option<String>,
    pub(crate) narrow: bool,
    pub(crate) product_name: String,
    pub(crate) logo_url: String,
    pub(crate) theme_css: String,
    pub(crate) realm_theme_css: Option<String>,
}

impl ServerErrorTemplate {
    pub(crate) fn new() -> Self {
        Self {
            chrome: false,
            active: "",
            user_email: None,
            is_admin: false,
            flash: None,
            csrf: None,
            narrow: true,
            product_name: "Hearth".to_string(),
            logo_url: super::DEFAULT_LOGO_URL.to_string(),
            theme_css: String::new(),
            realm_theme_css: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience renderers
// ---------------------------------------------------------------------------

use axum::http::StatusCode;
use axum::response::Response;

use super::templates::render_status;

/// Renders a 404 page with a custom message.
pub(crate) fn not_found(msg: &str) -> Response {
    render_status(
        &NotFoundTemplate::new(msg.to_string()),
        StatusCode::NOT_FOUND,
    )
}

/// Renders a 400 page with a custom message.
pub(crate) fn bad_request(msg: &str) -> Response {
    render_status(
        &NotFoundTemplate::new(msg.to_string()),
        StatusCode::BAD_REQUEST,
    )
}

/// Renders a generic 500 page.
pub(crate) fn server_error() -> Response {
    render_status(
        &ServerErrorTemplate::new(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}
