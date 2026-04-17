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
        }
    }
}
