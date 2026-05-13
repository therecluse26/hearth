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
///
/// Unauthenticated variant — used when no session context is available
/// (pre-login pages, public OIDC error paths). Renders without the
/// admin chrome, which is the right call for those paths but looks
/// jarring from inside the admin shell. Authenticated handlers should
/// prefer [`not_found_authed`] so the user keeps their navigation.
pub(crate) fn not_found(msg: &str) -> Response {
    render_status(
        &NotFoundTemplate::new(msg.to_string()),
        StatusCode::NOT_FOUND,
    )
}

/// Renders a 404 page inside the authenticated admin shell.
///
/// The 2026-04-29 UX audit caught the bare `not_found` rendering as a
/// stand-alone unstyled white page when an admin clicked through to a
/// missing resource — losing sidebar, user pill, theme. This variant
/// keeps the chrome so the user can navigate back without retracing
/// their URL.
pub(crate) fn not_found_authed(
    state: &super::WebState,
    session: &super::auth::UiSession,
    msg: &str,
) -> Response {
    render_status(
        &NotFoundTemplate {
            message: msg.to_string(),
            chrome: true,
            active: "",
            user_email: Some(session.user_email.clone()),
            // Caller is already inside an authenticated admin handler
            // (every internal use site is gated by `RequireAdmin`); we
            // don't re-check here because doing so would mean an extra
            // RBAC lookup just to set a layout flag.
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        },
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

// ---------------------------------------------------------------------------
// Friendly form extractor
// ---------------------------------------------------------------------------

/// `Form<T>`-equivalent extractor that intercepts deserialization
/// failures and returns a styled HTML page instead of axum's default
/// `text/plain` rejection body.
///
/// Plain-text rejections replace the entire admin page with a single
/// terse line (e.g., `Failed to deserialize form body: …`), which is a
/// jarring UX. This wrapper renders the standard 400 template — same
/// chrome, same dark theme — so the user can navigate back without
/// losing visual context.
///
/// The wrapped form data is retrievable via `.0`, mirroring `Form<T>`.
pub struct FriendlyForm<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for FriendlyForm<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Form::<T>::from_request(req, state).await {
            Ok(axum::Form(value)) => Ok(Self(value)),
            Err(rejection) => {
                tracing::warn!(error = %rejection, "form deserialization failed");
                Err(bad_request(
                    "We couldn't read that form. Please go back and try again.",
                ))
            }
        }
    }
}

/// Deserializer that maps both a missing key and an empty string to `None`.
///
/// Browsers always submit empty `<input type="number">` fields as
/// `field=` rather than omitting them, but `serde_urlencoded` only treats
/// *missing* keys as `None` for `Option<T>`. Without this helper, optional
/// numeric form fields fail with `cannot parse integer from empty string`.
///
/// # Errors
///
/// Returns a deserializer error if the value is non-empty but fails to
/// parse into `T`.
pub(crate) fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let opt: Option<String> = serde::Deserialize::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => s.parse::<T>().map(Some).map_err(serde::de::Error::custom),
    }
}
