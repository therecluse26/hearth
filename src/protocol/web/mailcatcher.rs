//! Mailcatcher browser UI routes (`/dev/mail/*`).
//!
//! Registered only when `email.transport = mailcatcher`. Guarded by an
//! HMAC-signed session cookie (`mcauth`) so the inbox is not world-readable.
//! Routes are never registered in production — the guard is `dev_mode` at
//! startup in `main.rs`.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Router;
use serde::Deserialize;

use crate::identity::email::mailcatcher::MailcatcherState;

const COOKIE_NAME: &str = "mcauth";

// ── Templates ────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "dev/mail_login.html")]
struct MailLoginTemplate {
    error: Option<String>,
}

/// A row in the inbox list.
#[derive(Debug, Clone)]
struct EmailSummary {
    id: String,
    to: String,
    subject: String,
    received_at: String,
}

#[derive(Template)]
#[template(path = "dev/mail_inbox.html")]
struct MailInboxTemplate {
    emails: Vec<EmailSummary>,
}

/// Full email view for the detail page.
#[derive(Debug, Clone)]
struct EmailDetailView {
    id: String,
    to: String,
    subject: String,
    received_at: String,
    html_body: String,
    text_body: String,
}

#[derive(Template)]
#[template(path = "dev/mail_detail.html")]
struct MailDetailTemplate {
    email: EmailDetailView,
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';').find_map(|part| {
                let part = part.trim();
                let (k, v) = part.split_once('=')?;
                (k.trim() == name).then(|| v.trim().to_string())
            })
        })
}

fn is_authenticated(state: &MailcatcherState, headers: &axum::http::HeaderMap) -> bool {
    extract_cookie(headers, COOKIE_NAME)
        .as_deref()
        .is_some_and(|v| state.verify_cookie(v))
}

fn set_cookie_header(value: &str) -> String {
    format!("{COOKIE_NAME}={value}; Path=/dev/mail; HttpOnly; SameSite=Lax")
}

// ── Render helper ─────────────────────────────────────────────────────────────

fn render<T: askama::Template>(template: &T) -> Response {
    match template.render() {
        Ok(body) => axum::response::Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "mailcatcher template render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Login handlers ────────────────────────────────────────────────────────────

/// Renders the mailcatcher login form.
pub async fn login_form(
    headers: HeaderMap,
    State(state): State<Arc<MailcatcherState>>,
) -> Response {
    if is_authenticated(&state, &headers) {
        return Redirect::to("/dev/mail").into_response();
    }
    render(&MailLoginTemplate { error: None })
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    password: String,
}

/// Validates the submitted password and issues the session cookie.
pub async fn login_submit(
    State(state): State<Arc<MailcatcherState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    if form.password == state.password {
        let cookie_value = state.session_cookie_value();
        (
            [(header::SET_COOKIE, set_cookie_header(&cookie_value))],
            Redirect::to("/dev/mail"),
        )
            .into_response()
    } else {
        render(&MailLoginTemplate {
            error: Some(
                "Incorrect password. Check your terminal for the access password \
                 shown when Hearth started."
                    .to_string(),
            ),
        })
    }
}

// ── Inbox handler ─────────────────────────────────────────────────────────────

/// Lists all captured emails, newest first.
pub async fn inbox(headers: HeaderMap, State(state): State<Arc<MailcatcherState>>) -> Response {
    if !is_authenticated(&state, &headers) {
        return Redirect::to("/dev/mail/login").into_response();
    }
    let emails = {
        let inbox = state.inbox.lock().unwrap_or_else(|e| e.into_inner());
        inbox
            .iter()
            .rev()
            .map(|e| EmailSummary {
                id: e.id.to_string(),
                to: e.to.clone(),
                subject: e.subject.clone(),
                received_at: e.received_at_display(),
            })
            .collect::<Vec<_>>()
    };
    render(&MailInboxTemplate { emails })
}

// ── Email detail handler ──────────────────────────────────────────────────────

/// Renders the detail view for a single captured email.
pub async fn email_detail(
    headers: HeaderMap,
    State(state): State<Arc<MailcatcherState>>,
    Path(id): Path<String>,
) -> Response {
    if !is_authenticated(&state, &headers) {
        return Redirect::to("/dev/mail/login").into_response();
    }
    let email = {
        let inbox = state.inbox.lock().unwrap_or_else(|e| e.into_inner());
        inbox
            .iter()
            .find(|e| e.id.to_string() == id)
            .map(|e| EmailDetailView {
                id: e.id.to_string(),
                to: e.to.clone(),
                subject: e.subject.clone(),
                received_at: e.received_at_display(),
                html_body: e.html_body.clone(),
                text_body: e.text_body.clone(),
            })
    };
    match email {
        Some(e) => render(&MailDetailTemplate { email: e }),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Delete handlers ───────────────────────────────────────────────────────────

/// Deletes a single email by id and redirects to the inbox.
pub async fn delete_email(
    headers: HeaderMap,
    State(state): State<Arc<MailcatcherState>>,
    Path(id): Path<String>,
) -> Response {
    if !is_authenticated(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let deleted = {
        let mut inbox = state.inbox.lock().unwrap_or_else(|e| e.into_inner());
        let before = inbox.len();
        inbox.retain(|e| e.id.to_string() != id);
        inbox.len() < before
    };
    if deleted {
        Redirect::to("/dev/mail").into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Clears all captured emails and redirects to the inbox.
pub async fn clear_inbox(
    headers: HeaderMap,
    State(state): State<Arc<MailcatcherState>>,
) -> Response {
    if !is_authenticated(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .inbox
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    Redirect::to("/dev/mail").into_response()
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Builds the `/dev/mail/*` router for the mailcatcher inbox browser.
///
/// Only call this when `email.transport = mailcatcher` and `dev_mode = true`.
pub fn mailcatcher_router(state: Arc<MailcatcherState>) -> Router {
    Router::new()
        .route("/dev/mail", axum::routing::get(inbox))
        .route("/dev/mail/clear", axum::routing::post(clear_inbox))
        .route(
            "/dev/mail/login",
            axum::routing::get(login_form).post(login_submit),
        )
        .route("/dev/mail/{id}", axum::routing::get(email_detail))
        .route("/dev/mail/{id}/delete", axum::routing::post(delete_email))
        .with_state(state)
}
