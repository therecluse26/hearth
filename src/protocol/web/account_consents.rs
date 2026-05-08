//! Self-service OAuth consent management (`/ui/account/applications`).
//!
//! This surface mirrors the session management module shape: listing,
//! per-item revoke, and "revoke all". Every action requires a valid
//! [`UiSession`] and a CSRF token on mutations. Revocation emits
//! [`AuditAction::ConsentRevoked`] with `metadata.via = "self"` so
//! operators can distinguish user-initiated revocation from admin-driven.
//!
//! # Routes
//!
//! * `GET  /ui/account/applications` — list the signed-in user's consents.
//! * `POST /ui/account/applications/{client_id}/revoke` — revoke one.
//! * `POST /ui/account/applications/revoke-all` — revoke every consent.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::core::ClientId;
use crate::identity::{ConsentListEntry, IdentityError};

use super::auth::{verify_csrf_form_field, UiSession};
use super::handlers_common;
use super::templates::{render, Flash};
use super::WebState;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

struct ConsentRow {
    client_id: String,
    client_name: String,
    client_logo_url: Option<String>,
    scopes: Vec<String>,
    granted_at: String,
    updated_at: String,
}

#[derive(Template)]
#[template(path = "ui/account/consents.html")]
#[allow(clippy::struct_excessive_bools)]
struct ConsentsIndexTemplate {
    consents: Vec<ConsentRow>,
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

impl ConsentsIndexTemplate {
    fn new(
        session: &UiSession,
        consents: Vec<ConsentRow>,
        is_admin: bool,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            consents,
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            realm_theme_css: None,
        }
    }
}

/// Template for the `GET /ui/account/applications` Connected Applications view.
#[derive(Template)]
#[template(path = "ui/account/applications.html")]
#[allow(clippy::struct_excessive_bools)]
struct AccountApplicationsTemplate {
    consents: Vec<ConsentRow>,
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /ui/account/applications` — Connected Applications page showing every
/// OAuth client the signed-in user has granted consent to, with per-row revoke.
pub async fn account_applications(
    State(state): State<Arc<WebState>>,
    session: UiSession,
) -> Response {
    let rows = load_consents(&state, &session);
    let admin = super::handlers::is_admin(state.as_ref(), &session);
    render(&AccountApplicationsTemplate {
        consents: rows,
        chrome: true,
        active: "account",
        user_email: Some(session.user_email.clone()),
        is_admin: admin,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

/// `GET /ui/account/applications` (legacy) — lists every OAuth client the signed-in
/// user has granted consent to, with per-row revoke actions.
pub async fn consents_index(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let rows = load_consents(&state, &session);
    let admin = super::handlers::is_admin(state.as_ref(), &session);
    let mut tmpl = ConsentsIndexTemplate::new(
        &session,
        rows,
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
}

/// CSRF-only form body.
#[derive(Debug, Deserialize)]
pub struct CsrfOnlyForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/account/applications/{client_id}/revoke`.
///
/// Revokes the signed-in user's consent for a single OAuth client and
/// redirects back to the index. Unknown client id returns 404.
pub async fn revoke_consent(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    axum::extract::Path(client_id_str): axum::extract::Path<String>,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let Ok(uuid) = client_id_str.parse::<uuid::Uuid>() else {
        return handlers_common::not_found("Consent not found");
    };
    let client_id = ClientId::new(uuid);
    match state
        .identity
        .revoke_consent(&session.realm_id, &session.user_id, &client_id)
    {
        Ok(()) => {
            // Engine now emits ConsentRevoked internally.
            Redirect::to("/ui/account/applications").into_response()
        }
        Err(IdentityError::ConsentNotFound) => handlers_common::not_found("Consent not found"),
        Err(e) => {
            tracing::warn!(error = %e, "revoke_consent failed");
            handlers_common::server_error()
        }
    }
}

/// `POST /ui/account/applications/revoke-all`.
///
/// Revokes every consent the signed-in user has granted in the current
/// realm. Each individual record revoked emits a `ConsentRevoked` event
/// with `metadata.batch = true`.
pub async fn revoke_all_consents(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    // List first to enumerate client ids for auditing, then delete each.
    let entries = match state
        .identity
        .list_consents_by_user(&session.realm_id, &session.user_id)
    {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "list_consents_by_user failed");
            return handlers_common::server_error();
        }
    };
    for entry in &entries {
        let _ = state
            .identity
            .revoke_consent(&session.realm_id, &session.user_id, &entry.record.client_id)
            .is_ok();
    }
    Redirect::to("/ui/account/applications").into_response()
}

// ---------------------------------------------------------------------------
// JSON/REST handlers (axum, under `/oauth/consents`)
// ---------------------------------------------------------------------------
//
// These are wired onto the main HTTP router (not the web UI) and expect
// a Bearer access token whose subject matches the user whose consents
// are being accessed.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_consents(state: &Arc<WebState>, session: &UiSession) -> Vec<ConsentRow> {
    state
        .identity
        .list_consents_by_user(&session.realm_id, &session.user_id)
        .unwrap_or_default()
        .into_iter()
        .map(|e: ConsentListEntry| ConsentRow {
            client_id: e.record.client_id.as_uuid().to_string(),
            client_name: e.client_name,
            client_logo_url: e.client_logo_url,
            scopes: e.record.granted_scopes,
            granted_at: format_ts(e.record.granted_at),
            updated_at: format_ts(e.record.updated_at),
        })
        .collect()
}

/// Formats a timestamp as `YYYY-MM-DD HH:MM UTC` — same shape the
/// sessions page uses so the account surface is visually consistent.
fn format_ts(ts: crate::core::Timestamp) -> String {
    let secs = ts.as_micros() / 1_000_000;
    let rem = secs.rem_euclid(86_400);
    let days = secs.div_euclid(86_400);
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

#[allow(clippy::similar_names)]
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
