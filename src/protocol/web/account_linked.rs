//! Self-service federation management: `/ui/account/linked-accounts`.
//!
//! Lets a signed-in user list their linked external IdPs and unlink
//! any of them. Mirrors the pattern used by
//! [`super::account_consents`].
//!
//! # Routes
//! * `GET  /ui/account/linked-accounts` — list the signed-in user's
//!   linked IdPs.
//! * `POST /ui/account/linked-accounts/{idp_id}/unlink` — unlink one.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::core::IdpId;
use crate::identity::IdentityError;

use super::auth::{verify_csrf_form_field, UiSession};
use super::federation::audit_federation_unlinked;
use super::handlers_common;
use super::templates::render;
use super::WebState;

struct LinkedRow {
    idp_id: String,
    display_name: String,
    external_sub: String,
}

#[derive(Template)]
#[template(path = "ui/account/linked_accounts.html")]
#[allow(clippy::struct_excessive_bools)]
struct LinkedAccountsPage {
    linked: Vec<LinkedRow>,
    chrome: bool,
    active: &'static str,
    narrow: bool,
    is_admin: bool,
    user_email: Option<String>,
    flash: Option<super::templates::Flash>,
    csrf: Option<String>,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/account/linked-accounts`
pub async fn linked_accounts_index(
    State(state): State<Arc<WebState>>,
    session: UiSession,
) -> Response {
    let pairs = state
        .identity
        .list_external_identities_for_user(&session.realm_id, &session.user_id)
        .unwrap_or_default();
    let mut rows = Vec::with_capacity(pairs.len());
    for (idp_id, external_sub) in pairs {
        let display = state
            .identity
            .get_idp(&session.realm_id, &idp_id)
            .ok()
            .flatten()
            .map(|c| c.display_name)
            .unwrap_or_else(|| "external IdP".to_string());
        rows.push(LinkedRow {
            idp_id: idp_id.as_uuid().to_string(),
            display_name: display,
            external_sub,
        });
    }
    let tmpl = LinkedAccountsPage {
        linked: rows,
        chrome: true,
        active: "account",
        narrow: true,
        is_admin: super::handlers::is_admin(state.as_ref(), &session),
        user_email: Some(session.user_email.clone()),
        flash: None,
        csrf: session.csrf.clone(),
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    };
    render(&tmpl)
}

#[derive(Debug, Deserialize)]
pub struct CsrfOnlyForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/account/linked-accounts/{idp_id}/unlink`
pub async fn unlink(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Path(idp_id_str): Path<String>,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let Ok(uuid) = idp_id_str.parse::<uuid::Uuid>() else {
        return handlers_common::not_found("Linked account not found");
    };
    let idp_id = IdpId::new(uuid);
    match state
        .identity
        .unlink_external_identity(&session.realm_id, &session.user_id, &idp_id)
    {
        Ok(()) => {
            audit_federation_unlinked(&state, &session.realm_id, &idp_id, &session.user_id, "self");
            Redirect::to("/ui/account/linked-accounts").into_response()
        }
        Err(IdentityError::FederationNotLinked) => {
            handlers_common::not_found("Linked account not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "unlink failed");
            handlers_common::server_error()
        }
    }
}
