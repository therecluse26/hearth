//! Identity provider (federation connector) list for the admin UI.

use super::*;
use crate::identity::federation::IdpConfig;

/// Flattened row used by the list template.
pub struct IdpRow {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub kind: String,
    pub issuer: String,
}

impl From<IdpConfig> for IdpRow {
    fn from(c: IdpConfig) -> Self {
        Self {
            id: c.id.to_string(),
            name: c.name,
            display_name: c.display_name,
            kind: c.kind.label().to_string(),
            issuer: c.issuer,
        }
    }
}

#[derive(Template)]
#[template(path = "ui/admin/identity_providers/list.html")]
struct IdpListTemplate {
    providers: Vec<IdpRow>,
    realm_name: String,
    active_tab: &'static str,
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

/// `GET /ui/admin/realms/{realm}/identity-providers`
pub async fn admin_idp_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    match state.identity.list_idps(target.id()) {
        Ok(idps) => render(&IdpListTemplate {
            providers: idps.into_iter().map(IdpRow::from).collect(),
            realm_name: target.0.name().to_string(),
            active_tab: "identity_providers",
            chrome: true,
            active: "realm-workspace",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "list_idps failed");
            super::handlers_common::server_error()
        }
    }
}
