//! OAuth client (application) registration and management.

use super::*;

// ---------------------------------------------------------------------------
// Application list
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/list.html")]
struct AppListTemplate {
    applications: Vec<OAuthClient>,
    next_cursor: Option<String>,
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

/// `GET /ui/admin/applications`.
pub async fn admin_apps_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_clients(target.id(), params.cursor.as_deref(), 20)
    {
        Ok(page) => render(&AppListTemplate {
            applications: page.items,
            next_cursor: page.next_cursor,
            realm_name: target.0.name().to_string(),
            active_tab: "applications",
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
            tracing::warn!(error = %e, "list_clients failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Application detail (read-only — apps managed via hearth.yaml)
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/detail.html")]
struct AppDetailTemplate {
    app: OAuthClient,
    realm_name: String,
    client_secret: Option<String>,
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

/// `GET /ui/admin/applications/:id`.
pub async fn admin_app_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
) -> Response {
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state.identity.get_client(target.id(), &client_id) {
        Ok(Some(app)) => render(&AppDetailTemplate {
            app,
            realm_name: target.0.name().to_string(),
            client_secret: None,
            chrome: true,
            active: "applications",
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
        Ok(None) => super::handlers_common::not_found("Application not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_client failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/applications/:id/regenerate-secret`.
///
/// Generates a new client secret for a confidential OAuth client.
/// Redirects back to the detail page with the new secret displayed once.
pub async fn admin_app_regenerate_secret(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state
        .identity
        .regenerate_client_secret(target.id(), &client_id)
    {
        Ok(new_secret) => {
            audit_app_event(&state, &session, &target.0, &client_id, "update");
            // Re-fetch the client to render the detail page with the new secret.
            match state.identity.get_client(target.id(), &client_id) {
                Ok(Some(app)) => render(&AppDetailTemplate {
                    app,
                    realm_name: target.0.name().to_string(),
                    client_secret: Some(new_secret),
                    chrome: true,
                    active: "applications",
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
                _ => Redirect::to(&format!(
                    "/ui/admin/realms/{}/applications/{}",
                    target.0.name(),
                    client_id.as_uuid()
                ))
                .into_response(),
            }
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        Err(IdentityError::InvalidInput { .. }) => {
            super::handlers_common::not_found("Cannot regenerate secret for a public client")
        }
        Err(e) => {
            tracing::warn!(error = %e, "regenerate_client_secret failed");
            super::handlers_common::server_error()
        }
    }
}

/// Best-effort audit for application operations.
fn audit_app_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    target_realm: &Realm,
    client_id: &ClientId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::ClientRegistered,
        "update" => AuditAction::ClientUpdated,
        "delete" => AuditAction::ClientDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: target_realm.id().clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "client".to_string(),
        resource_id: client_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "app admin audit append failed");
    }
}

// ---------------------------------------------------------------------------
// Application create
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/new.html")]
struct AppNewTemplate {
    error: Option<String>,
    realm_name: String,
    form_client_name: String,
    form_slug: String,
    form_client_type: String,
    form_redirect_uris: String,
    form_grant_authorization_code: bool,
    form_grant_client_credentials: bool,
    form_grant_refresh_token: bool,
    form_grant_device_code: bool,
    form_trust_level: String,
    form_require_consent: bool,
    form_declared_scopes: String,
    form_client_logo_url: String,
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

impl AppNewTemplate {
    fn blank(realm_name: String, session: &super::auth::UiSession, state: &Arc<WebState>) -> Self {
        Self {
            error: None,
            realm_name,
            form_client_name: String::new(),
            form_slug: String::new(),
            form_client_type: "public".to_string(),
            form_redirect_uris: String::new(),
            form_grant_authorization_code: true,
            form_grant_client_credentials: false,
            form_grant_refresh_token: false,
            form_grant_device_code: false,
            form_trust_level: "third_party".to_string(),
            form_require_consent: true,
            form_declared_scopes: String::new(),
            form_client_logo_url: String::new(),
            active_tab: "applications",
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
        }
    }
}

/// `GET /ui/admin/realms/{realm}/applications/new`
pub async fn admin_app_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&AppNewTemplate::blank(
        target.0.name().to_string(),
        &session,
        &state,
    ))
}

#[derive(Debug, Deserialize)]
pub struct AppCreateForm {
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub client_type: String,
    #[serde(default)]
    pub redirect_uris: String,
    #[serde(default)]
    pub grant_authorization_code: String,
    #[serde(default)]
    pub grant_client_credentials: String,
    #[serde(default)]
    pub grant_refresh_token: String,
    #[serde(default)]
    pub grant_device_code: String,
    #[serde(default)]
    pub trust_level: String,
    #[serde(default)]
    pub require_consent: String,
    #[serde(default)]
    pub declared_scopes: String,
    #[serde(default)]
    pub client_logo_url: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

fn parse_app_create_form(form: &AppCreateForm) -> RegisterClientRequest {
    let redirect_uris: Vec<String> = form
        .redirect_uris
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut grant_types = Vec::new();
    if form.grant_authorization_code == "1" {
        grant_types.push("authorization_code".to_string());
    }
    if form.grant_client_credentials == "1" {
        grant_types.push("client_credentials".to_string());
    }
    if form.grant_refresh_token == "1" {
        grant_types.push("refresh_token".to_string());
    }
    if form.grant_device_code == "1" {
        grant_types.push("urn:ietf:params:oauth:grant-type:device_code".to_string());
    }
    if grant_types.is_empty() {
        grant_types.push("authorization_code".to_string());
    }

    let client_secret = if form.client_type == "confidential" {
        Some(uuid::Uuid::new_v4().to_string())
    } else {
        None
    };

    let trust_level = if form.trust_level == "first_party" {
        ClientTrustLevel::FirstParty
    } else {
        ClientTrustLevel::ThirdParty
    };

    let declared_scopes: Vec<String> = form
        .declared_scopes
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let slug = if form.slug.is_empty() {
        None
    } else {
        Some(form.slug.clone())
    };

    let client_logo_url = if form.client_logo_url.is_empty() {
        None
    } else {
        Some(form.client_logo_url.clone())
    };

    RegisterClientRequest {
        client_name: form.client_name.clone(),
        redirect_uris,
        client_secret,
        grant_types,
        require_consent: form.require_consent == "1",
        client_logo_url,
        slug,
        trust_level,
        declared_scopes,
        consent_spans_orgs: false,
    }
}

/// `POST /ui/admin/realms/{realm}/applications/new`
pub async fn admin_app_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<AppCreateForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let req = parse_app_create_form(&form);
    let client_secret = req.client_secret.clone();
    let realm_name = target.0.name().to_string();

    match state.identity.register_client(target.id(), &req) {
        Ok(client) => {
            audit_app_event(&state, &session, &target.0, client.client_id(), "create");
            let secret_param = client_secret
                .map(|_s| format!("?secret_shown=1"))
                .unwrap_or_default();
            Redirect::to(&format!(
                "/ui/admin/realms/{}/applications/{}{}",
                realm_name,
                client.client_id().as_uuid(),
                secret_param,
            ))
            .into_response()
        }
        Err(IdentityError::InvalidInput { reason }) => {
            let mut tpl = AppNewTemplate::blank(realm_name, &session, &state);
            tpl.error = Some(reason);
            tpl.form_client_name = form.client_name.clone();
            tpl.form_slug = form.slug.clone();
            tpl.form_client_type = form.client_type.clone();
            tpl.form_redirect_uris = form.redirect_uris.clone();
            tpl.form_grant_authorization_code = form.grant_authorization_code == "1";
            tpl.form_grant_client_credentials = form.grant_client_credentials == "1";
            tpl.form_grant_refresh_token = form.grant_refresh_token == "1";
            tpl.form_grant_device_code = form.grant_device_code == "1";
            tpl.form_trust_level = form.trust_level.clone();
            tpl.form_require_consent = form.require_consent == "1";
            tpl.form_declared_scopes = form.declared_scopes.clone();
            tpl.form_client_logo_url = form.client_logo_url.clone();
            render(&tpl)
        }
        Err(e) => {
            tracing::warn!(error = %e, "register_client failed");
            let mut tpl = AppNewTemplate::blank(realm_name, &session, &state);
            tpl.error = Some("Unable to register application right now.".to_string());
            render(&tpl)
        }
    }
}

// ---------------------------------------------------------------------------
// Application edit
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/edit.html")]
struct AppEditTemplate {
    app: OAuthClient,
    error: Option<String>,
    realm_name: String,
    form_client_name: String,
    form_slug: String,
    form_redirect_uris: String,
    form_grant_authorization_code: bool,
    form_grant_client_credentials: bool,
    form_grant_refresh_token: bool,
    form_grant_device_code: bool,
    form_trust_level: String,
    form_require_consent: bool,
    form_declared_scopes: String,
    form_client_logo_url: String,
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

impl AppEditTemplate {
    fn from_client(
        app: OAuthClient,
        realm_name: String,
        session: &super::auth::UiSession,
        state: &Arc<WebState>,
    ) -> Self {
        let redirect_uris = app.redirect_uris().join("\n");
        let grant_authorization_code = app
            .grant_types()
            .contains(&"authorization_code".to_string());
        let grant_client_credentials = app
            .grant_types()
            .contains(&"client_credentials".to_string());
        let grant_refresh_token = app.grant_types().contains(&"refresh_token".to_string());
        let grant_device_code = app
            .grant_types()
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string());
        let trust_level = if format!("{:?}", app.trust_level()) == "FirstParty" {
            "first_party".to_string()
        } else {
            "third_party".to_string()
        };
        let declared_scopes = app.declared_scopes().join(" ");
        let client_logo_url = app.client_logo_url().unwrap_or("").to_string();
        let slug = app.slug().to_string();
        let require_consent = app.require_consent();

        Self {
            app,
            error: None,
            realm_name,
            form_client_name: String::new(),
            form_slug: slug,
            form_redirect_uris: redirect_uris,
            form_grant_authorization_code: grant_authorization_code,
            form_grant_client_credentials: grant_client_credentials,
            form_grant_refresh_token: grant_refresh_token,
            form_grant_device_code: grant_device_code,
            form_trust_level: trust_level,
            form_require_consent: require_consent,
            form_declared_scopes: declared_scopes,
            form_client_logo_url: client_logo_url,
            active_tab: "applications",
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
        }
    }
}

/// `GET /ui/admin/realms/{realm}/applications/{id}/edit`
pub async fn admin_app_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
) -> Response {
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };
    match state.identity.get_client(target.id(), &client_id) {
        Ok(Some(app)) => {
            let realm_name = target.0.name().to_string();
            let mut tpl = AppEditTemplate::from_client(app.clone(), realm_name, &session, &state);
            tpl.form_client_name = app.client_name().to_string();
            render(&tpl)
        }
        Ok(None) => super::handlers_common::not_found("Application not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_client failed");
            super::handlers_common::server_error()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AppEditForm {
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub redirect_uris: String,
    #[serde(default)]
    pub grant_authorization_code: String,
    #[serde(default)]
    pub grant_client_credentials: String,
    #[serde(default)]
    pub grant_refresh_token: String,
    #[serde(default)]
    pub grant_device_code: String,
    #[serde(default)]
    pub trust_level: String,
    #[serde(default)]
    pub require_consent: String,
    #[serde(default)]
    pub declared_scopes: String,
    #[serde(default)]
    pub client_logo_url: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/applications/{id}/edit`
pub async fn admin_app_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<AppEditForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    let redirect_uris: Vec<String> = form
        .redirect_uris
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut grant_types = Vec::new();
    if form.grant_authorization_code == "1" {
        grant_types.push("authorization_code".to_string());
    }
    if form.grant_client_credentials == "1" {
        grant_types.push("client_credentials".to_string());
    }
    if form.grant_refresh_token == "1" {
        grant_types.push("refresh_token".to_string());
    }
    if form.grant_device_code == "1" {
        grant_types.push("urn:ietf:params:oauth:grant-type:device_code".to_string());
    }
    if grant_types.is_empty() {
        grant_types.push("authorization_code".to_string());
    }

    let trust_level = if form.trust_level == "first_party" {
        Some(ClientTrustLevel::FirstParty)
    } else {
        Some(ClientTrustLevel::ThirdParty)
    };

    let declared_scopes: Vec<String> = form
        .declared_scopes
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let client_logo_url = if form.client_logo_url.is_empty() {
        Some(None)
    } else {
        Some(Some(form.client_logo_url.clone()))
    };

    let slug = if form.slug.is_empty() {
        None
    } else {
        Some(form.slug.clone())
    };

    let req = UpdateClientRequest {
        client_name: if form.client_name.is_empty() {
            None
        } else {
            Some(form.client_name.clone())
        },
        redirect_uris: Some(redirect_uris),
        grant_types: Some(grant_types),
        require_consent: Some(form.require_consent == "1"),
        client_logo_url,
        slug,
        trust_level,
        declared_scopes: Some(declared_scopes),
        consent_spans_orgs: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        post_logout_redirect_uris: None,
    };

    let realm_name = target.0.name().to_string();

    match state.identity.update_client(target.id(), &client_id, &req) {
        Ok(_client) => {
            audit_app_event(&state, &session, &target.0, &client_id, "update");
            Redirect::to(&format!(
                "/ui/admin/realms/{}/applications/{}",
                realm_name,
                client_id.as_uuid(),
            ))
            .into_response()
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        Err(IdentityError::InvalidInput { reason }) => {
            match state.identity.get_client(target.id(), &client_id) {
                Ok(Some(app)) => {
                    let mut tpl = AppEditTemplate::from_client(app, realm_name, &session, &state);
                    tpl.error = Some(reason);
                    tpl.form_client_name = form.client_name.clone();
                    render(&tpl)
                }
                _ => super::handlers_common::server_error(),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_client failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/realms/{realm}/applications/{id}/delete`
pub async fn admin_app_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    let realm_name = target.0.name().to_string();

    match state.identity.delete_client(target.id(), &client_id) {
        Ok(()) => {
            audit_app_event(&state, &session, &target.0, &client_id, "delete");
            Redirect::to(&format!("/ui/admin/realms/{}/applications", realm_name,)).into_response()
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete_client failed");
            super::handlers_common::server_error()
        }
    }
}
