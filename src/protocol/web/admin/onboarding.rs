//! Admin first-run onboarding wizard handlers.
//!
//! Implements the multi-step POST/Redirect/GET wizard introduced in HEA-487.
//! State is threaded between steps via query parameters (`?realm=`, `?invited=`,
//! etc.); no server-side wizard session is required because all handlers are
//! gated on `RequireAdmin`.
//!
//! # Routes
//!
//! | Method | Path | Step |
//! |--------|------|------|
//! | GET | `/admin/onboarding` | 1 — realm creation form |
//! | POST | `/admin/onboarding/realm` | 1 submit — creates realm |
//! | GET | `/admin/onboarding/app` | 2 — app registration form |
//! | POST | `/admin/onboarding/app` | 2 submit — registers OAuth client |
//! | GET | `/admin/onboarding/invite` | 3 — invite form |
//! | POST | `/admin/onboarding/invite` | 3 submit — creates user + sends link |
//! | GET | `/admin/onboarding/email` | 4 — email test form |
//! | POST | `/admin/onboarding/email/test` | HTMX partial — test email send |
//! | GET | `/admin/onboarding/complete` | Completion summary |

use super::*;
use crate::identity::oidc::ClientTrustLevel;
use crate::identity::RealmConfig;
use crate::protocol::web::themes::theme_css;
use crate::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};

/// Percent-encodes a query-parameter value using `form_urlencoded`.
fn qenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---------------------------------------------------------------------------
// Shared wizard query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WizardStepParams {
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub invited: String,
    #[serde(default)]
    pub app: String,
}

// ---------------------------------------------------------------------------
// Step 1 — Realm creation
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/onboarding/wizard.html")]
struct WizardTemplate {
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
    csrf: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    narrow: bool,
    error: Option<String>,
    form_realm_name: String,
    form_display_name: String,
    form_theme: String,
}

/// `GET /ui/admin/onboarding` — first-run wizard landing.
///
/// Redirects to the dashboard when at least one realm already exists,
/// so the wizard doesn't re-appear after completion.
pub async fn admin_onboarding_get(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    match state.onboarding.is_wizard_needed() {
        Ok(true) => {}
        Ok(false) => return Redirect::to("/ui").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "is_wizard_needed failed");
            return handlers_common::server_error();
        }
    }

    render(&WizardTemplate {
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
        csrf: session.csrf.clone(),
        chrome: true,
        active: "onboarding",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        narrow: false,
        error: None,
        form_realm_name: String::new(),
        form_display_name: String::new(),
        form_theme: "ember".to_string(),
    })
}

#[derive(Debug, Deserialize)]
pub struct RealmCreateForm {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub realm_name: String,
    #[serde(default)]
    pub theme: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/onboarding/realm` — creates the first realm.
pub async fn admin_onboarding_realm_post(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<RealmCreateForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let display_name = form.display_name.trim().to_string();
    let realm_name = form.realm_name.trim().to_string();
    let selected_theme = if form.theme.is_empty() {
        "ember".to_string()
    } else {
        form.theme.clone()
    };

    if display_name.is_empty() || realm_name.is_empty() {
        return render(&WizardTemplate {
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
            csrf: session.csrf.clone(),
            chrome: true,
            active: "onboarding",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            narrow: false,
            error: Some("Display name and realm name are required.".to_string()),
            form_realm_name: realm_name,
            form_display_name: display_name,
            form_theme: selected_theme,
        });
    }

    let realm_config = RealmConfig {
        web_theme_name: Some(selected_theme.clone()),
        web_theme_css: Some(theme_css(&selected_theme).to_string()),
        ..RealmConfig::default()
    };

    match state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(realm_config),
        }) {
        Ok(_realm) => {
            tracing::info!(realm = %realm_name, "onboarding: realm created");
            Redirect::to(&format!(
                "/ui/admin/onboarding/app?realm={}",
                qenc(&realm_name)
            ))
            .into_response()
        }
        Err(e) => {
            let msg = friendly_identity_error(&e);
            render(&WizardTemplate {
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
                csrf: session.csrf.clone(),
                chrome: true,
                active: "onboarding",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                narrow: false,
                error: Some(msg),
                form_realm_name: realm_name,
                form_display_name: display_name,
                form_theme: selected_theme,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Step 2 — OAuth application registration
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/onboarding/step_app.html")]
struct StepAppTemplate {
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
    csrf: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    narrow: bool,
    realm_name: String,
    error: Option<String>,
    form_app_name: String,
    form_redirect_uri: String,
    form_grant_authorization_code: bool,
    form_grant_refresh_token: bool,
    form_grant_client_credentials: bool,
}

/// `GET /ui/admin/onboarding/app` — step 2: OAuth app registration form.
pub async fn admin_onboarding_app_get(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<WizardStepParams>,
) -> Response {
    render(&StepAppTemplate {
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
        csrf: session.csrf.clone(),
        chrome: true,
        active: "onboarding",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        narrow: false,
        realm_name: params.realm,
        error: None,
        form_app_name: String::new(),
        form_redirect_uri: String::new(),
        form_grant_authorization_code: true,
        form_grant_refresh_token: false,
        form_grant_client_credentials: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct AppCreateWizardForm {
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub redirect_uri: String,
    /// "1" when the checkbox is checked, "" when absent.
    #[serde(default)]
    pub grant_authorization_code: String,
    #[serde(default)]
    pub grant_refresh_token: String,
    #[serde(default)]
    pub grant_client_credentials: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/onboarding/app` — creates the OAuth application.
pub async fn admin_onboarding_app_post(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<AppCreateWizardForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = form.realm.trim().to_string();
    let app_name = form.app_name.trim().to_string();
    let redirect_uri = form.redirect_uri.trim().to_string();

    if realm_name.is_empty() {
        return Redirect::to("/ui/admin/onboarding").into_response();
    }

    if app_name.is_empty() || redirect_uri.is_empty() {
        return render(&StepAppTemplate {
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
            csrf: session.csrf.clone(),
            chrome: true,
            active: "onboarding",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            narrow: false,
            realm_name: realm_name.clone(),
            error: Some("Application name and redirect URI are required.".to_string()),
            form_app_name: app_name,
            form_redirect_uri: redirect_uri,
            form_grant_authorization_code: form.grant_authorization_code == "1",
            form_grant_refresh_token: form.grant_refresh_token == "1",
            form_grant_client_credentials: form.grant_client_credentials == "1",
        });
    }

    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Some(id) => id,
        None => return handlers_common::not_found("Realm not found"),
    };

    let mut grant_types = Vec::new();
    if form.grant_authorization_code == "1" {
        grant_types.push("authorization_code".to_string());
    }
    if form.grant_refresh_token == "1" {
        grant_types.push("refresh_token".to_string());
    }
    if form.grant_client_credentials == "1" {
        grant_types.push("client_credentials".to_string());
    }
    if grant_types.is_empty() {
        grant_types.push("authorization_code".to_string());
    }

    let req = crate::identity::oidc::RegisterClientRequest {
        client_name: app_name.clone(),
        redirect_uris: vec![redirect_uri.clone()],
        client_secret: None,
        grant_types,
        require_consent: true,
        client_logo_url: None,
        slug: None,
        trust_level: ClientTrustLevel::ThirdParty,
        declared_scopes: Vec::new(),
        consent_spans_orgs: false,
    };

    match state.identity.register_client(&realm_id, &req) {
        Ok(client) => {
            let client_id = client.client_id().as_uuid().to_string();
            tracing::info!(
                realm = %realm_name,
                client_id = %client_id,
                "onboarding: OAuth client registered"
            );
            Redirect::to(&format!(
                "/ui/admin/onboarding/invite?realm={}&client_id={}&app={}",
                qenc(&realm_name),
                qenc(&client_id),
                qenc(&app_name),
            ))
            .into_response()
        }
        Err(e) => {
            let msg = friendly_identity_error(&e);
            render(&StepAppTemplate {
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
                csrf: session.csrf.clone(),
                chrome: true,
                active: "onboarding",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                narrow: false,
                realm_name,
                error: Some(msg),
                form_app_name: app_name,
                form_redirect_uri: redirect_uri,
                form_grant_authorization_code: form.grant_authorization_code == "1",
                form_grant_refresh_token: form.grant_refresh_token == "1",
                form_grant_client_credentials: form.grant_client_credentials == "1",
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Step 3 — Invite first admin
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/onboarding/step_invite.html")]
struct StepInviteTemplate {
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
    csrf: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    narrow: bool,
    realm_name: String,
    error: Option<String>,
    form_email: String,
    form_role: String,
    available_roles: Vec<String>,
}

/// `GET /ui/admin/onboarding/invite` — step 3: invite form.
pub async fn admin_onboarding_invite_get(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<WizardStepParams>,
) -> Response {
    render(&StepInviteTemplate {
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
        csrf: session.csrf.clone(),
        chrome: true,
        active: "onboarding",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        narrow: false,
        realm_name: params.realm,
        error: None,
        form_email: String::new(),
        form_role: "admin".to_string(),
        available_roles: vec!["admin".to_string(), "member".to_string()],
    })
}

#[derive(Debug, Deserialize)]
pub struct InviteWizardForm {
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/onboarding/invite` — creates a user and sends a setup link.
pub async fn admin_onboarding_invite_post(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<InviteWizardForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = form.realm.trim().to_string();
    let email = form.email.trim().to_string();
    let role = if form.role.is_empty() {
        "member".to_string()
    } else {
        form.role.clone()
    };

    if realm_name.is_empty() {
        return Redirect::to("/ui/admin/onboarding").into_response();
    }

    if email.is_empty() {
        return render(&StepInviteTemplate {
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
            csrf: session.csrf.clone(),
            chrome: true,
            active: "onboarding",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            narrow: false,
            realm_name: realm_name.clone(),
            error: Some("Email address is required.".to_string()),
            form_email: email,
            form_role: role,
            available_roles: vec!["admin".to_string(), "member".to_string()],
        });
    }

    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Some(id) => id,
        None => return handlers_common::not_found("Realm not found"),
    };

    // Create user with no password; they will set it via the reset link.
    let user = match state.identity.create_user(
        &realm_id,
        &crate::identity::CreateUserRequest {
            email: email.clone(),
            display_name: email.clone(),
            ..Default::default()
        },
    ) {
        Ok(u) => u,
        Err(e) => {
            let msg = friendly_identity_error(&e);
            return render(&StepInviteTemplate {
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
                csrf: session.csrf.clone(),
                chrome: true,
                active: "onboarding",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                narrow: false,
                realm_name: realm_name.clone(),
                error: Some(msg),
                form_email: email,
                form_role: role,
                available_roles: vec!["admin".to_string(), "member".to_string()],
            });
        }
    };

    // Assign RBAC role when "admin" is selected. All RBAC failures are
    // surfaced to the operator via the UI — silently swallowing them would
    // leave the invited user with no admin role and no way to detect it.
    if role == "admin" {
        macro_rules! rbac_err {
            ($msg:expr) => {
                return render(&StepInviteTemplate {
                    product_name: state.product_name.clone(),
                    logo_url: state.logo_url.clone(),
                    theme_css: state.theme_css.clone(),
                    realm_theme_css: state.realm_theme_css(),
                    csrf: session.csrf.clone(),
                    chrome: true,
                    active: "onboarding",
                    user_email: Some(session.user_email.clone()),
                    is_admin: true,
                    flash: None,
                    narrow: false,
                    realm_name: realm_name.clone(),
                    error: Some($msg),
                    form_email: email.clone(),
                    form_role: role.clone(),
                    available_roles: vec!["admin".to_string(), "member".to_string()],
                })
            };
        }

        if let Err(e) = state.rbac.seed_realm(&realm_id) {
            tracing::error!(error = %e, realm = %realm_name, "onboarding: seed_realm failed");
            rbac_err!(format!("Failed to initialise realm roles: {e}"));
        }
        let admin_role = match state.rbac.get_role_by_name(&realm_id, "realm.admin") {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::error!(realm = %realm_name, "onboarding: realm.admin role not found after seed");
                rbac_err!(
                    "Role 'realm.admin' missing after seed — please contact support".to_string()
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "onboarding: get_role_by_name failed");
                rbac_err!(format!("Failed to look up realm.admin role: {e}"));
            }
        };
        if let Err(e) = state.rbac.assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        ) {
            tracing::error!(error = %e, "onboarding: assign realm.admin failed");
            rbac_err!(format!("Failed to assign admin role: {e}"));
        }
    }

    // Issue a password reset token so the invited user can set their password.
    let base_url = state
        .config
        .as_ref()
        .and_then(|c| c.onboarding.base_url.as_deref())
        .unwrap_or("http://localhost:8420");

    if let Ok(Some(token)) = state.identity.request_password_reset(&realm_id, &email) {
        let reset_url = format!(
            "{}/ui/realms/{}/reset-password?token={}",
            base_url.trim_end_matches('/'),
            qenc(&realm_name),
            token
        );
        tracing::warn!(
            reset_url = %reset_url,
            invited = %email,
            "onboarding: invitation link (check logs if email delivery fails)"
        );

        if let Some(ref email_service) = state.email {
            let realm_branding = state
                .identity
                .get_realm(&realm_id)
                .ok()
                .flatten()
                .and_then(|r| r.config().email_branding.clone());

            if let Err(e) = email_service.send_password_reset_email(
                &email,
                &reset_url,
                realm_branding.as_ref(),
                None,
                None,
            ) {
                tracing::warn!(error = %e, "onboarding: invitation email delivery failed");
            }
        }
    }

    Redirect::to(&format!(
        "/ui/admin/onboarding/email?realm={}&invited={}&client_id={}&app={}",
        qenc(&realm_name),
        qenc(&email),
        qenc(&form.client_id),
        qenc(&form.app),
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// Step 4 — Email transport test
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/onboarding/step_email.html")]
struct StepEmailTemplate {
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
    csrf: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    narrow: bool,
    realm_name: String,
    configured_transport: String,
    admin_email: String,
}

/// `GET /ui/admin/onboarding/email` — step 4: email test form.
pub async fn admin_onboarding_email_get(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<WizardStepParams>,
) -> Response {
    let transport = email_transport_name(&state);
    let admin_email = if params.invited.is_empty() {
        session.user_email.clone()
    } else {
        params.invited.clone()
    };
    render(&StepEmailTemplate {
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
        csrf: session.csrf.clone(),
        chrome: true,
        active: "onboarding",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        narrow: false,
        realm_name: params.realm,
        configured_transport: transport,
        admin_email,
    })
}

#[derive(Debug, Deserialize)]
pub struct EmailTestForm {
    #[serde(default)]
    pub recipient: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

#[derive(Template)]
#[template(path = "ui/admin/onboarding/_email_test_result.html")]
struct EmailTestResultTemplate {
    success: bool,
    message: String,
}

/// `POST /ui/admin/onboarding/email/test` — HTMX partial: sends a test email.
///
/// Uses `spawn_blocking` because SMTP/HTTP transports are synchronous.
pub async fn admin_onboarding_email_test_post(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    FriendlyForm(form): FriendlyForm<EmailTestForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let recipient = form.recipient.trim().to_string();
    if recipient.is_empty() {
        return render(&EmailTestResultTemplate {
            success: false,
            message: "Recipient email is required.".to_string(),
        });
    }

    let (success, message) = match &state.email {
        None => (
            false,
            "Email service is not configured. Add an email transport to hearth.yaml.".to_string(),
        ),
        Some(email_service) => {
            let svc = Arc::clone(email_service);
            let to = recipient.clone();
            let base_url = state
                .config
                .as_ref()
                .and_then(|c| c.onboarding.base_url.as_deref())
                .unwrap_or("http://localhost:8420")
                .to_string();
            let result = tokio::task::spawn_blocking(move || {
                svc.send_setup_notification(
                    &to,
                    &format!(
                        "{}/ui/setup?token=test-email-check",
                        base_url.trim_end_matches('/')
                    ),
                )
            })
            .await;

            match result {
                Ok(Ok(())) => (
                    true,
                    format!("Test email sent to {recipient}. Check your inbox."),
                ),
                Ok(Err(e)) => (false, format!("Delivery failed: {e}")),
                Err(_) => (false, "Internal error sending test email.".to_string()),
            }
        }
    };

    render(&EmailTestResultTemplate { success, message })
}

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/onboarding/complete.html")]
struct CompleteTemplate {
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
    csrf: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    narrow: bool,
    realm_name: String,
    app_name: Option<String>,
    app_client_id: Option<String>,
    base_url: String,
    invited_email: Option<String>,
}

/// `GET /ui/admin/onboarding/complete` — wizard completion summary.
pub async fn admin_onboarding_complete_get(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<WizardStepParams>,
) -> Response {
    let base_url = state
        .config
        .as_ref()
        .and_then(|c| c.onboarding.base_url.as_deref())
        .unwrap_or("http://localhost:8420")
        .to_string();

    let app_name = if params.app.is_empty() {
        None
    } else {
        Some(params.app)
    };
    let app_client_id = if params.client_id.is_empty() {
        None
    } else {
        Some(params.client_id)
    };
    let invited_email = if params.invited.is_empty() {
        None
    } else {
        Some(params.invited)
    };

    render(&CompleteTemplate {
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
        csrf: session.csrf.clone(),
        chrome: true,
        active: "onboarding",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        narrow: false,
        realm_name: params.realm,
        app_name,
        app_client_id,
        base_url,
        invited_email,
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Resolves a realm slug to a `RealmId` by scanning the first page of realms.
///
/// On a fresh install there are ≤ 5 realms, so a linear scan is fine.
fn resolve_realm_by_name(state: &WebState, realm_name: &str) -> Option<RealmId> {
    let page = state.identity.list_realms(None, 50).ok()?;
    page.items
        .into_iter()
        .find(|r| r.name() == realm_name)
        .map(|r| r.id().clone())
}

/// Returns a short label for the currently configured email transport.
fn email_transport_name(state: &WebState) -> String {
    if state.email.is_none() {
        return "none".to_string();
    }
    if state.email_is_log_transport {
        return "log".to_string();
    }
    state
        .config
        .as_ref()
        .map(|c| match c.email.transport {
            crate::config::EmailTransport::Log => "log",
            crate::config::EmailTransport::Smtp => "smtp",
            crate::config::EmailTransport::Sendgrid => "sendgrid",
            crate::config::EmailTransport::Postmark => "postmark",
            crate::config::EmailTransport::Mailgun => "mailgun",
            crate::config::EmailTransport::Mailtrap => "mailtrap",
        })
        .unwrap_or("log")
        .to_string()
}

/// Maps identity-layer errors to user-visible messages (no internal detail).
fn friendly_identity_error(e: &crate::identity::IdentityError) -> String {
    match e {
        crate::identity::IdentityError::DuplicateRealmName => {
            "A realm with that name already exists. Choose a different name.".to_string()
        }
        crate::identity::IdentityError::DuplicateEmail => {
            "A user with that email already exists.".to_string()
        }
        _ => {
            tracing::warn!(error = %e, "onboarding identity error");
            "An unexpected error occurred. Please try again.".to_string()
        }
    }
}
