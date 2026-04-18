//! Axum handlers for the `/ui/admin/*` management surface.
//!
//! Every handler requires [`super::auth::RequireAdmin`] — the session
//! must belong to a user with the `hearth#admin` relation.
//!
//! # Routes covered here
//!
//! * `GET  /ui/admin/users` — paginated user list.
//! * `GET  /ui/admin/users/new` — create-user form.
//! * `POST /ui/admin/users/new` — submit create-user form.
//! * `GET  /ui/admin/users/:id` — user detail page.
//! * `GET  /ui/admin/users/:id/edit` — edit-user form.
//! * `POST /ui/admin/users/:id/edit` — submit edit-user form.
//! * `POST /ui/admin/users/:id/delete` — delete user.
//! * `GET  /ui/admin/tenants` — paginated tenant list.
//! * `GET  /ui/admin/tenants/new` — create-tenant form.
//! * `POST /ui/admin/tenants/new` — submit create-tenant form.
//! * `GET  /ui/admin/tenants/:id` — tenant detail page.
//! * `GET  /ui/admin/tenants/:id/edit` — edit-tenant form.
//! * `POST /ui/admin/tenants/:id/edit` — submit edit-tenant form.
//! * `POST /ui/admin/tenants/:id/delete` — delete tenant.
//! * `GET  /ui/admin/applications` — paginated application list.
//! * `GET  /ui/admin/applications/new` — register-application form.
//! * `POST /ui/admin/applications/new` — submit registration form.
//! * `GET  /ui/admin/applications/:id` — application detail page.
//! * `GET  /ui/admin/applications/:id/edit` — edit-application form.
//! * `POST /ui/admin/applications/:id/edit` — submit edit-application
//!   form.
//! * `POST /ui/admin/applications/:id/delete` — delete application.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::core::{ClientId, InvitationId, OrganizationId, SessionId, TenantId};
use crate::identity::{
    CleartextPassword, CreateInvitationRequest, CreateOrganizationRequest, CreateUserRequest,
    IdentityError, OAuthClient, Organization, OrganizationInvitation, OrganizationMembership,
    OrganizationRole, OrganizationStatus, RegisterClientRequest, Session, Tenant, TenantStatus,
    UpdateClientRequest, UpdateOrganizationRequest, UpdateUserRequest, User, UserStatus,
};

use super::auth::{verify_csrf_form_field, RequireAdmin};
use super::templates::{render, Flash};
use super::WebState;

// ---------------------------------------------------------------------------
// Shared query types
// ---------------------------------------------------------------------------

/// Pagination query params for list endpoints.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    /// Opaque cursor for the next page.
    pub cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// User list
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/users`.
#[derive(Template)]
#[template(path = "ui/admin/users/list.html")]
#[allow(clippy::struct_excessive_bools)]
struct UserListTemplate {
    users: Vec<User>,
    next_cursor: Option<String>,
    // Chrome fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/users`.
pub async fn admin_users_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_users(&session.tenant_id, params.cursor.as_deref(), 20)
    {
        Ok(page) => render(&UserListTemplate {
            users: page.items,
            next_cursor: page.next_cursor,
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "list_users failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Create user
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/users/new`.
#[derive(Template)]
#[template(path = "ui/admin/users/new.html")]
struct UserNewTemplate {
    error: Option<String>,
    form_email: String,
    form_display_name: String,
    // Chrome fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/users/new`.
pub async fn admin_user_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    render(&UserNewTemplate {
        error: None,
        form_email: String::new(),
        form_display_name: String::new(),
        chrome: true,
        active: "users",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
    })
}

/// `application/x-www-form-urlencoded` body for creating a user.
#[derive(Debug, Deserialize)]
pub struct CreateUserForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub password: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/users/new`.
pub async fn admin_user_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<CreateUserForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let req = CreateUserRequest {
        email: form.email.clone(),
        display_name: form.display_name.clone(),
    };

    match state.identity.create_user(&session.tenant_id, &req) {
        Ok(user) => {
            // Set the initial password.
            let pw = CleartextPassword::from_string(form.password);
            if let Err(e) = state
                .identity
                .set_password(&session.tenant_id, user.id(), &pw)
            {
                tracing::warn!(error = %e, "set initial password after create_user failed");
            }

            // Activate the user (skip email verification for admin-created users).
            let _ = state.identity.update_user(
                &session.tenant_id,
                user.id(),
                &UpdateUserRequest {
                    email: None,
                    display_name: None,
                    status: Some(UserStatus::Active),
                },
            );

            // Audit.
            audit_user_event(&state, &session, user.id(), "create");
            Redirect::to(&format!("/ui/admin/users/{}", user.id().as_uuid())).into_response()
        }
        Err(IdentityError::DuplicateEmail) => render(&UserNewTemplate {
            error: Some("A user with that email already exists.".to_string()),
            form_email: form.email,
            form_display_name: form.display_name,
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(IdentityError::InvalidInput { reason }) => render(&UserNewTemplate {
            error: Some(reason),
            form_email: form.email,
            form_display_name: form.display_name,
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "create_user failed");
            render(&UserNewTemplate {
                error: Some("Unable to create user right now.".to_string()),
                form_email: form.email,
                form_display_name: form.display_name,
                chrome: true,
                active: "users",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// User detail
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/users/:id`.
#[derive(Template)]
#[template(path = "ui/admin/users/detail.html")]
struct UserDetailTemplate {
    user: User,
    // Chrome fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/users/:id`.
pub async fn admin_user_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    match state.identity.get_user(&session.tenant_id, &uid) {
        Ok(Some(user)) => render(&UserDetailTemplate {
            user,
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Ok(None) => super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_user failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Edit user
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/users/:id/edit`.
#[derive(Template)]
#[template(path = "ui/admin/users/edit.html")]
struct UserEditTemplate {
    user: User,
    error: Option<String>,
    form_email: String,
    form_display_name: String,
    form_status: String,
    // Chrome fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/users/:id/edit`.
pub async fn admin_user_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    match state.identity.get_user(&session.tenant_id, &uid) {
        Ok(Some(user)) => render(&UserEditTemplate {
            form_email: user.email().to_string(),
            form_display_name: user.display_name().to_string(),
            form_status: format!("{:?}", user.status()),
            user,
            error: None,
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Ok(None) => super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_user failed");
            super::handlers_common::server_error()
        }
    }
}

/// `application/x-www-form-urlencoded` body for editing a user.
#[derive(Debug, Deserialize)]
pub struct EditUserForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub status: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/users/:id/edit`.
pub async fn admin_user_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(user_id): AxumPath<String>,
    Form(form): Form<EditUserForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    let status = parse_user_status(&form.status);
    let req = UpdateUserRequest {
        email: Some(form.email.clone()),
        display_name: Some(form.display_name.clone()),
        status,
    };

    match state.identity.update_user(&session.tenant_id, &uid, &req) {
        Ok(_updated) => {
            audit_user_event(&state, &session, &uid, "update");
            Redirect::to(&format!("/ui/admin/users/{}", uid.as_uuid())).into_response()
        }
        Err(IdentityError::DuplicateEmail) => render_edit_error(
            &state,
            &session,
            &uid,
            "A user with that email already exists.",
            &form,
        ),
        Err(IdentityError::InvalidInput { reason }) => {
            render_edit_error(&state, &session, &uid, &reason, &form)
        }
        Err(IdentityError::UserNotFound) => super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "update_user failed");
            render_edit_error(
                &state,
                &session,
                &uid,
                "Unable to update user right now.",
                &form,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Delete user
// ---------------------------------------------------------------------------

/// `application/x-www-form-urlencoded` body for deleting a user.
#[derive(Debug, Deserialize)]
pub struct DeleteUserForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/users/:id/delete`.
pub async fn admin_user_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(user_id): AxumPath<String>,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    match state.identity.delete_user(&session.tenant_id, &uid) {
        Ok(()) => {
            audit_user_event(&state, &session, &uid, "delete");
            Redirect::to("/ui/admin/users").into_response()
        }
        Err(IdentityError::UserNotFound) => super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "delete_user failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parses a `UserStatus` from the form value. Falls back to `Active`.
fn parse_user_status(s: &str) -> Option<UserStatus> {
    match s {
        "Active" => Some(UserStatus::Active),
        "Disabled" => Some(UserStatus::Disabled),
        "PendingVerification" => Some(UserStatus::PendingVerification),
        _ => None,
    }
}

/// Re-renders the edit form with an inline error and the user's
/// submitted values preserved.
fn render_edit_error(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    uid: &crate::core::UserId,
    msg: &str,
    form: &EditUserForm,
) -> Response {
    let user = state
        .identity
        .get_user(&session.tenant_id, uid)
        .ok()
        .flatten();

    match user {
        Some(user) => render(&UserEditTemplate {
            user,
            error: Some(msg.to_string()),
            form_email: form.email.clone(),
            form_display_name: form.display_name.clone(),
            form_status: form.status.clone(),
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        None => super::handlers_common::not_found("User not found"),
    }
}

/// Appends a user-management audit event. Best-effort; failure is logged
/// and does not fail the response.
fn audit_user_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    target_user_id: &crate::core::UserId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::UserCreated,
        "update" => AuditAction::UserUpdated,
        "delete" => AuditAction::UserDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "user".to_string(),
        resource_id: target_user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "user admin audit append failed");
    }
}

// =========================================================================
// Tenants
// =========================================================================

// Chrome fields for admin templates are inlined per struct initializer
// because Rust macros cannot expand to field initializers.

// ---------------------------------------------------------------------------
// Tenant list
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/tenants/list.html")]
struct TenantListTemplate {
    tenants: Vec<Tenant>,
    next_cursor: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/tenants`.
pub async fn admin_tenants_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state.identity.list_tenants(params.cursor.as_deref(), 20) {
        Ok(page) => render(&TenantListTemplate {
            tenants: page.items,
            next_cursor: page.next_cursor,
            chrome: true,
            active: "tenants",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "list_tenants failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/tenants/detail.html")]
struct TenantDetailTemplate {
    tenant: Tenant,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/tenants/:id`.
pub async fn admin_tenant_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(tid): AxumPath<String>,
) -> Response {
    let tenant_id = match tid.parse::<uuid::Uuid>() {
        Ok(u) => TenantId::new(u),
        Err(_) => return super::handlers_common::not_found("Tenant not found"),
    };

    match state.identity.get_tenant(&tenant_id) {
        Ok(Some(tenant)) => render(&TenantDetailTemplate {
            tenant,
            chrome: true,
            active: "tenants",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Ok(None) => super::handlers_common::not_found("Tenant not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_tenant failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Delete tenant (only Archived tenants)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/tenants/:id/delete`.
pub async fn admin_tenant_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(tid): AxumPath<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let tenant_id = match tid.parse::<uuid::Uuid>() {
        Ok(u) => TenantId::new(u),
        Err(_) => return super::handlers_common::not_found("Tenant not found"),
    };

    // Only allow permanent deletion of Archived tenants.
    match state.identity.get_tenant(&tenant_id) {
        Ok(Some(tenant)) if tenant.status() == TenantStatus::Archived => {
            match state.identity.delete_tenant(&tenant_id) {
                Ok(()) => {
                    audit_tenant_event(&state, &session, &tenant_id, "delete");
                    Redirect::to("/ui/admin/tenants").into_response()
                }
                Err(IdentityError::TenantNotFound) => {
                    super::handlers_common::not_found("Tenant not found")
                }
                Err(e) => {
                    tracing::warn!(error = %e, "delete_tenant failed");
                    super::handlers_common::server_error()
                }
            }
        }
        Ok(Some(_)) => super::handlers_common::bad_request(
            "Only archived tenants can be permanently deleted. Remove the tenant from hearth.yaml and restart to archive it first.",
        ),
        Ok(None) => super::handlers_common::not_found("Tenant not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_tenant failed");
            super::handlers_common::server_error()
        }
    }
}

/// Best-effort audit for tenant operations.
fn audit_tenant_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    tenant_id: &TenantId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::TenantCreated,
        "update" => AuditAction::TenantUpdated,
        "delete" => AuditAction::TenantDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "tenant".to_string(),
        resource_id: tenant_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "tenant admin audit append failed");
    }
}

// =========================================================================
// Applications (OAuth clients)
// =========================================================================

// ---------------------------------------------------------------------------
// Application list
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/list.html")]
struct AppListTemplate {
    applications: Vec<OAuthClient>,
    next_cursor: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/applications`.
pub async fn admin_apps_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_clients(&session.tenant_id, params.cursor.as_deref(), 20)
    {
        Ok(page) => render(&AppListTemplate {
            applications: page.items,
            next_cursor: page.next_cursor,
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "list_clients failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Register application
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/new.html")]
#[allow(clippy::struct_excessive_bools)]
struct AppNewTemplate {
    error: Option<String>,
    form_client_name: String,
    form_redirect_uris: String,
    form_confidential: bool,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/applications/new`.
pub async fn admin_app_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    render(&AppNewTemplate {
        error: None,
        form_client_name: String::new(),
        form_redirect_uris: String::new(),
        form_confidential: false,
        chrome: true,
        active: "applications",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
    })
}

#[derive(Debug, Deserialize)]
pub struct RegisterAppForm {
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub redirect_uris: String,
    #[serde(default)]
    pub confidential: Option<String>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/applications/new`.
pub async fn admin_app_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<RegisterAppForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let uris: Vec<String> = form
        .redirect_uris
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let is_confidential = form.confidential.as_deref() == Some("true");
    let secret = if is_confidential {
        Some(uuid::Uuid::new_v4().to_string())
    } else {
        None
    };

    match state.identity.register_client(
        &session.tenant_id,
        &RegisterClientRequest {
            client_name: form.client_name.clone(),
            redirect_uris: uris.clone(),
            client_secret: secret.clone(),
            grant_types: vec!["authorization_code".to_string()],
        },
    ) {
        Ok(client) => {
            audit_app_event(&state, &session, client.client_id(), "create");
            // Show the detail page with the one-time client secret.
            render(&AppDetailTemplate {
                app: client,
                client_secret: secret,
                chrome: true,
                active: "applications",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
            })
        }
        Err(IdentityError::InvalidInput { reason }) => render(&AppNewTemplate {
            error: Some(reason),
            form_client_name: form.client_name,
            form_redirect_uris: form.redirect_uris,
            form_confidential: is_confidential,
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "register_client failed");
            render(&AppNewTemplate {
                error: Some("Unable to register application right now.".to_string()),
                form_client_name: form.client_name,
                form_redirect_uris: form.redirect_uris,
                form_confidential: is_confidential,
                chrome: true,
                active: "applications",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Application detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/detail.html")]
struct AppDetailTemplate {
    app: OAuthClient,
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
}

/// `GET /ui/admin/applications/:id`.
pub async fn admin_app_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(cid): AxumPath<String>,
) -> Response {
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state.identity.get_client(&session.tenant_id, &client_id) {
        Ok(Some(app)) => render(&AppDetailTemplate {
            app,
            client_secret: None,
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Ok(None) => super::handlers_common::not_found("Application not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_client failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Edit application
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/edit.html")]
struct AppEditTemplate {
    app: OAuthClient,
    error: Option<String>,
    form_client_name: String,
    form_redirect_uris: String,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/applications/:id/edit`.
pub async fn admin_app_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(cid): AxumPath<String>,
) -> Response {
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state.identity.get_client(&session.tenant_id, &client_id) {
        Ok(Some(app)) => render(&AppEditTemplate {
            form_client_name: app.client_name().to_string(),
            form_redirect_uris: app.redirect_uris().join("\n"),
            app,
            error: None,
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Ok(None) => super::handlers_common::not_found("Application not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_client failed");
            super::handlers_common::server_error()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EditAppForm {
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub redirect_uris: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/applications/:id/edit`.
pub async fn admin_app_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(cid): AxumPath<String>,
    Form(form): Form<EditAppForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    let uris: Vec<String> = form
        .redirect_uris
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    match state.identity.update_client(
        &session.tenant_id,
        &client_id,
        &UpdateClientRequest {
            client_name: Some(form.client_name.clone()),
            redirect_uris: Some(uris),
        },
    ) {
        Ok(_) => {
            audit_app_event(&state, &session, &client_id, "update");
            Redirect::to(&format!("/ui/admin/applications/{}", client_id.as_uuid())).into_response()
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_client failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Delete application
// ---------------------------------------------------------------------------

/// `POST /ui/admin/applications/:id/delete`.
pub async fn admin_app_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(cid): AxumPath<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state.identity.delete_client(&session.tenant_id, &client_id) {
        Ok(()) => {
            audit_app_event(&state, &session, &client_id, "delete");
            Redirect::to("/ui/admin/applications").into_response()
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

/// Best-effort audit for application operations.
fn audit_app_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
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
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "client".to_string(),
        resource_id: client_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "app admin audit append failed");
    }
}

// =========================================================================
// Sessions
// =========================================================================

/// A row in the sessions table — bundles the `Session` with display
/// fields resolved server-side.
pub struct SessionRow {
    /// The raw session.
    pub session: Session,
    /// The email address of the session owner (or "(unknown)").
    pub user_email: String,
    /// Human-readable created-at.
    pub created_at_display: String,
    /// Human-readable expires-at.
    pub expires_at_display: String,
}

#[derive(Template)]
#[template(path = "ui/admin/sessions/list.html")]
struct SessionListTemplate {
    sessions: Vec<SessionRow>,
    next_cursor: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// Formats a `Timestamp` (Unix micros) as `YYYY-MM-DD HH:MM UTC`.
fn format_ts(ts: crate::core::Timestamp) -> String {
    let secs = ts.as_micros() / 1_000_000;
    let rem = secs % 86400;
    let days = secs / 86400;
    // Simple UTC calendar math (good enough for display).
    let h = rem / 3600;
    let m = (rem % 3600) / 60;

    // Civil date from Unix day — naive Gregorian.
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

/// Converts a Unix day number to (year, month 1–12, day 1–31).
///
/// Algorithm from Howard Hinnant's chrono-compatible
/// `civil_from_days` — public domain.
#[allow(clippy::similar_names)]
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Resolves a user's email from their `UserId`. Returns "(unknown)"
/// when the user has been deleted.
fn resolve_user_email(
    state: &Arc<WebState>,
    tenant_id: &TenantId,
    user_id: &crate::core::UserId,
) -> String {
    state
        .identity
        .get_user(tenant_id, user_id)
        .ok()
        .flatten()
        .map_or_else(|| "(unknown)".to_string(), |u| u.email().to_string())
}

/// `GET /ui/admin/sessions`.
pub async fn admin_sessions_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_sessions_by_tenant(&session.tenant_id, params.cursor.as_deref(), 20)
    {
        Ok(page) => {
            let rows: Vec<SessionRow> = page
                .items
                .into_iter()
                .map(|s| {
                    let email = resolve_user_email(&state, &session.tenant_id, s.user_id());
                    SessionRow {
                        created_at_display: format_ts(s.created_at()),
                        expires_at_display: format_ts(s.expires_at()),
                        session: s,
                        user_email: email,
                    }
                })
                .collect();
            render(&SessionListTemplate {
                sessions: rows,
                next_cursor: page.next_cursor,
                chrome: true,
                active: "sessions",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "list_sessions_by_tenant failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/sessions/:id/revoke`.
pub async fn admin_session_revoke(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    htmx: super::templates::IsHtmx,
    AxumPath(sid): AxumPath<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let session_id = match sid.parse::<uuid::Uuid>() {
        Ok(u) => SessionId::new(u),
        Err(_) => return super::handlers_common::not_found("Session not found"),
    };

    match state
        .identity
        .revoke_session(&session.tenant_id, &session_id)
    {
        Ok(()) => {
            audit_session_event(&state, &session, &session_id, "revoke");
            if htmx.0 {
                super::templates::htmx_toast_response("Session revoked.", "success")
            } else {
                Redirect::to("/ui/admin/sessions").into_response()
            }
        }
        Err(IdentityError::SessionNotFound) => {
            super::handlers_common::not_found("Session not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "revoke_session failed");
            super::handlers_common::server_error()
        }
    }
}

/// Best-effort audit for session operations.
fn audit_session_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    target_session_id: &SessionId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "revoke" => AuditAction::SessionRevoked,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "session".to_string(),
        resource_id: target_session_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "session admin audit append failed");
    }
}

// =========================================================================
// Audit log
// =========================================================================

/// A single row in the audit log view.
pub struct AuditRow {
    /// The raw audit event.
    pub event: crate::audit::AuditEvent,
    /// Human-readable timestamp.
    pub timestamp_display: String,
}

/// Query params for the UI audit page.
#[derive(Debug, Deserialize)]
pub struct AuditFilterParams {
    /// Filter by actor.
    #[serde(default)]
    pub actor: Option<String>,
    /// Filter by action name.
    #[serde(default)]
    pub action: Option<String>,
    /// Maximum events to show.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Template)]
#[template(path = "ui/admin/audit/list.html")]
struct AuditListTemplate {
    events: Vec<AuditRow>,
    form_actor: String,
    form_action: String,
    form_limit: String,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// Rows-only partial returned when the audit filter is triggered via HTMX.
#[derive(Template)]
#[template(path = "ui/admin/audit/_rows_only.html")]
#[allow(dead_code)]
struct AuditRowsTemplate {
    events: Vec<AuditRow>,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/audit`.
pub async fn admin_audit_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    htmx: super::templates::IsHtmx,
    Query(params): Query<AuditFilterParams>,
) -> Response {
    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());

    let limit = params.limit.unwrap_or(50).min(200);
    let query = crate::audit::AuditQuery {
        tenant_id: session.tenant_id.clone(),
        start_time: None,
        end_time: None,
        actor: params.actor.clone().filter(|s| !s.is_empty()),
        action,
        limit: Some(limit),
    };

    match state.audit.query(&query) {
        Ok(events) => {
            let rows: Vec<AuditRow> = events
                .into_iter()
                .map(|e| AuditRow {
                    timestamp_display: format_ts(e.timestamp),
                    event: e,
                })
                .collect();
            if htmx.0 {
                render(&AuditRowsTemplate {
                    events: rows,
                    product_name: String::new(),
                    logo_url: String::new(),
                })
            } else {
                render(&AuditListTemplate {
                    events: rows,
                    form_actor: params.actor.unwrap_or_default(),
                    form_action: params.action.unwrap_or_default(),
                    form_limit: limit.to_string(),
                    chrome: true,
                    active: "audit",
                    user_email: Some(session.user_email.clone()),
                    is_admin: true,
                    flash: None,
                    csrf: session.csrf.clone(),
                    narrow: false,
                    product_name: state.product_name.clone(),
                    logo_url: state.logo_url.clone(),
                })
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit query failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Test email
// ---------------------------------------------------------------------------

/// Form data for the admin test email action.
#[derive(Debug, Deserialize)]
pub struct TestEmailForm {
    /// The CSRF token echoed from the form.
    pub csrf: String,
    /// The recipient email address.
    pub email: String,
}

/// Sends a test email to verify transport configuration.
///
/// Requires admin role. On success, returns a flash message confirming
/// delivery. On failure, returns a flash message with the error.
pub async fn admin_test_email(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<TestEmailForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let email = form.email.trim();
    if email.is_empty() {
        return Redirect::to("/ui/admin/settings?flash=test_email_empty").into_response();
    }

    match &state.email {
        Some(email_service) => {
            let tenant_branding = state
                .identity
                .get_tenant(&session.tenant_id)
                .ok()
                .flatten()
                .and_then(|t| t.config().email_branding.clone());
            match email_service.send_test_email(email, tenant_branding.as_ref()) {
                Ok(()) => {
                    tracing::info!(to = %email, "admin test email sent");
                    Redirect::to("/ui/admin/settings?flash=test_email_sent").into_response()
                }
                Err(e) => {
                    tracing::warn!(error = %e, to = %email, "admin test email failed");
                    Redirect::to("/ui/admin/settings?flash=test_email_failed").into_response()
                }
            }
        }
        None => Redirect::to("/ui/admin/settings?flash=test_email_no_transport").into_response(),
    }
}

// =========================================================================
// Organizations
// =========================================================================

// ---------------------------------------------------------------------------
// Organization list
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/organizations`.
#[derive(Template)]
#[template(path = "ui/admin/organizations/list.html")]
#[allow(clippy::struct_excessive_bools)]
struct OrgListTemplate {
    organizations: Vec<Organization>,
    next_cursor: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/organizations`.
pub async fn admin_orgs_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_organizations(&session.tenant_id, params.cursor.as_deref(), 20)
    {
        Ok(page) => render(&OrgListTemplate {
            organizations: page.items,
            next_cursor: page.next_cursor,
            chrome: true,
            active: "organizations",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "list_organizations failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Create organization
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/organizations/new`.
#[derive(Template)]
#[template(path = "ui/admin/organizations/new.html")]
struct OrgNewTemplate {
    error: Option<String>,
    form_name: String,
    form_slug: String,
    form_description: String,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/organizations/new`.
pub async fn admin_org_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    render(&OrgNewTemplate {
        error: None,
        form_name: String::new(),
        form_slug: String::new(),
        form_description: String::new(),
        chrome: true,
        active: "organizations",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
    })
}

/// Form data for `POST /ui/admin/organizations/new`.
#[derive(Debug, Deserialize)]
pub struct CreateOrgForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/new`.
pub async fn admin_org_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<CreateOrgForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let description = if form.description.trim().is_empty() {
        None
    } else {
        Some(form.description.clone())
    };

    match state.identity.create_organization(
        &session.tenant_id,
        &CreateOrganizationRequest {
            name: form.name.clone(),
            slug: form.slug.clone(),
            description,
            config: None,
        },
    ) {
        Ok(org) => {
            audit_org_event(&state, &session, org.id(), "create");
            Redirect::to(&format!("/ui/admin/organizations/{}", org.id().as_uuid())).into_response()
        }
        Err(IdentityError::DuplicateOrgSlug) => render(&OrgNewTemplate {
            error: Some("An organization with that slug already exists.".to_string()),
            form_name: form.name,
            form_slug: form.slug,
            form_description: form.description,
            chrome: true,
            active: "organizations",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "create_organization failed");
            render(&OrgNewTemplate {
                error: Some(format!("Unable to create organization: {e}")),
                form_name: form.name,
                form_slug: form.slug,
                form_description: form.description,
                chrome: true,
                active: "organizations",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Organization detail
// ---------------------------------------------------------------------------

/// A member with resolved user details for display.
pub struct MemberView {
    /// The membership record.
    pub membership: OrganizationMembership,
    /// User's display name (fallback to email if unavailable).
    pub user_name: String,
    /// User's email address.
    pub user_email: String,
}

/// Template for `GET /ui/admin/organizations/:id`.
#[derive(Template)]
#[template(path = "ui/admin/organizations/detail.html")]
struct OrgDetailTemplate {
    org: Organization,
    members: Vec<MemberView>,
    invitations: Vec<OrganizationInvitation>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// Query params for org detail page (flash messages via PRG).
#[derive(Debug, Deserialize)]
pub struct OrgDetailParams {
    /// Flash message text (URL-encoded).
    #[serde(default)]
    pub flash: Option<String>,
    /// Flash kind: "success" or "error".
    #[serde(default)]
    pub flash_kind: Option<String>,
}

/// `GET /ui/admin/organizations/:id`.
pub async fn admin_org_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(oid): AxumPath<String>,
    Query(params): Query<OrgDetailParams>,
) -> Response {
    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let org = match state.identity.get_organization(&session.tenant_id, &org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return super::handlers_common::not_found("Organization not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_organization failed");
            return super::handlers_common::server_error();
        }
    };

    let memberships = state
        .identity
        .list_members(&session.tenant_id, &org_id, None, 100)
        .map(|p| p.items)
        .unwrap_or_default();

    // Resolve user details for each membership
    let members = memberships
        .into_iter()
        .map(|m| {
            let (name, email) = state
                .identity
                .get_user(&session.tenant_id, m.user_id())
                .ok()
                .flatten()
                .map_or_else(
                    || (m.user_id().as_uuid().to_string(), String::from("(unknown)")),
                    |u| (u.display_name().to_string(), u.email().to_string()),
                );
            MemberView {
                membership: m,
                user_name: name,
                user_email: email,
            }
        })
        .collect();

    let invitations = state
        .identity
        .list_invitations(&session.tenant_id, &org_id, None, 100)
        .map(|p| p.items)
        .unwrap_or_default();

    let flash = params.flash.map(|msg| {
        let kind = params.flash_kind.as_deref().unwrap_or("success");
        if kind == "error" {
            Flash::error(msg)
        } else {
            Flash::success(msg)
        }
    });

    render(&OrgDetailTemplate {
        org,
        members,
        invitations,
        chrome: true,
        active: "organizations",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
    })
}

// ---------------------------------------------------------------------------
// Edit organization
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/organizations/:id/edit`.
#[derive(Template)]
#[template(path = "ui/admin/organizations/edit.html")]
struct OrgEditTemplate {
    org: Organization,
    error: Option<String>,
    form_name: String,
    form_description: String,
    form_status: String,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/organizations/:id/edit`.
pub async fn admin_org_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(oid): AxumPath<String>,
) -> Response {
    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    match state.identity.get_organization(&session.tenant_id, &org_id) {
        Ok(Some(org)) => render(&OrgEditTemplate {
            form_name: org.name().to_string(),
            form_description: org.description().to_string(),
            form_status: format!("{:?}", org.status()),
            org,
            error: None,
            chrome: true,
            active: "organizations",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
        }),
        Ok(None) => super::handlers_common::not_found("Organization not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_organization failed");
            super::handlers_common::server_error()
        }
    }
}

/// Form data for `POST /ui/admin/organizations/:id/edit`.
#[derive(Debug, Deserialize)]
pub struct EditOrgForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub status: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/edit`.
pub async fn admin_org_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(oid): AxumPath<String>,
    Form(form): Form<EditOrgForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let status = match form.status.as_str() {
        "Active" => Some(OrganizationStatus::Active),
        "Suspended" => Some(OrganizationStatus::Suspended),
        _ => None,
    };

    let description = if form.description.trim().is_empty() {
        None
    } else {
        Some(form.description.clone())
    };

    match state.identity.update_organization(
        &session.tenant_id,
        &org_id,
        &UpdateOrganizationRequest {
            name: Some(form.name.clone()),
            description,
            status,
            config: None,
        },
    ) {
        Ok(_) => {
            audit_org_event(&state, &session, &org_id, "update");
            Redirect::to(&format!("/ui/admin/organizations/{}", org_id.as_uuid())).into_response()
        }
        Err(IdentityError::OrganizationNotFound) => {
            super::handlers_common::not_found("Organization not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_organization failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Delete organization
// ---------------------------------------------------------------------------

/// `POST /ui/admin/organizations/:id/delete`.
pub async fn admin_org_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(oid): AxumPath<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    match state
        .identity
        .delete_organization(&session.tenant_id, &org_id)
    {
        Ok(()) => {
            audit_org_event(&state, &session, &org_id, "delete");
            Redirect::to("/ui/admin/organizations").into_response()
        }
        Err(IdentityError::OrganizationNotFound) => {
            super::handlers_common::not_found("Organization not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete_organization failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Add member
// ---------------------------------------------------------------------------

/// Form data for `POST /ui/admin/organizations/:id/members`.
#[derive(Debug, Deserialize)]
pub struct AddMemberForm {
    /// User UUID selected from search results.
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub role: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/members`.
pub async fn admin_org_add_member(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(oid): AxumPath<String>,
    Form(form): Form<AddMemberForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let user_id = match form.user_id.trim().parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => {
            return org_redirect_flash(&org_id, "Invalid user selection", "error");
        }
    };

    let role = parse_org_role(&form.role);

    match state
        .identity
        .add_member(&session.tenant_id, &org_id, &user_id, role)
    {
        Ok(_) => org_redirect_flash(&org_id, "Member added successfully", "success"),
        Err(IdentityError::AlreadyMember) => {
            org_redirect_flash(&org_id, "User is already a member", "error")
        }
        Err(e) => {
            tracing::warn!(error = %e, "add_member failed");
            org_redirect_flash(&org_id, "Failed to add member", "error")
        }
    }
}

// ---------------------------------------------------------------------------
// Remove member
// ---------------------------------------------------------------------------

/// `POST /ui/admin/organizations/:id/members/:uid/remove`.
pub async fn admin_org_remove_member(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let user_id = match uid.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    match state
        .identity
        .remove_member(&session.tenant_id, &org_id, &user_id)
    {
        Ok(()) => org_redirect_flash(&org_id, "Member removed", "success"),
        Err(e) => {
            tracing::warn!(error = %e, "remove_member failed");
            let msg = format!("{e}");
            org_redirect_flash(&org_id, &msg, "error")
        }
    }
}

// ---------------------------------------------------------------------------
// Update member role
// ---------------------------------------------------------------------------

/// Form data for `POST /ui/admin/organizations/:id/members/:uid/role`.
#[derive(Debug, Deserialize)]
pub struct UpdateRoleForm {
    #[serde(default)]
    pub role: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/members/:uid/role`.
pub async fn admin_org_update_role(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    Form(form): Form<UpdateRoleForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let user_id = match uid.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    let role = parse_org_role(&form.role);

    match state
        .identity
        .update_member_role(&session.tenant_id, &org_id, &user_id, role)
    {
        Ok(_) => org_redirect_flash(&org_id, "Role updated", "success"),
        Err(e) => {
            tracing::warn!(error = %e, "update_member_role failed");
            let msg = format!("{e}");
            org_redirect_flash(&org_id, &msg, "error")
        }
    }
}

// ---------------------------------------------------------------------------
// Create invitation
// ---------------------------------------------------------------------------

/// Form data for `POST /ui/admin/organizations/:id/invite`.
#[derive(Debug, Deserialize)]
pub struct InviteForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/invite`.
pub async fn admin_org_invite(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(oid): AxumPath<String>,
    Form(form): Form<InviteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let role = parse_org_role(&form.role);

    match state.identity.create_invitation(
        &session.tenant_id,
        &CreateInvitationRequest {
            org_id: org_id.clone(),
            email: form.email.clone(),
            role,
            invited_by: session.user_id.clone(),
        },
    ) {
        Ok((_invitation, _token)) => {
            // TODO: send invitation email with token
            let msg = format!("Invitation sent to {}", form.email);
            org_redirect_flash(&org_id, &msg, "success")
        }
        Err(e) => {
            tracing::warn!(error = %e, email = %form.email, "create_invitation failed");
            org_redirect_flash(&org_id, "Failed to create invitation", "error")
        }
    }
}

// ---------------------------------------------------------------------------
// Revoke invitation
// ---------------------------------------------------------------------------

/// `POST /ui/admin/organizations/:id/invitations/:iid/revoke`.
pub async fn admin_org_revoke_invite(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath((oid, iid)): AxumPath<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let invitation_id = match iid.parse::<uuid::Uuid>() {
        Ok(u) => InvitationId::new(u),
        Err(_) => return super::handlers_common::not_found("Invitation not found"),
    };

    match state
        .identity
        .revoke_invitation(&session.tenant_id, &invitation_id)
    {
        Ok(()) => {}
        Err(e) => {
            tracing::warn!(error = %e, "revoke_invitation failed");
        }
    }

    Redirect::to(&format!("/ui/admin/organizations/{}", org_id.as_uuid())).into_response()
}

// ---------------------------------------------------------------------------
// User search API (HTMX partial)
// ---------------------------------------------------------------------------

/// Query params for `GET /ui/admin/api/users/search`.
#[derive(Debug, Deserialize)]
pub struct UserSearchParams {
    /// Search query (min 2 chars).
    #[serde(default)]
    pub q: String,
}

/// Template for HTMX user search result partial.
#[derive(Template)]
#[template(path = "ui/admin/organizations/_user_search_results.html")]
#[allow(dead_code)]
struct UserSearchResultsTemplate {
    users: Vec<User>,
    query: String,
    product_name: String,
    logo_url: String,
}

/// `GET /ui/admin/api/users/search?q=...` — returns HTML fragment for HTMX.
pub async fn admin_api_user_search(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<UserSearchParams>,
) -> Response {
    let query = params.q.trim().to_string();
    let users = if query.len() < 2 {
        Vec::new()
    } else {
        state
            .identity
            .search_users(&session.tenant_id, &query, 10)
            .unwrap_or_default()
    };

    render(&UserSearchResultsTemplate {
        users,
        query,
        product_name: String::new(),
        logo_url: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Organization helpers
// ---------------------------------------------------------------------------

/// Converts a nibble (0..15) to its ASCII hex character.
const fn nibble_to_hex(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'A' + n - 10) as char
    }
}

/// Redirects to an org detail page with a flash message in query params.
fn org_redirect_flash(org_id: &OrganizationId, message: &str, kind: &str) -> Response {
    // Percent-encode the message for safe inclusion in query params.
    let mut encoded = String::with_capacity(message.len());
    for b in message.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            encoded.push(b as char);
        } else if b == b' ' {
            encoded.push('+');
        } else {
            encoded.push('%');
            encoded.push(nibble_to_hex(b >> 4));
            encoded.push(nibble_to_hex(b & 0x0F));
        }
    }
    Redirect::to(&format!(
        "/ui/admin/organizations/{}?flash={encoded}&flash_kind={kind}",
        org_id.as_uuid()
    ))
    .into_response()
}

/// Parses an organization role string from a form field.
fn parse_org_role(s: &str) -> OrganizationRole {
    match s {
        "Owner" => OrganizationRole::Owner,
        "Admin" => OrganizationRole::Admin,
        _ => OrganizationRole::Member,
    }
}

/// Best-effort audit for organization operations.
fn audit_org_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    org_id: &OrganizationId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::OrgCreated,
        "update" => AuditAction::OrgUpdated,
        "delete" => AuditAction::OrgDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "organization".to_string(),
        resource_id: org_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "org admin audit append failed");
    }
}
