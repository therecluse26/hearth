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
//! * `GET  /ui/admin/realms` — paginated realm list.
//! * `GET  /ui/admin/realms/new` — create-realm form.
//! * `POST /ui/admin/realms/new` — submit create-realm form.
//! * `GET  /ui/admin/realms/:id` — realm detail page.
//! * `GET  /ui/admin/realms/:id/edit` — edit-realm form.
//! * `POST /ui/admin/realms/:id/edit` — submit edit-realm form.
//! * `POST /ui/admin/realms/:id/delete` — delete realm.
//! * `GET  /ui/admin/applications` — paginated application list.
//! * `GET  /ui/admin/applications/new` — register-application form.
//! * `POST /ui/admin/applications/new` — submit registration form.
//! * `GET  /ui/admin/applications/:id` — application detail page.
//! * `GET  /ui/admin/applications/:id/edit` — edit-application form.
//! * `POST /ui/admin/applications/:id/edit` — submit edit-application
//!   form.
//! * `POST /ui/admin/applications/:id/delete` — delete application.

use std::fmt::Write as _;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use base64::Engine as _;
use serde::Deserialize;

use crate::config::{Config, ValidationIssue};
use crate::core::{ClientId, InvitationId, OrganizationId, RealmId, SessionId};
use crate::identity::{
    CleartextPassword, CreateInvitationRequest, CreateOrganizationRequest, CreateUserRequest,
    IdentityError, OAuthClient, Organization, OrganizationConfig, OrganizationInvitation,
    OrganizationMembership, OrganizationRole, OrganizationStatus, Page, Realm, RealmStatus,
    Session, UpdateOrganizationRequest, UpdateUserRequest, User, UserStatus,
};

use crate::identity::claims_config::ClaimSource;
use crate::rbac::RoleScopeKind;

use super::auth::{verify_csrf_form_field, RequireAdmin, TargetRealm};
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

/// Query params for `GET /ui/admin/users`.
#[derive(Debug, Deserialize)]
pub struct UserListParams {
    /// Opaque cursor for the next page.
    pub cursor: Option<String>,
    /// Search query (email or name).
    pub q: Option<String>,
}

/// Template for `GET /ui/admin/users`.
#[derive(Template)]
#[template(path = "ui/admin/users/list.html")]
#[allow(clippy::struct_excessive_bools)]
struct UserListTemplate {
    users: Vec<User>,
    next_cursor: Option<String>,
    search_query: String,
    // Realm-workspace context. `Some` for `/admin/users?realm=<name>`
    // views (tenant workspace); `None` for `/admin/admin-users` which
    // is explicitly cross-workspace system-realm scope.
    target_realm_name: Option<String>,
    target_realm_id_hex: Option<String>,
    active_tab: &'static str,
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
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/admin/users`.
pub async fn admin_users_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    Query(params): Query<UserListParams>,
) -> Response {
    let search_query = params.q.clone().unwrap_or_default();
    let result = if search_query.len() >= 2 {
        state
            .identity
            .search_users(target.id(), &search_query, 20)
            .map(|users| Page {
                items: users,
                next_cursor: None,
            })
    } else {
        state
            .identity
            .list_users(target.id(), params.cursor.as_deref(), 20)
    };

    match result {
        Ok(page) => render(&UserListTemplate {
            users: page.items,
            next_cursor: page.next_cursor,
            search_query,
            target_realm_name: Some(target.0.name().to_string()),
            target_realm_id_hex: Some(target.id().as_uuid().to_string()),
            active_tab: "users",
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
            tracing::warn!(error = %e, "list_users failed");
            super::handlers_common::server_error()
        }
    }
}

/// `GET /ui/admin/admin-users`.
///
/// Lists users in the reserved system realm — the operators who can
/// sign into `/ui/admin/*`. Mirrors the tenant-realm user-list handler
/// but pins the scope to the system realm and renders under the
/// `admin-users` sidebar slot so the two surfaces cannot be confused.
pub async fn admin_admin_users_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<UserListParams>,
) -> Response {
    let system_realm = crate::identity::keys::system_realm_id();
    let search_query = params.q.clone().unwrap_or_default();
    let result = if search_query.len() >= 2 {
        state
            .identity
            .search_users(&system_realm, &search_query, 20)
            .map(|users| Page {
                items: users,
                next_cursor: None,
            })
    } else {
        state
            .identity
            .list_users(&system_realm, params.cursor.as_deref(), 20)
    };

    match result {
        Ok(page) => render(&UserListTemplate {
            users: page.items,
            next_cursor: page.next_cursor,
            search_query,
            target_realm_name: None,
            target_realm_id_hex: None,
            active_tab: "",
            chrome: true,
            active: "admin-users",
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
            tracing::warn!(error = %e, "admin_admin_users_list failed");
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
    form_first_name: String,
    form_last_name: String,
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
    theme_css: String,
    realm_theme_css: Option<String>,
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
        form_first_name: String::new(),
        form_last_name: String::new(),
        chrome: true,
        active: "users",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
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
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub password: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/users/new`.
pub async fn admin_user_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    Form(form): Form<CreateUserForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let req = CreateUserRequest {
        email: form.email.clone(),
        display_name: form.display_name.clone(),
        first_name: form.first_name.clone(),
        last_name: form.last_name.clone(),
    };

    match state.identity.create_user(target.id(), &req) {
        Ok(user) => {
            // Set the initial password.
            let pw = CleartextPassword::from_string(form.password);
            if let Err(e) = state.identity.set_password(target.id(), user.id(), &pw) {
                tracing::warn!(error = %e, "set initial password after create_user failed");
            }

            // Activate the user (skip email verification for admin-created users).
            let _ = state.identity.update_user(
                target.id(),
                user.id(),
                &UpdateUserRequest {
                    email: None,
                    display_name: None,
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            );

            // Audit.
            audit_user_event(&state, &session, &target.0, user.id(), "create");
            Redirect::to(&format!("/ui/admin/users/{}", user.id().as_uuid())).into_response()
        }
        Err(IdentityError::DuplicateEmail) => render(&UserNewTemplate {
            error: Some("A user with that email already exists.".to_string()),
            form_email: form.email.clone(),
            form_display_name: form.display_name.clone(),
            form_first_name: form.first_name.clone(),
            form_last_name: form.last_name.clone(),
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        }),
        Err(IdentityError::InvalidInput { reason }) => render(&UserNewTemplate {
            error: Some(reason),
            form_email: form.email.clone(),
            form_display_name: form.display_name.clone(),
            form_first_name: form.first_name.clone(),
            form_last_name: form.last_name.clone(),
            chrome: true,
            active: "users",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "create_user failed");
            render(&UserNewTemplate {
                error: Some("Unable to create user right now.".to_string()),
                form_email: form.email.clone(),
                form_display_name: form.display_name.clone(),
                form_first_name: form.first_name.clone(),
                form_last_name: form.last_name.clone(),
                chrome: true,
                active: "users",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// User detail
// ---------------------------------------------------------------------------

/// A row in the user detail page's sessions table.
pub struct UserSessionRow {
    /// Session UUID as string.
    pub id: String,
    /// Human-readable created-at.
    pub created_at: String,
    /// Human-readable expires-at.
    pub expires_at: String,
    /// Whether the session has been revoked.
    pub revoked: bool,
    /// Device label (e.g. "Chrome, Mac OSX") or "Unknown device".
    pub device_label: String,
    /// Client IP address or "\u{2014}" (em dash) if unavailable.
    pub ip_address: String,
}

/// A row in the user detail page's `WebAuthn` credentials table.
pub struct WebAuthnCredRow {
    /// Base64url-encoded credential ID (for use in URLs).
    pub id_b64url: String,
    /// Truncated credential ID for display.
    pub id_short: String,
    /// COSE algorithm identifier.
    pub algorithm: i64,
    /// Whether this is a discoverable (resident key) credential.
    pub discoverable: bool,
}

/// A row in the user detail page's organizations table.
pub struct OrgMembershipRow {
    /// Organization UUID as string.
    pub org_id: String,
    /// Organization display name.
    pub org_name: String,
    /// Organization slug.
    pub org_slug: String,
    /// Role display string.
    pub role: String,
}

/// A single RBAC role assignment row for the user detail page Roles tab.
pub struct UserRoleAssignmentRow {
    /// `AssignmentId` UUID string — used in the unassign POST URL.
    pub assignment_id: String,
    /// Human-readable role name.
    pub role_name: String,
    /// Display label for the scope ("Realm-wide" or "Org: {name}").
    pub scope_label: String,
    /// Wire value sent back in the unassign form ("realm" | "org:{uuid}").
    pub scope_raw: String,
}

/// A realm role available for assignment in the assign-role form.
pub struct AvailableRole {
    /// `RoleId` UUID string.
    pub id: String,
    /// Human-readable role name.
    pub name: String,
    /// Optional description shown as a hint in the dropdown.
    pub description: String,
    /// Where this role may be assigned: "Realm", "Organization", or "Any".
    pub scope_kind: String,
}

/// An organization available for scope selection in the assign forms.
pub struct AvailableOrg {
    /// `OrganizationId` UUID string.
    pub id: String,
    /// Organization display name.
    pub name: String,
}

/// A single org-scoped RBAC role held by a member (embedded in `MemberWithAccess`).
pub struct MemberRbacRole {
    /// `AssignmentId` UUID string — used in the unassign POST URL.
    pub assignment_id: String,
    /// `RoleId` UUID string.
    pub role_id: String,
    /// Human-readable role name.
    pub role_name: String,
}

/// A single org-scoped direct permission held by a member (embedded in `MemberWithAccess`).
pub struct MemberPermGrant {
    /// Permission string (e.g. `billing.read`).
    pub permission: String,
    /// Wire value sent back in the revoke form ("org:{uuid}").
    pub scope_raw: String,
}

/// A member view enriched with their org-scoped RBAC roles and direct permissions.
pub struct MemberWithAccess {
    /// Core member identity and membership info.
    pub view: MemberView,
    /// RBAC roles assigned to this member within this org.
    pub rbac_roles: Vec<MemberRbacRole>,
    /// Direct permissions granted to this member within this org.
    pub extra_perms: Vec<MemberPermGrant>,
}

/// A directly-granted permission row for the user detail page Extra Permissions tab.
pub struct UserPermissionGrantRow {
    /// The permission string (e.g. `documents.read`).
    pub permission: String,
    /// Display label for the scope ("Realm-wide" or "Org: {name}").
    pub scope_label: String,
    /// Wire value sent back in the revoke form ("realm" | "org:{uuid}").
    pub scope_raw: String,
}

/// Template for `GET /ui/admin/users/:id`.
#[derive(Template)]
#[template(path = "ui/admin/users/detail.html")]
#[allow(clippy::struct_excessive_bools)]
struct UserDetailTemplate {
    user: User,
    /// User UUID string — shared with embedded partials via `{% include %}`.
    user_id: String,
    sessions: Vec<UserSessionRow>,
    mfa_enabled: bool,
    webauthn_credentials: Vec<WebAuthnCredRow>,
    org_memberships: Vec<OrgMembershipRow>,
    flash_message: Option<String>,
    /// Whether the displayed user has the `hearth#admin` role.
    is_user_admin: bool,
    /// Current RBAC role assignments for this user in the active realm.
    role_assignments: Vec<UserRoleAssignmentRow>,
    /// All roles defined in the active realm (for the assign-role form).
    available_roles: Vec<AvailableRole>,
    /// All organizations in the realm (for the org scope picker).
    available_orgs: Vec<AvailableOrg>,
    /// Formatted creation timestamp.
    created_at_display: String,
    /// Formatted last-updated timestamp.
    updated_at_display: String,
    /// Directly-granted permissions with scope display info.
    extra_permissions: Vec<UserPermissionGrantRow>,
    /// Known permission strings across all realm roles (for the datalist).
    available_permissions: Vec<String>,
    /// Fully resolved effective permission names for this user.
    effective_permissions: Vec<String>,
    /// User attributes as sorted `(key, value)` pairs.
    attributes: Vec<(String, String)>,
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
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// Template for the Roles tab HTMX partial.
#[derive(Template)]
#[template(path = "ui/admin/users/_roles_tab.html")]
struct UserRolesTabTemplate {
    user_id: String,
    role_assignments: Vec<UserRoleAssignmentRow>,
    available_roles: Vec<AvailableRole>,
    available_orgs: Vec<AvailableOrg>,
    csrf: Option<String>,
}

/// Template for the Extra Permissions tab HTMX partial.
#[derive(Template)]
#[template(path = "ui/admin/users/_permissions_tab.html")]
struct UserPermissionsTabTemplate {
    user_id: String,
    extra_permissions: Vec<UserPermissionGrantRow>,
    available_permissions: Vec<String>,
    available_orgs: Vec<AvailableOrg>,
    csrf: Option<String>,
}

/// Query params for user detail page (flash messages).
#[derive(Debug, Deserialize, Default)]
pub struct UserDetailParams {
    /// Flash message key from redirect.
    pub flash: Option<String>,
}

/// `GET /ui/admin/users/:id`.
#[allow(clippy::too_many_lines)]
pub async fn admin_user_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
    Query(params): Query<UserDetailParams>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    let user = match state.identity.get_user(target.id(), &uid) {
        Ok(Some(u)) => u,
        Ok(None) => return super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_user failed");
            return super::handlers_common::server_error();
        }
    };

    // Load related data for the detail page
    let raw_sessions = state
        .identity
        .list_sessions_by_user(target.id(), &uid, None, 10)
        .unwrap_or_default();
    let sessions: Vec<UserSessionRow> = raw_sessions
        .items
        .iter()
        .map(|s| UserSessionRow {
            id: s.id().as_uuid().to_string(),
            created_at: format_ts(s.created_at()),
            expires_at: format_ts(s.expires_at()),
            revoked: s.is_revoked(),
            device_label: s.device_label().unwrap_or("Unknown device").to_string(),
            ip_address: s.ip_address().unwrap_or("\u{2014}").to_string(),
        })
        .collect();

    let mfa_enabled = state
        .identity
        .mfa_enabled(target.id(), &uid)
        .unwrap_or(false);

    let raw_creds = state
        .identity
        .list_webauthn_credentials(target.id(), &uid)
        .unwrap_or_default();
    let webauthn_credentials: Vec<WebAuthnCredRow> = raw_creds
        .iter()
        .map(|c| {
            let id_b64url = c.credential_id_b64url();
            let id_short = if id_b64url.len() > 16 {
                format!("{}...", &id_b64url[..16])
            } else {
                id_b64url.clone()
            };
            WebAuthnCredRow {
                id_b64url,
                id_short,
                algorithm: c.algorithm(),
                discoverable: c.discoverable(),
            }
        })
        .collect();

    // Load org memberships and resolve org names
    let memberships = state
        .identity
        .list_user_organizations(target.id(), &uid, None, 50)
        .unwrap_or_default();
    let mut org_memberships = Vec::with_capacity(memberships.items.len());
    for m in &memberships.items {
        let (org_name, org_slug) = match state.identity.get_organization(target.id(), m.org_id()) {
            Ok(Some(o)) => (o.name().to_string(), o.slug().to_string()),
            _ => ("(unknown)".to_string(), String::new()),
        };
        org_memberships.push(OrgMembershipRow {
            org_id: m.org_id().as_uuid().to_string(),
            org_name,
            org_slug,
            role: format!("{:?}", m.role()),
        });
    }

    // Map flash query param to human-readable message
    let flash_message = params.flash.as_deref().map(|f| match f {
        "reset_sent" => "Password reset email requested.".to_string(),
        "mfa_disabled" => "MFA has been disabled for this user.".to_string(),
        "session_revoked" => "Session revoked.".to_string(),
        "webauthn_revoked" => "WebAuthn credential revoked.".to_string(),
        "role_assigned" => "Role assigned.".to_string(),
        "role_unassigned" => "Role removed.".to_string(),
        "permission_granted" => "Permission granted.".to_string(),
        "permission_revoked" => "Permission revoked.".to_string(),
        other => other.to_string(),
    });

    let is_user_admin = check_user_admin(&state, target.id(), &uid);
    let created_at_display = format_ts(user.created_at());
    let updated_at_display = format_ts(user.updated_at());

    // Role assignments with display metadata.
    let role_assignments = build_role_assignment_rows(&state, target.id(), &uid);

    // All roles in this realm (for the assign-role form dropdown).
    let available_roles: Vec<AvailableRole> = state
        .rbac
        .list_roles(target.id(), None, 200)
        .map(|p| p.items)
        .unwrap_or_default()
        .into_iter()
        .map(|r| AvailableRole {
            id: r.id.as_uuid().to_string(),
            description: r.description.unwrap_or_default(),
            scope_kind: format!("{:?}", r.scope_kind),
            name: r.name,
        })
        .collect();

    // All orgs in this realm (for the scope picker).
    let available_orgs = build_available_orgs(&state, target.id());

    // Directly-granted permissions with scope display info.
    let extra_permissions = build_permission_grant_rows(&state, target.id(), &uid);

    // Known permission strings across all roles (autocomplete datalist).
    let available_permissions = collect_realm_permissions(&state, target.id());

    // Fully resolved effective permissions (union of roles + direct grants).
    let effective_permissions: Vec<String> = state
        .rbac
        .resolve_permissions(&uid, target.id(), None, None)
        .map(|r| r.permissions.into_iter().map(|p| p.into_string()).collect())
        .unwrap_or_default();

    // User attributes as sorted (key, value) pairs.
    let attributes: Vec<(String, String)> = user
        .attributes()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    render(&UserDetailTemplate {
        user_id: uid.as_uuid().to_string(),
        user,
        sessions,
        mfa_enabled,
        webauthn_credentials,
        org_memberships,
        flash_message,
        is_user_admin,
        role_assignments,
        available_roles,
        available_orgs,
        created_at_display,
        updated_at_display,
        extra_permissions,
        available_permissions,
        effective_permissions,
        attributes,
        chrome: true,
        active: "users",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

/// `POST /ui/admin/users/:id/reset-password` — sends a password reset email.
pub async fn admin_user_send_reset(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    let user = match state.identity.get_user(target.id(), &uid) {
        Ok(Some(u)) => u,
        Ok(None) => return super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_user failed");
            return super::handlers_common::server_error();
        }
    };

    match state
        .identity
        .request_password_reset(target.id(), user.email())
    {
        Ok(Some(_token)) => {
            // Token generated — in production, the email service sends it.
            // For now, flash success.
            tracing::info!(user_id = %uid, "admin triggered password reset");
        }
        Ok(None) => {
            // Rate-limited or other reason no token was generated
        }
        Err(e) => {
            tracing::warn!(error = %e, "request_password_reset failed");
        }
    }

    Redirect::to(&format!("/ui/admin/users/{user_id}?flash=reset_sent")).into_response()
}

/// `POST /ui/admin/users/:id/disable-mfa` — disables MFA for the user.
pub async fn admin_user_disable_mfa(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    match state.identity.disable_mfa(target.id(), &uid) {
        Ok(()) => {
            tracing::info!(user_id = %uid, admin = %session.user_email, "admin disabled MFA");
        }
        Err(e) => {
            tracing::warn!(error = %e, "disable_mfa failed");
        }
    }

    Redirect::to(&format!("/ui/admin/users/{user_id}?flash=mfa_disabled")).into_response()
}

/// `POST /ui/admin/users/:id/sessions/:sid/revoke` — revokes a single session.
pub async fn admin_user_revoke_session(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((user_id, session_id)): AxumPath<(String, String)>,
) -> Response {
    let sid = match session_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::SessionId::new(u),
        Err(_) => return super::handlers_common::not_found("Session not found"),
    };

    match state.identity.revoke_session(target.id(), &sid) {
        Ok(()) => {
            tracing::info!(session_id = %session_id, admin = %session.user_email, "admin revoked session");
        }
        Err(e) => {
            tracing::warn!(error = %e, "revoke_session failed");
        }
    }

    Redirect::to(&format!("/ui/admin/users/{user_id}?flash=session_revoked")).into_response()
}

/// `POST /ui/admin/users/:id/webauthn/:cred_id/revoke` — revokes a `WebAuthn` credential.
pub async fn admin_user_revoke_webauthn(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((user_id, cred_id_b64)): AxumPath<(String, String)>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    let Ok(cred_id_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cred_id_b64)
    else {
        return super::handlers_common::not_found("Invalid credential ID");
    };

    match state
        .identity
        .revoke_webauthn_credential(target.id(), &uid, &cred_id_bytes)
    {
        Ok(()) => {
            tracing::info!(user_id = %uid, admin = %session.user_email, "admin revoked WebAuthn credential");
        }
        Err(e) => {
            tracing::warn!(error = %e, "revoke_webauthn_credential failed");
        }
    }

    Redirect::to(&format!("/ui/admin/users/{user_id}?flash=webauthn_revoked")).into_response()
}

// ---------------------------------------------------------------------------
// Edit user
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/users/:id/edit`.
#[derive(Template)]
#[template(path = "ui/admin/users/edit.html")]
#[allow(clippy::struct_excessive_bools)]
struct UserEditTemplate {
    user: User,
    error: Option<String>,
    form_email: String,
    form_display_name: String,
    form_first_name: String,
    form_last_name: String,
    form_status: String,
    /// Whether the user currently has the `hearth#admin` role.
    is_user_admin: bool,
    /// Organizations this user belongs to (read-only display).
    org_memberships: Vec<UserOrgView>,
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
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// View model for a user's organization membership (displayed on user edit page).
pub struct UserOrgView {
    /// The organization name.
    pub org_name: String,
    /// The organization UUID (for linking to detail page).
    pub org_id: String,
    /// The user's role in the organization.
    pub role: OrganizationRole,
}

/// `GET /ui/admin/users/:id/edit`.
pub async fn admin_user_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };

    match state.identity.get_user(target.id(), &uid) {
        Ok(Some(user)) => {
            let is_user_admin = check_user_admin(&state, target.id(), &uid);
            let org_memberships = resolve_user_org_memberships(&state, target.id(), &uid);
            render(&UserEditTemplate {
                form_email: user.email().to_string(),
                form_display_name: user.display_name().to_string(),
                form_first_name: user.first_name().to_string(),
                form_last_name: user.last_name().to_string(),
                form_status: format!("{:?}", user.status()),
                user,
                error: None,
                is_user_admin,
                org_memberships,
                chrome: true,
                active: "users",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
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
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub status: String,
    /// If present (checkbox checked), the user should have the admin role.
    #[serde(default)]
    pub admin: Option<String>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/users/:id/edit`.
pub async fn admin_user_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
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
        first_name: Some(form.first_name.clone()),
        last_name: Some(form.last_name.clone()),
        status,
        attributes: None,
    };

    match state.identity.update_user(target.id(), &uid, &req) {
        Ok(_updated) => {
            // Sync admin role if changed
            let want_admin = form.admin.is_some();
            let has_admin = check_user_admin(&state, target.id(), &uid);
            if want_admin != has_admin {
                match set_user_admin(&state, target.id(), &uid, want_admin) {
                    Ok(()) => {
                        audit_role_event(
                            &state,
                            &session,
                            target.id(),
                            &uid,
                            want_admin,
                            "hearth",
                            "admin",
                            "admin",
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, user_id = %uid, want_admin, "admin role toggle failed");
                    }
                }
            }
            audit_user_event(&state, &session, &target.0, &uid, "update");
            Redirect::to(&format!("/ui/admin/users/{}", uid.as_uuid())).into_response()
        }
        Err(IdentityError::DuplicateEmail) => render_edit_error(
            &state,
            &session,
            &target.0,
            &uid,
            "A user with that email already exists.",
            &form,
        ),
        Err(IdentityError::InvalidInput { reason }) => {
            render_edit_error(&state, &session, &target.0, &uid, &reason, &form)
        }
        Err(IdentityError::UserNotFound) => super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "update_user failed");
            render_edit_error(
                &state,
                &session,
                &target.0,
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
    target: TargetRealm,
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

    match state.identity.delete_user(target.id(), &uid) {
        Ok(()) => {
            audit_user_event(&state, &session, &target.0, &uid, "delete");
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
    target: &Realm,
    uid: &crate::core::UserId,
    msg: &str,
    form: &EditUserForm,
) -> Response {
    let user = state.identity.get_user(target.id(), uid).ok().flatten();

    match user {
        Some(ref user) => {
            let is_user_admin = check_user_admin(state, target.id(), uid);
            let org_memberships = resolve_user_org_memberships(state, target.id(), uid);
            render(&UserEditTemplate {
                user: user.clone(),
                error: Some(msg.to_string()),
                form_email: form.email.clone(),
                form_display_name: form.display_name.clone(),
                form_first_name: form.first_name.clone(),
                form_last_name: form.last_name.clone(),
                form_status: form.status.clone(),
                is_user_admin,
                org_memberships,
                chrome: true,
                active: "users",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
        None => super::handlers_common::not_found("User not found"),
    }
}

/// Appends a user-management audit event. Best-effort; failure is logged
/// and does not fail the response.
fn audit_user_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    target_realm: &Realm,
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
        realm_id: target_realm.id().clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "user".to_string(),
        resource_id: target_user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "user admin audit append failed");
    }
}

/// Emits a `RoleAssigned` or `RoleRevoked` audit event for a realm-level
/// role change.
///
/// Logged-only on failure: role mutations are already durable in the RBAC
/// engine by the time this is called, so an audit failure must not overturn
/// the operator's action. Downstream readers should treat missing audit
/// entries as observability gaps, not authority gaps.
fn audit_role_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    target_user_id: &crate::core::UserId,
    assigned: bool,
    object_type: &str,
    object_id: &str,
    role: &str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = if assigned {
        AuditAction::RoleAssigned
    } else {
        AuditAction::RoleRevoked
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "user".to_string(),
        resource_id: target_user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({
            "via": "ui",
            "object_type": object_type,
            "object_id": object_id,
            "role": role,
        })),
    }) {
        tracing::warn!(error = %e, "role audit append failed");
    }
}

// =========================================================================
// Realms
// =========================================================================

// Chrome fields for admin templates are inlined per struct initializer
// because Rust macros cannot expand to field initializers.

// ---------------------------------------------------------------------------
// Realm list
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/realms/list.html")]
struct RealmListTemplate {
    realms: Vec<Realm>,
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
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/admin/realms`.
pub async fn admin_realms_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state.identity.list_realms(params.cursor.as_deref(), 20) {
        Ok(page) => render(&RealmListTemplate {
            realms: page.items,
            next_cursor: page.next_cursor,
            chrome: true,
            active: "realms",
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
            tracing::warn!(error = %e, "list_realms failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Realm detail
// ---------------------------------------------------------------------------

/// Display row for a realm administrator (user holding `hearth#admin`).
struct RealmAdminView {
    /// User UUID as string (for form action URLs + code badges).
    user_id: String,
    /// User's display name, falling back to email.
    display_name: String,
    /// User's email.
    email: String,
}

#[derive(Template)]
#[template(path = "ui/admin/realms/detail.html")]
struct RealmDetailTemplate {
    realm: Realm,
    /// Pre-formatted access token TTL (e.g. "15m", "1h").
    access_token_ttl_display: Option<String>,
    /// Pre-formatted refresh token TTL.
    refresh_token_ttl_display: Option<String>,
    /// Pre-formatted lockout duration.
    lockout_duration_display: Option<String>,
    /// Users holding `hearth#admin` on this realm.
    admins: Vec<RealmAdminView>,
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

/// `GET /ui/admin/realms/:id`.
pub async fn admin_realm_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(tid): AxumPath<String>,
) -> Response {
    let realm_id = match tid.parse::<uuid::Uuid>() {
        Ok(u) => RealmId::new(u),
        Err(_) => return super::handlers_common::not_found("Realm not found"),
    };

    match state.identity.get_realm(&realm_id) {
        Ok(Some(realm)) => {
            let cfg = realm.config();
            let access_token_ttl_display = cfg.access_token_ttl_micros.map(format_micros_human);
            let refresh_token_ttl_display = cfg.refresh_token_ttl_micros.map(format_micros_human);
            let lockout_duration_display = cfg.lockout_duration_micros.map(format_micros_human);
            let admins = resolve_realm_admins(&state, realm.id());
            render(&RealmDetailTemplate {
                realm,
                access_token_ttl_display,
                refresh_token_ttl_display,
                lockout_duration_display,
                admins,
                chrome: true,
                active: "realms",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
        Ok(None) => super::handlers_common::not_found("Realm not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_realm failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Delete realm (only Archived realms)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/:id/delete`.
pub async fn admin_realm_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(tid): AxumPath<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_id = match tid.parse::<uuid::Uuid>() {
        Ok(u) => RealmId::new(u),
        Err(_) => return super::handlers_common::not_found("Realm not found"),
    };

    // Only allow permanent deletion of Archived realms.
    match state.identity.get_realm(&realm_id) {
        Ok(Some(realm)) if realm.status() == RealmStatus::Archived => {
            match state.identity.delete_realm(&realm_id) {
                Ok(()) => {
                    audit_realm_event(&state, &session, &realm_id, "delete");
                    Redirect::to("/ui/admin/realms").into_response()
                }
                Err(IdentityError::RealmNotFound) => {
                    super::handlers_common::not_found("Realm not found")
                }
                Err(e) => {
                    tracing::warn!(error = %e, "delete_realm failed");
                    super::handlers_common::server_error()
                }
            }
        }
        Ok(Some(_)) => super::handlers_common::bad_request(
            "Only archived realms can be permanently deleted. Remove the realm from hearth.yaml and restart to archive it first.",
        ),
        Ok(None) => super::handlers_common::not_found("Realm not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_realm failed");
            super::handlers_common::server_error()
        }
    }
}

/// Best-effort audit for realm operations.
fn audit_realm_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::RealmCreated,
        "update" => AuditAction::RealmUpdated,
        "delete" => AuditAction::RealmDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "realm".to_string(),
        resource_id: realm_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "realm admin audit append failed");
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
    target_realm_name: Option<String>,
    target_realm_id_hex: Option<String>,
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
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_clients(target.id(), params.cursor.as_deref(), 20)
    {
        Ok(page) => render(&AppListTemplate {
            applications: page.items,
            next_cursor: page.next_cursor,
            target_realm_name: Some(target.0.name().to_string()),
            target_realm_id_hex: Some(target.id().as_uuid().to_string()),
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
    AxumPath(cid): AxumPath<String>,
) -> Response {
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state.identity.get_client(target.id(), &client_id) {
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
                    client_secret: Some(new_secret),
                    chrome: true,
                    active: "applications",
                    user_email: Some(session.user_email.clone()),
                    is_admin: true,
                    flash: None,
                    csrf: session.csrf.clone(),
                    narrow: true,
                    product_name: state.product_name.clone(),
                    logo_url: state.logo_url.clone(),
                    theme_css: state.theme_css.clone(),
                    realm_theme_css: state.realm_theme_css(),
                }),
                _ => Redirect::to(&format!("/ui/admin/applications/{}", client_id.as_uuid()))
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
    /// Device label (e.g. "Chrome, Mac OSX") or "Unknown device".
    pub device_label: String,
    /// Client IP address or "\u{2014}" (em dash) if unavailable.
    pub ip_address: String,
}

#[derive(Template)]
#[template(path = "ui/admin/sessions/list.html")]
struct SessionListTemplate {
    sessions: Vec<SessionRow>,
    next_cursor: Option<String>,
    target_realm_name: Option<String>,
    target_realm_id_hex: Option<String>,
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

/// Formats a `Timestamp` (Unix micros) as `YYYY-MM-DD HH:MM UTC`.
/// Checks if a specific user has the `hearth.admin` permission.
fn check_user_admin(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> bool {
    match state
        .rbac
        .resolve_permissions(user_id, realm_id, None, None)
    {
        Ok(resolved) => resolved
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin"),
        Err(_) => false,
    }
}

/// Resolves the list of organizations a user belongs to (for display on the user edit page).
fn resolve_user_org_memberships(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> Vec<UserOrgView> {
    let memberships = state
        .identity
        .list_user_organizations(realm_id, user_id, None, 50)
        .map(|p| p.items)
        .unwrap_or_default();

    memberships
        .into_iter()
        .map(|m| {
            let org_name = state
                .identity
                .get_organization(realm_id, m.org_id())
                .ok()
                .flatten()
                .map_or_else(
                    || m.org_id().as_uuid().to_string(),
                    |o| o.name().to_string(),
                );
            UserOrgView {
                org_name,
                org_id: m.org_id().as_uuid().to_string(),
                role: m.role(),
            }
        })
        .collect()
}

/// Grants or revokes the `realm.admin` role for a user.
///
/// Grant: seeds defaults (idempotent) and calls `assign_role` with the
/// seed `realm.admin` role.
/// Revoke: enumerates the user's assignments and removes every
/// `realm.admin` binding.
fn set_user_admin(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
    grant: bool,
) -> Result<(), crate::rbac::RbacError> {
    state.rbac.seed_realm(realm_id)?;
    let role = state
        .rbac
        .get_role_by_name(realm_id, "realm.admin")?
        .ok_or(crate::rbac::RbacError::RoleNotFound)?;
    if grant {
        state.rbac.assign_role(
            realm_id,
            &crate::rbac::AssignRoleRequest {
                subject: crate::rbac::Subject::User(user_id.clone()),
                role_id: role.id.clone(),
                scope: crate::rbac::Scope::Realm,
                assigned_by: None,
            },
        )?;
    } else {
        // Revoke every (user, role=realm.admin) assignment.
        let assignments = state.rbac.list_user_assignments(realm_id, user_id)?;
        for a in assignments {
            if a.role_id == role.id {
                state.rbac.unassign_role(realm_id, &a.id)?;
            }
        }
    }
    Ok(())
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

/// Formats a duration in microseconds as a human-readable string.
///
/// Examples: `900_000_000` → "15m", `86_400_000_000` → "24h", `3_600_000_000` → "1h".
fn format_micros_human(micros: i64) -> String {
    let secs = micros / 1_000_000;
    if secs <= 0 {
        return "0s".to_string();
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if mins > 0 {
        parts.push(format!("{mins}m"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
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
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> String {
    state
        .identity
        .get_user(realm_id, user_id)
        .ok()
        .flatten()
        .map_or_else(|| "(unknown)".to_string(), |u| u.email().to_string())
}

/// `GET /ui/admin/sessions`.
pub async fn admin_sessions_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_sessions_by_realm(target.id(), params.cursor.as_deref(), 20)
    {
        Ok(page) => {
            let rows: Vec<SessionRow> = page
                .items
                .into_iter()
                .map(|s| {
                    let email = resolve_user_email(&state, target.id(), s.user_id());
                    let device_label = s.device_label().unwrap_or("Unknown device").to_string();
                    let ip_address = s.ip_address().unwrap_or("\u{2014}").to_string();
                    SessionRow {
                        created_at_display: format_ts(s.created_at()),
                        expires_at_display: format_ts(s.expires_at()),
                        session: s,
                        user_email: email,
                        device_label,
                        ip_address,
                    }
                })
                .collect();
            render(&SessionListTemplate {
                sessions: rows,
                next_cursor: page.next_cursor,
                target_realm_name: Some(target.0.name().to_string()),
                target_realm_id_hex: Some(target.id().as_uuid().to_string()),
                active_tab: "sessions",
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
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "list_sessions_by_realm failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/sessions/:id/revoke`.
pub async fn admin_session_revoke(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
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

    match state.identity.revoke_session(target.id(), &session_id) {
        Ok(()) => {
            audit_session_event(&state, &session, &target.0, &session_id, "revoke");
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
    target_realm: &Realm,
    target_session_id: &SessionId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "revoke" => AuditAction::SessionRevoked,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: target_realm.id().clone(),
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
    /// Start date filter (`YYYY-MM-DD`).
    #[serde(default)]
    pub start_date: Option<String>,
    /// End date filter (`YYYY-MM-DD`).
    #[serde(default)]
    pub end_date: Option<String>,
    /// Maximum events to show.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Parses a `YYYY-MM-DD` date string into a `Timestamp` (start of that day, UTC).
fn parse_date_to_timestamp(date_str: &str) -> Option<crate::core::Timestamp> {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Simplified: compute days since epoch using a known-good formula
    // This is accurate for dates from 2000-2099
    let mut m = month;
    let mut y = year;
    if m <= 2 {
        m += 12;
        y -= 1;
    }
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + day - 719_469;
    Some(crate::core::Timestamp::from_micros(
        days * 86_400 * 1_000_000,
    ))
}

#[derive(Template)]
#[template(path = "ui/admin/audit/list.html")]
struct AuditListTemplate {
    events: Vec<AuditRow>,
    form_actor: String,
    form_action: String,
    form_start_date: String,
    form_end_date: String,
    form_limit: String,
    flash_message: Option<String>,
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

/// Rows-only partial returned when the audit filter is triggered via HTMX.
#[derive(Template)]
#[template(path = "ui/admin/audit/_rows_only.html")]
#[allow(dead_code)]
struct AuditRowsTemplate {
    events: Vec<AuditRow>,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/admin/audit`.
pub async fn admin_audit_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    htmx: super::templates::IsHtmx,
    Query(params): Query<AuditFilterParams>,
) -> Response {
    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());

    let start_time = params
        .start_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(parse_date_to_timestamp);
    let end_time = params
        .end_date
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|d| {
            // End date is exclusive — advance to start of next day
            parse_date_to_timestamp(d).map(|t| t.add_micros(86_400 * 1_000_000))
        });

    let limit = params.limit.unwrap_or(50).min(200);
    let query = crate::audit::AuditQuery {
        realm_id: target.id().clone(),
        start_time,
        end_time,
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
                    theme_css: state.theme_css.clone(),
                    realm_theme_css: None,
                })
            } else {
                render(&AuditListTemplate {
                    events: rows,
                    form_actor: params.actor.unwrap_or_default(),
                    form_action: params.action.unwrap_or_default(),
                    form_start_date: params.start_date.unwrap_or_default(),
                    form_end_date: params.end_date.unwrap_or_default(),
                    form_limit: limit.to_string(),
                    flash_message: None,
                    chrome: true,
                    active: "audit",
                    user_email: Some(session.user_email.clone()),
                    is_admin: true,
                    flash: None,
                    csrf: session.csrf.clone(),
                    narrow: false,
                    product_name: state.product_name.clone(),
                    logo_url: state.logo_url.clone(),
                    theme_css: state.theme_css.clone(),
                    realm_theme_css: state.realm_theme_css(),
                })
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit query failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/audit/verify` — verifies audit log integrity.
pub async fn admin_audit_verify_integrity(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
) -> Response {
    match state.audit.verify_integrity(target.id(), None, None) {
        Ok(true) => render(&AuditListTemplate {
            events: Vec::new(),
            form_actor: String::new(),
            form_action: String::new(),
            form_start_date: String::new(),
            form_end_date: String::new(),
            form_limit: "50".to_string(),
            flash_message: Some("Audit chain integrity verified successfully.".to_string()),
            chrome: true,
            active: "audit",
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
        Ok(false) => render(&AuditListTemplate {
            events: Vec::new(),
            form_actor: String::new(),
            form_action: String::new(),
            form_start_date: String::new(),
            form_end_date: String::new(),
            form_limit: "50".to_string(),
            flash_message: Some(
                "Integrity violation detected! The audit chain may have been tampered with."
                    .to_string(),
            ),
            chrome: true,
            active: "audit",
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
            tracing::warn!(error = %e, "audit verify_integrity failed");
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
    target: TargetRealm,
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
            let realm_branding = state
                .identity
                .get_realm(target.id())
                .ok()
                .flatten()
                .and_then(|t| t.config().email_branding.clone());
            match email_service.send_test_email(email, realm_branding.as_ref()) {
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
    target_realm_name: Option<String>,
    target_realm_id_hex: Option<String>,
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

/// `GET /ui/admin/organizations`.
pub async fn admin_orgs_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .identity
        .list_organizations(target.id(), params.cursor.as_deref(), 20)
    {
        Ok(page) => render(&OrgListTemplate {
            organizations: page.items,
            next_cursor: page.next_cursor,
            target_realm_name: Some(target.0.name().to_string()),
            target_realm_id_hex: Some(target.id().as_uuid().to_string()),
            active_tab: "organizations",
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
    form_max_members: Option<u32>,
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
        form_max_members: None,
        chrome: true,
        active: "organizations",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
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
    #[serde(default)]
    pub max_members: Option<u32>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/new`.
pub async fn admin_org_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
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

    let config = form.max_members.map(|max_members| OrganizationConfig {
        max_members: Some(max_members),
    });

    match state.identity.create_organization(
        target.id(),
        &CreateOrganizationRequest {
            name: form.name.clone(),
            slug: form.slug.clone(),
            description,
            config,
        },
    ) {
        Ok(org) => {
            audit_org_event(&state, &session, &target.0, org.id(), "create");
            Redirect::to(&format!("/ui/admin/organizations/{}", org.id().as_uuid())).into_response()
        }
        Err(IdentityError::DuplicateOrgSlug) => render(&OrgNewTemplate {
            error: Some("An organization with that slug already exists.".to_string()),
            form_name: form.name,
            form_slug: form.slug,
            form_description: form.description,
            form_max_members: form.max_members,
            chrome: true,
            active: "organizations",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "create_organization failed");
            render(&OrgNewTemplate {
                error: Some(format!("Unable to create organization: {e}")),
                form_name: form.name,
                form_slug: form.slug,
                form_description: form.description,
                form_max_members: form.max_members,
                chrome: true,
                active: "organizations",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: true,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
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
    /// Org UUID string — shared with embedded partials via `{% include %}`.
    org_id: String,
    members: Vec<MemberWithAccess>,
    invitations: Vec<OrganizationInvitation>,
    max_members: Option<u32>,
    /// All realm roles for the per-member assign form.
    available_roles: Vec<AvailableRole>,
    /// Permission suggestions for the per-member grant form (datalist).
    available_permissions: Vec<String>,
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
    target: TargetRealm,
    AxumPath(oid): AxumPath<String>,
    Query(params): Query<OrgDetailParams>,
) -> Response {
    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let org = match state.identity.get_organization(target.id(), &org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return super::handlers_common::not_found("Organization not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_organization failed");
            return super::handlers_common::server_error();
        }
    };

    let memberships = state
        .identity
        .list_members(target.id(), &org_id, None, 100)
        .map(|p| p.items)
        .unwrap_or_default();

    let available_roles = build_org_available_roles(&state, target.id());
    let available_permissions = collect_org_permissions(&state, target.id());
    let org_id_str = org_id.as_uuid().to_string();

    // Resolve user details and RBAC access for each membership
    let members: Vec<MemberWithAccess> = memberships
        .into_iter()
        .map(|m| {
            let (name, email) = state
                .identity
                .get_user(target.id(), m.user_id())
                .ok()
                .flatten()
                .map_or_else(
                    || (m.user_id().as_uuid().to_string(), String::from("(unknown)")),
                    |u| (u.display_name().to_string(), u.email().to_string()),
                );
            let view = MemberView {
                membership: m,
                user_name: name,
                user_email: email,
            };
            build_member_with_access(&state, target.id(), &org_id, view)
        })
        .collect();

    let invitations = state
        .identity
        .list_invitations(target.id(), &org_id, None, 100)
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

    let max_members = org.config().max_members;

    render(&OrgDetailTemplate {
        org,
        org_id: org_id_str,
        members,
        invitations,
        max_members,
        available_roles,
        available_permissions,
        chrome: true,
        active: "organizations",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
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
    form_max_members: Option<u32>,
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

/// `GET /ui/admin/organizations/:id/edit`.
pub async fn admin_org_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(oid): AxumPath<String>,
) -> Response {
    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    match state.identity.get_organization(target.id(), &org_id) {
        Ok(Some(org)) => render(&OrgEditTemplate {
            form_name: org.name().to_string(),
            form_description: org.description().to_string(),
            form_status: format!("{:?}", org.status()),
            form_max_members: org.config().max_members,
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
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
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
    #[serde(default)]
    pub max_members: Option<u32>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/edit`.
pub async fn admin_org_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
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

    let org_config = Some(OrganizationConfig {
        max_members: form.max_members,
    });

    match state.identity.update_organization(
        target.id(),
        &org_id,
        &UpdateOrganizationRequest {
            name: Some(form.name.clone()),
            description,
            status,
            config: org_config,
        },
    ) {
        Ok(_) => {
            audit_org_event(&state, &session, &target.0, &org_id, "update");
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
    target: TargetRealm,
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

    match state.identity.delete_organization(target.id(), &org_id) {
        Ok(()) => {
            audit_org_event(&state, &session, &target.0, &org_id, "delete");
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
    target: TargetRealm,
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
        .add_member(target.id(), &org_id, &user_id, role)
    {
        Ok(_) => {
            mirror_org_member_added(&state, &session, target.id(), &org_id, &user_id, role);
            org_redirect_flash(&org_id, "Member added successfully", "success")
        }
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
// Member picker modal (HTMX)
// ---------------------------------------------------------------------------

/// Template for the inline picker rows partial. Rendered as the response
/// to `GET /ui/admin/organizations/:id/members/picker` and swapped into
/// `#member-picker-results` on the org detail page.
#[derive(Template)]
#[template(path = "ui/admin/organizations/_member_picker_rows.html")]
#[allow(dead_code)]
struct MemberPickerRowsTemplate {
    org_id: String,
    users: Vec<User>,
    query: String,
    next_cursor: Option<String>,
    csrf: Option<String>,
    /// All realm roles for the per-row role dropdown (replaces hardcoded Member/Admin/Owner).
    available_roles: Vec<AvailableRole>,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// Template for a single member row (`<tbody>`). Included by `detail.html` in the
/// member loop, and returned standalone as an HTMX partial from role/perm handlers
/// so the row block swaps in place without a full-page reload.
#[derive(Template)]
#[template(path = "ui/admin/organizations/_member_row.html")]
#[allow(dead_code)]
struct MemberRowTemplate {
    org_id: String,
    m: MemberWithAccess,
    /// All realm roles for the assign-role inline form.
    available_roles: Vec<AvailableRole>,
    /// Permission suggestions for the grant-permission inline form (datalist).
    available_permissions: Vec<String>,
    csrf: Option<String>,
}

/// Query params for member picker.
#[derive(Debug, Deserialize)]
pub struct MemberPickerParams {
    /// Search query.
    #[serde(default)]
    pub q: String,
    /// Pagination cursor.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// `GET /ui/admin/organizations/:id/members/picker` — inline search results.
///
/// Rendered into `#member-picker-results` on the org detail page via HTMX.
/// Always returns the rows partial; there is no modal wrapper.
pub async fn admin_org_member_picker(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(oid): AxumPath<String>,
    Query(params): Query<MemberPickerParams>,
) -> Response {
    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let query = params.q.trim().to_string();
    let page = if query.len() >= 2 {
        state
            .identity
            .search_users(target.id(), &query, 20)
            .map(|users| Page {
                items: users,
                next_cursor: None,
            })
    } else {
        state
            .identity
            .list_users(target.id(), params.cursor.as_deref(), 20)
    };

    let (users, next_cursor) = match page {
        Ok(p) => (p.items, p.next_cursor),
        Err(e) => {
            tracing::warn!(error = %e, "member picker list_users failed");
            (Vec::new(), None)
        }
    };

    let org_id_str = org_id.as_uuid().to_string();

    // The picker is always rendered inline into `#member-picker-results`
    // on the org detail page — no modal wrapper. CSRF is threaded in so
    // each per-row Add form can echo the token.
    let available_roles = build_org_available_roles(&state, target.id());
    render(&MemberPickerRowsTemplate {
        org_id: org_id_str,
        users,
        query,
        next_cursor,
        csrf: session.csrf.clone(),
        available_roles,
        product_name: String::new(),
        logo_url: String::new(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: None,
    })
}

// ---------------------------------------------------------------------------
// Remove member
// ---------------------------------------------------------------------------

/// `POST /ui/admin/organizations/:id/members/:uid/remove`.
///
/// HTMX caller (confirm-to-remove button in the members table) gets an
/// empty body + `HX-Trigger: showToast`, which the `hx-swap="outerHTML"`
/// on the row form interprets as "replace the row with nothing." Plain
/// form POST (curl, no-JS) gets the familiar redirect-with-flash.
pub async fn admin_org_remove_member(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
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

    let is_htmx = is_htmx_request(&headers);

    // Capture the role before removal so we can emit the matching
    // audit event. If lookup fails, we still proceed with the remove.
    let prior_role = state
        .identity
        .get_membership(target.id(), &org_id, &user_id)
        .ok()
        .flatten()
        .map(|m| m.role());

    match state.identity.remove_member(target.id(), &org_id, &user_id) {
        Ok(()) => {
            if let Some(role) = prior_role {
                mirror_org_member_removed(&state, &session, target.id(), &org_id, &user_id, role);
            }
            if is_htmx {
                super::templates::htmx_toast_response("Member removed", "success")
            } else {
                org_redirect_flash(&org_id, "Member removed", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "remove_member failed");
            let msg = format!("{e}");
            if is_htmx {
                // Return the row unchanged so HTMX's outerHTML swap puts
                // the member back — the server is the source of truth.
                // Re-render by fetching the membership; if that fails,
                // fall back to an empty error toast.
                if let Ok(Some(m)) = state
                    .identity
                    .get_membership(target.id(), &org_id, &user_id)
                {
                    return render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        &msg,
                        "error",
                    );
                }
                super::templates::htmx_toast_response(&msg, "error")
            } else {
                org_redirect_flash(&org_id, &msg, "error")
            }
        }
    }
}

/// Returns `true` when the request carries the `HX-Request: true` header
/// that HTMX attaches to every fetch it initiates.
fn is_htmx_request(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "true")
}

/// Re-renders a single member `<tbody>` block with an attached `HX-Trigger: showToast`.
/// Used by role-update, perm grant/revoke, and RBAC assign/unassign handlers
/// to swap the row block in place while firing a client-side toast.
fn render_member_row_with_toast(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm: &RealmId,
    org_id: &OrganizationId,
    m: OrganizationMembership,
    message: &str,
    kind: &str,
) -> Response {
    let (name, email) = state
        .identity
        .get_user(realm, m.user_id())
        .ok()
        .flatten()
        .map_or_else(
            || (m.user_id().as_uuid().to_string(), String::from("(unknown)")),
            |u| (u.display_name().to_string(), u.email().to_string()),
        );
    let view = MemberView {
        membership: m,
        user_name: name,
        user_email: email,
    };
    let m_access = build_member_with_access(state, realm, org_id, view);
    let available_roles = build_org_available_roles(state, realm);
    let available_permissions = collect_org_permissions(state, realm);
    let tmpl = MemberRowTemplate {
        org_id: org_id.as_uuid().to_string(),
        m: m_access,
        available_roles,
        available_permissions,
        csrf: session.csrf.clone(),
    };
    let mut response = render(&tmpl);
    let json = format!(
        r#"{{"showToast":{{"message":"{}","kind":"{}"}}}}"#,
        message.replace('"', r#"\""#),
        kind.replace('"', r#"\""#),
    );
    if let Ok(val) = axum::http::HeaderValue::from_str(&json) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            val,
        );
    }
    response
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
///
/// HTMX caller (role dropdown with `hx-trigger="change"`) receives the
/// refreshed member row partial + `HX-Trigger: showToast` so the row
/// updates in place and a toast confirms the change. Plain-form caller
/// (curl, no-JS) gets the familiar redirect-with-flash so scripted
/// integrations keep working.
pub async fn admin_org_update_role(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
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

    let new_role = parse_org_role(&form.role);
    let is_htmx = is_htmx_request(&headers);
    // Capture the old role before update so we can emit paired
    // role-removed / role-added audit events.
    let old_role = state
        .identity
        .get_membership(target.id(), &org_id, &user_id)
        .ok()
        .flatten()
        .map(|m| m.role());

    match state
        .identity
        .update_member_role(target.id(), &org_id, &user_id, new_role)
    {
        Ok(_) => {
            if let Some(old) = old_role {
                mirror_org_role_changed(
                    &state,
                    &session,
                    target.id(),
                    &org_id,
                    &user_id,
                    old,
                    new_role,
                );
            } else {
                // Legacy record existed before our lookup but lookup failed
                // — fall back to treating this as a fresh add so the tuple
                // at least lands for the new role.
                mirror_org_member_added(&state, &session, target.id(), &org_id, &user_id, new_role);
            }
            if is_htmx {
                if let Ok(Some(m)) = state.identity.get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        "Role updated",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Role updated", "success")
                }
            } else {
                org_redirect_flash(&org_id, "Role updated", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_member_role failed");
            let msg = format!("{e}");
            if is_htmx {
                if let Ok(Some(m)) = state.identity.get_membership(target.id(), &org_id, &user_id)
                {
                    return render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        &msg,
                        "error",
                    );
                }
                super::templates::htmx_toast_response(&msg, "error")
            } else {
                org_redirect_flash(&org_id, &msg, "error")
            }
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
    target: TargetRealm,
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
        target.id(),
        &CreateInvitationRequest {
            org_id: org_id.clone(),
            email: form.email.clone(),
            role,
            invited_by: session.user_id.clone(),
        },
    ) {
        Ok((_invitation, token)) => {
            // Send invitation email if email service is configured
            if let Some(ref email_service) = state.email {
                let org_name = state
                    .identity
                    .get_organization(target.id(), &org_id)
                    .ok()
                    .flatten()
                    .map_or_else(|| "your organization".to_string(), |o| o.name().to_string());

                let base_url = state
                    .config
                    .as_ref()
                    .and_then(|c| c.onboarding.base_url.clone())
                    .unwrap_or_else(|| "https://hearth.local".to_string());
                let accept_url = format!("{base_url}/ui/accept-invitation?token={token}");

                let realm_branding = state
                    .identity
                    .get_realm(target.id())
                    .ok()
                    .flatten()
                    .and_then(|t| t.config().email_branding.clone());

                if let Err(e) = email_service.send_invitation_email(
                    &form.email,
                    &accept_url,
                    &org_name,
                    &session.user_email,
                    realm_branding.as_ref(),
                ) {
                    tracing::warn!(error = %e, "failed to send invitation email");
                }
            }
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
    target: TargetRealm,
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
        .revoke_invitation(target.id(), &invitation_id)
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
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// `GET /ui/admin/api/users/search?q=...` — returns HTML fragment for HTMX.
pub async fn admin_api_user_search(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    Query(params): Query<UserSearchParams>,
) -> Response {
    let query = params.q.trim().to_string();
    let users = if query.len() < 2 {
        Vec::new()
    } else {
        state
            .identity
            .search_users(target.id(), &query, 10)
            .unwrap_or_default()
    };

    render(&UserSearchResultsTemplate {
        users,
        query,
        product_name: String::new(),
        logo_url: String::new(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: None,
    })
}

// ---------------------------------------------------------------------------
// Config reload API
// ---------------------------------------------------------------------------

/// Form body for `POST /ui/admin/switch-realm`.
#[derive(Debug, serde::Deserialize)]
pub struct SwitchRealmForm {
    /// Target realm name. Validated by [`super::auth::TargetRealm`]
    /// on the next admin request; persisted in the
    /// `hearth_ui_admin_target` cookie here.
    pub realm: String,
    /// CSRF token echoed from the `hearth_ui_csrf` cookie.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    /// Optional `return_to` path — admins usually land back on the
    /// same page they were administering.
    #[serde(default)]
    pub return_to: Option<String>,
}

/// `POST /ui/admin/switch-realm` — changes the admin's currently-
/// targeted application realm by setting the
/// `hearth_ui_admin_target` cookie. Redirects back to `return_to`.
pub async fn admin_switch_realm(
    State(_state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<SwitchRealmForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    // The realm name is NOT validated here — TargetRealm validates on
    // every subsequent request and falls back to the first realm if
    // the cookie is stale. Keep this handler cheap: no storage hit.
    // Reject the reserved system name to avoid an obviously-wrong
    // cookie value being set.
    if form.realm == crate::identity::keys::SYSTEM_REALM_NAME || form.realm.is_empty() {
        return (StatusCode::BAD_REQUEST, "invalid realm name").into_response();
    }

    // Default landing page after a switch is the realm workspace's
    // Users tab with `?realm=<name>` so the operator sees the workspace
    // chrome (breadcrumb + tab bar) instead of a flat "Users" view that
    // hides the scope.
    let default_return_to = format!("/ui/admin/users?realm={}", form.realm);
    let return_to = form
        .return_to
        .as_deref()
        .and_then(super::auth::sanitize_return_to)
        .unwrap_or(default_return_to);

    let cookie = format!(
        "{}={}; HttpOnly; Path=/ui; SameSite=Lax",
        super::auth::ADMIN_TARGET_COOKIE,
        form.realm,
    );
    let mut response = Redirect::to(&return_to).into_response();
    #[allow(clippy::unwrap_used)]
    let cookie_header = axum::http::HeaderValue::from_str(&cookie).unwrap();
    response.headers_mut().append("set-cookie", cookie_header);
    response
}

/// `POST /admin/api/config/reload` — triggers config hot-reload.
///
/// `GET /ui/admin/_nav/realms.json` — returns the realm list used by the
/// sidebar navigation tree. Client-rendered (Alpine.js) so we don't need
/// to thread the list through every admin template struct.
///
/// Filters out the system realm (which is reachable via separate top-level
/// links: `Admin Users`, `Realms`, `System Info`). Includes archived realms
/// with a flag so the sidebar can dim them.
pub async fn admin_api_nav_realms(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
) -> Response {
    let mut items: Vec<serde_json::Value> = Vec::new();
    let system_id = crate::identity::keys::system_realm_id();
    let mut cursor: Option<String> = None;
    loop {
        let page = match state.identity.list_realms(cursor.as_deref(), 100) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "list_realms failed in nav endpoint");
                return super::handlers_common::server_error();
            }
        };
        for realm in &page.items {
            if realm.id() == &system_id {
                continue;
            }
            items.push(serde_json::json!({
                "name": realm.name(),
                "archived": realm.status() == RealmStatus::Archived,
            }));
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    axum::response::Json(serde_json::json!({ "realms": items })).into_response()
}

/// Notifies the SIGHUP handler loop to re-read the config file and run
/// reconciliation. Returns a JSON acknowledgement.
pub async fn admin_api_config_reload(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
) -> Response {
    if let Some(notify) = &state.reload_notify {
        notify.notify_one();
        axum::response::Json(serde_json::json!({
            "status": "ok",
            "message": "configuration reload triggered"
        }))
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::response::Json(serde_json::json!({
                "status": "error",
                "message": "reload not available (no config file loaded)"
            })),
        )
            .into_response()
    }
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
    target_realm: &Realm,
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
        realm_id: target_realm.id().clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "organization".to_string(),
        resource_id: org_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "org admin audit append failed");
    }
}

// =========================================================================
// System Info
// =========================================================================

/// Template for `GET /ui/admin/settings`.
#[derive(Template)]
#[template(path = "ui/admin/settings/system.html")]
struct SystemInfoTemplate {
    /// Full server configuration. `None` when running without a config file
    /// (e.g. in embedded tests).
    config: Option<Arc<Config>>,
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

/// `GET /ui/admin/settings` — read-only system information page.
pub async fn admin_system_info(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
) -> Response {
    render(&SystemInfoTemplate {
        config: state.config.clone(),
        chrome: true,
        active: "settings",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// Config Editor
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/settings/editor`.
#[derive(Template)]
#[template(path = "ui/admin/settings/editor.html")]
#[allow(dead_code, clippy::struct_excessive_bools)]
struct ConfigEditorTemplate {
    yaml_content: String,
    /// JSON representation of the raw YAML tree (for the visual editor).
    config_json: String,
    read_only: bool,
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

/// Template for the diff preview partial.
#[derive(Template)]
#[template(path = "ui/admin/settings/_diff_preview.html")]
#[allow(dead_code)]
struct DiffPreviewTemplate {
    diff: String,
    diff_lines: Vec<String>,
    error: Option<String>,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// Form data for config editor actions.
#[derive(Debug, Deserialize)]
pub struct ConfigEditorForm {
    #[serde(default)]
    pub yaml: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Query params for config editor page (flash messages via redirect).
#[derive(Debug, Deserialize)]
pub struct ConfigEditorParams {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_kind: Option<String>,
}

/// `GET /ui/admin/settings/editor` — config editor page.
pub async fn admin_config_editor(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<ConfigEditorParams>,
) -> Response {
    let (yaml_content, read_only) = read_config_yaml(&state);
    let config_json = yaml_to_editor_json(&yaml_content).unwrap_or_else(|_| "{}".to_string());

    let flash = params.flash.map(|msg| {
        let kind = params.flash_kind.as_deref().unwrap_or("success");
        if kind == "error" {
            Flash::error(msg)
        } else {
            Flash::success(msg)
        }
    });

    render(&ConfigEditorTemplate {
        yaml_content,
        config_json,
        read_only,
        chrome: true,
        active: "settings",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

/// `POST /ui/admin/settings/editor/preview` — HTMX diff preview.
pub async fn admin_config_editor_preview(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    Form(form): Form<ConfigEditorForm>,
) -> Response {
    let new_yaml = form.yaml;

    // Validate the new config
    let validation_error = Config::from_yaml_str(&new_yaml)
        .err()
        .map(|e| e.to_string());

    let diff = if validation_error.is_some() {
        String::new()
    } else {
        let (old_yaml, _) = read_config_yaml(&state);
        compute_unified_diff(&old_yaml, &new_yaml)
    };

    let diff_lines: Vec<String> = diff.lines().map(String::from).collect();

    render(&DiffPreviewTemplate {
        diff,
        diff_lines,
        error: validation_error,
        product_name: String::new(),
        logo_url: String::new(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: None,
    })
}

/// `POST /ui/admin/settings/editor/apply` — validate, write to disk, trigger reload.
pub async fn admin_config_editor_apply(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    Form(form): Form<ConfigEditorForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let new_yaml = form.yaml;

    // Validate first
    if let Err(e) = Config::from_yaml_str(&new_yaml) {
        return render_config_editor_with_flash(
            &state,
            &session,
            &new_yaml,
            Flash::error(format!("Validation failed: {e}")),
        );
    }

    // Write to disk
    let Some(config_path) = &state.config_path else {
        return render_config_editor_with_flash(
            &state,
            &session,
            &new_yaml,
            Flash::error("No config file path configured — cannot write".to_string()),
        );
    };

    if let Err(e) = std::fs::write(config_path, &new_yaml) {
        tracing::error!(error = %e, "failed to write config file");
        return render_config_editor_with_flash(
            &state,
            &session,
            &new_yaml,
            Flash::error(format!("Failed to write file: {e}")),
        );
    }

    // Trigger hot-reload
    if let Some(notify) = &state.reload_notify {
        notify.notify_one();
    }

    tracing::info!("config file updated via editor, reload triggered");

    Redirect::to(
        "/ui/admin/settings/editor?flash=Configuration+applied+successfully&flash_kind=success",
    )
    .into_response()
}

/// `GET /ui/admin/settings/editor/export` — download the current YAML file.
pub async fn admin_config_editor_export(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
) -> Response {
    let (yaml_content, _) = read_config_yaml(&state);

    (
        [
            (axum::http::header::CONTENT_TYPE, "application/x-yaml"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"hearth.yaml\"",
            ),
        ],
        yaml_content,
    )
        .into_response()
}

/// `POST /ui/admin/settings/editor/visual/export` — convert the visual editor's
/// JSON state to YAML and return it as plain text. This lets the export modal
/// show the *current* editor state rather than the on-disk file, which matters
/// in read-only / container environments where "Apply" cannot write to disk.
pub async fn admin_config_editor_visual_export(
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    match editor_json_to_yaml(&json) {
        Ok(yaml) => (StatusCode::OK, yaml).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

// --- Config editor helpers ---

/// Reads the raw YAML from the config file on disk.
/// Returns `(yaml_content, read_only)`. `read_only` is true when no file path is available.
fn read_config_yaml(state: &Arc<WebState>) -> (String, bool) {
    match &state.config_path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(content) => (content, false),
            Err(e) => {
                tracing::warn!(error = %e, "failed to read config file for editor");
                (format!("# Error reading config file: {e}"), true)
            }
        },
        None => (
            "# No config file path available.\n# Running in embedded/dev mode.\n".to_string(),
            true,
        ),
    }
}

/// Renders the config editor template with a flash message (for inline error display).
fn render_config_editor_with_flash(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    yaml_content: &str,
    flash: Flash,
) -> Response {
    let read_only = state.config_path.is_none();
    let config_json = yaml_to_editor_json(yaml_content).unwrap_or_else(|_| "{}".to_string());
    render(&ConfigEditorTemplate {
        yaml_content: yaml_content.to_string(),
        config_json,
        read_only,
        chrome: true,
        active: "settings",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: Some(flash),
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// --- Visual config editor helpers ---

/// Parses raw YAML (without env substitution) into a JSON string for the
/// visual editor. Env var references like `${PORT:-8420}` stay as literal
/// strings in the JSON.
fn yaml_to_editor_json(yaml_str: &str) -> Result<String, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml_str).map_err(|e| format!("YAML parse error: {e}"))?;
    serde_json::to_string(&value).map_err(|e| format!("JSON serialization error: {e}"))
}

/// Try to extract a dotted field path from a `serde_yaml` parse error.
///
/// `serde_yaml` errors for type mismatches typically look like:
/// `server.port: invalid type: string "asdf", expected u16 at line 3 column 9`
///
/// Returns the extracted field path, or `"_yaml"` if no path can be parsed.
fn field_from_parse_error(msg: &str) -> &str {
    if let Some(pos) = msg.find(": ") {
        let candidate = &msg[..pos];
        if !candidate.is_empty()
            && candidate.contains('.')
            && candidate
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        {
            return candidate;
        }
    }
    "_yaml"
}

/// Converts editor JSON back to a YAML string. The resulting YAML is
/// machine-generated (no comments, consistent ordering).
fn editor_json_to_yaml(json: &serde_json::Value) -> Result<String, String> {
    let value: serde_yaml::Value =
        serde_json::from_value(json.clone()).map_err(|e| format!("JSON→YAML conversion: {e}"))?;
    serde_yaml::to_string(&value).map_err(|e| format!("YAML serialization error: {e}"))
}

/// `POST /ui/admin/settings/editor/visual/preview` — JSON-based diff preview.
///
/// Accepts the visual editor's config state as a JSON body, converts to YAML,
/// validates via the full `Config::from_yaml_str` pipeline, and returns a
/// diff preview HTML partial.
pub async fn admin_config_editor_visual_preview(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    let new_yaml = match editor_json_to_yaml(&json) {
        Ok(y) => y,
        Err(e) => {
            return render(&DiffPreviewTemplate {
                diff: String::new(),
                diff_lines: Vec::new(),
                error: Some(e),
                product_name: String::new(),
                logo_url: String::new(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: None,
            });
        }
    };

    let validation_error = Config::from_yaml_str(&new_yaml)
        .err()
        .map(|e| e.to_string());

    let diff = if validation_error.is_some() {
        String::new()
    } else {
        let (old_yaml, _) = read_config_yaml(&state);
        compute_unified_diff(&old_yaml, &new_yaml)
    };

    let diff_lines: Vec<String> = diff.lines().map(String::from).collect();

    render(&DiffPreviewTemplate {
        diff,
        diff_lines,
        error: validation_error,
        product_name: String::new(),
        logo_url: String::new(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: None,
    })
}

/// `POST /ui/admin/settings/editor/visual/validate` — JSON-based validation.
///
/// Accepts the visual editor's config state as JSON, converts to YAML,
/// parses without validation, then runs `validate_all()` to collect every
/// issue. Returns a JSON response with field-level errors.
pub async fn admin_config_editor_visual_validate(
    State(_state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    let new_yaml = match editor_json_to_yaml(&json) {
        Ok(y) => y,
        Err(e) => {
            return axum::response::Json(serde_json::json!({
                "valid": false,
                "errors": [{ "field": "_yaml", "reason": e }],
            }))
            .into_response();
        }
    };

    let config = match Config::from_yaml_str_unchecked(&new_yaml) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            let field = field_from_parse_error(&msg);
            return axum::response::Json(serde_json::json!({
                "valid": false,
                "errors": [{ "field": field, "reason": msg }],
            }))
            .into_response();
        }
    };

    let issues = config.validate_all();
    let valid = issues.is_empty();

    axum::response::Json(serde_json::json!({
        "valid": valid,
        "errors": issues,
    }))
    .into_response()
}

/// `POST /ui/admin/settings/editor/visual/apply` — JSON-based apply.
///
/// Accepts the visual editor's config state as JSON, converts to YAML,
/// validates (collecting all errors), writes to disk, and triggers a
/// hot-reload.
pub async fn admin_config_editor_visual_apply(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    axum::Json(json): axum::Json<serde_json::Value>,
) -> Response {
    // Convert JSON → YAML
    let new_yaml = match editor_json_to_yaml(&json) {
        Ok(y) => y,
        Err(e) => {
            return axum::response::Json(serde_json::json!({
                "ok": false,
                "error": e,
            }))
            .into_response();
        }
    };

    // Parse without validation so we can run validate_all()
    let config = match Config::from_yaml_str_unchecked(&new_yaml) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            let field = field_from_parse_error(&msg);
            return axum::response::Json(serde_json::json!({
                "ok": false,
                "error": format!("Parse error: {msg}"),
                "errors": [{ "field": field, "reason": msg }],
            }))
            .into_response();
        }
    };

    // Run full validation and report all issues
    let issues: Vec<ValidationIssue> = config.validate_all();
    if !issues.is_empty() {
        let count = issues.len();
        return axum::response::Json(serde_json::json!({
            "ok": false,
            "error": format!("{count} validation error(s)"),
            "errors": issues,
        }))
        .into_response();
    }

    // Write to disk
    let Some(config_path) = &state.config_path else {
        return axum::response::Json(serde_json::json!({
            "ok": false,
            "error": "No config file path configured — cannot write",
        }))
        .into_response();
    };

    if let Err(e) = std::fs::write(config_path, &new_yaml) {
        tracing::error!(error = %e, "failed to write config file (visual editor)");
        return axum::response::Json(serde_json::json!({
            "ok": false,
            "error": format!("Failed to write file: {e}"),
        }))
        .into_response();
    }

    // Trigger hot-reload
    if let Some(notify) = &state.reload_notify {
        notify.notify_one();
    }

    tracing::info!("config file updated via visual editor, reload triggered");

    axum::response::Json(serde_json::json!({
        "ok": true,
        "message": "Configuration applied successfully",
    }))
    .into_response()
}

/// Computes a simple unified diff between two YAML strings.
#[allow(clippy::too_many_lines)]
fn compute_unified_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    if old_lines == new_lines {
        return String::new();
    }

    // Simple Myers-like diff: find longest common subsequence, then output
    // additions and deletions in unified format.
    let mut output = String::new();
    output.push_str("--- hearth.yaml (current)\n");
    output.push_str("+++ hearth.yaml (proposed)\n");

    // Walk both sequences, emitting context/add/remove lines
    let mut old_idx = 0;
    let mut new_idx = 0;
    let mut hunk_lines: Vec<String> = Vec::new();
    let mut hunk_old_start = 0usize;
    let mut hunk_new_start = 0usize;
    let mut hunk_old_count = 0u32;
    let mut hunk_new_count = 0u32;
    let mut trailing_context = 0u32;

    while old_idx < old_lines.len() || new_idx < new_lines.len() {
        if old_idx < old_lines.len()
            && new_idx < new_lines.len()
            && old_lines[old_idx] == new_lines[new_idx]
        {
            // Matching line
            if !hunk_lines.is_empty() {
                trailing_context += 1;
                hunk_lines.push(format!(" {}", old_lines[old_idx]));
                hunk_old_count += 1;
                hunk_new_count += 1;
                if trailing_context >= 3 {
                    // Flush hunk
                    let _ = writeln!(
                        output,
                        "@@ -{},{} +{},{} @@",
                        hunk_old_start + 1,
                        hunk_old_count,
                        hunk_new_start + 1,
                        hunk_new_count,
                    );
                    for l in &hunk_lines {
                        output.push_str(l);
                        output.push('\n');
                    }
                    hunk_lines.clear();
                    hunk_old_count = 0;
                    hunk_new_count = 0;
                    trailing_context = 0;
                }
            }
            old_idx += 1;
            new_idx += 1;
        } else if new_idx < new_lines.len()
            && (old_idx >= old_lines.len()
                || !old_lines[old_idx..]
                    .iter()
                    .take(10)
                    .any(|l| *l == new_lines[new_idx]))
        {
            // Added line (not found in next few old lines)
            trailing_context = 0;
            if hunk_lines.is_empty() {
                hunk_old_start = old_idx.saturating_sub(3);
                hunk_new_start = new_idx.saturating_sub(3);
                // Prepend context
                let ctx_start = old_idx.saturating_sub(3);
                for line in &old_lines[ctx_start..old_idx] {
                    hunk_lines.push(format!(" {line}"));
                    hunk_old_count += 1;
                    hunk_new_count += 1;
                }
            }
            hunk_lines.push(format!("+{}", new_lines[new_idx]));
            hunk_new_count += 1;
            new_idx += 1;
        } else if old_idx < old_lines.len() {
            // Deleted line
            trailing_context = 0;
            if hunk_lines.is_empty() {
                hunk_old_start = old_idx.saturating_sub(3);
                hunk_new_start = new_idx.saturating_sub(3);
                let ctx_start = old_idx.saturating_sub(3);
                for line in &old_lines[ctx_start..old_idx] {
                    hunk_lines.push(format!(" {line}"));
                    hunk_old_count += 1;
                    hunk_new_count += 1;
                }
            }
            hunk_lines.push(format!("-{}", old_lines[old_idx]));
            hunk_old_count += 1;
            old_idx += 1;
        } else {
            new_idx += 1;
        }
    }

    // Flush remaining hunk
    if !hunk_lines.is_empty() {
        let _ = writeln!(
            output,
            "@@ -{},{} +{},{} @@",
            hunk_old_start + 1,
            hunk_old_count,
            hunk_new_start + 1,
            hunk_new_count,
        );
        for l in &hunk_lines {
            output.push_str(l);
            output.push('\n');
        }
    }

    output
}

// ---------------------------------------------------------------------------
// Admin: user consents
// ---------------------------------------------------------------------------

struct AdminConsentRow {
    client_id: String,
    client_name: String,
    client_logo_url: Option<String>,
    scopes: Vec<String>,
    granted_at: String,
    updated_at: String,
}

#[derive(Template)]
#[template(path = "ui/admin/users/consents.html")]
#[allow(clippy::struct_excessive_bools)]
struct AdminUserConsentsTemplate {
    target_user_id: String,
    target_user_email: String,
    consents: Vec<AdminConsentRow>,
    realm_name: String,
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

/// `GET /ui/admin/users/{id}/applications` — lists every OAuth consent the
/// target user has granted in the admin's target realm.
pub async fn admin_user_consents_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target_realm: TargetRealm,
    AxumPath(user_id_str): AxumPath<String>,
) -> Response {
    let Ok(uuid) = user_id_str.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("User not found");
    };
    let user_id = crate::core::UserId::new(uuid);

    let target_user = match state.identity.get_user(target_realm.id(), &user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return super::handlers_common::not_found("User not found"),
        Err(e) => {
            tracing::warn!(error = %e, "admin_user_consents_list: get_user failed");
            return super::handlers_common::server_error();
        }
    };

    let rows = state
        .identity
        .list_consents_by_user(target_realm.id(), &user_id)
        .unwrap_or_default()
        .into_iter()
        .map(|e| AdminConsentRow {
            client_id: e.record.client_id.as_uuid().to_string(),
            client_name: e.client_name,
            client_logo_url: e.client_logo_url,
            scopes: e.record.granted_scopes,
            granted_at: format_ts_admin(e.record.granted_at),
            updated_at: format_ts_admin(e.record.updated_at),
        })
        .collect();

    let mut tmpl = AdminUserConsentsTemplate {
        target_user_id: user_id.as_uuid().to_string(),
        target_user_email: target_user.email().to_string(),
        consents: rows,
        realm_name: target_realm.0.name().to_string(),
        chrome: true,
        active: "users",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: String::new(),
        realm_theme_css: None,
    };
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
}

/// `POST /ui/admin/users/{id}/applications/{client_id}/revoke` — admin
/// revoke-on-behalf. Emits a `ConsentRevoked` audit with
/// `metadata.via = "admin"` so operators can distinguish from self-revokes.
pub async fn admin_user_consent_revoke(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target_realm: TargetRealm,
    AxumPath((user_id_str, client_id_str)): AxumPath<(String, String)>,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let Ok(uuid_u) = user_id_str.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("User not found");
    };
    let Ok(uuid_c) = client_id_str.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Client not found");
    };
    let user_id = crate::core::UserId::new(uuid_u);
    let client_id = ClientId::new(uuid_c);

    match state
        .identity
        .revoke_consent(target_realm.id(), &user_id, &client_id)
    {
        Ok(()) => {
            let _ = state.audit.append(&crate::audit::CreateAuditEvent {
                realm_id: target_realm.id().clone(),
                actor: session.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ConsentRevoked,
                resource_type: "oauth_client".to_string(),
                resource_id: client_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({
                    "via": "admin",
                    "target_user": user_id.as_uuid().to_string(),
                    "client_id": client_id.as_uuid().to_string(),
                })),
            });
            Redirect::to(&format!(
                "/ui/admin/users/{}/applications",
                user_id.as_uuid()
            ))
            .into_response()
        }
        Err(IdentityError::ConsentNotFound) => {
            super::handlers_common::not_found("Consent not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin revoke_consent failed");
            super::handlers_common::server_error()
        }
    }
}

/// Shared CSRF-only form body for admin consent actions.
#[derive(Debug, Deserialize)]
pub struct CsrfOnlyForm {
    /// CSRF double-submit token.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::min_ident_chars
)]
fn format_ts_admin(ts: crate::core::Timestamp) -> String {
    let secs = ts.as_micros() / 1_000_000;
    let rem = secs.rem_euclid(86_400);
    let days = secs.div_euclid(86_400);
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let (y, mo, d) = {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (if m <= 2 { y + 1 } else { y }, m, d)
    };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

// =========================================================================
// Realm administrators (Roles & Permissions — Phase 3)
// =========================================================================

/// Resolves the list of users with the `realm.admin` role on a realm.
///
/// Uses `rbac.list_role_members` on the seeded `realm.admin` role, then
/// hydrates display fields via `identity.get_user`. Users whose records
/// can no longer be loaded are silently omitted — the assignment is
/// effectively orphaned and a stale display would confuse operators more
/// than a missing row.
fn resolve_realm_admins(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<RealmAdminView> {
    let Ok(Some(role)) = state.rbac.get_role_by_name(realm_id, "realm.admin") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match state
            .rbac
            .list_role_members(realm_id, &role.id, cursor.as_deref(), 100)
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "list realm admins: list_role_members failed");
                return out;
            }
        };
        for member in page.items {
            let crate::rbac::RoleSubject::User(uid) = member else {
                continue;
            };
            let Ok(Some(user)) = state.identity.get_user(realm_id, &uid) else {
                continue;
            };
            let display_name = if user.display_name().is_empty() {
                user.email().to_string()
            } else {
                user.display_name().to_string()
            };
            out.push(RealmAdminView {
                user_id: uid.as_uuid().to_string(),
                display_name,
                email: user.email().to_string(),
            });
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    out.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    out
}

/// `application/x-www-form-urlencoded` body for granting realm admin.
#[derive(Debug, Deserialize)]
pub struct RealmAdminGrantForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub user_id: String,
}

/// `POST /ui/admin/realms/:id/admins/grant`.
pub async fn admin_realm_admin_grant(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(rid): AxumPath<String>,
    Form(form): Form<RealmAdminGrantForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let Ok(realm_uuid) = rid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Realm not found");
    };
    let realm_id = RealmId::new(realm_uuid);
    let Ok(user_uuid) = form.user_id.trim().parse::<uuid::Uuid>() else {
        return super::handlers_common::bad_request("Invalid user ID");
    };
    let target_user = crate::core::UserId::new(user_uuid);

    match state.identity.get_user(&realm_id, &target_user) {
        Ok(Some(_)) => {}
        Ok(None) => return super::handlers_common::not_found("User not found in this realm"),
        Err(e) => {
            tracing::warn!(error = %e, "grant realm admin: get_user failed");
            return super::handlers_common::server_error();
        }
    }

    if check_user_admin(&state, &realm_id, &target_user) {
        return Redirect::to(&format!("/ui/admin/realms/{}", realm_id.as_uuid())).into_response();
    }

    if let Err(e) = set_user_admin(&state, &realm_id, &target_user, true) {
        tracing::warn!(error = %e, "grant realm admin failed");
        return super::handlers_common::server_error();
    }
    audit_role_event(
        &state,
        &session,
        &realm_id,
        &target_user,
        true,
        "hearth",
        "admin",
        "admin",
    );
    Redirect::to(&format!("/ui/admin/realms/{}", realm_id.as_uuid())).into_response()
}

/// `POST /ui/admin/realms/:id/admins/:uid/revoke`.
pub async fn admin_realm_admin_revoke(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath((rid, uid)): AxumPath<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let Ok(realm_uuid) = rid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Realm not found");
    };
    let realm_id = RealmId::new(realm_uuid);
    let Ok(user_uuid) = uid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("User not found");
    };
    let target_user = crate::core::UserId::new(user_uuid);

    // Self-revocation guard: a session-owning admin shouldn't be able to
    // accidentally lock themselves out. They can still revoke themselves
    // from another admin's browser.
    if session.user_id == target_user {
        return super::handlers_common::bad_request(
            "Refusing to revoke your own admin role — have another admin do it.",
        );
    }

    if !check_user_admin(&state, &realm_id, &target_user) {
        return Redirect::to(&format!("/ui/admin/realms/{}", realm_id.as_uuid())).into_response();
    }

    if let Err(e) = set_user_admin(&state, &realm_id, &target_user, false) {
        tracing::warn!(error = %e, "revoke realm admin failed");
        return super::handlers_common::server_error();
    }
    audit_role_event(
        &state,
        &session,
        &realm_id,
        &target_user,
        false,
        "hearth",
        "admin",
        "admin",
    );
    Redirect::to(&format!("/ui/admin/realms/{}", realm_id.as_uuid())).into_response()
}

// =========================================================================
// RBAC debugger: resolve effective permissions for a user
// =========================================================================

#[derive(Template)]
#[template(path = "ui/admin/rbac/debug.html")]
struct RbacDebugTemplate {
    /// UUID string of the user being resolved, if any.
    user_id_input: String,
    /// Optional org UUID input narrowing the scope.
    org_id_input: String,
    /// Optional OAuth scope string input narrowing permissions.
    scope_input: String,
    /// Resolved roles (by name), populated after a successful lookup.
    roles: Vec<String>,
    /// Resolved group slugs.
    groups: Vec<String>,
    /// Resolved permission strings.
    permissions: Vec<String>,
    /// Realm UUID used to run the resolution.
    realm_uuid: String,
    /// Human-readable error message, if any.
    error: Option<String>,
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

/// Query parameters for the RBAC debugger.
#[derive(Debug, Deserialize)]
pub struct RbacDebugQuery {
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub org_id: String,
    #[serde(default)]
    pub scope: String,
}

/// `GET /ui/admin/rbac/debug`.
///
/// Resolves the RBAC effective permissions for the given user (and
/// optional org / scope) in the current target realm. Empty form → no
/// resolution is run.
pub async fn admin_rbac_debug(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    Query(q): Query<RbacDebugQuery>,
) -> Response {
    let user_id_input = q.user_id.trim().to_string();
    let org_id_input = q.org_id.trim().to_string();
    let scope_input = q.scope.trim().to_string();

    let mut roles: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut permissions: Vec<String> = Vec::new();
    let mut error: Option<String> = None;

    if !user_id_input.is_empty() {
        let uuid = user_id_input
            .strip_prefix("user_")
            .unwrap_or(user_id_input.as_str())
            .parse::<uuid::Uuid>();
        match uuid {
            Err(_) => error = Some("Invalid user UUID".to_string()),
            Ok(u) => {
                let user_id = crate::core::UserId::new(u);
                let org_id = if org_id_input.is_empty() {
                    None
                } else {
                    org_id_input
                        .strip_prefix("org_")
                        .unwrap_or(org_id_input.as_str())
                        .parse::<uuid::Uuid>()
                        .ok()
                        .map(crate::core::OrganizationId::new)
                };
                let scope = if scope_input.is_empty() {
                    None
                } else {
                    Some(scope_input.clone())
                };
                match state.rbac.resolve_permissions(
                    &user_id,
                    target.id(),
                    org_id.as_ref(),
                    scope.as_deref(),
                ) {
                    Ok(resolved) => {
                        roles = resolved.roles;
                        groups = resolved.groups;
                        permissions = resolved
                            .permissions
                            .into_iter()
                            .map(|p| p.into_string())
                            .collect();
                    }
                    Err(e) => error = Some(format!("Resolution failed: {e}")),
                }
            }
        }
    }

    render(&RbacDebugTemplate {
        user_id_input,
        org_id_input,
        scope_input,
        roles,
        groups,
        permissions,
        realm_uuid: target.id().as_uuid().to_string(),
        error,
        chrome: true,
        active: "rbac_debug",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// =========================================================================
// RBAC token preview (POST /ui/admin/rbac/token-preview)
// =========================================================================

/// Form body for the token preview endpoint.
#[derive(Debug, Deserialize)]
pub struct TokenPreviewForm {
    /// UUID (bare or with `user_` prefix) of the user to preview.
    #[serde(default)]
    pub user_id: String,
}

/// `POST /ui/admin/rbac/token-preview` — returns a JSON snippet previewing
/// the access-token claims that would be embedded for the given user in the
/// current realm.
pub async fn admin_rbac_token_preview(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    axum::Form(form): axum::Form<TokenPreviewForm>,
) -> Response {
    use axum::response::IntoResponse;
    use serde_json::{json, to_string_pretty};

    let user_id_str = form.user_id.trim().to_string();
    let uuid_result = user_id_str
        .strip_prefix("user_")
        .unwrap_or(user_id_str.as_str())
        .parse::<uuid::Uuid>();

    let json_text = match uuid_result {
        Err(_) => {
            let v = json!({"error": "Invalid user UUID"});
            to_string_pretty(&v).unwrap_or_default()
        }
        Ok(u) => {
            let uid = crate::core::UserId::new(u);
            match state
                .rbac
                .resolve_permissions(&uid, target.id(), None, None)
            {
                Err(e) => {
                    let v = json!({"error": format!("Resolution failed: {e}")});
                    to_string_pretty(&v).unwrap_or_default()
                }
                Ok(resolved) => {
                    let permissions: Vec<String> = resolved
                        .permissions
                        .into_iter()
                        .map(|p| p.into_string())
                        .collect();
                    let v = json!({
                        "sub": format!("user_{u}"),
                        "oid": null,
                        "realm": target.id().as_uuid().to_string(),
                        "roles": resolved.roles,
                        "groups": resolved.groups,
                        "permissions": permissions,
                        "_note": "Mock preview — iss/aud/exp/iat omitted"
                    });
                    to_string_pretty(&v).unwrap_or_default()
                }
            }
        }
    };

    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json_text,
    )
        .into_response()
}

// =========================================================================
// RBAC scopes list (GET /ui/admin/rbac/scopes)
// =========================================================================

/// A single row on the scopes list page.
struct ScopeRow {
    /// Bundle name (e.g. `read:docs`).
    name: String,
    /// Optional human-readable description.
    description: String,
    /// Comma-separated list of permission names this bundle grants.
    permissions: String,
}

/// Template for `GET /ui/admin/rbac/scopes`.
#[derive(Template)]
#[template(path = "ui/admin/rbac/scopes.html")]
struct RbacScopesTemplate {
    /// Scope bundle rows for the current realm.
    scopes: Vec<ScopeRow>,
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

/// `GET /ui/admin/rbac/scopes` — read-only list of registered scope bundles.
///
/// Reads the realm's scope bundle definitions from config; these are
/// YAML-managed and not editable through the UI.
pub async fn admin_rbac_scopes(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
) -> Response {
    let realm_name = state
        .identity
        .get_realm(target.id())
        .ok()
        .flatten()
        .map(|r| r.name().to_string());

    let scopes = realm_name
        .as_deref()
        .and_then(|name| {
            state
                .config
                .as_ref()
                .and_then(|cfg| cfg.realms.as_ref())
                .and_then(|realms| realms.get(name))
        })
        .and_then(|r| r.scopes.as_ref())
        .map(|bundles| {
            bundles
                .iter()
                .map(|b| ScopeRow {
                    name: b.name.clone(),
                    description: b.description.clone().unwrap_or_default(),
                    permissions: b
                        .permissions
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    render(&RbacScopesTemplate {
        scopes,
        chrome: true,
        active: "rbac_scopes",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// =========================================================================
// Realm admin picker (Phase 6 — Roles UI second pass)
// =========================================================================

#[derive(Template)]
#[template(path = "ui/admin/realms/_admin_picker_rows.html")]
struct RealmAdminPickerRowsTemplate {
    realm_id: String,
    users: Vec<crate::identity::User>,
    query: String,
    csrf: Option<String>,
}

/// Query params for the realm admin picker.
#[derive(Debug, Deserialize)]
pub struct RealmAdminPickerParams {
    #[serde(default)]
    pub q: String,
}

/// `GET /ui/admin/realms/:id/admins/picker` — HTMX rows-only partial.
///
/// Drives the live-search list under the Administrators section on the
/// realm detail page. Each row is its own one-click grant form, so the
/// operator never has to copy a UUID by hand.
pub async fn admin_realm_admin_picker(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(rid): AxumPath<String>,
    Query(params): Query<RealmAdminPickerParams>,
) -> Response {
    let Ok(realm_uuid) = rid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Realm not found");
    };
    let realm_id = RealmId::new(realm_uuid);
    let query = params.q.trim().to_string();

    // Short queries show the prompt hint in the template; avoid hitting
    // list_users for what would otherwise be a noisy broad listing.
    let users = if query.len() >= 2 {
        state
            .identity
            .search_users(&realm_id, &query, 20)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    render(&RealmAdminPickerRowsTemplate {
        realm_id: realm_id.as_uuid().to_string(),
        users,
        query,
        csrf: session.csrf.clone(),
    })
}

// =========================================================================
// Organization role audit helpers — emit structured audit events for
// membership changes on the identity-engine `OrganizationMembership`
// record.
// =========================================================================

/// Maps `OrganizationRole` to its relation-name label for audit events.
fn org_role_to_relation(role: OrganizationRole) -> &'static str {
    match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    }
}

/// Records an org-membership-added audit event.
///
/// Under the RBAC model, organization membership and role live on the
/// identity-engine `OrganizationMembership` record. This helper emits
/// the audit event for the membership change.
fn mirror_org_member_added(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    org_id: &OrganizationId,
    user_id: &crate::core::UserId,
    role: OrganizationRole,
) {
    let relation = org_role_to_relation(role);
    audit_role_event(
        state,
        session,
        realm_id,
        user_id,
        true,
        "organization",
        &org_id.as_uuid().to_string(),
        relation,
    );
}

/// Emits paired revoke/assign audit events for an org role change.
fn mirror_org_role_changed(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    org_id: &OrganizationId,
    user_id: &crate::core::UserId,
    old: OrganizationRole,
    new: OrganizationRole,
) {
    if old == new {
        return;
    }
    let old_rel = org_role_to_relation(old);
    let new_rel = org_role_to_relation(new);
    audit_role_event(
        state,
        session,
        realm_id,
        user_id,
        false,
        "organization",
        &org_id.as_uuid().to_string(),
        old_rel,
    );
    audit_role_event(
        state,
        session,
        realm_id,
        user_id,
        true,
        "organization",
        &org_id.as_uuid().to_string(),
        new_rel,
    );
}

/// Emits a member-removed audit event.
fn mirror_org_member_removed(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    org_id: &OrganizationId,
    user_id: &crate::core::UserId,
    role: OrganizationRole,
) {
    let relation = org_role_to_relation(role);
    audit_role_event(
        state,
        session,
        realm_id,
        user_id,
        false,
        "organization",
        &org_id.as_uuid().to_string(),
        relation,
    );
}

/// Hydrates the per-user Access panel using RBAC assignments + organization
/// memberships. Role assignments are grouped under the synthetic object
/// type `"role"`, and organization memberships under `"organization"`.
///
/// Failures at any step fall back to an empty panel rather than surfacing
/// an error — operators should still be able to use the rest of the user
/// detail page even if the RBAC engine is briefly unavailable.
/// Builds role assignment display rows for the user detail Roles tab.
fn build_role_assignment_rows(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> Vec<UserRoleAssignmentRow> {
    let assignments = state
        .rbac
        .list_user_assignments(realm_id, user_id)
        .unwrap_or_default();
    let mut rows = Vec::with_capacity(assignments.len());
    for a in assignments {
        let role_name = match state.rbac.get_role(realm_id, &a.role_id) {
            Ok(Some(r)) => r.name,
            _ => a.role_id.as_uuid().to_string(),
        };
        let (scope_label, scope_raw) = match &a.scope {
            crate::rbac::Scope::Realm => ("Realm-wide".to_string(), "realm".to_string()),
            crate::rbac::Scope::Org { org_id } => {
                let org_name = state
                    .identity
                    .get_organization(realm_id, org_id)
                    .ok()
                    .flatten()
                    .map_or_else(|| org_id.as_uuid().to_string(), |o| o.name().to_string());
                (
                    format!("Org: {org_name}"),
                    format!("org:{}", org_id.as_uuid()),
                )
            }
        };
        rows.push(UserRoleAssignmentRow {
            assignment_id: a.id.as_uuid().to_string(),
            role_name,
            scope_label,
            scope_raw,
        });
    }
    rows.sort_by(|a, b| {
        a.role_name
            .cmp(&b.role_name)
            .then(a.scope_label.cmp(&b.scope_label))
    });
    rows
}

/// Builds permission grant display rows for the user detail Extra Permissions tab.
fn build_permission_grant_rows(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> Vec<UserPermissionGrantRow> {
    state
        .rbac
        .list_user_permissions(realm_id, user_id)
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            let (scope_label, scope_raw) = match &g.scope {
                crate::rbac::Scope::Realm => ("Realm-wide".to_string(), "realm".to_string()),
                crate::rbac::Scope::Org { org_id } => {
                    let org_name = state
                        .identity
                        .get_organization(realm_id, org_id)
                        .ok()
                        .flatten()
                        .map_or_else(|| org_id.as_uuid().to_string(), |o| o.name().to_string());
                    (
                        format!("Org: {org_name}"),
                        format!("org:{}", org_id.as_uuid()),
                    )
                }
            };
            UserPermissionGrantRow {
                permission: g.permission.into_string(),
                scope_label,
                scope_raw,
            }
        })
        .collect()
}

/// Collects all unique permission strings defined across all roles in the realm,
/// for use as autocomplete suggestions.
fn collect_realm_permissions(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<String> {
    use std::collections::BTreeSet;
    let roles = state
        .rbac
        .list_roles(realm_id, None, 500)
        .map(|p| p.items)
        .unwrap_or_default();
    let mut set = BTreeSet::new();
    for r in roles {
        for p in r.permissions {
            set.insert(p.into_string());
        }
    }
    set.into_iter().collect()
}

/// Permission name suggestions appropriate for org-scope grants: only those
/// defined on `Organization` or `Any` scope-kind roles. Realm-only permissions
/// (e.g. `realm.admin`, `hearth.admin`) are excluded because they have no
/// meaning at org scope.
fn collect_org_permissions(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<String> {
    use std::collections::BTreeSet;
    let roles = state
        .rbac
        .list_roles(realm_id, None, 500)
        .map(|p| p.items)
        .unwrap_or_default();
    let mut set = BTreeSet::new();
    for r in roles {
        if !matches!(
            r.scope_kind,
            crate::rbac::RoleScopeKind::Organization | crate::rbac::RoleScopeKind::Any
        ) {
            continue;
        }
        for p in r.permissions {
            set.insert(p.into_string());
        }
    }
    set.into_iter().collect()
}

/// Loads all organizations in the realm for the org scope picker.
fn build_available_orgs(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<AvailableOrg> {
    state
        .identity
        .list_organizations(realm_id, None, 200)
        .map(|p| p.items)
        .unwrap_or_default()
        .into_iter()
        .map(|o| AvailableOrg {
            id: o.id().as_uuid().to_string(),
            name: o.name().to_string(),
        })
        .collect()
}

/// Parses a scope string ("realm" | "org:{uuid}") into an RBAC `Scope`.
fn parse_rbac_scope(scope: &str) -> Result<crate::rbac::Scope, String> {
    if scope == "realm" {
        return Ok(crate::rbac::Scope::Realm);
    }
    if let Some(rest) = scope.strip_prefix("org:") {
        let uuid = rest
            .parse::<uuid::Uuid>()
            .map_err(|_| format!("invalid org UUID: {rest}"))?;
        return Ok(crate::rbac::Scope::Org {
            org_id: OrganizationId::new(uuid),
        });
    }
    Err(format!("unrecognised scope: {scope}"))
}

// =========================================================================
// User role/permission mutation handlers
// =========================================================================

#[derive(Deserialize)]
pub struct AssignRoleForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    role_id: String,
    scope: String,
}

#[derive(Deserialize)]
pub struct UnassignRoleForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct GrantPermissionForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    permission: String,
    scope: String,
}

#[derive(Deserialize)]
pub struct RevokePermissionForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    permission: String,
    scope: String,
}

/// Renders the Roles tab partial for HTMX responses.
fn render_roles_tab(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> Response {
    let user_id_str = user_id.as_uuid().to_string();
    let role_assignments = build_role_assignment_rows(state, realm_id, user_id);
    let available_roles: Vec<AvailableRole> = state
        .rbac
        .list_roles(realm_id, None, 200)
        .map(|p| p.items)
        .unwrap_or_default()
        .into_iter()
        .map(|r| AvailableRole {
            id: r.id.as_uuid().to_string(),
            description: r.description.unwrap_or_default(),
            scope_kind: format!("{:?}", r.scope_kind),
            name: r.name,
        })
        .collect();
    let available_orgs = build_available_orgs(state, realm_id);
    render(&UserRolesTabTemplate {
        user_id: user_id_str,
        role_assignments,
        available_roles,
        available_orgs,
        csrf: session.csrf.clone(),
    })
}

/// Renders the Extra Permissions tab partial for HTMX responses.
fn render_permissions_tab(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    user_id: &crate::core::UserId,
) -> Response {
    let user_id_str = user_id.as_uuid().to_string();
    let extra_permissions = build_permission_grant_rows(state, realm_id, user_id);
    let available_permissions = collect_realm_permissions(state, realm_id);
    let available_orgs = build_available_orgs(state, realm_id);
    render(&UserPermissionsTabTemplate {
        user_id: user_id_str,
        extra_permissions,
        available_permissions,
        available_orgs,
        csrf: session.csrf.clone(),
    })
}

/// `POST /ui/admin/users/:id/roles/assign` — assigns a realm RBAC role to a user.
pub async fn admin_user_assign_role(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(form): Form<AssignRoleForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };
    let Ok(role_uuid) = form.role_id.parse::<uuid::Uuid>() else {
        return if is_htmx_request(&headers) {
            super::templates::htmx_toast_response("Invalid role ID", "error")
        } else {
            Redirect::to(&format!("/ui/admin/users/{user_id}?flash=invalid_role")).into_response()
        };
    };
    let role_id = crate::rbac::RoleId::new(role_uuid);
    let scope = match parse_rbac_scope(&form.scope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "invalid scope in assign_role form");
            return if is_htmx_request(&headers) {
                super::templates::htmx_toast_response("Invalid scope", "error")
            } else {
                Redirect::to(&format!("/ui/admin/users/{user_id}?flash=invalid_scope"))
                    .into_response()
            };
        }
    };
    let req = crate::rbac::AssignRoleRequest {
        subject: crate::rbac::Subject::User(uid.clone()),
        role_id,
        scope,
        assigned_by: Some(session.user_id.clone()),
    };
    match state.rbac.assign_role(target.id(), &req) {
        Ok(_) => {
            audit_role_event(
                &state,
                &session,
                target.id(),
                &uid,
                true,
                "user",
                &uid.as_uuid().to_string(),
                &form.role_id,
            );
            if is_htmx_request(&headers) {
                render_roles_tab(&state, &session, target.id(), &uid)
            } else {
                Redirect::to(&format!("/ui/admin/users/{user_id}?flash=role_assigned"))
                    .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "assign_role failed");
            if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(&format!("{e}"), "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=assign_role_failed"
                ))
                .into_response()
            }
        }
    }
}

/// `POST /ui/admin/users/:id/roles/:assignment_id/unassign` — removes a role assignment.
pub async fn admin_user_unassign_role(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((user_id, assignment_id)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    Form(form): Form<UnassignRoleForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };
    let Ok(assign_uuid) = assignment_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Assignment not found");
    };
    let aid = crate::rbac::AssignmentId::new(assign_uuid);
    match state.rbac.unassign_role(target.id(), &aid) {
        Ok(()) => {
            audit_role_event(
                &state,
                &session,
                target.id(),
                &uid,
                false,
                "user",
                &uid.as_uuid().to_string(),
                &assignment_id,
            );
            if is_htmx_request(&headers) {
                render_roles_tab(&state, &session, target.id(), &uid)
            } else {
                Redirect::to(&format!("/ui/admin/users/{user_id}?flash=role_unassigned"))
                    .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "unassign_role failed");
            if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(&format!("{e}"), "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=unassign_role_failed"
                ))
                .into_response()
            }
        }
    }
}

/// `POST /ui/admin/users/:id/permissions/grant` — grants a direct permission to a user.
pub async fn admin_user_grant_permission(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(form): Form<GrantPermissionForm>,
) -> Response {
    use crate::core::Timestamp;
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };
    let permission = match crate::rbac::Permission::new(form.permission.trim().to_string()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "invalid permission in grant form");
            return if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(
                    "Invalid permission string (use dot-separated segments, e.g. users.read)",
                    "error",
                )
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=invalid_permission"
                ))
                .into_response()
            };
        }
    };
    let scope = match parse_rbac_scope(&form.scope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "invalid scope in grant_permission form");
            return if is_htmx_request(&headers) {
                super::templates::htmx_toast_response("Invalid scope", "error")
            } else {
                Redirect::to(&format!("/ui/admin/users/{user_id}?flash=invalid_scope"))
                    .into_response()
            };
        }
    };
    let grant = crate::rbac::UserPermissionGrant {
        realm_id: target.id().clone(),
        user_id: uid.clone(),
        permission,
        scope,
        granted_at: Timestamp::from_micros(0),
        granted_by: Some(session.user_id.clone()),
    };
    match state.rbac.grant_user_permission(target.id(), &grant) {
        Ok(_) => {
            use crate::audit::{AuditAction, CreateAuditEvent};
            if let Err(e) = state.audit.append(&CreateAuditEvent {
                realm_id: target.id().clone(),
                actor: session.user_id.as_uuid().to_string(),
                action: AuditAction::UserPermissionGranted,
                resource_type: "user".to_string(),
                resource_id: uid.as_uuid().to_string(),
                metadata: Some(serde_json::json!({
                    "via": "ui",
                    "permission": grant.permission.as_str(),
                    "scope": form.scope,
                })),
            }) {
                tracing::warn!(error = %e, "permission grant audit append failed");
            }
            if is_htmx_request(&headers) {
                render_permissions_tab(&state, &session, target.id(), &uid)
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=permission_granted"
                ))
                .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "grant_user_permission failed");
            if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(&format!("{e}"), "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=grant_permission_failed"
                ))
                .into_response()
            }
        }
    }
}

/// `POST /ui/admin/users/:id/permissions/revoke` — revokes a direct permission from a user.
pub async fn admin_user_revoke_permission(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(user_id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(form): Form<RevokePermissionForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };
    let permission = match crate::rbac::Permission::new(form.permission.clone()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "invalid permission in revoke form");
            return if is_htmx_request(&headers) {
                super::templates::htmx_toast_response("Invalid permission string", "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=invalid_permission"
                ))
                .into_response()
            };
        }
    };
    let scope = match parse_rbac_scope(&form.scope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "invalid scope in revoke_permission form");
            return if is_htmx_request(&headers) {
                super::templates::htmx_toast_response("Invalid scope", "error")
            } else {
                Redirect::to(&format!("/ui/admin/users/{user_id}?flash=invalid_scope"))
                    .into_response()
            };
        }
    };
    match state
        .rbac
        .revoke_user_permission(target.id(), &uid, &permission, &scope)
    {
        Ok(()) => {
            use crate::audit::{AuditAction, CreateAuditEvent};
            if let Err(e) = state.audit.append(&CreateAuditEvent {
                realm_id: target.id().clone(),
                actor: session.user_id.as_uuid().to_string(),
                action: AuditAction::UserPermissionRevoked,
                resource_type: "user".to_string(),
                resource_id: uid.as_uuid().to_string(),
                metadata: Some(serde_json::json!({
                    "via": "ui",
                    "permission": permission.as_str(),
                    "scope": form.scope,
                })),
            }) {
                tracing::warn!(error = %e, "permission revoke audit append failed");
            }
            if is_htmx_request(&headers) {
                render_permissions_tab(&state, &session, target.id(), &uid)
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=permission_revoked"
                ))
                .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "revoke_user_permission failed");
            if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(&format!("{e}"), "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/users/{user_id}?flash=revoke_permission_failed"
                ))
                .into_response()
            }
        }
    }
}

// =========================================================================
// Per-member RBAC role and permission management (org context)
// =========================================================================

/// Builds a `MemberWithAccess` from a `MemberView` by loading org-scoped RBAC roles
/// and direct permissions for the member.
fn build_member_with_access(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    org_id: &OrganizationId,
    view: MemberView,
) -> MemberWithAccess {
    let uid = view.membership.user_id();
    let org_scope = crate::rbac::Scope::Org {
        org_id: org_id.clone(),
    };
    let rbac_roles = state
        .rbac
        .list_user_assignments(realm_id, uid)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.scope == org_scope)
        .filter_map(|a| {
            let role = state
                .rbac
                .get_role(realm_id, &a.role_id)
                .ok()
                .flatten();
            // Skip roles defined as Realm-only scope — they don't belong on
            // the org page even if an assignment exists at org scope.
            if let Some(ref r) = role {
                if r.scope_kind == crate::rbac::RoleScopeKind::Realm {
                    return None;
                }
            }
            let role_name = role.map_or_else(
                || a.role_id.as_uuid().to_string(),
                |r| r.name,
            );
            Some(MemberRbacRole {
                assignment_id: a.id.as_uuid().to_string(),
                role_id: a.role_id.as_uuid().to_string(),
                role_name,
            })
        })
        .collect();
    let scope_raw = format!("org:{}", org_id.as_uuid());
    let extra_perms = state
        .rbac
        .list_user_permissions(realm_id, uid)
        .unwrap_or_default()
        .into_iter()
        .filter(|g| g.scope == org_scope)
        .map(|g| MemberPermGrant {
            permission: g.permission.into_string(),
            scope_raw: scope_raw.clone(),
        })
        .collect();
    MemberWithAccess {
        view,
        rbac_roles,
        extra_perms,
    }
}

/// Loads all realm roles as `AvailableRole` display structs.
fn build_realm_available_roles(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<AvailableRole> {
    state
        .rbac
        .list_roles(realm_id, None, 200)
        .map(|p| p.items)
        .unwrap_or_default()
        .into_iter()
        .map(|r| AvailableRole {
            id: r.id.as_uuid().to_string(),
            name: r.name,
            description: r.description.unwrap_or_default(),
            scope_kind: format!("{:?}", r.scope_kind),
        })
        .collect()
}

/// Loads roles appropriate for org-scope assignment: `Organization` and `Any` only.
/// Excludes `Realm`-scoped roles, which have no meaning at org context.
fn build_org_available_roles(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<AvailableRole> {
    state
        .rbac
        .list_roles(realm_id, None, 200)
        .map(|p| p.items)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| {
            matches!(
                r.scope_kind,
                crate::rbac::RoleScopeKind::Organization | crate::rbac::RoleScopeKind::Any
            )
        })
        .map(|r| AvailableRole {
            id: r.id.as_uuid().to_string(),
            name: r.name,
            description: r.description.unwrap_or_default(),
            scope_kind: format!("{:?}", r.scope_kind),
        })
        .collect()
}

/// Form for assigning an RBAC role to an org member inline.
#[derive(Debug, Deserialize)]
pub struct MemberAssignRoleForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    /// UUID of the role to assign.
    pub role_id: String,
}

/// Form for unassigning an RBAC role from an org member.
#[derive(Debug, Deserialize)]
pub struct MemberUnassignRoleForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Form for granting a direct permission to an org member.
#[derive(Debug, Deserialize)]
pub struct MemberGrantPermForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub permission: String,
    pub scope: String,
}

/// Form for revoking a direct permission from an org member.
#[derive(Debug, Deserialize)]
pub struct MemberRevokePermForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub permission: String,
    pub scope: String,
}

/// `POST /ui/admin/organizations/:id/members/:uid/rbac/assign` — assigns an RBAC role to a member.
pub async fn admin_org_member_assign_role(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    Form(form): Form<MemberAssignRoleForm>,
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
    let Ok(role_uuid) = form.role_id.parse::<uuid::Uuid>() else {
        return super::templates::htmx_toast_response("Invalid role ID", "error");
    };
    let role_id = crate::rbac::RoleId::new(role_uuid);
    let scope = crate::rbac::Scope::Org {
        org_id: org_id.clone(),
    };
    let req = crate::rbac::AssignRoleRequest {
        subject: crate::rbac::Subject::User(user_id.clone()),
        role_id,
        scope,
        assigned_by: Some(session.user_id.clone()),
    };
    match state.rbac.assign_role(target.id(), &req) {
        Ok(_) => {
            audit_role_event(
                &state,
                &session,
                target.id(),
                &user_id,
                true,
                "organization",
                &oid,
                &form.role_id,
            );
            if is_htmx_request(&headers) {
                if let Ok(Some(m)) =
                    state.identity.get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        "Role assigned",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Role assigned", "success")
                }
            } else {
                org_redirect_flash(&org_id, "Role assigned", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "org member assign_role failed");
            super::templates::htmx_toast_response(&format!("{e}"), "error")
        }
    }
}

/// `POST /ui/admin/organizations/:id/members/:uid/rbac/:aid/unassign` — removes an RBAC role from a member.
pub async fn admin_org_member_unassign_role(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((oid, uid, aid)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    Form(form): Form<MemberUnassignRoleForm>,
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
    let Ok(assign_uuid) = aid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Assignment not found");
    };
    let assignment_id = crate::rbac::AssignmentId::new(assign_uuid);
    match state.rbac.unassign_role(target.id(), &assignment_id) {
        Ok(()) => {
            if is_htmx_request(&headers) {
                if let Ok(Some(m)) =
                    state.identity.get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        "Role removed",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Role removed", "success")
                }
            } else {
                org_redirect_flash(&org_id, "Role removed", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "org member unassign_role failed");
            super::templates::htmx_toast_response(&format!("{e}"), "error")
        }
    }
}

/// `POST /ui/admin/organizations/:id/members/:uid/permissions/grant` — grants a direct permission to a member.
pub async fn admin_org_member_grant_perm(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    Form(form): Form<MemberGrantPermForm>,
) -> Response {
    use crate::core::Timestamp;
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
    let permission = match crate::rbac::Permission::new(form.permission.trim().to_string()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "invalid permission in org member grant form");
            return super::templates::htmx_toast_response("Invalid permission string", "error");
        }
    };
    let scope = match parse_rbac_scope(&form.scope) {
        Ok(s) => s,
        Err(_) => crate::rbac::Scope::Org {
            org_id: org_id.clone(),
        },
    };
    let grant = crate::rbac::UserPermissionGrant {
        realm_id: target.id().clone(),
        user_id: user_id.clone(),
        permission,
        scope,
        granted_at: Timestamp::now(),
        granted_by: Some(session.user_id.clone()),
    };
    match state.rbac.grant_user_permission(target.id(), &grant) {
        Ok(_) => {
            if is_htmx_request(&headers) {
                if let Ok(Some(m)) =
                    state.identity.get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        "Permission granted",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Permission granted", "success")
                }
            } else {
                org_redirect_flash(&org_id, "Permission granted", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "org member grant_perm failed");
            super::templates::htmx_toast_response(&format!("{e}"), "error")
        }
    }
}

/// `POST /ui/admin/organizations/:id/members/:uid/permissions/revoke` — revokes a direct permission from a member.
pub async fn admin_org_member_revoke_perm(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((oid, uid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    Form(form): Form<MemberRevokePermForm>,
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
    let permission = match crate::rbac::Permission::new(form.permission.clone()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "invalid permission in org member revoke form");
            return super::templates::htmx_toast_response("Invalid permission string", "error");
        }
    };
    let scope = match parse_rbac_scope(&form.scope) {
        Ok(s) => s,
        Err(_) => crate::rbac::Scope::Org {
            org_id: org_id.clone(),
        },
    };
    match state
        .rbac
        .revoke_user_permission(target.id(), &user_id, &permission, &scope)
    {
        Ok(()) => {
            if is_htmx_request(&headers) {
                if let Ok(Some(m)) =
                    state.identity.get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        &org_id,
                        m,
                        "Permission revoked",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Permission revoked", "success")
                }
            } else {
                org_redirect_flash(&org_id, "Permission revoked", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "org member revoke_perm failed");
            super::templates::htmx_toast_response(&format!("{e}"), "error")
        }
    }
}

// =========================================================================
// RBAC permissions list
// =========================================================================

/// Template for `GET /ui/admin/rbac/permissions`.
#[derive(Template)]
#[template(path = "ui/admin/rbac/permissions.html")]
struct RbacPermissionsTemplate {
    /// One row per known permission (declared in YAML or referenced by a role).
    permissions: Vec<PermissionRow>,
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

/// Row data for a permission in the permissions list template.
struct PermissionRow {
    name: String,
    description: String,
    /// True if the permission is declared in the YAML `permissions:` block.
    /// False means it was discovered only via a role's permission list.
    declared: bool,
    /// Names of roles that grant this permission, sorted alphabetically.
    roles: Vec<String>,
}

/// `GET /ui/admin/rbac/permissions` — list every permission known in the realm.
///
/// Merges YAML-declared permissions (which carry descriptions) with permissions
/// referenced by any role. For each permission, reports the count and names of
/// roles that grant it; flags permissions referenced by roles but missing from
/// the YAML `permissions:` block as `declared: false`.
pub async fn admin_rbac_permissions(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
) -> Response {
    // Look up realm name so we can index into config by name.
    let realm_name = state
        .identity
        .get_realm(target.id())
        .ok()
        .flatten()
        .map(|r| r.name().to_string());

    // Source 1: YAML-declared permissions (only place descriptions live).
    let yaml_perms: Vec<(String, String)> = realm_name
        .as_deref()
        .and_then(|name| {
            state
                .config
                .as_ref()
                .and_then(|cfg| cfg.realms.as_ref())
                .and_then(|realms| realms.get(name))
        })
        .and_then(|r| r.permissions.as_ref())
        .map(|perms| {
            perms
                .iter()
                .map(|p| (p.name.clone(), p.description.clone().unwrap_or_default()))
                .collect()
        })
        .unwrap_or_default();

    // Source 2: roles + their direct permissions.
    let roles_page = state
        .rbac
        .list_roles(target.id(), None, 200)
        .unwrap_or_default();

    let mut by_name: std::collections::BTreeMap<String, PermissionRow> =
        std::collections::BTreeMap::new();

    for (name, description) in yaml_perms {
        by_name.insert(
            name.clone(),
            PermissionRow {
                name,
                description,
                declared: true,
                roles: Vec::new(),
            },
        );
    }

    for role in &roles_page.items {
        for perm in &role.permissions {
            let entry = by_name
                .entry(perm.as_str().to_string())
                .or_insert_with(|| PermissionRow {
                    name: perm.as_str().to_string(),
                    description: String::new(),
                    declared: false,
                    roles: Vec::new(),
                });
            entry.roles.push(role.name.clone());
        }
    }

    let permissions: Vec<PermissionRow> = by_name
        .into_values()
        .map(|mut row| {
            row.roles.sort();
            row.roles.dedup();
            // Backfill descriptions for built-in seed permissions when the
            // realm's YAML config doesn't declare an override.
            if row.description.is_empty() {
                if let Some(d) = crate::rbac::seed_permission_description(&row.name) {
                    row.description = d.to_string();
                }
            }
            row
        })
        .collect();

    render(&RbacPermissionsTemplate {
        permissions,
        chrome: true,
        active: "rbac_permissions",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// =========================================================================
// RBAC roles list
// =========================================================================

/// Row data for a role in the roles list template.
struct RoleRow {
    name: String,
    scope: String,
    /// Direct permission names granted by this role (sorted, deduped).
    /// Does not include permissions inherited via `parent_roles`.
    permissions: Vec<String>,
    description: String,
}

/// Template for `GET /ui/admin/rbac/roles`.
#[derive(Template)]
#[template(path = "ui/admin/rbac/roles.html")]
struct RbacRolesTemplate {
    /// Rows for each role in the current realm.
    roles: Vec<RoleRow>,
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

/// `GET /ui/admin/rbac/roles` — read-only list of defined roles.
pub async fn admin_rbac_roles(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
) -> Response {
    let page = state
        .rbac
        .list_roles(target.id(), None, 200)
        .unwrap_or_default();

    let roles = page
        .items
        .into_iter()
        .map(|r| {
            let mut permissions: Vec<String> = r
                .permissions
                .iter()
                .map(|p| p.as_str().to_string())
                .collect();
            permissions.sort();
            permissions.dedup();
            RoleRow {
                name: r.name.clone(),
                scope: match r.scope_kind {
                    RoleScopeKind::Realm => "realm".to_string(),
                    RoleScopeKind::Organization => "organization".to_string(),
                    RoleScopeKind::Any => "any".to_string(),
                },
                permissions,
                description: r.description.clone().unwrap_or_default(),
            }
        })
        .collect();

    render(&RbacRolesTemplate {
        roles,
        chrome: true,
        active: "rbac_roles",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

// =========================================================================
// Realm claim profile viewer
// =========================================================================

/// A single row in the claim profile table.
struct ClaimMappingRow {
    claim: String,
    source: String,
    include_in_access_token: bool,
    include_in_id_token: bool,
    include_in_userinfo: bool,
    first_party_only: bool,
    required_scopes: Vec<String>,
}

/// Template for `GET /ui/admin/realms/:id/claims`.
#[derive(Template)]
#[template(path = "ui/admin/realms/claims/view.html")]
struct RealmClaimsTemplate {
    realm_id: String,
    realm_name: String,
    mappings: Vec<ClaimMappingRow>,
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

/// Converts a [`ClaimSource`] to a short human-readable label.
fn claim_source_label(source: &ClaimSource) -> String {
    match source {
        ClaimSource::RolesFromAssignments => "roles_from_assignments".to_string(),
        ClaimSource::GroupsFromMemberships => "groups_from_memberships".to_string(),
        ClaimSource::EffectivePermissions => "effective_permissions".to_string(),
        ClaimSource::OrgContext => "org_context".to_string(),
        ClaimSource::CanonicalUserField { field } => format!("user.{field:?}").to_lowercase(),
        ClaimSource::UserAttribute { attribute } => format!("attribute:{attribute}"),
        ClaimSource::RoleSubset { prefix } => format!("role_subset:{prefix}"),
        ClaimSource::Constant { value } => format!("constant:{value}"),
        ClaimSource::Omit => "omit".to_string(),
    }
}

/// `GET /ui/admin/realms/:id/claims` — read-only claim profile viewer.
pub async fn admin_realm_claims(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    AxumPath(rid): AxumPath<String>,
) -> Response {
    let Ok(realm_uuid) = rid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Realm not found");
    };
    let realm_id = RealmId::new(realm_uuid);

    let realm = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r,
        _ => return super::handlers_common::not_found("Realm not found"),
    };

    // Attempt to find the claim profile from config (YAML-managed) or fall
    // back to an empty list when no profile has been declared.
    let mappings = state
        .config
        .as_ref()
        .and_then(|cfg| cfg.realms.as_ref())
        .and_then(|realms| realms.get(realm.name()))
        .and_then(|r| r.claims.as_ref())
        .map(|profile| {
            profile
                .mappings
                .iter()
                .map(|m| ClaimMappingRow {
                    claim: m.claim.clone(),
                    source: claim_source_label(&m.source),
                    include_in_access_token: m.include_in_access_token,
                    include_in_id_token: m.include_in_id_token,
                    include_in_userinfo: m.include_in_userinfo,
                    first_party_only: m.first_party_only,
                    required_scopes: m.required_scopes.clone().unwrap_or_default(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    render(&RealmClaimsTemplate {
        realm_id: realm_id.as_uuid().to_string(),
        realm_name: realm.name().to_string(),
        mappings,
        chrome: true,
        active: "realms",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}
