//! RBAC tooling: debugger, scopes viewer, role definitions, permissions browser,
//! and org-member role/permission management.

use super::orgs::{org_redirect_flash, render_member_row_with_toast};
use super::*;

// =========================================================================
// RBAC debug / token preview / scopes / realm admin picker
// =========================================================================
// =========================================================================
// RBAC debugger: resolve effective permissions for a user
// =========================================================================

#[derive(Template)]
#[template(path = "ui/admin/rbac/debug.html")]
struct RbacDebugTemplate {
    realm_name: String,
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

/// `GET /ui/admin/permissions/resolve`.
///
/// Canonical alias to the RBAC debug page. Preserves query string so
/// links of the form `/ui/admin/permissions/resolve?user_id=…&org_id=…`
/// land on the same resolver as `/ui/admin/rbac/debug?user_id=…&org_id=…`.
/// 302 redirect (not 308) — the resolver is GET-only and idempotent.
pub async fn admin_permissions_resolve_alias(
    AxumPath(realm_name): AxumPath<String>,
    raw_query: axum::extract::RawQuery,
) -> axum::response::Redirect {
    let target = match raw_query.0 {
        Some(q) if !q.is_empty() => {
            format!("/ui/admin/realms/{realm_name}/rbac/debug?{q}")
        }
        _ => format!("/ui/admin/realms/{realm_name}/rbac/debug"),
    };
    axum::response::Redirect::to(&target)
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
    AxumPath(_realm_name): AxumPath<String>,
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
        realm_name: target.0.name().to_string(),
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
    AxumPath(_realm_name): AxumPath<String>,
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
    AxumPath(_realm_name): AxumPath<String>,
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
    #[allow(dead_code)]
    realm_id: String,
    realm_name: String,
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
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<RealmAdminPickerParams>,
) -> Response {
    let realm_id = target.id().clone();
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
        realm_name: target.0.name().to_string(),
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

// =========================================================================
// Per-member org RBAC (form types + handlers)
// =========================================================================

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
    AxumPath((_realm_name, oid, uid)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<MemberAssignRoleForm>,
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
                if let Ok(Some(m)) = state
                    .identity
                    .get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        target.0.name(),
                        &org_id,
                        m,
                        "Role assigned",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Role assigned", "success")
                }
            } else {
                org_redirect_flash(&org_id, target.0.name(), "Role assigned", "success")
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
    AxumPath((_realm_name, oid, uid, aid)): AxumPath<(String, String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<MemberUnassignRoleForm>,
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
                if let Ok(Some(m)) = state
                    .identity
                    .get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        target.0.name(),
                        &org_id,
                        m,
                        "Role removed",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Role removed", "success")
                }
            } else {
                org_redirect_flash(&org_id, target.0.name(), "Role removed", "success")
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
    AxumPath((_realm_name, oid, uid)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<MemberGrantPermForm>,
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
                if let Ok(Some(m)) = state
                    .identity
                    .get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        target.0.name(),
                        &org_id,
                        m,
                        "Permission granted",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Permission granted", "success")
                }
            } else {
                org_redirect_flash(&org_id, target.0.name(), "Permission granted", "success")
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
    AxumPath((_realm_name, oid, uid)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<MemberRevokePermForm>,
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
                if let Ok(Some(m)) = state
                    .identity
                    .get_membership(target.id(), &org_id, &user_id)
                {
                    render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        target.0.name(),
                        &org_id,
                        m,
                        "Permission revoked",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Permission revoked", "success")
                }
            } else {
                org_redirect_flash(&org_id, target.0.name(), "Permission revoked", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "org member revoke_perm failed");
            super::templates::htmx_toast_response(&format!("{e}"), "error")
        }
    }
}

// =========================================================================
// RBAC permissions browser + role definitions
// =========================================================================
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
    /// True for permissions baked into Hearth's RBAC seed (`realm.admin`,
    /// `org.read`, …). The 2026-04-29 audit caught the legacy "UNDECLARED"
    /// badge surfacing on every seed permission — technically accurate
    /// (they aren't in the YAML), but unhelpful: an operator can't
    /// "declare" a built-in permission, and seeing the warning everywhere
    /// trains them to ignore it. The template renders these as "Built-in"
    /// so the truly orphan permissions (a role referencing a typoed name,
    /// for instance) stand out.
    seed_bundled: bool,
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
    AxumPath(_realm_name): AxumPath<String>,
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
                seed_bundled: false,
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
                    seed_bundled: false,
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
            // realm's YAML config doesn't declare an override. A permission
            // with a known seed description is bundled with Hearth's RBAC
            // model, not "missing" — the template uses `seed_bundled` to
            // tell the two cases apart.
            if let Some(d) = crate::rbac::seed_permission_description(&row.name) {
                if row.description.is_empty() {
                    row.description = d.to_string();
                }
                row.seed_bundled = true;
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
// RBAC role CRUD (create / detail / edit / delete)
// =========================================================================

// ---------------------------------------------------------------------------
// Role create
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/rbac/role_new.html")]
struct RoleNewTemplate {
    error: Option<String>,
    realm_name: String,
    form_name: String,
    form_description: String,
    form_scope_kind: String,
    form_permissions: String,
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

impl RoleNewTemplate {
    fn blank(realm_name: String, session: &super::auth::UiSession, state: &Arc<WebState>) -> Self {
        Self {
            error: None,
            realm_name,
            form_name: String::new(),
            form_description: String::new(),
            form_scope_kind: "realm".to_string(),
            form_permissions: String::new(),
            active_tab: "rbac_roles",
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
        }
    }
}

/// `GET /ui/admin/realms/{realm}/rbac/roles/new`
pub async fn admin_role_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&RoleNewTemplate::blank(
        target.0.name().to_string(),
        &session,
        &state,
    ))
}

#[derive(Debug, Deserialize)]
pub struct RoleCreateForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scope_kind: String,
    #[serde(default)]
    pub permissions: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

fn parse_permissions_field(raw: &str) -> Result<Vec<Permission>, String> {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|p| Permission::new(p).map_err(|e| format!("Invalid permission '{p}': {e}")))
        .collect()
}

fn parse_scope_kind(s: &str) -> RoleScopeKind {
    match s {
        "organization" => RoleScopeKind::Organization,
        "any" => RoleScopeKind::Any,
        _ => RoleScopeKind::Realm,
    }
}

/// `POST /ui/admin/realms/{realm}/rbac/roles/new`
pub async fn admin_role_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<RoleCreateForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = target.0.name().to_string();

    let permissions = match parse_permissions_field(&form.permissions) {
        Ok(p) => p,
        Err(msg) => {
            let mut tpl = RoleNewTemplate::blank(realm_name, &session, &state);
            tpl.error = Some(msg);
            tpl.form_name = form.name.clone();
            tpl.form_description = form.description.clone();
            tpl.form_scope_kind = form.scope_kind.clone();
            tpl.form_permissions = form.permissions.clone();
            return render(&tpl);
        }
    };

    let req = CreateRoleRequest {
        name: form.name.clone(),
        description: if form.description.is_empty() {
            None
        } else {
            Some(form.description.clone())
        },
        permissions,
        parent_roles: Vec::new(),
        scope_kind: parse_scope_kind(&form.scope_kind),
    };

    match state.rbac.create_role(target.id(), &req) {
        Ok(role) => Redirect::to(&format!(
            "/ui/admin/realms/{}/rbac/roles/{}",
            realm_name,
            role.id.as_uuid(),
        ))
        .into_response(),
        Err(crate::rbac::RbacError::DuplicateRoleName) => {
            let mut tpl = RoleNewTemplate::blank(realm_name, &session, &state);
            tpl.error = Some("A role with that name already exists in this realm.".to_string());
            tpl.form_name = form.name.clone();
            tpl.form_description = form.description.clone();
            tpl.form_scope_kind = form.scope_kind.clone();
            tpl.form_permissions = form.permissions.clone();
            render(&tpl)
        }
        Err(crate::rbac::RbacError::InvalidRoleName { reason }) => {
            let mut tpl = RoleNewTemplate::blank(realm_name, &session, &state);
            tpl.error = Some(reason);
            tpl.form_name = form.name.clone();
            tpl.form_description = form.description.clone();
            tpl.form_scope_kind = form.scope_kind.clone();
            tpl.form_permissions = form.permissions.clone();
            render(&tpl)
        }
        Err(e) => {
            tracing::warn!(error = %e, "create_role failed");
            let mut tpl = RoleNewTemplate::blank(realm_name, &session, &state);
            tpl.error = Some("Unable to create role right now.".to_string());
            render(&tpl)
        }
    }
}

// ---------------------------------------------------------------------------
// Role detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/rbac/role_detail.html")]
struct RoleDetailTemplate {
    role: Role,
    scope: String,
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

/// `GET /ui/admin/realms/{realm}/rbac/roles/{id}`
pub async fn admin_role_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, rid)): AxumPath<(String, String)>,
) -> Response {
    let role_id = match rid.parse::<uuid::Uuid>() {
        Ok(u) => RoleId::new(u),
        Err(_) => return super::handlers_common::not_found("Role not found"),
    };
    match state.rbac.get_role(target.id(), &role_id) {
        Ok(Some(role)) => {
            let scope = match role.scope_kind {
                RoleScopeKind::Organization => "organization".to_string(),
                RoleScopeKind::Any => "any".to_string(),
                RoleScopeKind::Realm => "realm".to_string(),
            };
            render(&RoleDetailTemplate {
                role,
                scope,
                realm_name: target.0.name().to_string(),
                active_tab: "rbac_roles",
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
        Ok(None) => super::handlers_common::not_found("Role not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_role failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Role edit
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/rbac/role_edit.html")]
struct RoleEditTemplate {
    role: Role,
    error: Option<String>,
    realm_name: String,
    form_name: String,
    form_description: String,
    form_scope_kind: String,
    form_permissions: String,
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

impl RoleEditTemplate {
    fn from_role(
        role: Role,
        realm_name: String,
        session: &super::auth::UiSession,
        state: &Arc<WebState>,
    ) -> Self {
        let form_permissions = role
            .permissions
            .iter()
            .map(|p| p.as_str().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let form_scope_kind = match role.scope_kind {
            RoleScopeKind::Organization => "organization".to_string(),
            RoleScopeKind::Any => "any".to_string(),
            RoleScopeKind::Realm => "realm".to_string(),
        };
        let form_name = role.name.clone();
        let form_description = role.description.clone().unwrap_or_default();
        Self {
            role,
            error: None,
            realm_name,
            form_name,
            form_description,
            form_scope_kind,
            form_permissions,
            active_tab: "rbac_roles",
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
        }
    }
}

/// `GET /ui/admin/realms/{realm}/rbac/roles/{id}/edit`
pub async fn admin_role_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, rid)): AxumPath<(String, String)>,
) -> Response {
    let role_id = match rid.parse::<uuid::Uuid>() {
        Ok(u) => RoleId::new(u),
        Err(_) => return super::handlers_common::not_found("Role not found"),
    };
    match state.rbac.get_role(target.id(), &role_id) {
        Ok(Some(role)) => render(&RoleEditTemplate::from_role(
            role,
            target.0.name().to_string(),
            &session,
            &state,
        )),
        Ok(None) => super::handlers_common::not_found("Role not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_role failed");
            super::handlers_common::server_error()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RoleEditForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scope_kind: String,
    #[serde(default)]
    pub permissions: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/rbac/roles/{id}/edit`
pub async fn admin_role_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, rid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<RoleEditForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let role_id = match rid.parse::<uuid::Uuid>() {
        Ok(u) => RoleId::new(u),
        Err(_) => return super::handlers_common::not_found("Role not found"),
    };

    let realm_name = target.0.name().to_string();

    let permissions = match parse_permissions_field(&form.permissions) {
        Ok(p) => p,
        Err(msg) => {
            return match state.rbac.get_role(target.id(), &role_id) {
                Ok(Some(role)) => {
                    let mut tpl = RoleEditTemplate::from_role(role, realm_name, &session, &state);
                    tpl.error = Some(msg);
                    tpl.form_name = form.name.clone();
                    tpl.form_description = form.description.clone();
                    tpl.form_scope_kind = form.scope_kind.clone();
                    tpl.form_permissions = form.permissions.clone();
                    render(&tpl)
                }
                _ => super::handlers_common::server_error(),
            };
        }
    };

    let req = UpdateRoleRequest {
        name: if form.name.is_empty() {
            None
        } else {
            Some(form.name.clone())
        },
        description: Some(if form.description.is_empty() {
            None
        } else {
            Some(form.description.clone())
        }),
        permissions: Some(permissions),
        parent_roles: None,
        scope_kind: Some(parse_scope_kind(&form.scope_kind)),
        status: None,
    };

    match state.rbac.update_role(target.id(), &role_id, &req) {
        Ok(_) => Redirect::to(&format!(
            "/ui/admin/realms/{}/rbac/roles/{}",
            realm_name,
            role_id.as_uuid(),
        ))
        .into_response(),
        Err(crate::rbac::RbacError::RoleNotFound) => {
            super::handlers_common::not_found("Role not found")
        }
        Err(crate::rbac::RbacError::DuplicateRoleName) => {
            match state.rbac.get_role(target.id(), &role_id) {
                Ok(Some(role)) => {
                    let mut tpl = RoleEditTemplate::from_role(role, realm_name, &session, &state);
                    tpl.error =
                        Some("A role with that name already exists in this realm.".to_string());
                    tpl.form_name = form.name.clone();
                    tpl.form_description = form.description.clone();
                    tpl.form_scope_kind = form.scope_kind.clone();
                    tpl.form_permissions = form.permissions.clone();
                    render(&tpl)
                }
                _ => super::handlers_common::server_error(),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_role failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/realms/{realm}/rbac/roles/{id}/delete`
pub async fn admin_role_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, rid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let role_id = match rid.parse::<uuid::Uuid>() {
        Ok(u) => RoleId::new(u),
        Err(_) => return super::handlers_common::not_found("Role not found"),
    };

    let realm_name = target.0.name().to_string();

    match state.rbac.delete_role(target.id(), &role_id) {
        Ok(()) => {
            Redirect::to(&format!("/ui/admin/realms/{}/rbac/roles", realm_name)).into_response()
        }
        Err(crate::rbac::RbacError::RoleNotFound) => {
            super::handlers_common::not_found("Role not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete_role failed");
            super::handlers_common::server_error()
        }
    }
}

// =========================================================================
// RBAC roles list
// =========================================================================

/// Row data for a role in the roles list template.
struct RoleRow {
    id: String,
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

/// `GET /ui/admin/rbac/roles` — list of defined roles with links to detail.
pub async fn admin_rbac_roles(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
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
                id: r.id.as_uuid().to_string(),
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
        realm_name: target.0.name().to_string(),
        active_tab: "rbac_roles",
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
    #[allow(dead_code)]
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

// =========================================================================
// Realm claims viewer
// =========================================================================
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

/// `GET /ui/admin/realms/{realm}/claims` — read-only claim profile viewer.
pub async fn admin_realm_claims(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    let realm_id = target.id().clone();

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
