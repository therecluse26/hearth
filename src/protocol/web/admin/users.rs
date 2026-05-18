//! User CRUD, sessions, consents, and per-user role/permission assignment.

use super::*;

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
    realm_name: String,
    /// Base URL the search form submits to, also used as the `hx-get`
    /// target for live search. `/ui/admin/realms/{name}/users` for
    /// tenant realms, `/ui/admin/admin-users` for the system-realm
    /// operator surface.
    list_url: String,
    active_tab: &'static str,
    /// See `UserRowsTemplate::user_base_url`.
    user_base_url: String,
    /// See `UserRowsTemplate::user_detail_qs`.
    user_detail_qs: String,
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

/// Rows-only partial returned when the user list is filtered live via
/// HTMX. Keeps the response payload to a single `<tbody>` swap so the
/// page chrome doesn't re-render on every keystroke.
#[derive(Template)]
#[template(path = "ui/admin/users/_rows.html")]
struct UserRowsTemplate {
    users: Vec<User>,
    /// Path prefix for user detail/edit links, e.g.
    /// `/ui/admin/realms/foo/users`.
    user_base_url: String,
    /// Optional query-string suffix appended after each detail/edit
    /// path segment, e.g. `""` for tenant realms or
    /// `"?admin_target=system"` for the system realm so `TargetRealm`
    /// resolves correctly without a path-segment realm name.
    user_detail_qs: String,
}

/// `GET /ui/admin/users`.
pub async fn admin_users_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    htmx: super::templates::IsHtmx,
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
        Ok(page) => {
            let realm_name = target.0.name().to_string();
            let user_base_url = format!("/ui/admin/realms/{realm_name}/users");
            if htmx.0 {
                return render(&UserRowsTemplate {
                    users: page.items,
                    user_base_url,
                    user_detail_qs: String::new(),
                });
            }
            render(&UserListTemplate {
                users: page.items,
                next_cursor: page.next_cursor,
                search_query,
                list_url: format!("/ui/admin/realms/{realm_name}/users"),
                active_tab: "users",
                user_base_url,
                user_detail_qs: String::new(),
                realm_name,
                chrome: true,
                active: "realm-workspace",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name_for(target.id()),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "list_users failed");
            super::handlers_common::server_error()
        }
    }
}

/// `GET /ui/admin/admin-users/new`.
///
/// 302 alias to `/ui/admin/users/new?admin_target=system`. The generic
/// user-create form already pre-scopes to the system realm when its
/// `TargetRealm` extractor sees `?admin_target=system`, so this is a thin
/// redirect — no template duplication. POST submissions go to
/// `/ui/admin/users/new?admin_target=system` (the form's own action),
/// not back through this alias.
pub async fn admin_admin_user_create_alias() -> axum::response::Redirect {
    axum::response::Redirect::to("/ui/admin/users/new?admin_target=system")
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
    htmx: super::templates::IsHtmx,
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
        Ok(page) => {
            if htmx.0 {
                return render(&UserRowsTemplate {
                    users: page.items,
                    user_base_url: "/ui/admin/realms/system/users".to_string(),
                    user_detail_qs: "?admin_target=system".to_string(),
                });
            }
            render(&UserListTemplate {
                users: page.items,
                next_cursor: page.next_cursor,
                search_query,
                realm_name: String::new(),
                list_url: "/ui/admin/admin-users".to_string(),
                active_tab: "",
                user_base_url: "/ui/admin/realms/system/users".to_string(),
                user_detail_qs: "?admin_target=system".to_string(),
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
            })
        }
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
    realm_name: String,
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
    AxumPath(realm_name): AxumPath<String>,
) -> Response {
    render(&UserNewTemplate {
        error: None,
        realm_name,
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
        narrow: false,
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
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<CreateUserForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let req = CreateUserRequest {
        email: form.email.clone(),
        display_name: form.display_name.clone(),
        first_name: form.first_name.clone(),
        last_name: form.last_name.clone(),
        attributes: Default::default(),
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
            Redirect::to(&format!(
                "/ui/admin/realms/{}/users/{}",
                target.0.name(),
                user.id().as_uuid()
            ))
            .into_response()
        }
        Err(IdentityError::DuplicateEmail) => render(&UserNewTemplate {
            error: Some("A user with that email already exists.".to_string()),
            realm_name: target.0.name().to_string(),
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
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        }),
        Err(IdentityError::InvalidInput { reason }) => render(&UserNewTemplate {
            error: Some(reason),
            realm_name: target.0.name().to_string(),
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
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "create_user failed");
            render(&UserNewTemplate {
                error: Some("Unable to create user right now.".to_string()),
                realm_name: target.0.name().to_string(),
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
                narrow: false,
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
    /// Whether the session has passed its expires_at relative to wall-clock
    /// at request time. The 2026-04-30 UX audit caught listings showing
    /// already-expired sessions as "Active" simply because the storage row
    /// hadn't been touched. Computed server-side; the template branches on
    /// this before showing the success-coloured "Active" badge.
    pub expired: bool,
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

/// Template for `GET /ui/admin/users/:id`.
#[derive(Template)]
#[template(path = "ui/admin/users/detail.html")]
#[allow(clippy::struct_excessive_bools)]
struct UserDetailTemplate {
    user: User,
    realm_name: String,
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
    /// Per-role groups of inherited permissions, used to attribute each
    /// inherited permission to its source role + scope in the Permissions tab.
    role_inherited_groups: Vec<RoleInheritedGroup>,
    /// Known permission strings not already inherited via roles (for the datalist).
    available_permissions: Vec<String>,
    /// Fully resolved effective permission names for this user.
    effective_permissions: Vec<String>,
    /// JSON object mapping role UUID → sorted permission strings, for Alpine.js.
    role_perms_json: String,
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
    realm_name: String,
    user_id: String,
    role_assignments: Vec<UserRoleAssignmentRow>,
    available_roles: Vec<AvailableRole>,
    available_orgs: Vec<AvailableOrg>,
    /// JSON object mapping role UUID → sorted permission strings, for Alpine.js in-browser lookup.
    role_perms_json: String,
    csrf: Option<String>,
}

/// Template for the Extra Permissions tab HTMX partial.
#[derive(Template)]
#[template(path = "ui/admin/users/_permissions_tab.html")]
struct UserPermissionsTabTemplate {
    realm_name: String,
    user_id: String,
    extra_permissions: Vec<UserPermissionGrantRow>,
    /// Per-role groups of inherited permissions for attribution display.
    role_inherited_groups: Vec<RoleInheritedGroup>,
    /// Known permission strings not already inherited via roles (for the datalist).
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
    Query(params): Query<UserDetailParams>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => {
            return super::handlers_common::not_found_authed(&state, &session, "User not found");
        }
    };

    let user = match state.identity.get_user(target.id(), &uid) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return super::handlers_common::not_found_authed(&state, &session, "User not found");
        }
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
    // Single now-snapshot for the whole list so two rows can't disagree
    // on whether they're past expiry within the same render.
    let now_micros = crate::core::Timestamp::now().as_micros();
    let sessions: Vec<UserSessionRow> = raw_sessions
        .items
        .iter()
        .map(|s| UserSessionRow {
            id: s.id().as_uuid().to_string(),
            created_at: format_ts(s.created_at()),
            expires_at: format_ts(s.expires_at()),
            revoked: s.is_revoked(),
            expired: s.expires_at().as_micros() <= now_micros,
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
    let role_inherited_groups = build_role_inherited_groups(&role_assignments);

    // All roles in this realm (for the assign-role form dropdown).
    let available_roles: Vec<AvailableRole> = state
        .rbac
        .list_roles(target.id(), None, 200)
        .map(|p| p.items)
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            let mut perms: Vec<String> = r
                .permissions
                .iter()
                .map(|p| p.as_str().to_string())
                .collect();
            perms.sort_unstable();
            AvailableRole {
                id: r.id.as_uuid().to_string(),
                description: r.description.unwrap_or_default(),
                scope_kind: format!("{:?}", r.scope_kind),
                name: r.name,
                permissions: perms,
            }
        })
        .collect();

    // Build role_id → [permissions] JSON map for Alpine.js in-browser lookup.
    let role_perms_map: std::collections::HashMap<&str, &[String]> = available_roles
        .iter()
        .map(|r| (r.id.as_str(), r.permissions.as_slice()))
        .collect();
    let role_perms_json =
        serde_json::to_string(&role_perms_map).unwrap_or_else(|_| "{}".to_string());

    // All orgs in this realm (for the scope picker).
    let available_orgs = build_available_orgs(&state, target.id());

    // Directly-granted permissions with scope display info.
    let extra_permissions = build_permission_grant_rows(&state, target.id(), &uid);

    // Fully resolved effective permissions (union of roles + direct grants).
    let effective_permissions: Vec<String> = state
        .rbac
        .resolve_permissions(&uid, target.id(), None, None)
        .map(|r| r.permissions.into_iter().map(|p| p.into_string()).collect())
        .unwrap_or_default();

    // Permissions the user inherits via roles (effective minus direct grants).
    let direct_grant_set: std::collections::HashSet<&str> = extra_permissions
        .iter()
        .map(|p| p.permission.as_str())
        .collect();
    let mut role_inherited_permissions: Vec<String> = effective_permissions
        .iter()
        .filter(|p| !direct_grant_set.contains(p.as_str()))
        .cloned()
        .collect();
    role_inherited_permissions.sort_unstable();
    let role_inherited_set: std::collections::HashSet<&str> = role_inherited_permissions
        .iter()
        .map(String::as_str)
        .collect();

    // Known permission strings not already covered by roles (datalist autocomplete).
    let available_permissions: Vec<String> = collect_realm_permissions(&state, target.id())
        .into_iter()
        .filter(|p| !role_inherited_set.contains(p.as_str()))
        .collect();

    // User attributes as sorted (key, value) pairs.
    let attributes: Vec<(String, String)> = user
        .attributes()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    render(&UserDetailTemplate {
        user_id: uid.as_uuid().to_string(),
        user,
        realm_name: target.0.name().to_string(),
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
        role_inherited_groups,
        available_permissions,
        effective_permissions,
        role_perms_json,
        attributes,
        chrome: true,
        active: "users",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
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

    Redirect::to(&format!(
        "/ui/admin/realms/{}/users/{user_id}?flash=reset_sent",
        target.0.name()
    ))
    .into_response()
}

/// `POST /ui/admin/users/:id/disable-mfa` — disables MFA for the user.
pub async fn admin_user_disable_mfa(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
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

    Redirect::to(&format!(
        "/ui/admin/realms/{}/users/{user_id}?flash=mfa_disabled",
        target.0.name()
    ))
    .into_response()
}

/// Template showing new recovery codes after an admin reset.
#[derive(askama::Template)]
#[template(path = "ui/admin/mfa_codes_reset.html")]
struct AdminMfaCodesResetTemplate {
    codes: Vec<String>,
    user_id: String,
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

/// `POST /ui/admin/users/:id/reset-mfa-codes` — regenerates recovery codes for the user.
///
/// Generates a new set of Argon2id-hashed recovery codes (invalidating any
/// existing ones) and renders them once on a confirmation page.
pub async fn admin_user_reset_mfa_codes(
    State(state): State<Arc<WebState>>,
    RequireAdmin(admin_session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
) -> Response {
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };
    let uid_str = uid.as_uuid().to_string();

    let realm_id = target.id().clone();
    let identity = state.identity.clone();
    let result =
        tokio::task::spawn_blocking(move || identity.regenerate_recovery_codes(&realm_id, &uid))
            .await;

    match result {
        Ok(Ok(codes)) => {
            tracing::info!(user_id = %uid_str, admin = %admin_session.user_email, "admin reset MFA recovery codes");
            let tmpl = AdminMfaCodesResetTemplate {
                codes,
                user_id: user_id.clone(),
                realm_name: target.0.name().to_string(),
                chrome: true,
                active: "admin",
                user_email: Some(admin_session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: None,
                narrow: false,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            };
            render(&tmpl)
        }
        Ok(Err(IdentityError::MfaNotEnabled)) => Redirect::to(&format!(
            "/ui/admin/realms/{}/users/{user_id}?flash=mfa_not_enabled",
            target.0.name()
        ))
        .into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "admin reset_mfa_codes failed");
            Redirect::to(&format!(
                "/ui/admin/realms/{}/users/{user_id}?flash=mfa_reset_error",
                target.0.name()
            ))
            .into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin reset_mfa_codes panicked");
            Redirect::to(&format!(
                "/ui/admin/realms/{}/users/{user_id}?flash=mfa_reset_error",
                target.0.name()
            ))
            .into_response()
        }
    }
}

/// `POST /ui/admin/users/:id/sessions/:sid/revoke` — revokes a single session.
pub async fn admin_user_revoke_session(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, user_id, session_id)): AxumPath<(String, String, String)>,
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

    Redirect::to(&format!(
        "/ui/admin/realms/{}/users/{user_id}?flash=session_revoked",
        target.0.name()
    ))
    .into_response()
}

/// `POST /ui/admin/users/:id/webauthn/:cred_id/revoke` — revokes a `WebAuthn` credential.
pub async fn admin_user_revoke_webauthn(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, user_id, cred_id_b64)): AxumPath<(String, String, String)>,
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

    Redirect::to(&format!(
        "/ui/admin/realms/{}/users/{user_id}?flash=webauthn_revoked",
        target.0.name()
    ))
    .into_response()
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
    realm_name: String,
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
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
                realm_name: target.0.name().to_string(),
                error: None,
                is_user_admin,
                org_memberships,
                chrome: true,
                active: "users",
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<EditUserForm>,
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
            Redirect::to(&format!(
                "/ui/admin/realms/{}/users/{}",
                target.0.name(),
                uid.as_uuid()
            ))
            .into_response()
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteUserForm>,
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
            Redirect::to(&format!("/ui/admin/realms/{}/users", target.0.name())).into_response()
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
                realm_name: target.name().to_string(),
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
                narrow: false,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            })
        }
        None => super::handlers_common::not_found("User not found"),
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
    /// Display name of the realm this session lives in. `"system"` for
    /// admin sessions, the realm name for tenant sessions. Surfaced as a
    /// column in the global sessions view at `/ui/admin/sessions`.
    pub realm_name: String,
    /// Query string the revoke form must append so the
    /// `admin_session_revoke` handler resolves the right realm — either
    /// `"?admin_target=system"` for the system realm or
    /// `"?realm=<name>"` for a tenant.
    pub realm_target_query: String,
    /// `true` when the session is neither revoked nor past its
    /// `expires_at`. Drives the Active/Expired filter and the row badge.
    pub is_active: bool,
}

#[derive(Template)]
#[template(path = "ui/admin/sessions/list.html")]
struct SessionListTemplate {
    sessions: Vec<SessionRow>,
    next_cursor: Option<String>,
    realm_name: String,
    /// `true` when the page is rendering the cross-realm aggregation at
    /// `/ui/admin/sessions` (no `?realm=` / `?admin_target=`). The list
    /// template uses this to swap the heading and reveal the Realm
    /// column.
    is_global: bool,
    /// Currently selected expiry filter — `"active"`, `"expired"`, or
    /// `"all"`. Defaults to `"active"`. Drives the filter pill highlight
    /// and the per-row classification.
    status_filter: String,
    /// Counts before filtering — surfaced in the filter pill labels so
    /// operators can see the cardinality without flipping tabs.
    count_active: usize,
    count_expired: usize,
    /// Realm-context query prefix the filter pill links append to
    /// `/ui/admin/sessions`. Empty for the global view; `"&realm=foo"` or
    /// `"&admin_target=system"` for the scoped views. Allows pill links
    /// to keep the page in its current realm scope when switching status.
    #[allow(dead_code)]
    realm_query_suffix: String,
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

/// Query params for the sessions list page. Extends pagination with an
/// expiry filter. Default semantics: no `status` → show only Active.
#[derive(Debug, Deserialize, Default)]
pub struct SessionsListParams {
    /// Opaque cursor for the next page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Expiry filter — `"active"` (default), `"expired"`, or `"all"`.
    #[serde(default)]
    pub status: Option<String>,
}

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
///
/// Renders one of three views depending on the request's realm context:
///
/// 1. `?realm=<name>` — sessions in that tenant realm only.
/// 2. `?admin_target=system` — sessions in the system realm (operators).
/// 3. No realm query param — **global** view aggregating across the
///    system realm + every tenant realm. Surfaces the admin's own
///    session, which would otherwise be invisible from the tenant-only
///    fallback that the legacy handler used. Reveals a "Realm" column
///    so each row's origin is unambiguous, and routes per-row revoke
///    requests back to the row's realm via `realm_target_query`.
///
/// Cursor pagination is intentionally disabled for the global view —
/// stitching cursors across realms would require a fan-out paginator
/// that this PR doesn't introduce. A LIMIT-per-realm cap keeps the
/// query bounded; busy deployments should narrow with `?realm=` until
/// a real cross-realm cursor is added.
pub async fn admin_sessions_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<SessionsListParams>,
) -> Response {
    // Single now-snapshot per request — two rows can't disagree on
    // whether they're past expiry within the same render.
    let now_micros = crate::core::Timestamp::now().as_micros();
    let status_filter = match params.status.as_deref() {
        Some("expired") => "expired".to_string(),
        Some("all") => "all".to_string(),
        _ => "active".to_string(),
    };

    let realm_name = target.0.name().to_string();
    // Per-row revoke forms POST to a path-based URL; the suffix is
    // empty under R-1 because the realm now lives in the path, not in
    // a query string. Kept as a template field so the partial doesn't
    // need to know whether realm context survives in query params.
    let row_target_query = String::new();

    match state
        .identity
        .list_sessions_by_realm(target.id(), params.cursor.as_deref(), 20)
    {
        Ok(page) => {
            let all_rows: Vec<SessionRow> = page
                .items
                .into_iter()
                .map(|s| {
                    build_session_row(
                        &state,
                        target.id(),
                        &realm_name,
                        &row_target_query,
                        s,
                        now_micros,
                    )
                })
                .collect();
            let count_active = all_rows.iter().filter(|r| r.is_active).count();
            let count_expired = all_rows.len() - count_active;
            let rows = filter_session_rows(all_rows, &status_filter);
            render(&SessionListTemplate {
                sessions: rows,
                next_cursor: page.next_cursor,
                realm_name: realm_name.clone(),
                is_global: false,
                status_filter: status_filter.clone(),
                count_active,
                count_expired,
                realm_query_suffix: String::new(),
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

/// Applies the `?status=` filter to a freshly-built row collection. Pure
/// function so the unit test can pin behaviour without spinning up a
/// `WebState`.
fn filter_session_rows(rows: Vec<SessionRow>, status: &str) -> Vec<SessionRow> {
    match status {
        "expired" => rows.into_iter().filter(|r| !r.is_active).collect(),
        "all" => rows,
        _ => rows.into_iter().filter(|r| r.is_active).collect(),
    }
}

/// Builds a [`SessionRow`] with display fields and the realm-context
/// query string used by the revoke form. Centralises the per-row glue
/// so both single-realm and global views render identical row shapes.
fn build_session_row(
    state: &Arc<WebState>,
    realm_id: &crate::core::RealmId,
    realm_name: &str,
    target_query: &str,
    s: Session,
    now_micros: i64,
) -> SessionRow {
    let user_email = resolve_user_email(state, realm_id, s.user_id());
    let device_label = s.device_label().unwrap_or("Unknown device").to_string();
    let ip_address = s.ip_address().unwrap_or("\u{2014}").to_string();
    let is_active = !s.is_revoked() && s.expires_at().as_micros() > now_micros;
    SessionRow {
        created_at_display: format_ts(s.created_at()),
        expires_at_display: format_ts(s.expires_at()),
        session: s,
        user_email,
        device_label,
        ip_address,
        realm_name: realm_name.to_string(),
        realm_target_query: target_query.to_string(),
        is_active,
    }
}

/// `POST /ui/admin/sessions/:id/revoke`.
pub async fn admin_session_revoke(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    htmx: super::templates::IsHtmx,
    AxumPath((_realm_name, sid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
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
                Redirect::to(&format!("/ui/admin/realms/{}/sessions", target.0.name()))
                    .into_response()
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

// ---------------------------------------------------------------------------
// User consents
// ---------------------------------------------------------------------------
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
    AxumPath((_realm_name, user_id_str)): AxumPath<(String, String)>,
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
        narrow: false,
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
    AxumPath((_realm_name, user_id_str, client_id_str)): AxumPath<(String, String, String)>,
    FriendlyForm(form): FriendlyForm<CsrfOnlyForm>,
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
        Ok(()) => Redirect::to(&format!(
            "/ui/admin/realms/{}/users/{}/applications",
            target_realm.0.name(),
            user_id.as_uuid()
        ))
        .into_response(),
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

// ---------------------------------------------------------------------------
// User role / permission HTMX handlers (render_roles_tab, render_permissions_tab)
// and mutation handlers
// ---------------------------------------------------------------------------

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
pub(super) fn render_roles_tab(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    realm_name: &str,
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
        .map(|r| {
            let mut perms: Vec<String> = r
                .permissions
                .iter()
                .map(|p| p.as_str().to_string())
                .collect();
            perms.sort_unstable();
            AvailableRole {
                id: r.id.as_uuid().to_string(),
                description: r.description.unwrap_or_default(),
                scope_kind: format!("{:?}", r.scope_kind),
                name: r.name,
                permissions: perms,
            }
        })
        .collect();
    let role_perms_map: std::collections::HashMap<&str, &[String]> = available_roles
        .iter()
        .map(|r| (r.id.as_str(), r.permissions.as_slice()))
        .collect();
    let role_perms_json =
        serde_json::to_string(&role_perms_map).unwrap_or_else(|_| "{}".to_string());
    let available_orgs = build_available_orgs(state, realm_id);
    render(&UserRolesTabTemplate {
        realm_name: realm_name.to_string(),
        user_id: user_id_str,
        role_assignments,
        available_roles,
        available_orgs,
        role_perms_json,
        csrf: session.csrf.clone(),
    })
}

/// Renders the Extra Permissions tab partial for HTMX responses.
pub(super) fn render_permissions_tab(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    realm_name: &str,
    user_id: &crate::core::UserId,
) -> Response {
    let user_id_str = user_id.as_uuid().to_string();
    let extra_permissions = build_permission_grant_rows(state, realm_id, user_id);
    let role_assignments = build_role_assignment_rows(state, realm_id, user_id);
    let role_inherited_groups = build_role_inherited_groups(&role_assignments);
    let effective_permissions: Vec<String> = state
        .rbac
        .resolve_permissions(user_id, realm_id, None, None)
        .map(|r| r.permissions.into_iter().map(|p| p.into_string()).collect())
        .unwrap_or_default();
    let direct_grant_set: std::collections::HashSet<&str> = extra_permissions
        .iter()
        .map(|p| p.permission.as_str())
        .collect();
    let mut role_inherited_permissions: Vec<String> = effective_permissions
        .into_iter()
        .filter(|p| !direct_grant_set.contains(p.as_str()))
        .collect();
    role_inherited_permissions.sort_unstable();
    let role_inherited_set: std::collections::HashSet<&str> = role_inherited_permissions
        .iter()
        .map(String::as_str)
        .collect();
    let available_permissions: Vec<String> = collect_realm_permissions(state, realm_id)
        .into_iter()
        .filter(|p| !role_inherited_set.contains(p.as_str()))
        .collect();
    let available_orgs = build_available_orgs(state, realm_id);
    render(&UserPermissionsTabTemplate {
        realm_name: realm_name.to_string(),
        user_id: user_id_str,
        extra_permissions,
        role_inherited_groups,
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<AssignRoleForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let uid = match user_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::UserId::new(u),
        Err(_) => return super::handlers_common::not_found("User not found"),
    };
    let realm_name = target.0.name();
    let Ok(role_uuid) = form.role_id.parse::<uuid::Uuid>() else {
        return if is_htmx_request(&headers) {
            super::templates::htmx_toast_response("Invalid role ID", "error")
        } else {
            Redirect::to(&format!(
                "/ui/admin/realms/{realm_name}/users/{user_id}?flash=invalid_role"
            ))
            .into_response()
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
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=invalid_scope"
                ))
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
                render_roles_tab(&state, &session, target.id(), target.0.name(), &uid)
            } else {
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=role_assigned"
                ))
                .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "assign_role failed");
            if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(&format!("{e}"), "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=assign_role_failed"
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
    AxumPath((_realm_name, user_id, assignment_id)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<UnassignRoleForm>,
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
    let realm_name = target.0.name();
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
                render_roles_tab(&state, &session, target.id(), target.0.name(), &uid)
            } else {
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=role_unassigned"
                ))
                .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "unassign_role failed");
            if is_htmx_request(&headers) {
                super::templates::htmx_toast_response(&format!("{e}"), "error")
            } else {
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=unassign_role_failed"
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<GrantPermissionForm>,
) -> Response {
    use crate::core::Timestamp;
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let realm_name = target.0.name();
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
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=invalid_permission"
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
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=invalid_scope"
                ))
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
                render_permissions_tab(&state, &session, target.id(), target.0.name(), &uid)
            } else {
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=permission_granted"
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
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=grant_permission_failed"
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
    AxumPath((_realm_name, user_id)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<RevokePermissionForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let realm_name = target.0.name();
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
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=invalid_permission"
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
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=invalid_scope"
                ))
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
                render_permissions_tab(&state, &session, target.id(), target.0.name(), &uid)
            } else {
                Redirect::to(&format!(
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=permission_revoked"
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
                    "/ui/admin/realms/{realm_name}/users/{user_id}?flash=revoke_permission_failed"
                ))
                .into_response()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bulk action
// ---------------------------------------------------------------------------

/// Form body for bulk user actions.
#[derive(Debug, Deserialize)]
pub struct BulkActionForm {
    /// Comma-separated list of user UUID strings selected by the client.
    #[serde(default)]
    pub ids: String,
    /// One of: `assign_role`, `send_invite`, `deactivate`, `export`.
    #[serde(default)]
    pub bulk_action: String,
    /// Role UUID — required when `bulk_action == "assign_role"`.
    #[serde(default)]
    pub role_id: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/users/bulk-action`
pub async fn admin_users_bulk_action(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<BulkActionForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let user_ids: Vec<crate::core::UserId> = form
        .ids
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.trim().parse::<uuid::Uuid>().ok())
        .map(crate::core::UserId::new)
        .collect();

    if user_ids.is_empty() {
        return Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/users?flash=no_users_selected"
        ))
        .into_response();
    }

    match form.bulk_action.as_str() {
        "deactivate" => {
            let req = UpdateUserRequest {
                email: None,
                display_name: None,
                first_name: None,
                last_name: None,
                attributes: None,
                status: Some(UserStatus::Disabled),
            };
            for uid in &user_ids {
                if let Err(e) = state.identity.update_user(target.id(), uid, &req) {
                    tracing::warn!(error = %e, user_id = %uid.as_uuid(), "bulk deactivate failed");
                }
            }
            Redirect::to(&format!(
                "/ui/admin/realms/{realm_name}/users?flash=bulk_deactivated"
            ))
            .into_response()
        }
        "send_invite" => {
            for uid in &user_ids {
                match state.identity.get_user(target.id(), uid) {
                    Ok(Some(user)) => {
                        if let Err(e) = state
                            .identity
                            .request_password_reset(target.id(), user.email())
                        {
                            tracing::warn!(error = %e, user_id = %uid.as_uuid(), "bulk send_invite failed");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, user_id = %uid.as_uuid(), "get_user for bulk invite failed");
                    }
                }
            }
            Redirect::to(&format!(
                "/ui/admin/realms/{realm_name}/users?flash=bulk_invited"
            ))
            .into_response()
        }
        "assign_role" => {
            let role_uuid = match form.role_id.parse::<uuid::Uuid>() {
                Ok(u) => u,
                Err(_) => {
                    return Redirect::to(&format!(
                        "/ui/admin/realms/{realm_name}/users?flash=invalid_role"
                    ))
                    .into_response();
                }
            };
            let role_id = crate::rbac::RoleId::new(role_uuid);
            for uid in &user_ids {
                let req = crate::rbac::AssignRoleRequest {
                    subject: crate::rbac::Subject::User(uid.clone()),
                    role_id: role_id.clone(),
                    scope: crate::rbac::Scope::Realm,
                    assigned_by: Some(session.user_id.clone()),
                };
                if let Err(e) = state.rbac.assign_role(target.id(), &req) {
                    tracing::warn!(error = %e, user_id = %uid.as_uuid(), "bulk assign_role failed");
                }
            }
            Redirect::to(&format!(
                "/ui/admin/realms/{realm_name}/users?flash=bulk_role_assigned"
            ))
            .into_response()
        }
        _ => Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/users?flash=unknown_action"
        ))
        .into_response(),
    }
}

// ---------------------------------------------------------------------------
// User CSV import
// ---------------------------------------------------------------------------

/// Template struct for the import form.
#[derive(Template)]
#[template(path = "ui/admin/users/import.html")]
struct UserImportTemplate {
    error: Option<String>,
    realm_name: String,
    list_url: String,
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

/// `GET /ui/admin/realms/{realm}/users/import`
pub async fn admin_users_import_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(realm_name): AxumPath<String>,
) -> Response {
    render(&UserImportTemplate {
        error: None,
        realm_name: realm_name.clone(),
        list_url: format!("/ui/admin/realms/{realm_name}/users"),
        active_tab: "users",
        chrome: true,
        active: "realm-workspace",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    })
}

/// `GET /ui/admin/realms/{realm}/users/import/template.csv`
pub async fn admin_users_import_template_csv(
    RequireAdmin(_session): RequireAdmin,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    let csv = "email,name,role\nexample@company.com,Jane Doe,admin\n";
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "text/csv; charset=utf-8")
        .header(
            "Content-Disposition",
            "attachment; filename=\"users_template.csv\"",
        )
        .body(axum::body::Body::from(csv))
        .unwrap_or_else(|_| super::handlers_common::server_error())
}

/// Summary returned after a CSV import.
struct ImportSummary {
    created: usize,
    updated: usize,
    skipped: usize,
    errors: Vec<String>,
}

/// `POST /ui/admin/realms/{realm}/users/import` — process uploaded CSV.
pub async fn admin_users_import_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(realm_name): AxumPath<String>,
    mut multipart: axum::extract::Multipart,
) -> Response {
    // Extract CSV bytes and column mapping from the multipart form.
    let mut csv_bytes: Option<Vec<u8>> = None;
    let mut col_email = String::new();
    let mut col_name = String::new();
    let mut col_role = String::new();
    let mut csrf_token = String::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "csv_file" => {
                csv_bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            "col_email" => {
                col_email = field.text().await.unwrap_or_default();
            }
            "col_name" => {
                col_name = field.text().await.unwrap_or_default();
            }
            "col_role" => {
                col_role = field.text().await.unwrap_or_default();
            }
            "_csrf" => {
                csrf_token = field.text().await.unwrap_or_default();
            }
            _ => {}
        }
    }

    if let Err(resp) = verify_csrf_form_field(&session, &csrf_token) {
        return resp;
    }

    let bytes = match csv_bytes {
        Some(b) if !b.is_empty() => b,
        _ => {
            return render(&UserImportTemplate {
                error: Some("No file uploaded.".to_string()),
                realm_name: realm_name.clone(),
                list_url: format!("/ui/admin/realms/{realm_name}/users"),
                active_tab: "users",
                chrome: true,
                active: "realm-workspace",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name_for(target.id()),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            });
        }
    };

    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => {
            return render(&UserImportTemplate {
                error: Some("File is not valid UTF-8.".to_string()),
                realm_name: realm_name.clone(),
                list_url: format!("/ui/admin/realms/{realm_name}/users"),
                active_tab: "users",
                chrome: true,
                active: "realm-workspace",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name_for(target.id()),
                logo_url: state.logo_url.clone(),
                theme_css: state.theme_css.clone(),
                realm_theme_css: state.realm_theme_css(),
            });
        }
    };

    if col_email.is_empty() {
        return render(&UserImportTemplate {
            error: Some("Email column mapping is required.".to_string()),
            realm_name: realm_name.clone(),
            list_url: format!("/ui/admin/realms/{realm_name}/users"),
            active_tab: "users",
            chrome: true,
            active: "realm-workspace",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name_for(target.id()),
            logo_url: state.logo_url.clone(),
            theme_css: state.theme_css.clone(),
            realm_theme_css: state.realm_theme_css(),
        });
    }

    let summary = process_csv_import(&state, target.id(), &text, &col_email, &col_name, &col_role);
    let flash = format!(
        "import_done:created={},updated={},skipped={},errors={}",
        summary.created,
        summary.updated,
        summary.skipped,
        summary.errors.len()
    );

    Redirect::to(&format!(
        "/ui/admin/realms/{realm_name}/users?flash={flash}"
    ))
    .into_response()
}

/// Parses the CSV text and creates/updates users, returning a summary.
fn process_csv_import(
    state: &Arc<WebState>,
    realm_id: &crate::core::RealmId,
    text: &str,
    col_email: &str,
    col_name: &str,
    col_role: &str,
) -> ImportSummary {
    let mut summary = ImportSummary {
        created: 0,
        updated: 0,
        skipped: 0,
        errors: Vec::new(),
    };

    let mut lines = text.lines();
    let header_line = match lines.next() {
        Some(l) => l,
        None => return summary,
    };

    let headers: Vec<&str> = header_line.split(',').map(str::trim).collect();
    let idx_email = headers.iter().position(|h| *h == col_email);
    let idx_name = if col_name.is_empty() {
        None
    } else {
        headers.iter().position(|h| *h == col_name)
    };
    let idx_role = if col_role.is_empty() {
        None
    } else {
        headers.iter().position(|h| *h == col_role)
    };

    let email_idx = match idx_email {
        Some(i) => i,
        None => {
            summary
                .errors
                .push(format!("Column '{col_email}' not found in CSV header."));
            return summary;
        }
    };

    for (line_num, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.splitn(headers.len(), ',').map(str::trim).collect();
        let email = match fields.get(email_idx) {
            Some(e) if !e.is_empty() => (*e).to_owned(),
            _ => {
                summary
                    .errors
                    .push(format!("Row {}: missing email.", line_num + 2));
                summary.skipped += 1;
                continue;
            }
        };
        let name = idx_name
            .and_then(|i| fields.get(i))
            .copied()
            .unwrap_or("")
            .to_string();
        let role_slug = idx_role
            .and_then(|i| fields.get(i))
            .copied()
            .unwrap_or("")
            .to_string();

        // Check if user already exists via search.
        let existing = state
            .identity
            .search_users(realm_id, &email, 1)
            .ok()
            .and_then(|mut v| {
                v.retain(|u| u.email().eq_ignore_ascii_case(&email));
                v.into_iter().next()
            });

        if let Some(user) = existing {
            // Update name if provided.
            if !name.is_empty() {
                let req = UpdateUserRequest {
                    display_name: Some(name.clone()),
                    first_name: None,
                    last_name: None,
                    attributes: None,
                    status: None,
                    email: None,
                };
                if let Err(e) = state.identity.update_user(realm_id, user.id(), &req) {
                    tracing::warn!(error = %e, email = %email, "import update failed");
                    summary
                        .errors
                        .push(format!("Row {}: update failed — {e}.", line_num + 2));
                    continue;
                }
            }
            assign_role_by_slug(state, realm_id, user.id(), &role_slug);
            summary.updated += 1;
        } else {
            // Create new user.
            let req = CreateUserRequest {
                email: email.clone(),
                display_name: if name.is_empty() {
                    String::new()
                } else {
                    name.clone()
                },
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            };
            match state.identity.create_user(realm_id, &req) {
                Ok(user) => {
                    assign_role_by_slug(state, realm_id, user.id(), &role_slug);
                    summary.created += 1;
                }
                Err(e) => {
                    tracing::warn!(error = %e, email = %email, "import create_user failed");
                    summary
                        .errors
                        .push(format!("Row {}: create failed — {e}.", line_num + 2));
                }
            }
        }
    }

    summary
}

/// Looks up a role by slug name and assigns it to the user (best-effort, silent on miss).
fn assign_role_by_slug(
    state: &Arc<WebState>,
    realm_id: &crate::core::RealmId,
    user_id: &crate::core::UserId,
    role_slug: &str,
) {
    if role_slug.is_empty() {
        return;
    }
    let Ok(page) = state.rbac.list_roles(realm_id, None, 500) else {
        return;
    };
    let roles = page.items;
    let Some(role) = roles
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(role_slug))
    else {
        return;
    };
    let req = crate::rbac::AssignRoleRequest {
        subject: crate::rbac::Subject::User(user_id.clone()),
        role_id: role.id.clone(),
        scope: crate::rbac::Scope::Realm,
        assigned_by: None,
    };
    if let Err(e) = state.rbac.assign_role(realm_id, &req) {
        tracing::warn!(error = %e, role_slug = %role_slug, "import assign_role failed");
    }
}
