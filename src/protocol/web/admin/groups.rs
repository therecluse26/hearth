//! Group CRUD, membership management, and role assignments.

use super::*;

/// Query params for `GET /ui/admin/groups`.
#[derive(Debug, Deserialize)]
pub struct GroupListParams {
    /// Opaque cursor for the next page.
    pub cursor: Option<String>,
    /// Search query (name or slug).
    pub q: Option<String>,
}

/// Template for `GET /ui/admin/groups`.
#[derive(Template)]
#[template(path = "ui/admin/groups/list.html")]
#[allow(clippy::struct_excessive_bools)]
struct GroupListTemplate {
    groups: Vec<Group>,
    next_cursor: Option<String>,
    search_query: String,
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

pub async fn admin_groups_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<GroupListParams>,
) -> Response {
    let search_query = params.q.clone().unwrap_or_default();
    // Mirror the org-list strategy: scan a bounded window and filter
    // in-handler when searching, since the engine has no name-substring
    // index on groups today.
    let result = if search_query.len() >= 2 {
        state.rbac.list_groups(target.id(), None, 200).map(|page| {
            let needle = search_query.to_ascii_lowercase();
            let filtered: Vec<Group> = page
                .items
                .into_iter()
                .filter(|g| {
                    g.name.to_ascii_lowercase().contains(&needle)
                        || g.slug.to_ascii_lowercase().contains(&needle)
                })
                .collect();
            crate::rbac::Page {
                items: filtered,
                next_cursor: None,
            }
        })
    } else {
        state
            .rbac
            .list_groups(target.id(), params.cursor.as_deref(), 20)
    };

    match result {
        Ok(page) => render(&GroupListTemplate {
            groups: page.items,
            next_cursor: page.next_cursor,
            search_query,
            realm_name: target.0.name().to_string(),
            active_tab: "groups",
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
            tracing::warn!(error = %e, "list_groups failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Create group
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/groups/new`.
#[derive(Template)]
#[template(path = "ui/admin/groups/new.html")]
#[allow(clippy::struct_excessive_bools)]
struct GroupNewTemplate {
    error: Option<String>,
    realm_name: String,
    form_name: String,
    form_slug: String,
    form_description: String,
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

/// `GET /ui/admin/groups/new`.
pub async fn admin_group_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&GroupNewTemplate {
        error: None,
        realm_name: target.0.name().to_string(),
        form_name: String::new(),
        form_slug: String::new(),
        form_description: String::new(),
        active_tab: "groups",
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

/// Form data for `POST /ui/admin/groups/new`.
#[derive(Debug, Deserialize)]
pub struct CreateGroupForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/groups/new`.
pub async fn admin_group_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<CreateGroupForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let description = if form.description.trim().is_empty() {
        None
    } else {
        Some(form.description.clone())
    };

    let realm_name = target.0.name().to_string();

    match state.rbac.create_group(
        target.id(),
        &CreateGroupRequest {
            name: form.name.clone(),
            slug: form.slug.clone(),
            description,
        },
    ) {
        Ok(group) => {
            audit_group_event(&state, &session, &target.0, &group.id, "create", None);
            Redirect::to(&format!(
                "/ui/admin/realms/{}/groups/{}",
                realm_name,
                group.id.as_uuid()
            ))
            .into_response()
        }
        Err(e) => {
            let msg = match &e {
                crate::rbac::RbacError::DuplicateGroupSlug => {
                    "A group with that slug already exists.".to_string()
                }
                _ => format!("Unable to create group: {e}"),
            };
            tracing::warn!(error = %e, "create_group failed");
            render(&GroupNewTemplate {
                error: Some(msg),
                realm_name: realm_name.clone(),
                form_name: form.name,
                form_slug: form.slug,
                form_description: form.description,
                active_tab: "groups",
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
    }
}

// ---------------------------------------------------------------------------
// Group detail
// ---------------------------------------------------------------------------

/// Display row for a group member (user or nested group).
pub struct GroupMemberView {
    /// "user" or "group" — drives template branching.
    pub member_kind: &'static str,
    /// UUID string used in URLs and DOM IDs.
    pub member_id_uuid: String,
    /// Display name (user.display_name() or group.name).
    pub display_name: String,
    /// Subtitle line — user email or group slug.
    pub subtitle: String,
}

/// Standalone re-render of a single group-member row, used by HTMX
/// error paths that need to swap a row back into the table when a
/// mutation fails. Empty bodies + `outerHTML` swap would silently
/// delete the row from the DOM and lie about success — see BUG-004.
#[derive(Template)]
#[template(path = "ui/admin/groups/_member_row.html")]
struct GroupMemberRowTemplate {
    realm_name: String,
    group_id: String,
    m: GroupMemberView,
    csrf: Option<String>,
}

/// Re-renders a single group-member row plus an `HX-Trigger: showToast`
/// header. Mirrors `render_member_row_with_toast` for the org case.
/// On engine failure the caller HTMX-swaps the same row back into the
/// table with an error toast, instead of returning an empty body that
/// would visually delete the row even though the data is unchanged.
fn render_group_member_row_with_toast(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm: &RealmId,
    realm_name: &str,
    group_id: &GroupId,
    member: &GroupMember,
    message: &str,
    kind: &str,
) -> Response {
    let view = match member {
        GroupMember::User(uid) => match state.identity.get_user(realm, uid) {
            Ok(Some(u)) => GroupMemberView {
                member_kind: "user",
                member_id_uuid: uid.as_uuid().to_string(),
                display_name: u.display_name().to_string(),
                subtitle: u.email().to_string(),
            },
            _ => GroupMemberView {
                member_kind: "user",
                member_id_uuid: uid.as_uuid().to_string(),
                display_name: format!("user_{}", uid.as_uuid()),
                subtitle: "unknown user".to_string(),
            },
        },
        GroupMember::Group(gid) => match state.rbac.get_group(realm, gid) {
            Ok(Some(g)) => GroupMemberView {
                member_kind: "group",
                member_id_uuid: gid.as_uuid().to_string(),
                display_name: g.name,
                subtitle: g.slug,
            },
            _ => GroupMemberView {
                member_kind: "group",
                member_id_uuid: gid.as_uuid().to_string(),
                display_name: format!("group_{}", gid.as_uuid()),
                subtitle: "unknown group".to_string(),
            },
        },
    };
    let tmpl = GroupMemberRowTemplate {
        realm_name: realm_name.to_string(),
        group_id: group_id.as_uuid().to_string(),
        m: view,
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

/// Display row for a role assignment on the detail Roles tab.
pub struct GroupRoleAssignmentView {
    /// `AssignmentId` UUID string — used in the unassign POST URL.
    pub assignment_id: String,
    /// Resolved role label ("Editor" or "<unknown role>").
    pub role_label: String,
    /// "Realm" or "Org: <slug>" — already resolved for display.
    pub scope_label: String,
}

/// Template for `GET /ui/admin/groups/:id`.
#[derive(Template)]
#[template(path = "ui/admin/groups/detail.html")]
#[allow(clippy::struct_excessive_bools)]
struct GroupDetailTemplate {
    group: Group,
    realm_name: String,
    /// Group UUID string — shared with the embedded `_member_row.html`
    /// partial so member-row form actions can use the parent group's ID.
    group_id: String,
    members: Vec<GroupMemberView>,
    member_count: usize,
    role_assignments: Vec<GroupRoleAssignmentView>,
    role_count: usize,
    /// Roles available to assign on the Roles tab. Includes `Realm`,
    /// `Organization`, and `Any`-scoped roles — the form's scope `<select>`
    /// decides which of those scopes the assignment is recorded against.
    available_roles: Vec<AvailableRole>,
    /// Orgs available as scope targets in the Roles-tab assign form
    /// (only shown when the user picks "Org" in the scope dropdown).
    available_orgs: Vec<AvailableOrg>,
    /// First page of users for the Members-tab picker, rendered inline so
    /// the list is visible immediately on tab open without depending on
    /// `hx-trigger="load"` firing client-side. Subsequent pages append via
    /// the infinite-scroll sentinel; filter changes reset the container
    /// via the search input's HTMX target. Field names match the picker
    /// partial (`_member_picker_rows.html`) so it can be `{% include %}`'d
    /// from `detail.html` using the parent scope.
    users: Vec<User>,
    /// Initial picker query string — empty on first render.
    query: String,
    /// Cursor for the second page, when the realm has more than the
    /// initial page size.
    next_cursor: Option<String>,
    active_subtab: &'static str,
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

/// Query params for the group-detail page (sub-tab selection).
#[derive(Debug, Deserialize)]
pub struct GroupDetailParams {
    #[serde(default)]
    pub tab: Option<String>,
}

/// `GET /ui/admin/groups/:id`.
pub async fn admin_group_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
    Query(params): Query<GroupDetailParams>,
) -> Response {
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };

    let group = match state.rbac.get_group(target.id(), &group_id) {
        Ok(Some(g)) => g,
        Ok(None) => return super::handlers_common::not_found("Group not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_group failed");
            return super::handlers_common::server_error();
        }
    };

    // Resolve direct members (users + nested groups).
    let members = build_group_member_views(&state, target.id(), &group_id);
    let member_count = members.len();

    // Role assignments held by this group.
    let role_assignments_raw = state
        .rbac
        .list_group_assignments(target.id(), &group_id)
        .unwrap_or_default();
    let role_assignments = role_assignments_raw
        .iter()
        .map(|ra| {
            let role_label = state
                .rbac
                .get_role(target.id(), &ra.role_id)
                .ok()
                .flatten()
                .map(|r| r.name)
                .unwrap_or_else(|| "<unknown role>".to_string());
            let scope_label = match &ra.scope {
                RbacScope::Realm => "Realm".to_string(),
                RbacScope::Org { org_id } => state
                    .identity
                    .get_organization(target.id(), org_id)
                    .ok()
                    .flatten()
                    .map(|o| format!("Org: {}", o.slug()))
                    .unwrap_or_else(|| format!("Org: {}", org_id.as_uuid())),
            };
            GroupRoleAssignmentView {
                assignment_id: ra.id.as_uuid().to_string(),
                role_label,
                scope_label,
            }
        })
        .collect::<Vec<_>>();
    let role_count = role_assignments.len();

    // First page of users for the Members-tab picker. Pre-rendering here
    // (rather than relying on `hx-trigger="load"` to fetch client-side on
    // tab open) guarantees the list is visible immediately and works even
    // when HTMX hasn't finished initializing or the realm genuinely has no
    // users — the empty-state copy renders inline. Subsequent pages append
    // via the picker's infinite-scroll sentinel; filter changes still
    // reset the container via the search input's HTMX target.
    //
    // Already-assigned members are excluded so the picker doesn't show
    // them as add-able candidates.
    let initial_exclude = group_member_user_ids(&state, target.id(), &group_id);
    let (initial_users, initial_next_cursor) =
        match state.identity.list_users(target.id(), None, 20) {
            Ok(p) => {
                let filtered: Vec<User> = p
                    .items
                    .into_iter()
                    .filter(|u| !initial_exclude.contains(u.id().as_uuid()))
                    .collect();
                (filtered, p.next_cursor)
            }
            Err(e) => {
                tracing::warn!(error = %e, "initial picker list_users failed");
                (Vec::new(), None)
            }
        };

    // All realm roles (any scope_kind) — the assign form's scope dropdown
    // decides which scope the assignment is recorded against. We use the
    // realm-wide listing here rather than `build_org_available_roles`
    // because groups can hold both realm-scoped and org-scoped roles.
    let available_roles = build_realm_available_roles(&state, target.id());
    // Orgs in the realm — surfaced as options when the assign-form scope
    // dropdown is set to "Org". An empty list disables the Org option.
    let available_orgs: Vec<AvailableOrg> = state
        .identity
        .list_organizations(target.id(), None, 200)
        .map(|p| {
            p.items
                .into_iter()
                .map(|o| AvailableOrg {
                    id: o.id().as_uuid().to_string(),
                    name: o.name().to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    let active_subtab: &'static str = match params.tab.as_deref() {
        Some("members") => "members",
        Some("roles") => "roles",
        Some("danger") => "danger",
        _ => "overview",
    };

    let group_id_str = group.id.as_uuid().to_string();
    render(&GroupDetailTemplate {
        group,
        realm_name: target.0.name().to_string(),
        group_id: group_id_str,
        members,
        member_count,
        role_assignments,
        role_count,
        available_roles,
        available_orgs,
        users: initial_users,
        query: String::new(),
        next_cursor: initial_next_cursor,
        active_subtab,
        active_tab: "groups",
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

/// Returns the UUIDs of users that are already direct members of the
/// given group. Used to exclude already-assigned users from the
/// add-member picker so the same user can't be added twice (and the
/// picker doesn't waste rows on people who are already in the group).
///
/// Bounded fetch — for groups with extreme member counts (>1000) this
/// is a soft cap that mirrors the picker's own scan-window strategy.
/// Best-effort: a fetch failure returns an empty set rather than
/// blocking the picker.
fn group_member_user_ids(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    group_id: &GroupId,
) -> std::collections::HashSet<uuid::Uuid> {
    state
        .rbac
        .list_group_members(realm_id, group_id, None, 1000)
        .map(|p| {
            p.items
                .into_iter()
                .filter_map(|m| match m {
                    GroupMember::User(uid) => Some(*uid.as_uuid()),
                    GroupMember::Group(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Resolves direct members of a group into display views.
///
/// Best-effort: failures fetching individual users/groups are logged and
/// produce a placeholder row rather than aborting the whole list.
fn build_group_member_views(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    group_id: &GroupId,
) -> Vec<GroupMemberView> {
    let page = match state.rbac.list_group_members(realm_id, group_id, None, 500) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "list_group_members failed");
            return Vec::new();
        }
    };
    page.items
        .into_iter()
        .map(|m| match m {
            GroupMember::User(uid) => match state.identity.get_user(realm_id, &uid) {
                Ok(Some(u)) => GroupMemberView {
                    member_kind: "user",
                    member_id_uuid: uid.as_uuid().to_string(),
                    display_name: u.display_name().to_string(),
                    subtitle: u.email().to_string(),
                },
                _ => GroupMemberView {
                    member_kind: "user",
                    member_id_uuid: uid.as_uuid().to_string(),
                    display_name: format!("user_{}", uid.as_uuid()),
                    subtitle: "unknown user".to_string(),
                },
            },
            GroupMember::Group(gid) => match state.rbac.get_group(realm_id, &gid) {
                Ok(Some(g)) => GroupMemberView {
                    member_kind: "group",
                    member_id_uuid: gid.as_uuid().to_string(),
                    display_name: g.name,
                    subtitle: g.slug,
                },
                _ => GroupMemberView {
                    member_kind: "group",
                    member_id_uuid: gid.as_uuid().to_string(),
                    display_name: format!("group_{}", gid.as_uuid()),
                    subtitle: "unknown group".to_string(),
                },
            },
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Edit group
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/groups/:id/edit`.
#[derive(Template)]
#[template(path = "ui/admin/groups/edit.html")]
#[allow(clippy::struct_excessive_bools)]
struct GroupEditTemplate {
    group: Group,
    realm_name: String,
    error: Option<String>,
    form_name: String,
    form_slug: String,
    form_description: String,
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

/// `GET /ui/admin/groups/:id/edit`.
pub async fn admin_group_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
) -> Response {
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    match state.rbac.get_group(target.id(), &group_id) {
        Ok(Some(group)) => {
            let form_name = group.name.clone();
            let form_slug = group.slug.clone();
            let form_description = group.description.clone().unwrap_or_default();
            render(&GroupEditTemplate {
                group,
                realm_name: target.0.name().to_string(),
                error: None,
                form_name,
                form_slug,
                form_description,
                active_tab: "groups",
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
        Ok(None) => super::handlers_common::not_found("Group not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_group failed");
            super::handlers_common::server_error()
        }
    }
}

/// Form data for `POST /ui/admin/groups/:id/edit`.
#[derive(Debug, Deserialize)]
pub struct UpdateGroupForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/groups/:id/edit`.
pub async fn admin_group_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<UpdateGroupForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let realm_name = target.0.name().to_string();
    let req = UpdateGroupRequest {
        name: Some(form.name.clone()),
        slug: Some(form.slug.clone()),
        description: Some(if form.description.trim().is_empty() {
            None
        } else {
            Some(form.description.clone())
        }),
    };
    match state.rbac.update_group(target.id(), &group_id, &req) {
        Ok(_) => {
            audit_group_event(&state, &session, &target.0, &group_id, "update", None);
            Redirect::to(&format!(
                "/ui/admin/realms/{}/groups/{}",
                realm_name,
                group_id.as_uuid()
            ))
            .into_response()
        }
        Err(e) => {
            let msg = match &e {
                crate::rbac::RbacError::DuplicateGroupSlug => {
                    "A group with that slug already exists.".to_string()
                }
                _ => format!("Unable to update group: {e}"),
            };
            tracing::warn!(error = %e, "update_group failed");
            // Re-fetch the original group to re-render the edit form.
            let group = match state.rbac.get_group(target.id(), &group_id) {
                Ok(Some(g)) => g,
                _ => return super::handlers_common::not_found("Group not found"),
            };
            render(&GroupEditTemplate {
                group,
                realm_name: realm_name.clone(),
                error: Some(msg),
                form_name: form.name,
                form_slug: form.slug,
                form_description: form.description,
                active_tab: "groups",
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
    }
}

// ---------------------------------------------------------------------------
// Delete group
// ---------------------------------------------------------------------------

/// `POST /ui/admin/groups/:id/delete`.
pub async fn admin_group_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let realm_name = target.0.name().to_string();
    match state.rbac.delete_group(target.id(), &group_id) {
        Ok(()) => {
            audit_group_event(&state, &session, &target.0, &group_id, "delete", None);
            Redirect::to(&format!("/ui/admin/realms/{realm_name}/groups")).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete_group failed");
            super::templates::redirect_with_flash(
                &format!(
                    "/ui/admin/realms/{realm_name}/groups/{}",
                    group_id.as_uuid()
                ),
                &format!("Unable to delete group: {e}"),
                "error",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Group members — picker, add, remove
// ---------------------------------------------------------------------------

/// Template for the inline member-picker HTMX response.
#[derive(Template)]
#[template(path = "ui/admin/groups/_member_picker_rows.html")]
struct GroupMemberPickerRowsTemplate {
    realm_name: String,
    group_id: String,
    users: Vec<User>,
    query: String,
    next_cursor: Option<String>,
    csrf: Option<String>,
}

/// `GET /ui/admin/groups/:id/members/picker` — HTMX user-search results.
pub async fn admin_group_member_picker(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
    Query(params): Query<MemberPickerParams>,
) -> Response {
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let query = params.q.trim().to_string();
    // Existing direct members of the group are excluded from the picker —
    // re-adding a user errors at the engine level, and showing them as
    // available options is misleading.
    let exclude = group_member_user_ids(&state, target.id(), &group_id);
    // Empty query: cursor-paginated browse. Non-empty query: scan a
    // bounded window and filter case-insensitively in-handler against
    // both display_name and email. The previous `search_users` path was
    // matching against unexpected fields / casing — for example, "Bill"
    // wouldn't match a user named "Bill Williams" with email
    // "bill@test.com". Mirrors the in-handler substring filter used by
    // `admin_orgs_list:2844-2873`. For realms with thousands of users
    // this needs a dedicated index, but at admin-UI scale (a few
    // hundred) it's acceptable.
    let page = if query.is_empty() {
        state
            .identity
            .list_users(target.id(), params.cursor.as_deref(), 20)
            .map(|p| {
                let filtered: Vec<User> = p
                    .items
                    .into_iter()
                    .filter(|u| !exclude.contains(u.id().as_uuid()))
                    .collect();
                Page {
                    items: filtered,
                    next_cursor: p.next_cursor,
                }
            })
    } else {
        state.identity.list_users(target.id(), None, 200).map(|p| {
            let needle = query.to_ascii_lowercase();
            let filtered: Vec<User> = p
                .items
                .into_iter()
                .filter(|u| !exclude.contains(u.id().as_uuid()))
                .filter(|u| {
                    u.display_name().to_ascii_lowercase().contains(&needle)
                        || u.email().to_ascii_lowercase().contains(&needle)
                })
                .collect();
            Page {
                items: filtered,
                next_cursor: None,
            }
        })
    };
    let (users, next_cursor) = match page {
        Ok(p) => (p.items, p.next_cursor),
        Err(e) => {
            tracing::warn!(error = %e, "group member picker list_users failed");
            (Vec::new(), None)
        }
    };
    render(&GroupMemberPickerRowsTemplate {
        realm_name: target.0.name().to_string(),
        group_id: group_id.as_uuid().to_string(),
        users,
        query,
        next_cursor,
        csrf: session.csrf.clone(),
    })
}

/// Form data for `POST /ui/admin/groups/:id/members`.
#[derive(Debug, Deserialize)]
pub struct AddGroupMemberForm {
    /// "user" or "group".
    #[serde(default)]
    pub member_kind: String,
    /// UUID of the user or nested group.
    #[serde(default)]
    pub member_id: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/groups/:id/members`.
pub async fn admin_group_member_add(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<AddGroupMemberForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let realm_name = target.0.name().to_string();
    let member_uuid = match form.member_id.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return super::templates::redirect_with_flash(
                &format!(
                    "/ui/admin/realms/{realm_name}/groups/{}?tab=members",
                    group_id.as_uuid()
                ),
                "Invalid member ID.",
                "error",
            );
        }
    };
    let member = match form.member_kind.as_str() {
        "group" => GroupMember::Group(GroupId::new(member_uuid)),
        _ => GroupMember::User(crate::core::UserId::new(member_uuid)),
    };
    let metadata = serde_json::json!({
        "via": "ui",
        "member_type": form.member_kind,
        "member_id": form.member_id,
    });
    match state.rbac.add_group_member(target.id(), &group_id, &member) {
        Ok(_) => {
            audit_group_event(
                &state,
                &session,
                &target.0,
                &group_id,
                "member_add",
                Some(metadata),
            );
            super::templates::redirect_with_flash(
                &format!(
                    "/ui/admin/realms/{realm_name}/groups/{}?tab=members",
                    group_id.as_uuid()
                ),
                "Member added.",
                "success",
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "add_group_member failed");
            super::templates::redirect_with_flash(
                &format!(
                    "/ui/admin/realms/{realm_name}/groups/{}?tab=members",
                    group_id.as_uuid()
                ),
                &format!("Unable to add member: {e}"),
                "error",
            )
        }
    }
}

/// `POST /ui/admin/groups/:gid/members/:kind/:mid/remove`.
///
/// `kind` is the URL-segment string `"user"` or `"group"`. HTMX caller
/// (per-row Remove form) gets an empty body + `HX-Trigger: showToast`.
pub async fn admin_group_member_remove(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid, kind, mid)): AxumPath<(String, String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let member_uuid = match mid.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => return super::handlers_common::not_found("Member not found"),
    };
    let member = match kind.as_str() {
        "group" => GroupMember::Group(GroupId::new(member_uuid)),
        "user" => GroupMember::User(crate::core::UserId::new(member_uuid)),
        _ => return super::handlers_common::not_found("Unknown member kind"),
    };
    let is_htmx = is_htmx_request(&headers);
    let realm_name = target.0.name().to_string();
    let metadata = serde_json::json!({
        "via": "ui",
        "member_type": kind,
        "member_id": mid,
    });
    match state
        .rbac
        .remove_group_member(target.id(), &group_id, &member)
    {
        Ok(()) => {
            audit_group_event(
                &state,
                &session,
                &target.0,
                &group_id,
                "member_remove",
                Some(metadata),
            );
            if is_htmx {
                super::templates::htmx_toast_response("Member removed", "success")
            } else {
                super::templates::redirect_with_flash(
                    &format!(
                        "/ui/admin/realms/{realm_name}/groups/{}?tab=members",
                        group_id.as_uuid()
                    ),
                    "Member removed.",
                    "success",
                )
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "remove_group_member failed");
            if is_htmx {
                // BUG-004 fix: re-render the row instead of returning an
                // empty body. The Remove button uses `hx-swap="outerHTML"`,
                // so an empty error response would visually delete the row
                // and mask the failure. Mirroring the org pattern keeps
                // the row in place and surfaces the error via toast.
                render_group_member_row_with_toast(
                    &state,
                    &session,
                    target.id(),
                    &realm_name,
                    &group_id,
                    &member,
                    &format!("Unable to remove member: {e}"),
                    "error",
                )
            } else {
                super::templates::redirect_with_flash(
                    &format!(
                        "/ui/admin/realms/{realm_name}/groups/{}?tab=members",
                        group_id.as_uuid()
                    ),
                    &format!("Unable to remove member: {e}"),
                    "error",
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Group role assignment
// ---------------------------------------------------------------------------

/// Form data for `POST /ui/admin/groups/:id/roles/assign`.
///
/// `scope` is the composed string consumed by [`parse_rbac_scope`]:
/// `"realm"` for realm-wide assignments, or `"org:<uuid>"` to bind the
/// role to an org-scoped context. The Alpine-driven detail-page form
/// builds this string from two `<select>` widgets before submit.
#[derive(Debug, Deserialize)]
pub struct GroupAssignRoleForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    /// UUID of the role to assign.
    #[serde(default)]
    pub role_id: String,
    /// Composed scope string ("realm" or "org:<uuid>").
    #[serde(default)]
    pub scope: String,
}

/// `POST /ui/admin/groups/:id/roles/assign`.
///
/// Binds a realm or org-scoped role to a group. All transitive members of
/// the group inherit the role's permissions (subject to the assignment's
/// scope) at next token issue.
pub async fn admin_group_role_assign(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<GroupAssignRoleForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let realm_name = target.0.name().to_string();
    let detail_url = format!(
        "/ui/admin/realms/{realm_name}/groups/{}?tab=roles",
        group_id.as_uuid()
    );
    let Ok(role_uuid) = form.role_id.parse::<uuid::Uuid>() else {
        return super::templates::redirect_with_flash(&detail_url, "Invalid role ID.", "error");
    };
    let role_id = crate::rbac::RoleId::new(role_uuid);
    let scope = match parse_rbac_scope(&form.scope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "group role assign: bad scope string");
            return super::templates::redirect_with_flash(
                &detail_url,
                "Invalid assignment scope.",
                "error",
            );
        }
    };
    let req = crate::rbac::AssignRoleRequest {
        subject: crate::rbac::Subject::Group(group_id.clone()),
        role_id,
        scope,
        assigned_by: Some(session.user_id.clone()),
    };
    match state.rbac.assign_role(target.id(), &req) {
        Ok(_) => {
            audit_group_role_event(
                &state,
                &session,
                target.id(),
                &group_id,
                true,
                &form.role_id,
            );
            super::templates::redirect_with_flash(&detail_url, "Role assigned.", "success")
        }
        Err(e) => {
            tracing::warn!(error = %e, "group assign_role failed");
            super::templates::redirect_with_flash(
                &detail_url,
                &format!("Unable to assign role: {e}"),
                "error",
            )
        }
    }
}

/// `POST /ui/admin/groups/:id/roles/:aid/unassign`.
///
/// Removes a previously-assigned role from a group. The matching member
/// permissions disappear at next token issue (no immediate revocation —
/// already-issued tokens remain valid until they expire).
pub async fn admin_group_role_unassign(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, gid, aid)): AxumPath<(String, String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    let group_id = match gid.parse::<uuid::Uuid>() {
        Ok(u) => GroupId::new(u),
        Err(_) => return super::handlers_common::not_found("Group not found"),
    };
    let realm_name = target.0.name().to_string();
    let detail_url = format!(
        "/ui/admin/realms/{realm_name}/groups/{}?tab=roles",
        group_id.as_uuid()
    );
    let Ok(assign_uuid) = aid.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Assignment not found");
    };
    let assignment_id = crate::rbac::AssignmentId::new(assign_uuid);
    match state.rbac.unassign_role(target.id(), &assignment_id) {
        Ok(()) => {
            audit_group_role_event(&state, &session, target.id(), &group_id, false, &aid);
            super::templates::redirect_with_flash(&detail_url, "Role removed.", "success")
        }
        Err(e) => {
            tracing::warn!(error = %e, "group unassign_role failed");
            super::templates::redirect_with_flash(
                &detail_url,
                &format!("Unable to remove role: {e}"),
                "error",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Group audit helpers
// ---------------------------------------------------------------------------

/// Best-effort audit for role assign/unassign on a group subject.
///
/// Mirrors `audit_role_event` but uses `resource_type: "group"` and the
/// group's UUID as the resource ID. The role argument is whatever string
/// the caller has on hand (the role's UUID is fine when the human-readable
/// name isn't already loaded).
fn audit_group_role_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm_id: &RealmId,
    group_id: &GroupId,
    assigned: bool,
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
        resource_type: "group".to_string(),
        resource_id: group_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({
            "via": "ui",
            "subject_type": "group",
            "role": role,
        })),
    }) {
        tracing::warn!(error = %e, "group role audit append failed");
    }
}

/// Best-effort audit for group operations.
///
/// Mirrors `audit_org_event` but emits `Group*` actions and lets callers
/// pass per-operation metadata (e.g. member kind/id for membership events).
fn audit_group_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    target_realm: &Realm,
    group_id: &GroupId,
    op: &'static str,
    extra_metadata: Option<serde_json::Value>,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::GroupCreated,
        "update" => AuditAction::GroupUpdated,
        "delete" => AuditAction::GroupDeleted,
        "member_add" => AuditAction::GroupMemberAdded,
        "member_remove" => AuditAction::GroupMemberRemoved,
        _ => return,
    };
    let metadata = extra_metadata.unwrap_or_else(|| serde_json::json!({ "via": "ui" }));
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: target_realm.id().clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "group".to_string(),
        resource_id: group_id.as_uuid().to_string(),
        metadata: Some(metadata),
    }) {
        tracing::warn!(error = %e, "group admin audit append failed");
    }
}

// ---------------------------------------------------------------------------
// Realm-level role builder (only used in group detail view)
// ---------------------------------------------------------------------------
fn build_realm_available_roles(state: &Arc<WebState>, realm_id: &RealmId) -> Vec<AvailableRole> {
    state
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
                name: r.name,
                description: r.description.unwrap_or_default(),
                scope_kind: format!("{:?}", r.scope_kind),
                permissions: perms,
            }
        })
        .collect()
}
