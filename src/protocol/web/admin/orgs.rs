//! Organization management, membership, roles, and invitations.

use super::*;

// ---------------------------------------------------------------------------
// Org-member types (moved here because MemberView lives in this module)
// ---------------------------------------------------------------------------
/// A single org-scoped RBAC role held by a member (embedded in `MemberWithAccess`).
pub struct MemberRbacRole {
    /// `AssignmentId` UUID string — used in the unassign POST URL.
    pub assignment_id: String,
    /// `RoleId` UUID string.
    pub role_id: String,
    /// Human-readable role name.
    pub role_name: String,
    /// Permissions granted by this role (sorted, deduplicated). Empty if the
    /// role lookup failed or the role grants no permissions.
    pub permissions: Vec<String>,
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
    /// True when this member is the *only* Owner of the org. The remove
    /// button and role-downgrade dropdown are rendered disabled in the UI
    /// to keep admins from learning the engine's `LastOwner` guard the
    /// hard way.
    pub is_last_owner: bool,
    /// RBAC roles assigned to this member within this org.
    pub rbac_roles: Vec<MemberRbacRole>,
    /// Direct permissions granted to this member within this org.
    pub extra_perms: Vec<MemberPermGrant>,
    /// Permission strings still grantable to this member at this org scope:
    /// the union of org-applicable permissions minus any already granted
    /// directly or inherited via this member's org-scoped role assignments.
    pub available_permissions: Vec<String>,
}

// Organizations
// =========================================================================

// ---------------------------------------------------------------------------
// Organization list
// ---------------------------------------------------------------------------

/// Query params for `GET /ui/admin/organizations`.
#[derive(Debug, Deserialize)]
pub struct OrgListParams {
    /// Opaque cursor for the next page.
    pub cursor: Option<String>,
    /// Search query (matches name or slug, case-insensitive substring).
    pub q: Option<String>,
}

/// Template for `GET /ui/admin/organizations`.
#[derive(Template)]
#[template(path = "ui/admin/organizations/list.html")]
#[allow(clippy::struct_excessive_bools)]
struct OrgListTemplate {
    organizations: Vec<Organization>,
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

/// `GET /ui/admin/organizations`.
pub async fn admin_orgs_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<OrgListParams>,
) -> Response {
    let search_query = params.q.clone().unwrap_or_default();
    let result = if search_query.len() >= 2 {
        // No engine-level secondary index on org name/slug yet; scan a
        // bounded window and filter in-handler. Bound matches the
        // assignment-flow fan-out at admin.rs §RBAC and is a soft cap —
        // realms with thousands of orgs will need a dedicated engine
        // method, tracked as future work.
        state
            .identity
            .list_organizations(target.id(), None, 200)
            .map(|page| {
                let needle = search_query.to_ascii_lowercase();
                let filtered: Vec<Organization> = page
                    .items
                    .into_iter()
                    .filter(|o| {
                        o.name().to_ascii_lowercase().contains(&needle)
                            || o.slug().to_ascii_lowercase().contains(&needle)
                    })
                    .collect();
                Page {
                    items: filtered,
                    next_cursor: None,
                }
            })
    } else {
        state
            .identity
            .list_organizations(target.id(), params.cursor.as_deref(), 20)
    };

    match result {
        Ok(page) => render(&OrgListTemplate {
            organizations: page.items,
            next_cursor: page.next_cursor,
            search_query,
            realm_name: target.0.name().to_string(),
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
    realm_name: String,
    form_name: String,
    form_slug: String,
    form_description: String,
    form_max_members: Option<u32>,
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

/// `GET /ui/admin/organizations/new`.
pub async fn admin_org_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&OrgNewTemplate {
        error: None,
        realm_name: target.0.name().to_string(),
        form_name: String::new(),
        form_slug: String::new(),
        form_description: String::new(),
        form_max_members: None,
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
    #[serde(
        default,
        deserialize_with = "super::handlers_common::empty_string_as_none"
    )]
    pub max_members: Option<u32>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/new`.
pub async fn admin_org_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<CreateOrgForm>,
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

    let realm_name = target.0.name().to_string();

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
            // Auto-add the creator as Owner when they live in the target realm.
            // Cross-realm system admins (creator in `hearth#admin`, org in a
            // tenant realm) are not realm users — skip silently and rely on
            // the cross-realm "Initial owner email" affordance to seed the
            // first owner via invitation.
            if session.realm_id == *target.id() {
                match state.identity.add_member(
                    target.id(),
                    org.id(),
                    &session.user_id,
                    OrganizationRole::Owner,
                ) {
                    Ok(_) => {
                        mirror_org_member_added(
                            &state,
                            &session,
                            target.id(),
                            org.id(),
                            &session.user_id,
                            OrganizationRole::Owner,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            org_id = %org.id().as_uuid(),
                            "auto-add creator as owner failed; org was created without an owner"
                        );
                    }
                }
            }
            Redirect::to(&format!(
                "/ui/admin/realms/{}/organizations/{}",
                realm_name,
                org.id().as_uuid()
            ))
            .into_response()
        }
        Err(IdentityError::DuplicateOrgSlug) => render(&OrgNewTemplate {
            error: Some("An organization with that slug already exists.".to_string()),
            realm_name: realm_name.clone(),
            form_name: form.name,
            form_slug: form.slug,
            form_description: form.description,
            form_max_members: form.max_members,
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
            tracing::warn!(error = %e, "create_organization failed");
            render(&OrgNewTemplate {
                error: Some(format!("Unable to create organization: {e}")),
                realm_name: realm_name.clone(),
                form_name: form.name,
                form_slug: form.slug,
                form_description: form.description,
                form_max_members: form.max_members,
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
    realm_name: String,
    /// Org UUID string — shared with embedded partials via `{% include %}`.
    org_id: String,
    members: Vec<MemberWithAccess>,
    /// Member count (length of `members`) — surfaced separately so the
    /// header can display "N members" without iterating the list in
    /// templating logic.
    member_count: usize,
    invitations: Vec<OrganizationInvitation>,
    max_members: Option<u32>,
    /// All realm roles for the per-member assign form.
    available_roles: Vec<AvailableRole>,
    /// Active sub-tab name (`overview`, `members`, `invitations`,
    /// `danger`). Driven by `?tab=` query string. Defaults to
    /// `overview`. Shareable URLs surface the right tab on first paint.
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

/// Query params for org detail page (flash messages via PRG).
#[derive(Debug, Deserialize)]
pub struct OrgDetailParams {
    /// Flash message text (URL-encoded).
    #[serde(default)]
    pub flash: Option<String>,
    /// Flash kind: "success" or "error".
    #[serde(default)]
    pub flash_kind: Option<String>,
    /// Active sub-tab. One of `overview`, `members`, `invitations`,
    /// `danger`. Anything else is treated as `overview`.
    #[serde(default)]
    pub tab: Option<String>,
}

/// `GET /ui/admin/organizations/:id`.
pub async fn admin_org_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
    Query(params): Query<OrgDetailParams>,
    headers: axum::http::HeaderMap,
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
    let org_id_str = org_id.as_uuid().to_string();

    // Pre-count owners once so each member row can decide whether it's the
    // last-owner — saving N redundant scans.
    let owner_count = memberships
        .iter()
        .filter(|m| m.role() == OrganizationRole::Owner)
        .count();

    // Resolve user details and RBAC access for each membership
    let members: Vec<MemberWithAccess> = memberships
        .into_iter()
        .map(|m| {
            let is_last_owner = m.role() == OrganizationRole::Owner && owner_count == 1;
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
            build_member_with_access(&state, target.id(), &org_id, view, is_last_owner)
        })
        .collect();

    let invitations = state
        .identity
        .list_invitations(target.id(), &org_id, None, 100)
        .map(|p| p.items)
        .unwrap_or_default();

    // Cookie-based flash: read once, render, then clear via Set-Cookie
    // on the response. Falls back to legacy `?flash=…` query params for
    // a single release so any in-flight redirects already in transit
    // when this binary boots still display correctly.
    let flash = super::templates::take_flash_cookie(&headers).or_else(|| {
        params.flash.clone().map(|msg| {
            let kind = params.flash_kind.as_deref().unwrap_or("success");
            if kind == "error" {
                Flash::error(msg)
            } else {
                Flash::success(msg)
            }
        })
    });

    let max_members = org.config().max_members;
    let member_count = members.len();

    let active_subtab = match params.tab.as_deref() {
        Some("members") => "members",
        Some("invitations") => "invitations",
        Some("danger") => "danger",
        _ => "overview",
    };

    let had_flash = flash.is_some();
    let mut response = render(&OrgDetailTemplate {
        org,
        realm_name: target.0.name().to_string(),
        org_id: org_id_str,
        members,
        member_count,
        invitations,
        max_members,
        available_roles,
        active_subtab,
        active_tab: "organizations",
        chrome: true,
        active: "realm-workspace",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    });
    if had_flash {
        if let Ok(value) =
            axum::http::HeaderValue::from_str(&super::templates::clear_flash_cookie())
        {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}

// ---------------------------------------------------------------------------
// Edit organization
// ---------------------------------------------------------------------------

/// Template for `GET /ui/admin/organizations/:id/edit`.
#[derive(Template)]
#[template(path = "ui/admin/organizations/edit.html")]
struct OrgEditTemplate {
    org: Organization,
    realm_name: String,
    error: Option<String>,
    form_name: String,
    form_description: String,
    form_status: String,
    form_max_members: Option<u32>,
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

/// `GET /ui/admin/organizations/:id/edit`.
pub async fn admin_org_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
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
            realm_name: target.0.name().to_string(),
            error: None,
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
    #[serde(
        default,
        deserialize_with = "super::handlers_common::empty_string_as_none"
    )]
    pub max_members: Option<u32>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/edit`.
pub async fn admin_org_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<EditOrgForm>,
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

    let realm_name = target.0.name().to_string();

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
            Redirect::to(&format!(
                "/ui/admin/realms/{}/organizations/{}",
                realm_name,
                org_id.as_uuid()
            ))
            .into_response()
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
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let realm_name = target.0.name().to_string();

    match state.identity.delete_organization(target.id(), &org_id) {
        Ok(()) => {
            audit_org_event(&state, &session, &target.0, &org_id, "delete");
            Redirect::to(&format!("/ui/admin/realms/{realm_name}/organizations")).into_response()
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
// Bulk-delete organizations
// ---------------------------------------------------------------------------

/// Form data for `POST /ui/admin/organizations/bulk-delete`.
///
/// `ids` is a comma-separated list of organization UUIDs. We use a
/// single string rather than `Vec<String>` because axum's default form
/// extractor (`serde_urlencoded`) does not handle repeated keys; the
/// client builds the list in Alpine before submitting.
#[derive(Debug, Deserialize)]
pub struct BulkDeleteOrgsForm {
    #[serde(default)]
    pub ids: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/bulk-delete`.
///
/// Deletes each selected organization and audits each as its own event.
/// Mid-batch failures are logged but do not abort the rest — the user
/// can retry; cascade deletion is idempotent (see
/// `MEMORY.md: Idempotent delete_realm`).
pub async fn admin_orgs_bulk_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<BulkDeleteOrgsForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = target.0.name().to_string();
    for raw in form.ids.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Ok(uuid) = raw.parse::<uuid::Uuid>() else {
            continue;
        };
        let org_id = OrganizationId::new(uuid);
        match state.identity.delete_organization(target.id(), &org_id) {
            Ok(()) => audit_org_event(&state, &session, &target.0, &org_id, "delete"),
            Err(IdentityError::OrganizationNotFound) => {}
            Err(e) => {
                tracing::warn!(error = %e, org_id = %org_id.as_uuid(), "bulk delete_organization failed");
            }
        }
    }

    Redirect::to(&format!("/ui/admin/realms/{realm_name}/organizations")).into_response()
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
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<AddMemberForm>,
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
            return org_redirect_flash(&org_id, target.0.name(), "Invalid user selection", "error");
        }
    };

    let role = parse_org_role(&form.role);

    match state
        .identity
        .add_member(target.id(), &org_id, &user_id, role)
    {
        Ok(_) => {
            mirror_org_member_added(&state, &session, target.id(), &org_id, &user_id, role);
            org_redirect_flash(
                &org_id,
                target.0.name(),
                "Member added successfully",
                "success",
            )
        }
        Err(IdentityError::AlreadyMember) => org_redirect_flash(
            &org_id,
            target.0.name(),
            "User is already a member",
            "error",
        ),
        Err(e) => {
            tracing::warn!(error = %e, "add_member failed");
            org_redirect_flash(&org_id, target.0.name(), "Failed to add member", "error")
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
    realm_name: String,
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
    realm_name: String,
    org_id: String,
    m: MemberWithAccess,
    /// All realm roles for the assign-role inline form.
    available_roles: Vec<AvailableRole>,
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
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
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
        realm_name: target.0.name().to_string(),
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
    AxumPath((_realm_name, oid, uid)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
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
                org_redirect_flash(&org_id, target.0.name(), "Member removed", "success")
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
                        target.0.name(),
                        &org_id,
                        m,
                        &msg,
                        "error",
                    );
                }
                super::templates::htmx_toast_response(&msg, "error")
            } else {
                org_redirect_flash(&org_id, target.0.name(), &msg, "error")
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
pub(super) fn render_member_row_with_toast(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    realm: &RealmId,
    realm_name: &str,
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
    let owners_left = count_org_owners(state, realm, org_id);
    let is_last_owner = m.role() == OrganizationRole::Owner && owners_left == 1;
    let view = MemberView {
        membership: m,
        user_name: name,
        user_email: email,
    };
    let m_access = build_member_with_access(state, realm, org_id, view, is_last_owner);
    let available_roles = build_org_available_roles(state, realm);
    let tmpl = MemberRowTemplate {
        realm_name: realm_name.to_string(),
        org_id: org_id.as_uuid().to_string(),
        m: m_access,
        available_roles,
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
    AxumPath((_realm_name, oid, uid)): AxumPath<(String, String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<UpdateRoleForm>,
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
                        "Role updated",
                        "success",
                    )
                } else {
                    super::templates::htmx_toast_response("Role updated", "success")
                }
            } else {
                org_redirect_flash(&org_id, target.0.name(), "Role updated", "success")
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_member_role failed");
            let msg = format!("{e}");
            if is_htmx {
                if let Ok(Some(m)) = state
                    .identity
                    .get_membership(target.id(), &org_id, &user_id)
                {
                    return render_member_row_with_toast(
                        &state,
                        &session,
                        target.id(),
                        target.0.name(),
                        &org_id,
                        m,
                        &msg,
                        "error",
                    );
                }
                super::templates::htmx_toast_response(&msg, "error")
            } else {
                org_redirect_flash(&org_id, target.0.name(), &msg, "error")
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
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<InviteForm>,
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

                let stored_invitation = state
                    .identity
                    .get_realm(target.id())
                    .ok()
                    .flatten()
                    .and_then(|t| t.config().email_templates.get("invitation").cloned());
                if let Err(e) = email_service.send_invitation_email(
                    &form.email,
                    &accept_url,
                    &org_name,
                    &session.user_email,
                    realm_branding.as_ref(),
                    stored_invitation.as_ref(),
                    None,
                ) {
                    tracing::warn!(error = %e, "failed to send invitation email");
                }
            }
            let msg = format!("Invitation sent to {}", form.email);
            org_redirect_flash(&org_id, target.0.name(), &msg, "success")
        }
        Err(e) => {
            tracing::warn!(error = %e, email = %form.email, "create_invitation failed");
            org_redirect_flash(
                &org_id,
                target.0.name(),
                "Failed to create invitation",
                "error",
            )
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
    AxumPath((_realm_name, oid, iid)): AxumPath<(String, String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
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

    Redirect::to(&format!(
        "/ui/admin/realms/{}/organizations/{}",
        target.0.name(),
        org_id.as_uuid()
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// Toggle organization status (Active <-> Suspended)
// ---------------------------------------------------------------------------

/// Form data for `POST /ui/admin/organizations/:id/status`.
#[derive(Debug, Deserialize)]
pub struct StatusToggleForm {
    /// Target status — must be `"Active"` or `"Suspended"`.
    #[serde(default)]
    pub status: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/organizations/:id/status`.
///
/// One-click status toggle exposed in the org detail header so admins
/// can suspend or resume an organization without opening the edit form.
pub async fn admin_org_status_toggle(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, oid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<StatusToggleForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let org_id = match oid.parse::<uuid::Uuid>() {
        Ok(u) => OrganizationId::new(u),
        Err(_) => return super::handlers_common::not_found("Organization not found"),
    };

    let new_status = match form.status.as_str() {
        "Active" => OrganizationStatus::Active,
        "Suspended" => OrganizationStatus::Suspended,
        _ => {
            return org_redirect_flash(
                &org_id,
                target.0.name(),
                "Unknown organization status",
                "error",
            )
        }
    };

    match state.identity.update_organization(
        target.id(),
        &org_id,
        &UpdateOrganizationRequest {
            name: None,
            description: None,
            status: Some(new_status),
            config: None,
        },
    ) {
        Ok(_) => {
            audit_org_event(&state, &session, &target.0, &org_id, "status_change");
            let label = match new_status {
                OrganizationStatus::Active => "Organization resumed",
                OrganizationStatus::Suspended => "Organization suspended",
            };
            org_redirect_flash(&org_id, target.0.name(), label, "success")
        }
        Err(IdentityError::OrganizationNotFound) => {
            super::handlers_common::not_found("Organization not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_organization (status) failed");
            org_redirect_flash(&org_id, target.0.name(), "Failed to change status", "error")
        }
    }
}

// ---------------------------------------------------------------------------
// Resend invitation
// ---------------------------------------------------------------------------

/// `POST /ui/admin/organizations/:id/invitations/:iid/resend`.
///
/// Rotates an invitation: revokes the existing record (if pending) and
/// creates a fresh one for the same email + role, re-emitting the email
/// with a brand-new accept link. Existing tokens are invalidated — only
/// the fresh link works. The cleartext token is not stored, so a true
/// "re-send the same link" is not implementable.
pub async fn admin_org_resend_invite(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, oid, iid)): AxumPath<(String, String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
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

    let existing = match state
        .identity
        .list_invitations(target.id(), &org_id, None, 200)
    {
        Ok(page) => page
            .items
            .into_iter()
            .find(|i| i.id().as_uuid() == invitation_id.as_uuid()),
        Err(e) => {
            tracing::warn!(error = %e, "list_invitations failed during resend");
            return org_redirect_flash(
                &org_id,
                target.0.name(),
                "Failed to load invitation",
                "error",
            );
        }
    };

    let Some(existing) = existing else {
        return super::handlers_common::not_found("Invitation not found");
    };

    let email = existing.email().to_string();
    let role = existing.role();

    // Revoke first so we don't leave two pending invites for the same
    // address. If revoke fails (already-revoked, expired) we still try
    // the re-create — the worst case is two records but the new token
    // is what the user receives.
    if let Err(e) = state
        .identity
        .revoke_invitation(target.id(), &invitation_id)
    {
        tracing::debug!(error = %e, "revoke_invitation during resend (non-fatal)");
    }

    match state.identity.create_invitation(
        target.id(),
        &CreateInvitationRequest {
            org_id: org_id.clone(),
            email: email.clone(),
            role,
            invited_by: session.user_id.clone(),
        },
    ) {
        Ok((_invitation, token)) => {
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
                let stored_invitation = state
                    .identity
                    .get_realm(target.id())
                    .ok()
                    .flatten()
                    .and_then(|t| t.config().email_templates.get("invitation").cloned());
                if let Err(e) = email_service.send_invitation_email(
                    &email,
                    &accept_url,
                    &org_name,
                    &session.user_email,
                    realm_branding.as_ref(),
                    stored_invitation.as_ref(),
                    None,
                ) {
                    tracing::warn!(error = %e, "failed to send resend invitation email");
                }
            }
            let msg = format!("Invitation resent to {email}");
            org_redirect_flash(&org_id, target.0.name(), &msg, "success")
        }
        Err(e) => {
            tracing::warn!(error = %e, email = %email, "resend create_invitation failed");
            org_redirect_flash(
                &org_id,
                target.0.name(),
                "Failed to resend invitation",
                "error",
            )
        }
    }
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
    AxumPath(_realm_name): AxumPath<String>,
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

/// HTMX partial for the RBAC debug page autocomplete. Same backend
/// search as [`admin_api_user_search`] but renders a click-to-fill
/// dropdown instead of the org member-picker variant. Kept separate so
/// the partial template can be self-contained (no parent Alpine state
/// assumed beyond `userId` + `showDropdown`).
#[derive(Template)]
#[template(path = "ui/admin/rbac/_user_search_options.html")]
struct RbacUserSearchOptionsTemplate {
    users: Vec<User>,
    query: String,
}

/// `GET /ui/admin/rbac/api/users/search?q=...` — RBAC-debug autocomplete.
pub async fn admin_api_rbac_user_search(
    State(state): State<Arc<WebState>>,
    RequireAdmin(_session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
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
    render(&RbacUserSearchOptionsTemplate { users, query })
}

// ---------------------------------------------------------------------------
// Config reload API
// ---------------------------------------------------------------------------

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

/// Redirects to an org detail page with a flash message stored in a
/// short-lived `hearth_ui_flash` cookie.
///
/// `realm_name` is included so the redirect preserves the realm context
/// across the post-redirect-get cycle. Without it, drilling into an org
/// detail page after a member action would silently switch to the
/// default realm.
pub(super) fn org_redirect_flash(
    org_id: &OrganizationId,
    realm_name: &str,
    message: &str,
    kind: &str,
) -> Response {
    // Cookie-based flash: redirect URL stays clean (no `?flash=…`)
    // so refreshes / bookmarks / back-button traversals don't replay the
    // banner, and there is no reflected-text surface in the URL.
    let url = format!(
        "/ui/admin/realms/{realm_name}/organizations/{}",
        org_id.as_uuid()
    );
    super::templates::redirect_with_flash(&url, message, kind)
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
// Groups (RBAC)
// ---------------------------------------------------------------------------
// Org-role audit helpers (live here; only used by org handlers)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Org member helpers (build_member_with_access, count_org_owners, build_org_available_roles)
// ---------------------------------------------------------------------------
fn build_member_with_access(
    state: &Arc<WebState>,
    realm_id: &RealmId,
    org_id: &OrganizationId,
    view: MemberView,
    is_last_owner: bool,
) -> MemberWithAccess {
    let uid = view.membership.user_id();
    let org_scope = crate::rbac::Scope::Org {
        org_id: org_id.clone(),
    };
    let rbac_roles: Vec<MemberRbacRole> = state
        .rbac
        .list_user_assignments(realm_id, uid)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.scope == org_scope)
        .filter_map(|a| {
            let role = state.rbac.get_role(realm_id, &a.role_id).ok().flatten();
            // Skip roles defined as Realm-only scope — they don't belong on
            // the org page even if an assignment exists at org scope.
            if let Some(ref r) = role {
                if r.scope_kind == crate::rbac::RoleScopeKind::Realm {
                    return None;
                }
            }
            let (role_name, mut permissions) = match role {
                Some(r) => {
                    let perms: Vec<String> = r
                        .permissions
                        .iter()
                        .map(|p| p.as_str().to_string())
                        .collect();
                    (r.name, perms)
                }
                None => (a.role_id.as_uuid().to_string(), Vec::new()),
            };
            permissions.sort_unstable();
            permissions.dedup();
            Some(MemberRbacRole {
                assignment_id: a.id.as_uuid().to_string(),
                role_id: a.role_id.as_uuid().to_string(),
                role_name,
                permissions,
            })
        })
        .collect();
    let scope_raw = format!("org:{}", org_id.as_uuid());
    let extra_perms: Vec<MemberPermGrant> = state
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
    // Per-member grantable permissions: org-applicable perms minus any
    // already granted directly or inherited via this member's org roles.
    let mut already_held: std::collections::HashSet<String> =
        extra_perms.iter().map(|p| p.permission.clone()).collect();
    for r in &rbac_roles {
        for p in &r.permissions {
            already_held.insert(p.clone());
        }
    }
    let available_permissions: Vec<String> = collect_org_permissions(state, realm_id)
        .into_iter()
        .filter(|p| !already_held.contains(p))
        .collect();
    MemberWithAccess {
        view,
        is_last_owner,
        rbac_roles,
        extra_perms,
        available_permissions,
    }
}

/// Counts how many members of `org_id` hold the `Owner` role.
///
/// Used by every code path that rebuilds a member row so the UI can
/// disable destructive controls on the only owner. Cheap: a single
/// `list_members` scan capped at 1000 entries (orgs are not expected to
/// hold thousands of owners specifically; we'd revisit if proven wrong).
fn count_org_owners(state: &Arc<WebState>, realm_id: &RealmId, org_id: &OrganizationId) -> usize {
    state
        .identity
        .list_members(realm_id, org_id, None, 1000)
        .map(|p| {
            p.items
                .into_iter()
                .filter(|m| m.role() == OrganizationRole::Owner)
                .count()
        })
        .unwrap_or(0)
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
