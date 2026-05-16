//! Axum handlers for the `/ui/admin/*` management surface.
//!
//! Handlers are split into per-entity sub-modules:
//! * [`users`] — user CRUD, sessions, consents, role/permission assignments
//! * [`realms`] — realm CRUD, audit log, config editor, realm admin management
//! * [`clients`] — OAuth client (application) registration/management
//! * [`orgs`] — organization management, member management
//! * [`groups`] — group CRUD, membership, role assignments
//! * [`rbac`] — role definitions, permissions browser, RBAC debug tooling

use std::fmt::Write as _;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use serde::Deserialize;

use super::auth::{verify_csrf_form_field, RequireAdmin, TargetRealm};
use super::handlers_common::FriendlyForm;
use super::templates::{render, Flash};
use super::WebState;
use crate::config::{Config, ValidationIssue};
use crate::core::{ClientId, InvitationId, OrganizationId, RealmId, SessionId};
use crate::identity::claims_config::ClaimSource;
use crate::identity::oidc::{ClientTrustLevel, RegisterClientRequest, UpdateClientRequest};
use crate::identity::{
    CleartextPassword, CreateInvitationRequest, CreateOrganizationRequest, CreateUserRequest,
    IdentityError, OAuthClient, Organization, OrganizationConfig, OrganizationInvitation,
    OrganizationMembership, OrganizationRole, OrganizationStatus, Page, Realm, RealmStatus,
    Session, UpdateOrganizationRequest, UpdateUserRequest, User, UserStatus,
};
use crate::rbac::{
    CreateGroupRequest, CreateRoleRequest, Group, GroupId, GroupMember, Permission, Role, RoleId,
    RoleScopeKind, Scope as RbacScope, UpdateGroupRequest, UpdateRoleRequest,
};

// Re-export web-layer modules so sub-modules can use `super::auth::*`,
// `super::handlers_common::*`, and `super::templates::*`.
pub use super::auth;
pub(crate) use super::handlers_common;
pub(crate) use super::templates;

pub mod clients;
pub mod groups;
pub mod identity_providers;
pub mod migrations;
pub mod onboarding;
pub mod orgs;
pub mod rbac;
pub mod realms;
pub mod users;
pub mod webhooks;

// Re-export all public handlers so `web/mod.rs` keeps `admin::fn_name` paths.
pub use clients::*;
pub use groups::*;
pub use identity_providers::*;
pub use migrations::*;
pub use onboarding::*;
pub use orgs::*;
pub use rbac::*;
pub use realms::*;
pub use users::*;
pub use webhooks::*;

// ---------------------------------------------------------------------------
// Shared query type
// ---------------------------------------------------------------------------
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
// Shared RBAC view types (used by mod.rs helpers and/or multiple sub-modules)
// ---------------------------------------------------------------------------
pub struct UserRoleAssignmentRow {
    /// `AssignmentId` UUID string — used in the unassign POST URL.
    pub assignment_id: String,
    /// `RoleId` UUID string — used as a stable key in the template.
    pub role_id: String,
    /// Human-readable role name.
    pub role_name: String,
    /// Display label for the scope ("Realm-wide" or "Org: {name}").
    pub scope_label: String,
    /// Wire value sent back in the unassign form ("realm" | "org:{uuid}").
    pub scope_raw: String,
    /// Permissions granted by this role (sorted). Empty if the role lookup
    /// failed or the role grants no permissions.
    pub permissions: Vec<String>,
}

/// Permissions inherited by a user, grouped by the role assignment that
/// granted them. Rendered in the Permissions tab to attribute each
/// inherited permission to its source role + scope.
pub struct RoleInheritedGroup {
    /// Human-readable role name.
    pub role_name: String,
    /// Display label for the scope ("Realm-wide" or "Org: {name}").
    pub scope_label: String,
    /// Permissions granted by this assignment (sorted).
    pub permissions: Vec<String>,
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
    /// Direct permissions granted by this role (sorted).
    pub permissions: Vec<String>,
}

/// An organization available for scope selection in the assign forms.
pub struct AvailableOrg {
    /// `OrganizationId` UUID string.
    pub id: String,
    /// Organization display name.
    pub name: String,
}

pub struct UserPermissionGrantRow {
    /// The permission string (e.g. `documents.read`).
    pub permission: String,
    /// Display label for the scope ("Realm-wide" or "Org: {name}").
    pub scope_label: String,
    /// Wire value sent back in the revoke form ("realm" | "org:{uuid}").
    pub scope_raw: String,
}

// ---------------------------------------------------------------------------
// Shared cross-module helpers
// ---------------------------------------------------------------------------
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

/// Formats an Argon2id memory-cost value (already in KiB) as a human-readable
/// string with the original KiB count alongside.
///
/// Examples: `131_072` → "128 MiB (131072 KiB)", `4_096` → "4 MiB (4096 KiB)",
/// `512` → "512 KiB". The 2026-04-30 UX audit caught the raw number leaking
/// to operators with no unit conversion.
fn format_kib_human(kib: u32) -> String {
    if kib >= 1024 {
        let mib = f64::from(kib) / 1024.0;
        // Whole-MiB values render without trailing zero noise.
        if (mib.fract()).abs() < f64::EPSILON {
            format!("{} MiB ({kib} KiB)", mib as u32)
        } else {
            format!("{mib:.1} MiB ({kib} KiB)")
        }
    } else {
        format!("{kib} KiB")
    }
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

fn is_htmx_request(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "true")
}

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
        let (role_name, mut permissions) = match state.rbac.get_role(realm_id, &a.role_id) {
            Ok(Some(r)) => {
                let perms: Vec<String> = r
                    .permissions
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect();
                (r.name, perms)
            }
            _ => (a.role_id.as_uuid().to_string(), Vec::new()),
        };
        permissions.sort_unstable();
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
            role_id: a.role_id.as_uuid().to_string(),
            role_name,
            scope_label,
            scope_raw,
            permissions,
        });
    }
    rows.sort_by(|a, b| {
        a.role_name
            .cmp(&b.role_name)
            .then(a.scope_label.cmp(&b.scope_label))
    });
    rows
}

/// Builds the per-role inheritance groups shown in the Permissions tab.
/// Skips assignments whose role grants no permissions, so the UI is not
/// cluttered with empty groups.
fn build_role_inherited_groups(rows: &[UserRoleAssignmentRow]) -> Vec<RoleInheritedGroup> {
    rows.iter()
        .filter(|r| !r.permissions.is_empty())
        .map(|r| RoleInheritedGroup {
            role_name: r.role_name.clone(),
            scope_label: r.scope_label.clone(),
            permissions: r.permissions.clone(),
        })
        .collect()
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
