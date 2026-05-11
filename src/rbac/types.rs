//! RBAC domain types.
//!
//! See `docs/specs/AUTHORIZATION.md` § 2 and § 6.3 for the normative model.
//!
//! Identifier newtypes introduced here (`RoleId`, `GroupId`, `AssignmentId`)
//! follow the same wrap-a-UUID, prefixed-display pattern as the global
//! IDs in `src/core/types.rs`. They live in the RBAC module rather than
//! `core/` to keep cross-layer surface minimal.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::{OrganizationId, RealmId, Timestamp, UserId};

/// Maximum length of a permission string, per AUTHORIZATION.md § 2.5.
pub const MAX_PERMISSION_LENGTH: usize = 128;

/// Reserved global permission namespace prefix.
pub const RESERVED_PREFIX: &str = "hearth.";

// ---------------------------------------------------------------------------
// ID newtypes
// ---------------------------------------------------------------------------

macro_rules! define_rbac_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(
            Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps an existing UUID.
            pub fn new(id: Uuid) -> Self {
                Self(id)
            }

            /// Generates a new random ID.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Accessor for the inner UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }
    };
}

define_rbac_id!(
    /// Unique identifier for a role within a realm.
    RoleId, "role_"
);

define_rbac_id!(
    /// Unique identifier for a group within a realm.
    GroupId, "group_"
);

define_rbac_id!(
    /// Unique identifier for a single role assignment (user→role or group→role).
    AssignmentId, "assign_"
);

// ---------------------------------------------------------------------------
// Permission (validated newtype)
// ---------------------------------------------------------------------------

/// A validated permission string, per AUTHORIZATION.md § 2.5.
///
/// Grammar:
/// `^[A-Za-z0-9_\\-]+(\\.[A-Za-z0-9_\\-]+)+$`, max 128 chars.
///
/// The dotted notation is a readability convention, not a prefix-matching
/// semantic — `docs.edit` does NOT grant `docs.edit.comments`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Permission(String);

impl Permission {
    /// Attempts to construct a permission from a string. Returns the raw
    /// reason string on failure so callers can wrap it into the layer
    /// error of their choice.
    pub fn new(raw: impl Into<String>) -> Result<Self, String> {
        let s = raw.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// Returns the permission as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the permission and returns the owned string.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Whether this permission is in the reserved `hearth.*` namespace.
    pub fn is_reserved(&self) -> bool {
        self.0.starts_with(RESERVED_PREFIX)
    }

    /// Validates a candidate permission string without constructing one.
    ///
    /// Rules (AUTHORIZATION.md § 2.5):
    /// - non-empty, max 128 chars
    /// - dot-delimited segments, at least two
    /// - each segment is non-empty and contains only ASCII alnum, `_`, `-`
    pub fn validate(s: &str) -> Result<(), String> {
        if s.is_empty() {
            return Err("permission must not be empty".to_string());
        }
        if s.len() > MAX_PERMISSION_LENGTH {
            return Err(format!(
                "permission exceeds maximum length of {MAX_PERMISSION_LENGTH} chars"
            ));
        }
        if s.contains(':') {
            return Err("permission must not contain ':'".to_string());
        }
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() < 2 {
            return Err("permission must contain at least one '.' separator".to_string());
        }
        if s.starts_with('.') || s.ends_with('.') {
            return Err("permission must not start or end with '.'".to_string());
        }
        for (i, segment) in segments.into_iter().enumerate() {
            if segment.is_empty() {
                return Err(format!("permission has empty segment at index {i}"));
            }
            for c in segment.chars() {
                if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                    return Err(format!(
                        "segment {i} contains invalid character '{c}' (allowed: A-Z, a-z, 0-9, _, -)"
                    ));
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Core entity types
// ---------------------------------------------------------------------------

/// YAML-defined permission metadata loaded into the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDefinition {
    pub name: Permission,
    pub display_name: String,
    pub description: Option<String>,
    pub category: Option<String>,
}

/// Optional coarse-grained consent bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeBundle {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub permissions: Vec<Permission>,
}

/// Registration for a specific RFC 8707 protected resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub resource_uri: String,
    pub display_name: String,
    #[serde(default)]
    pub scopes: Vec<ScopeBundle>,
}

/// Valid assignment boundary for a role definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleScopeKind {
    Realm,
    Organization,
    Any,
}

impl Default for RoleScopeKind {
    fn default() -> Self {
        Self::Realm
    }
}

/// A named set of permissions with optional parent-role composition edges.
///
/// Effective permissions are the union of `permissions` and the transitive
/// effective sets of `parent_roles`. See AUTHORIZATION.md § 2.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Opaque role identifier.
    pub id: RoleId,
    /// Realm this role belongs to; resolution never crosses realms.
    pub realm_id: RealmId,
    /// Human-readable name. Unique per realm.
    pub name: String,
    /// Optional description shown in the admin UI.
    pub description: Option<String>,
    /// Permissions granted directly by this role.
    pub permissions: Vec<Permission>,
    /// Parent role IDs. Composition is transitive; cycles rejected at write time.
    pub parent_roles: Vec<RoleId>,
    /// Where this role may be assigned.
    #[serde(default = "default_role_scope_kind")]
    pub scope_kind: RoleScopeKind,
    /// Creation timestamp (UTC microseconds).
    pub created_at: Timestamp,
    /// Last-update timestamp (UTC microseconds).
    pub updated_at: Timestamp,
}

const fn default_role_scope_kind() -> RoleScopeKind {
    RoleScopeKind::Realm
}

/// A named collection of users and/or other groups. Membership resolves
/// transitively during permission resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// Opaque group identifier.
    pub id: GroupId,
    /// Realm this group belongs to.
    pub realm_id: RealmId,
    /// Human-readable name.
    pub name: String,
    /// URL-safe slug. Unique per realm.
    pub slug: String,
    /// Optional description.
    pub description: Option<String>,
    /// Creation timestamp (UTC microseconds).
    pub created_at: Timestamp,
    /// Last-update timestamp (UTC microseconds).
    pub updated_at: Timestamp,
}

/// A user or group that can be a member of another group.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "lowercase")]
pub enum GroupMember {
    /// A user member.
    User(UserId),
    /// A nested-group member.
    Group(GroupId),
}

/// Edge from a group to a user or another group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMembership {
    /// The owning group.
    pub group_id: GroupId,
    /// The member being added.
    pub member: GroupMember,
    /// When the membership was recorded.
    pub added_at: Timestamp,
    /// Optional identifier of the admin who added the member.
    pub added_by: Option<UserId>,
}

/// Subject of a role assignment: either a user or a group.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "lowercase")]
pub enum Subject {
    /// Role bound directly to a user.
    User(UserId),
    /// Role bound to a group; resolves for all transitive members.
    Group(GroupId),
}

/// Applicability boundary for a role assignment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Scope {
    /// Applies whenever the user acts in the realm.
    Realm,
    /// Applies only when the token is issued with `oid` matching this org.
    #[serde(rename = "org")]
    Org {
        /// Organization ID the assignment is scoped to.
        #[serde(rename = "org_id")]
        org_id: OrganizationId,
    },
}

/// Binds a subject to a role within a scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    /// Opaque assignment identifier.
    pub id: AssignmentId,
    /// Realm this assignment lives in.
    pub realm_id: RealmId,
    /// User or group being granted the role.
    pub subject: Subject,
    /// Role being granted.
    pub role_id: RoleId,
    /// Applicability boundary.
    pub scope: Scope,
    /// When the assignment was created.
    pub assigned_at: Timestamp,
    /// Optional identifier of the admin who created it.
    pub assigned_by: Option<UserId>,
}

/// Listing shape used for `list_role_members`: either a user or a group,
/// returned by realm iteration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "lowercase")]
pub enum RoleSubject {
    /// A user assigned the role (possibly through assignment scope).
    User(UserId),
    /// A group assigned the role.
    Group(GroupId),
}

// ---------------------------------------------------------------------------
// Resolved output
// ---------------------------------------------------------------------------

/// Output of `resolve_permissions`.
///
/// `roles` and `groups` are carried by **name / slug** (not ID) for SDK
/// legibility; `permissions` is the authoritative authorization surface.
/// Each collection is sorted and de-duplicated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPermissions {
    /// De-duplicated, sorted role names reachable by the subject.
    pub roles: Vec<String>,
    /// De-duplicated, sorted group slugs for the subject.
    pub groups: Vec<String>,
    /// De-duplicated, sorted effective permissions after scope narrowing.
    pub permissions: Vec<Permission>,
    /// Requested scopes that were actually granted for this token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scopes: Vec<String>,
}

/// Declarative role definition consumed by `RbacEngine::reconcile_roles`.
///
/// Carries parent and permission references by *name* so the engine can
/// resolve them against the realm's current state at reconcile time, rather
/// than relying on caller-generated UUIDs that won't match storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleSpec {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub parent_names: Vec<String>,
    pub scope_kind: RoleScopeKind,
}

/// Declarative scope-bundle definition consumed by `RbacEngine::reconcile_scopes`.
///
/// `permissions: None` means an OIDC standard scope (no narrowing); `Some(list)`
/// is the literal permission set the scope maps to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeSpec {
    pub name: String,
    pub permissions: Option<Vec<String>>,
}

/// Runtime direct permission grant for a user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPermissionGrant {
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub permission: Permission,
    pub scope: Scope,
    pub granted_at: Timestamp,
    pub granted_by: Option<UserId>,
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Input for `create_role`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    /// Role name, unique per realm.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Permissions to grant directly.
    pub permissions: Vec<Permission>,
    /// Parent role IDs for composition.
    pub parent_roles: Vec<RoleId>,
    /// Where this role may be assigned.
    #[serde(default = "default_role_scope_kind")]
    pub scope_kind: RoleScopeKind,
}

/// Input for `update_role`. Fields left `None` are unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    /// New name (if changing); still validated for uniqueness.
    pub name: Option<String>,
    /// New description (or clear to `None` via `Some(None)` pattern at the
    /// engine; simpler `Option<String>` kept here for ergonomics).
    pub description: Option<Option<String>>,
    /// New permission set; replaces entirely when `Some`.
    pub permissions: Option<Vec<Permission>>,
    /// New parent-role list; replaces entirely when `Some`.
    pub parent_roles: Option<Vec<RoleId>>,
    /// New assignment boundary; replaces when `Some`.
    pub scope_kind: Option<RoleScopeKind>,
}

/// Input for `create_group`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    /// Group name.
    pub name: String,
    /// URL-safe slug, unique per realm.
    pub slug: String,
    /// Optional description.
    pub description: Option<String>,
}

/// Input for `update_group`. Fields left `None` are unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    /// New name, if provided.
    pub name: Option<String>,
    /// New slug, if provided; must remain unique per realm.
    pub slug: Option<String>,
    /// New description (nested Option for explicit clear).
    pub description: Option<Option<String>>,
}

/// Input for `assign_role`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    /// Subject (user or group) receiving the role.
    pub subject: Subject,
    /// Role being granted.
    pub role_id: RoleId,
    /// Applicability boundary.
    pub scope: Scope,
    /// Optional identifier of the admin who created the assignment.
    pub assigned_by: Option<UserId>,
}

// ---------------------------------------------------------------------------
// Traversal & cycle-detection taxonomies
// ---------------------------------------------------------------------------

/// Identifies the graph in which a cycle was detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleKind {
    /// Cycle among role parent edges.
    RoleComposition,
    /// Cycle among group membership edges.
    GroupMembership,
}

impl fmt::Display for CycleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleComposition => f.write_str("role_composition"),
            Self::GroupMembership => f.write_str("group_membership"),
        }
    }
}

/// Identifies which traversal exceeded a depth or breadth bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalKind {
    /// Transitive group membership BFS.
    GroupMembership,
    /// Role composition DFS.
    RoleComposition,
}

impl fmt::Display for TraversalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupMembership => f.write_str("group_membership"),
            Self::RoleComposition => f.write_str("role_composition"),
        }
    }
}

// ---------------------------------------------------------------------------
// Paging
// ---------------------------------------------------------------------------

/// Generic paged listing result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// The current page of items.
    pub items: Vec<T>,
    /// Cursor to fetch the next page, or `None` if the end has been reached.
    pub next_cursor: Option<String>,
}

impl<T> Default for Page<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Permission grammar (§ 2.5) =====

    // Per AUTHZ_EXPANSION.md the permission grammar is
    // `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$` — at least one dot required,
    // case-insensitive, leading digits / underscores / hyphens permitted.
    // Single-word names are reserved for IETF OIDC scopes.

    #[test]
    fn permission_rejects_single_segment() {
        assert!(
            Permission::new("docs").is_err(),
            "single-segment names belong to the OIDC scope namespace"
        );
    }

    #[test]
    fn permission_accepts_dotted() {
        assert!(Permission::new("docs.edit").is_ok());
        assert!(Permission::new("org.billing.view").is_ok());
    }

    #[test]
    fn permission_accepts_digits_and_underscores_in_non_first_position() {
        assert!(Permission::new("docs.v1").is_ok());
        assert!(Permission::new("docs.edit_self").is_ok());
        assert!(Permission::new("a1b2c3.x_y").is_ok());
    }

    #[test]
    fn permission_rejects_empty() {
        assert!(Permission::new("").is_err());
    }

    #[test]
    fn permission_accepts_mixed_case() {
        // Per AUTHZ_EXPANSION.md the grammar is case-insensitive.
        assert!(Permission::new("Docs.edit").is_ok());
        assert!(Permission::new("docs.Edit").is_ok());
    }

    #[test]
    fn permission_accepts_leading_digit() {
        // Grammar permits any ASCII alnum/underscore/hyphen at any position.
        assert!(Permission::new("1docs.x").is_ok());
        assert!(Permission::new("docs.1bad").is_ok());
    }

    #[test]
    fn permission_accepts_leading_underscore() {
        // Same grammar relaxation as above.
        assert!(Permission::new("_docs.x").is_ok());
        assert!(Permission::new("docs._bad").is_ok());
    }

    #[test]
    fn permission_accepts_hyphen() {
        // Hyphens are explicitly part of the AUTHZ_EXPANSION grammar.
        assert!(Permission::new("docs-edit.read").is_ok());
        assert!(Permission::new("docs.edit-self").is_ok());
    }

    #[test]
    fn permission_rejects_empty_segment() {
        assert!(Permission::new("docs..edit").is_err());
        assert!(Permission::new(".docs").is_err());
        assert!(Permission::new("docs.").is_err());
    }

    #[test]
    fn permission_rejects_special_chars() {
        assert!(Permission::new("docs-edit").is_err());
        assert!(Permission::new("docs edit").is_err());
        assert!(Permission::new("docs/edit").is_err());
        assert!(Permission::new("docs:edit").is_err());
    }

    #[test]
    fn permission_rejects_overlength() {
        let long = format!("a.{}", "b".repeat(MAX_PERMISSION_LENGTH));
        assert!(long.len() > MAX_PERMISSION_LENGTH);
        assert!(Permission::new(long).is_err());
    }

    #[test]
    fn permission_accepts_exactly_max_length() {
        // 128 chars total. Must contain a `.` per the AUTHZ_EXPANSION grammar.
        // Use 63 'a's, a single '.', then 64 'b's = 128 chars.
        let ok = format!("{}.{}", "a".repeat(63), "b".repeat(64));
        assert_eq!(ok.len(), MAX_PERMISSION_LENGTH);
        assert!(Permission::new(ok).is_ok());
    }

    #[test]
    fn permission_is_reserved_detects_hearth_prefix() {
        // Per AUTHZ_EXPANSION.md the global namespace prefix is `hearth.*`.
        let p = Permission::new("hearth.admin").expect("valid");
        assert!(p.is_reserved());
        let q = Permission::new("docs.edit").expect("valid");
        assert!(!q.is_reserved());
        // Segment-boundary: `hearthadmin.x` must NOT be reserved.
        let r = Permission::new("hearthadmin.x").expect("valid");
        assert!(!r.is_reserved());
    }

    #[test]
    fn permission_serde_roundtrip() {
        let p = Permission::new("org.billing").expect("valid");
        let s = serde_json::to_string(&p).expect("serialize");
        // #[serde(transparent)] → JSON string, not struct wrapper.
        assert_eq!(s, "\"org.billing\"");
        let back: Permission = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, p);
    }

    #[test]
    fn permission_display_shows_raw_string() {
        let p = Permission::new("docs.edit").expect("valid");
        assert_eq!(format!("{p}"), "docs.edit");
    }

    // ===== ID newtypes =====

    #[test]
    fn role_id_prefixed_display() {
        let id = RoleId::generate();
        assert!(format!("{id}").starts_with("role_"));
    }

    #[test]
    fn group_id_prefixed_display() {
        let id = GroupId::generate();
        assert!(format!("{id}").starts_with("group_"));
    }

    #[test]
    fn assignment_id_prefixed_display() {
        let id = AssignmentId::generate();
        assert!(format!("{id}").starts_with("assign_"));
    }

    #[test]
    fn rbac_ids_generate_unique() {
        assert_ne!(RoleId::generate(), RoleId::generate());
        assert_ne!(GroupId::generate(), GroupId::generate());
        assert_ne!(AssignmentId::generate(), AssignmentId::generate());
    }

    #[test]
    fn rbac_ids_serde_roundtrip() {
        let r = RoleId::generate();
        let j = serde_json::to_string(&r).expect("ser");
        let back: RoleId = serde_json::from_str(&j).expect("de");
        assert_eq!(r, back);
    }

    // ===== Scope serde shape =====

    #[test]
    fn scope_realm_serializes_tagged() {
        let s = Scope::Realm;
        let j = serde_json::to_value(&s).expect("ser");
        assert_eq!(j, serde_json::json!({"type": "realm"}));
    }

    #[test]
    fn scope_org_serializes_tagged_with_id() {
        let oid = OrganizationId::generate();
        let s = Scope::Org {
            org_id: oid.clone(),
        };
        let j = serde_json::to_value(&s).expect("ser");
        assert_eq!(j["type"], "org");
        assert_eq!(j["org_id"], serde_json::to_value(&oid).expect("oid"));
    }

    // ===== CycleKind / TraversalKind =====

    #[test]
    fn cycle_kind_displays_snake_case() {
        assert_eq!(
            format!("{}", CycleKind::RoleComposition),
            "role_composition"
        );
        assert_eq!(
            format!("{}", CycleKind::GroupMembership),
            "group_membership"
        );
    }

    #[test]
    fn traversal_kind_displays_snake_case() {
        assert_eq!(
            format!("{}", TraversalKind::RoleComposition),
            "role_composition"
        );
        assert_eq!(
            format!("{}", TraversalKind::GroupMembership),
            "group_membership"
        );
    }

    // ===== Resolved shape =====

    #[test]
    fn resolved_permissions_default_is_empty() {
        let r = ResolvedPermissions::default();
        assert!(r.roles.is_empty());
        assert!(r.groups.is_empty());
        assert!(r.permissions.is_empty());
    }

    // ===== Page<T> =====

    #[test]
    fn page_default_is_empty() {
        let p: Page<Role> = Page::default();
        assert!(p.items.is_empty());
        assert!(p.next_cursor.is_none());
    }
}
