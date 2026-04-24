//! Claims-based role-based access control (RBAC) engine.
//!
//! Resolves a user's effective permissions at token-issue time from
//! role assignments (direct or via transitive group membership), role
//! composition, and optional OAuth-scope narrowing. The resolution is
//! embedded into the JWT as flat claims (`roles`, `groups`,
//! `permissions`); client- and server-side authorization then reads
//! synchronously from the verified token without contacting the engine.
//!
//! See `docs/specs/AUTHORIZATION.md` for the normative specification.
//!
//! # Module layout
//!
//! Per ARCHITECTURE.md § 13, this module file contains ONLY the trait,
//! re-exports, and module declarations. No implementation lives here.

mod engine;
pub mod error;
pub(crate) mod keys;
mod resolve;
mod seed;
mod types;

pub use engine::EmbeddedRbacEngine;
pub use error::RbacError;
pub use types::{
    AssignRoleRequest, AssignmentId, CreateGroupRequest, CreateRoleRequest, CycleKind, Group,
    GroupId, GroupMember, GroupMembership, Page, Permission, ResolvedPermissions, Role,
    RoleAssignment, RoleId, RoleSubject, Scope, Subject, TraversalKind, UpdateGroupRequest,
    UpdateRoleRequest,
};

use crate::core::{OrganizationId, RealmId, UserId};

/// Trait defining the claims-based RBAC engine interface.
///
/// All methods are realm-scoped: every operation takes a `&RealmId`
/// first parameter and MUST NOT read or write state in another realm.
/// See AUTHORIZATION.md § 10 for the multi-tenancy invariants.
pub trait RbacEngine: Send + Sync {
    // ------- Permission resolution -------

    /// Resolves the effective permission set for a user at token-issue time.
    ///
    /// Honors realm and optional organization scope. If `requested_scope` is
    /// `Some`, intersects the resolved set with the scope's declared
    /// permission mapping. See AUTHORIZATION.md § 3.
    fn resolve_permissions(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scope: Option<&str>,
    ) -> Result<ResolvedPermissions, RbacError>;

    // ------- Roles -------

    /// Creates a new role in the given realm.
    fn create_role(&self, realm_id: &RealmId, req: &CreateRoleRequest) -> Result<Role, RbacError>;

    /// Fetches a role by ID.
    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError>;

    /// Fetches a role by its (realm-unique) name.
    fn get_role_by_name(&self, realm_id: &RealmId, name: &str) -> Result<Option<Role>, RbacError>;

    /// Updates an existing role.
    fn update_role(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        req: &UpdateRoleRequest,
    ) -> Result<Role, RbacError>;

    /// Deletes a role and its indexes.
    fn delete_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<(), RbacError>;

    /// Lists roles in a realm with paging.
    fn list_roles(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Role>, RbacError>;

    // ------- Groups -------

    /// Creates a new group in the given realm.
    fn create_group(
        &self,
        realm_id: &RealmId,
        req: &CreateGroupRequest,
    ) -> Result<Group, RbacError>;

    /// Fetches a group by ID.
    fn get_group(&self, realm_id: &RealmId, group_id: &GroupId)
        -> Result<Option<Group>, RbacError>;

    /// Updates an existing group.
    fn update_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        req: &UpdateGroupRequest,
    ) -> Result<Group, RbacError>;

    /// Deletes a group and its memberships.
    fn delete_group(&self, realm_id: &RealmId, group_id: &GroupId) -> Result<(), RbacError>;

    /// Lists groups in a realm with paging.
    fn list_groups(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Group>, RbacError>;

    /// Adds a user or child group as a member of the target group.
    fn add_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<GroupMembership, RbacError>;

    /// Removes a member from the target group.
    fn remove_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<(), RbacError>;

    /// Lists a group's direct members (users and nested groups) with paging.
    fn list_group_members(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<GroupMember>, RbacError>;

    // ------- Assignments -------

    /// Assigns a role to a user or group, optionally scoped to an organization.
    fn assign_role(
        &self,
        realm_id: &RealmId,
        req: &AssignRoleRequest,
    ) -> Result<RoleAssignment, RbacError>;

    /// Removes a role assignment by ID.
    fn unassign_role(
        &self,
        realm_id: &RealmId,
        assignment_id: &AssignmentId,
    ) -> Result<(), RbacError>;

    /// Lists all role assignments directly bound to a user.
    fn list_user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Lists all role assignments directly bound to a group.
    fn list_group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Lists subjects (users and groups) assigned a specific role, with paging.
    fn list_role_members(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<RoleSubject>, RbacError>;

    // ------- Bootstrap -------

    /// Installs the default role, permission, and scope seed for a new realm.
    ///
    /// Idempotent: re-running on a realm that already has seed state is a
    /// no-op. See AUTHORIZATION.md § 9.
    fn seed_realm(&self, realm_id: &RealmId) -> Result<(), RbacError>;
}
