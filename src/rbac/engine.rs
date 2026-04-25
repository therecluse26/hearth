//! Storage-backed implementation of [`RbacEngine`].
//!
//! Thread-safe via the underlying [`StorageEngine`]. All write paths that
//! touch two or more keys use [`StorageEngine::put_batch`] so that index
//! entries can never lag behind their primary records on crash recovery.
//!
//! Cycle detection for role parents and group membership runs at write
//! time (write-time rejection is cheaper than paying for it on every
//! token issuance; `resolve.rs` still tolerates a late-appearing cycle
//! in case storage was corrupted out-of-band).

use std::collections::HashSet;
use std::sync::Arc;

use crate::core::{Clock, OrganizationId, RealmId, UserId};
use crate::storage::StorageEngine;

use super::error::RbacError;
use super::keys;
use super::resolve::{self, Resolver};
use super::seed::{self, StoredScope};
use super::types::{
    AssignRoleRequest, AssignmentId, CreateGroupRequest, CreateRoleRequest, CycleKind, Group,
    GroupId, GroupMember, GroupMembership, Page, Permission, ResolvedPermissions, Role,
    RoleAssignment, RoleId, RoleSubject, Scope, Subject, TraversalKind, UpdateGroupRequest,
    UpdateRoleRequest, UserPermissionGrant,
};
use super::RbacEngine;

/// Embedded RBAC engine backed by [`StorageEngine`].
pub struct EmbeddedRbacEngine {
    storage: Arc<dyn StorageEngine>,
    clock: Arc<dyn Clock>,
}

impl EmbeddedRbacEngine {
    /// Creates a new embedded RBAC engine.
    pub fn new(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> Self {
        Self { storage, clock }
    }

    // -------------------- helpers (serde wrapping) --------------------

    fn ser<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, RbacError> {
        serde_json::to_vec(v).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })
    }

    fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, RbacError> {
        serde_json::from_slice(bytes).map_err(|e| RbacError::Serialization {
            reason: e.to_string(),
        })
    }

    // -------------------- role helpers --------------------

    fn load_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        let k = keys::encode_role(role_id);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => {
                let role: Role = Self::de(&bytes)?;
                if &role.realm_id != realm_id {
                    // Belongs to another realm — treat as not found here.
                    return Ok(None);
                }
                Ok(Some(role))
            }
            None => Ok(None),
        }
    }

    fn load_role_id_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<RoleId>, RbacError> {
        let k = keys::encode_role_name(realm_id, name);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => Ok(Some(Self::de::<RoleId>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn validate_role_name(name: &str) -> Result<(), RbacError> {
        if name.is_empty() {
            return Err(RbacError::InvalidRoleName {
                reason: "role name must not be empty".to_string(),
            });
        }
        if name.len() > 128 {
            return Err(RbacError::InvalidRoleName {
                reason: "role name exceeds 128 chars".to_string(),
            });
        }
        for c in name.chars() {
            if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
                return Err(RbacError::InvalidRoleName {
                    reason: format!("role name contains invalid char '{c}'"),
                });
            }
        }
        Ok(())
    }

    fn validate_group_slug(slug: &str) -> Result<(), RbacError> {
        if slug.is_empty() {
            return Err(RbacError::InvalidGroupSlug {
                reason: "slug must not be empty".to_string(),
            });
        }
        if slug.len() > 128 {
            return Err(RbacError::InvalidGroupSlug {
                reason: "slug exceeds 128 chars".to_string(),
            });
        }
        for c in slug.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
                return Err(RbacError::InvalidGroupSlug {
                    reason: format!("slug contains invalid char '{c}' (a-z, 0-9, -, _)"),
                });
            }
        }
        Ok(())
    }

    fn validate_permissions_for_operator(perms: &[Permission]) -> Result<(), RbacError> {
        for p in perms {
            if p.is_reserved() {
                return Err(RbacError::ReservedNamespace {
                    permission: p.as_str().to_string(),
                });
            }
        }
        Ok(())
    }

    /// Walk role parents (DFS) to ensure no cycle involves `start` via
    /// `parents`. Also ensures depth bound.
    fn check_role_parents_no_cycle(
        &self,
        realm_id: &RealmId,
        start: &RoleId,
        parents: &[RoleId],
    ) -> Result<(), RbacError> {
        let mut visited: HashSet<RoleId> = HashSet::new();
        for p in parents {
            if p == start {
                return Err(RbacError::CycleDetected {
                    kind: CycleKind::RoleComposition,
                    entity: start.to_string(),
                });
            }
            self.walk_role_parents(realm_id, start, p, &mut visited, 1)?;
        }
        Ok(())
    }

    fn walk_role_parents(
        &self,
        realm_id: &RealmId,
        start: &RoleId,
        current: &RoleId,
        visited: &mut HashSet<RoleId>,
        depth: usize,
    ) -> Result<(), RbacError> {
        if depth > resolve::MAX_ROLE_DEPTH {
            return Err(RbacError::DepthExceeded {
                kind: TraversalKind::RoleComposition,
                limit: resolve::MAX_ROLE_DEPTH,
            });
        }
        if !visited.insert(current.clone()) {
            return Ok(());
        }
        let Some(role) = self.load_role(realm_id, current)? else {
            return Ok(());
        };
        for parent in &role.parent_roles {
            if parent == start {
                return Err(RbacError::CycleDetected {
                    kind: CycleKind::RoleComposition,
                    entity: start.to_string(),
                });
            }
            self.walk_role_parents(realm_id, start, parent, visited, depth + 1)?;
        }
        Ok(())
    }

    // -------------------- group helpers --------------------

    fn load_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<Group>, RbacError> {
        let k = keys::encode_group(group_id);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => {
                let g: Group = Self::de(&bytes)?;
                if &g.realm_id != realm_id {
                    return Ok(None);
                }
                Ok(Some(g))
            }
            None => Ok(None),
        }
    }

    fn load_group_id_by_slug(
        &self,
        realm_id: &RealmId,
        slug: &str,
    ) -> Result<Option<GroupId>, RbacError> {
        let k = keys::encode_group_slug(realm_id, slug);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => Ok(Some(Self::de::<GroupId>(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check that adding `member` to `group` would not create a cycle.
    ///
    /// Only relevant when `member` is itself a group: walk from `member`
    /// through forward edges (group → members) and confirm the target
    /// `group` is not reachable.
    fn check_group_no_cycle(
        &self,
        realm_id: &RealmId,
        target_group: &GroupId,
        member: &GroupMember,
    ) -> Result<(), RbacError> {
        let GroupMember::Group(member_group) = member else {
            return Ok(());
        };
        if member_group == target_group {
            return Err(RbacError::CycleDetected {
                kind: CycleKind::GroupMembership,
                entity: target_group.to_string(),
            });
        }

        // BFS forward edges from member_group; if we can reach target_group,
        // adding member→target would create a cycle (target would contain a
        // group that transitively contains target).
        let mut visited: HashSet<GroupId> = HashSet::new();
        let mut stack: Vec<(GroupId, usize)> = vec![(member_group.clone(), 0)];

        while let Some((cur, depth)) = stack.pop() {
            if depth > resolve::MAX_GROUP_DEPTH {
                return Err(RbacError::DepthExceeded {
                    kind: TraversalKind::GroupMembership,
                    limit: resolve::MAX_GROUP_DEPTH,
                });
            }
            if !visited.insert(cur.clone()) {
                continue;
            }
            // Walk forward members of `cur` that are themselves groups.
            let prefix = keys::gm_forward_scan_prefix(&cur);
            let end = keys::prefix_end(&prefix);
            for entry in self.storage.scan(realm_id, &prefix, &end)? {
                // Decode the stored GroupMember to see if it's a group we must traverse.
                let decoded: GroupMember = Self::de(&entry.value)?;
                if let GroupMember::Group(child) = decoded {
                    if &child == target_group {
                        return Err(RbacError::CycleDetected {
                            kind: CycleKind::GroupMembership,
                            entity: target_group.to_string(),
                        });
                    }
                    stack.push((child, depth + 1));
                }
            }
        }

        Ok(())
    }

    // -------------------- assignment helpers --------------------

    fn load_assignment(
        &self,
        realm_id: &RealmId,
        id: &AssignmentId,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        let k = keys::encode_assignment(id);
        match self.storage.get(realm_id, &k)? {
            Some(bytes) => {
                let a: RoleAssignment = Self::de(&bytes)?;
                if &a.realm_id != realm_id {
                    return Ok(None);
                }
                Ok(Some(a))
            }
            None => Ok(None),
        }
    }

    fn scan_assignments_by_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let end = keys::prefix_end(prefix);
        let entries = self.storage.scan(realm_id, prefix, &end)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let aid: AssignmentId = Self::de(&entry.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                out.push(a);
            }
        }
        Ok(out)
    }

    fn load_user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        let prefix = keys::user_permission_scan_prefix(realm_id, user_id);
        let end = keys::prefix_end(&prefix);
        let mut out = Vec::new();
        for entry in self.storage.scan(realm_id, &prefix, &end)? {
            out.push(Self::de::<UserPermissionGrant>(&entry.value)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Resolver impl — allows resolve.rs to drive the DB.
// ---------------------------------------------------------------------------

impl Resolver for EmbeddedRbacEngine {
    fn parent_groups_of(
        &self,
        realm_id: &RealmId,
        member: &GroupMember,
    ) -> Result<Vec<GroupId>, RbacError> {
        let prefix = keys::gm_reverse_scan_prefix(member);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let gid: GroupId = Self::de(&entry.value)?;
            out.push(gid);
        }
        Ok(out)
    }

    fn user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_user_scan_prefix(user_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_group_scan_prefix(group_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        self.load_role(realm_id, role_id)
    }

    fn get_group_slug(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<String>, RbacError> {
        Ok(self.load_group(realm_id, group_id)?.map(|g| g.slug))
    }

    fn scope_permissions(
        &self,
        realm_id: &RealmId,
        scope_name: &str,
    ) -> Result<Option<Vec<Permission>>, RbacError> {
        let key = keys::encode_scope(realm_id, scope_name);
        match self.storage.get(realm_id, &key)? {
            None => Ok(Some(Vec::new())),
            Some(bytes) => {
                let s: StoredScope = Self::de(&bytes)?;
                Ok(s.permissions)
            }
        }
    }

    fn user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        self.load_user_permissions(realm_id, user_id)
    }
}

// ---------------------------------------------------------------------------
// RbacEngine trait impl
// ---------------------------------------------------------------------------

impl RbacEngine for EmbeddedRbacEngine {
    fn resolve_permissions(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scope: Option<&str>,
    ) -> Result<ResolvedPermissions, RbacError> {
        resolve::resolve_permissions(self, user_id, realm_id, org_id, requested_scope)
    }

    fn grant_user_permission(
        &self,
        realm_id: &RealmId,
        grant: &UserPermissionGrant,
    ) -> Result<UserPermissionGrant, RbacError> {
        let primary = keys::encode_user_permission(
            realm_id,
            &grant.user_id,
            &grant.scope,
            grant.permission.as_str(),
        );
        let reverse = keys::encode_user_permission_by_perm(
            realm_id,
            grant.permission.as_str(),
            &grant.scope,
            &grant.user_id,
        );
        let bytes = Self::ser(grant)?;
        self.storage
            .put_batch(realm_id, &[(primary, bytes), (reverse, Vec::new())])?;
        Ok(grant.clone())
    }

    fn revoke_user_permission(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        permission: &Permission,
        scope: &Scope,
    ) -> Result<(), RbacError> {
        let primary = keys::encode_user_permission(realm_id, user_id, scope, permission.as_str());
        let reverse =
            keys::encode_user_permission_by_perm(realm_id, permission.as_str(), scope, user_id);
        self.storage.delete(realm_id, &primary)?;
        self.storage.delete(realm_id, &reverse)?;
        Ok(())
    }

    fn list_user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        self.load_user_permissions(realm_id, user_id)
    }

    // ---------- Roles ----------

    fn create_role(&self, realm_id: &RealmId, req: &CreateRoleRequest) -> Result<Role, RbacError> {
        Self::validate_role_name(&req.name)?;
        Self::validate_permissions_for_operator(&req.permissions)?;

        if self.load_role_id_by_name(realm_id, &req.name)?.is_some() {
            return Err(RbacError::DuplicateRoleName);
        }

        // Verify parents exist + no immediate cycle.
        for p in &req.parent_roles {
            if self.load_role(realm_id, p)?.is_none() {
                return Err(RbacError::RoleNotFound);
            }
        }

        let now = self.clock.now();
        let role = Role {
            id: RoleId::generate(),
            realm_id: realm_id.clone(),
            name: req.name.clone(),
            description: req.description.clone(),
            permissions: req.permissions.clone(),
            parent_roles: req.parent_roles.clone(),
            scope_kind: req.scope_kind,
            created_at: now,
            updated_at: now,
        };

        // Self-edge cycle check isn't strictly needed for create (id is
        // freshly generated and can't appear in parent_roles), but calling
        // through keeps behavior consistent and respects MAX_ROLE_DEPTH.
        self.check_role_parents_no_cycle(realm_id, &role.id, &role.parent_roles)?;

        let role_key = keys::encode_role(&role.id);
        let name_key = keys::encode_role_name(realm_id, &role.name);
        self.storage.put_batch(
            realm_id,
            &[
                (role_key, Self::ser(&role)?),
                (name_key, Self::ser(&role.id)?),
            ],
        )?;

        Ok(role)
    }

    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        self.load_role(realm_id, role_id)
    }

    fn get_role_by_name(&self, realm_id: &RealmId, name: &str) -> Result<Option<Role>, RbacError> {
        let Some(id) = self.load_role_id_by_name(realm_id, name)? else {
            return Ok(None);
        };
        self.load_role(realm_id, &id)
    }

    fn update_role(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        req: &UpdateRoleRequest,
    ) -> Result<Role, RbacError> {
        let Some(mut role) = self.load_role(realm_id, role_id)? else {
            return Err(RbacError::RoleNotFound);
        };

        let mut rename: Option<(Vec<u8>, Vec<u8>)> = None;
        if let Some(new_name) = &req.name {
            Self::validate_role_name(new_name)?;
            if new_name != &role.name {
                if self.load_role_id_by_name(realm_id, new_name)?.is_some() {
                    return Err(RbacError::DuplicateRoleName);
                }
                rename = Some((
                    keys::encode_role_name(realm_id, &role.name),
                    keys::encode_role_name(realm_id, new_name),
                ));
                role.name.clone_from(new_name);
            }
        }

        if let Some(desc) = &req.description {
            role.description.clone_from(desc);
        }

        if let Some(perms) = &req.permissions {
            Self::validate_permissions_for_operator(perms)?;
            role.permissions.clone_from(perms);
        }

        if let Some(parents) = &req.parent_roles {
            for p in parents {
                if self.load_role(realm_id, p)?.is_none() {
                    return Err(RbacError::RoleNotFound);
                }
            }
            self.check_role_parents_no_cycle(realm_id, role_id, parents)?;
            role.parent_roles.clone_from(parents);
        }

        if let Some(scope_kind) = req.scope_kind {
            role.scope_kind = scope_kind;
        }

        role.updated_at = self.clock.now();

        let role_key = keys::encode_role(&role.id);
        let mut writes: Vec<(Vec<u8>, Vec<u8>)> = vec![(role_key, Self::ser(&role)?)];
        if let Some((_old, new)) = &rename {
            writes.push((new.clone(), Self::ser(&role.id)?));
        }
        self.storage.put_batch(realm_id, &writes)?;

        if let Some((old, _)) = rename {
            self.storage.delete(realm_id, &old)?;
        }

        Ok(role)
    }

    fn delete_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<(), RbacError> {
        let Some(role) = self.load_role(realm_id, role_id)? else {
            return Err(RbacError::RoleNotFound);
        };
        self.storage.delete(realm_id, &keys::encode_role(role_id))?;
        self.storage
            .delete(realm_id, &keys::encode_role_name(realm_id, &role.name))?;
        Ok(())
    }

    fn list_roles(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Role>, RbacError> {
        let prefix = keys::role_name_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let start = match cursor {
            Some(c) => {
                let mut v = prefix.clone();
                v.extend_from_slice(c.as_bytes());
                // Exclusive: bump one byte.
                v.push(0);
                v
            }
            None => prefix.clone(),
        };
        let entries = self.storage.scan(realm_id, &start, &end)?;

        let mut items = Vec::new();
        let mut next_cursor = None;
        for entry in entries {
            if items.len() >= limit {
                // Derive cursor from the previous entry's name (strip prefix).
                let name_bytes = &items
                    .last()
                    .map(|r: &Role| r.name.clone())
                    .unwrap_or_default();
                next_cursor = Some(name_bytes.to_string());
                break;
            }
            let id: RoleId = Self::de(&entry.value)?;
            if let Some(role) = self.load_role(realm_id, &id)? {
                items.push(role);
            }
        }

        Ok(Page { items, next_cursor })
    }

    // ---------- Groups ----------

    fn create_group(
        &self,
        realm_id: &RealmId,
        req: &CreateGroupRequest,
    ) -> Result<Group, RbacError> {
        Self::validate_group_slug(&req.slug)?;
        if req.name.is_empty() {
            return Err(RbacError::InvalidGroupSlug {
                reason: "group name must not be empty".to_string(),
            });
        }
        if self.load_group_id_by_slug(realm_id, &req.slug)?.is_some() {
            return Err(RbacError::DuplicateGroupSlug);
        }

        let now = self.clock.now();
        let group = Group {
            id: GroupId::generate(),
            realm_id: realm_id.clone(),
            name: req.name.clone(),
            slug: req.slug.clone(),
            description: req.description.clone(),
            created_at: now,
            updated_at: now,
        };

        self.storage.put_batch(
            realm_id,
            &[
                (keys::encode_group(&group.id), Self::ser(&group)?),
                (
                    keys::encode_group_slug(realm_id, &group.slug),
                    Self::ser(&group.id)?,
                ),
            ],
        )?;

        Ok(group)
    }

    fn get_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<Group>, RbacError> {
        self.load_group(realm_id, group_id)
    }

    fn update_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        req: &UpdateGroupRequest,
    ) -> Result<Group, RbacError> {
        let Some(mut group) = self.load_group(realm_id, group_id)? else {
            return Err(RbacError::GroupNotFound);
        };

        let mut reslug: Option<(Vec<u8>, Vec<u8>)> = None;
        if let Some(new_slug) = &req.slug {
            Self::validate_group_slug(new_slug)?;
            if new_slug != &group.slug {
                if self.load_group_id_by_slug(realm_id, new_slug)?.is_some() {
                    return Err(RbacError::DuplicateGroupSlug);
                }
                reslug = Some((
                    keys::encode_group_slug(realm_id, &group.slug),
                    keys::encode_group_slug(realm_id, new_slug),
                ));
                group.slug.clone_from(new_slug);
            }
        }

        if let Some(name) = &req.name {
            group.name.clone_from(name);
        }
        if let Some(desc) = &req.description {
            group.description.clone_from(desc);
        }
        group.updated_at = self.clock.now();

        let mut writes: Vec<(Vec<u8>, Vec<u8>)> =
            vec![(keys::encode_group(&group.id), Self::ser(&group)?)];
        if let Some((_, new)) = &reslug {
            writes.push((new.clone(), Self::ser(&group.id)?));
        }
        self.storage.put_batch(realm_id, &writes)?;

        if let Some((old, _)) = reslug {
            self.storage.delete(realm_id, &old)?;
        }

        Ok(group)
    }

    fn delete_group(&self, realm_id: &RealmId, group_id: &GroupId) -> Result<(), RbacError> {
        let Some(group) = self.load_group(realm_id, group_id)? else {
            return Err(RbacError::GroupNotFound);
        };

        // Cascade: remove forward + reverse memberships and group-scoped assignments.
        let fwd_prefix = keys::gm_forward_scan_prefix(group_id);
        let fwd_end = keys::prefix_end(&fwd_prefix);
        for e in self.storage.scan(realm_id, &fwd_prefix, &fwd_end)? {
            let member: GroupMember = Self::de(&e.value)?;
            self.storage.delete(realm_id, &e.key)?;
            self.storage
                .delete(realm_id, &keys::encode_gm_reverse(&member, group_id))?;
        }

        // Also walk the reverse index keyed as this group-as-member, so we
        // remove its edges out of any parent group.
        let rev_prefix = keys::gm_reverse_scan_prefix(&GroupMember::Group(group_id.clone()));
        let rev_end = keys::prefix_end(&rev_prefix);
        for e in self.storage.scan(realm_id, &rev_prefix, &rev_end)? {
            let parent_group: GroupId = Self::de(&e.value)?;
            self.storage.delete(realm_id, &e.key)?;
            self.storage.delete(
                realm_id,
                &keys::encode_gm_forward(&parent_group, &GroupMember::Group(group_id.clone())),
            )?;
        }

        // Remove all role assignments bound to this group.
        let asgn_prefix = keys::assign_group_scan_prefix(group_id);
        let asgn_end = keys::prefix_end(&asgn_prefix);
        for e in self.storage.scan(realm_id, &asgn_prefix, &asgn_end)? {
            let aid: AssignmentId = Self::de(&e.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                self.storage
                    .delete(realm_id, &keys::encode_assignment(&aid))?;
                self.storage
                    .delete(realm_id, &keys::encode_assign_role(&a.role_id, &aid))?;
            }
            self.storage.delete(realm_id, &e.key)?;
        }

        self.storage
            .delete(realm_id, &keys::encode_group(group_id))?;
        self.storage
            .delete(realm_id, &keys::encode_group_slug(realm_id, &group.slug))?;
        Ok(())
    }

    fn list_groups(
        &self,
        realm_id: &RealmId,
        _cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Group>, RbacError> {
        let prefix = keys::group_slug_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;

        let mut items = Vec::new();
        for entry in entries {
            if items.len() >= limit {
                break;
            }
            let gid: GroupId = Self::de(&entry.value)?;
            if let Some(g) = self.load_group(realm_id, &gid)? {
                items.push(g);
            }
        }
        Ok(Page {
            items,
            next_cursor: None,
        })
    }

    fn add_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<GroupMembership, RbacError> {
        if self.load_group(realm_id, group_id)?.is_none() {
            return Err(RbacError::GroupNotFound);
        }
        // If member is a group, verify it exists.
        if let GroupMember::Group(g) = member {
            if self.load_group(realm_id, g)?.is_none() {
                return Err(RbacError::GroupNotFound);
            }
        }

        self.check_group_no_cycle(realm_id, group_id, member)?;

        let now = self.clock.now();
        let membership = GroupMembership {
            group_id: group_id.clone(),
            member: member.clone(),
            added_at: now,
            added_by: None,
        };

        // Forward value holds the GroupMember (for cycle scans).
        // Reverse value holds the GroupId (so user → parent groups list is cheap).
        self.storage.put_batch(
            realm_id,
            &[
                (
                    keys::encode_gm_forward(group_id, member),
                    Self::ser(member)?,
                ),
                (
                    keys::encode_gm_reverse(member, group_id),
                    Self::ser(group_id)?,
                ),
            ],
        )?;

        Ok(membership)
    }

    fn remove_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<(), RbacError> {
        self.storage
            .delete(realm_id, &keys::encode_gm_forward(group_id, member))?;
        self.storage
            .delete(realm_id, &keys::encode_gm_reverse(member, group_id))?;
        Ok(())
    }

    fn list_group_members(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        _cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<GroupMember>, RbacError> {
        let prefix = keys::gm_forward_scan_prefix(group_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;

        let mut items = Vec::new();
        for entry in entries {
            if items.len() >= limit {
                break;
            }
            let m: GroupMember = Self::de(&entry.value)?;
            items.push(m);
        }
        Ok(Page {
            items,
            next_cursor: None,
        })
    }

    // ---------- Assignments ----------

    fn assign_role(
        &self,
        realm_id: &RealmId,
        req: &AssignRoleRequest,
    ) -> Result<RoleAssignment, RbacError> {
        if self.load_role(realm_id, &req.role_id)?.is_none() {
            return Err(RbacError::RoleNotFound);
        }
        // Subject existence: user existence is the identity layer's concern;
        // here we just verify group subject exists if that's what was named.
        if let Subject::Group(g) = &req.subject {
            if self.load_group(realm_id, g)?.is_none() {
                return Err(RbacError::GroupNotFound);
            }
        }

        let now = self.clock.now();
        let id = AssignmentId::generate();
        let assignment = RoleAssignment {
            id: id.clone(),
            realm_id: realm_id.clone(),
            subject: req.subject.clone(),
            role_id: req.role_id.clone(),
            scope: req.scope.clone(),
            assigned_at: now,
            assigned_by: req.assigned_by.clone(),
        };

        let pri = keys::encode_assignment(&id);
        let subject_idx = match &assignment.subject {
            Subject::User(u) => keys::encode_assign_user(u, &id),
            Subject::Group(g) => keys::encode_assign_group(g, &id),
        };
        let role_idx = keys::encode_assign_role(&assignment.role_id, &id);

        self.storage.put_batch(
            realm_id,
            &[
                (pri, Self::ser(&assignment)?),
                (subject_idx, Self::ser(&id)?),
                (role_idx, Self::ser(&id)?),
            ],
        )?;

        Ok(assignment)
    }

    fn unassign_role(
        &self,
        realm_id: &RealmId,
        assignment_id: &AssignmentId,
    ) -> Result<(), RbacError> {
        let Some(a) = self.load_assignment(realm_id, assignment_id)? else {
            return Err(RbacError::AssignmentNotFound);
        };

        self.storage
            .delete(realm_id, &keys::encode_assignment(assignment_id))?;
        let subject_idx = match &a.subject {
            Subject::User(u) => keys::encode_assign_user(u, assignment_id),
            Subject::Group(g) => keys::encode_assign_group(g, assignment_id),
        };
        self.storage.delete(realm_id, &subject_idx)?;
        self.storage.delete(
            realm_id,
            &keys::encode_assign_role(&a.role_id, assignment_id),
        )?;
        Ok(())
    }

    fn list_user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_user_scan_prefix(user_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn list_group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        let prefix = keys::assign_group_scan_prefix(group_id);
        self.scan_assignments_by_prefix(realm_id, &prefix)
    }

    fn list_role_members(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        _cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<RoleSubject>, RbacError> {
        let prefix = keys::assign_role_scan_prefix(role_id);
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(realm_id, &prefix, &end)?;
        let mut items = Vec::new();
        for entry in entries {
            if items.len() >= limit {
                break;
            }
            let aid: AssignmentId = Self::de(&entry.value)?;
            if let Some(a) = self.load_assignment(realm_id, &aid)? {
                let subject = match a.subject {
                    Subject::User(u) => RoleSubject::User(u),
                    Subject::Group(g) => RoleSubject::Group(g),
                };
                items.push(subject);
            }
        }
        Ok(Page {
            items,
            next_cursor: None,
        })
    }

    // ---------- Bootstrap ----------

    fn seed_realm(&self, realm_id: &RealmId) -> Result<(), RbacError> {
        seed::seed_realm(&self.storage, &self.clock, realm_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn mk_engine() -> (EmbeddedRbacEngine, RealmId) {
        let tmp = tempfile::tempdir().expect("tmp");
        let storage = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf()))
                .expect("storage"),
        ) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1))) as Arc<dyn Clock>;
        std::mem::forget(tmp);
        (EmbeddedRbacEngine::new(storage, clock), RealmId::generate())
    }

    fn perm(s: &str) -> Permission {
        Permission::new(s).expect("valid perm")
    }

    #[test]
    fn create_and_get_role_roundtrip() {
        let (engine, realm) = mk_engine();
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "docs.viewer".to_string(),
                    description: Some("read docs".to_string()),
                    permissions: vec![perm("docs.view")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create");
        let fetched = RbacEngine::get_role(&engine, &realm, &role.id)
            .expect("get")
            .expect("some");
        assert_eq!(fetched.id, role.id);
        assert_eq!(fetched.name, "docs.viewer");

        let by_name = engine
            .get_role_by_name(&realm, "docs.viewer")
            .expect("get by name")
            .expect("some");
        assert_eq!(by_name.id, role.id);
    }

    #[test]
    fn duplicate_role_name_rejected() {
        let (engine, realm) = mk_engine();
        engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("first");
        let result = engine.create_role(
            &realm,
            &CreateRoleRequest {
                name: "r".to_string(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                ..Default::default()
            },
        );
        match result {
            Err(RbacError::DuplicateRoleName) => {}
            other => panic!("expected DuplicateRoleName, got {other:?}"),
        }
    }

    #[test]
    fn reserved_namespace_rejected_for_operator_role() {
        // Per AUTHZ_EXPANSION.md the global namespace is `system.*` —
        // operator-created roles may not include it directly.
        let (engine, realm) = mk_engine();
        let result = engine.create_role(
            &realm,
            &CreateRoleRequest {
                name: "evil".to_string(),
                description: None,
                permissions: vec![perm("system.admin")],
                parent_roles: vec![],
                ..Default::default()
            },
        );
        match result {
            Err(RbacError::ReservedNamespace { permission }) => {
                assert_eq!(permission, "system.admin");
            }
            other => panic!("expected ReservedNamespace, got {other:?}"),
        }
    }

    #[test]
    fn create_group_and_membership() {
        let (engine, realm) = mk_engine();
        let g = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "Engineering".to_string(),
                    slug: "eng".to_string(),
                    description: None,
                },
            )
            .expect("create group");
        let user = UserId::generate();
        engine
            .add_group_member(&realm, &g.id, &GroupMember::User(user.clone()))
            .expect("add member");

        let page = engine
            .list_group_members(&realm, &g.id, None, 100)
            .expect("list");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0], GroupMember::User(user));
    }

    #[test]
    fn duplicate_slug_rejected() {
        let (engine, realm) = mk_engine();
        engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "A".to_string(),
                    slug: "slug".to_string(),
                    description: None,
                },
            )
            .expect("first");
        let result = engine.create_group(
            &realm,
            &CreateGroupRequest {
                name: "B".to_string(),
                slug: "slug".to_string(),
                description: None,
            },
        );
        match result {
            Err(RbacError::DuplicateGroupSlug) => {}
            other => panic!("expected DuplicateGroupSlug, got {other:?}"),
        }
    }

    #[test]
    fn group_cycle_rejected_at_write_time() {
        let (engine, realm) = mk_engine();
        let a = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "A".to_string(),
                    slug: "a".to_string(),
                    description: None,
                },
            )
            .expect("a");
        let b = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "B".to_string(),
                    slug: "b".to_string(),
                    description: None,
                },
            )
            .expect("b");
        // A contains B.
        engine
            .add_group_member(&realm, &a.id, &GroupMember::Group(b.id.clone()))
            .expect("add b to a");
        // Adding A to B would create a cycle.
        let result = engine.add_group_member(&realm, &b.id, &GroupMember::Group(a.id.clone()));
        match result {
            Err(RbacError::CycleDetected {
                kind: CycleKind::GroupMembership,
                ..
            }) => {}
            other => panic!("expected group cycle, got {other:?}"),
        }
    }

    #[test]
    fn role_parent_cycle_rejected_at_update_time() {
        let (engine, realm) = mk_engine();
        let a = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "a".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("a");
        let b = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "b".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![a.id.clone()],
                    ..Default::default()
                },
            )
            .expect("b with parent a");
        // Now attempt to make A a child of B → cycle.
        let result = engine.update_role(
            &realm,
            &a.id,
            &UpdateRoleRequest {
                parent_roles: Some(vec![b.id.clone()]),
                ..UpdateRoleRequest::default()
            },
        );
        match result {
            Err(RbacError::CycleDetected {
                kind: CycleKind::RoleComposition,
                ..
            }) => {}
            other => panic!("expected role cycle, got {other:?}"),
        }
    }

    #[test]
    fn assign_and_unassign_role_to_user() {
        let (engine, realm) = mk_engine();
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![perm("docs.view")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        let user = UserId::generate();
        let a = engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let list = engine.list_user_assignments(&realm, &user).expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, a.id);

        engine.unassign_role(&realm, &a.id).expect("unassign");
        let list = engine.list_user_assignments(&realm, &user).expect("list");
        assert!(list.is_empty());
    }

    #[test]
    fn resolve_permissions_through_engine_returns_union() {
        let (engine, realm) = mk_engine();
        let r1 = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r1".to_string(),
                    description: None,
                    permissions: vec![perm("docs.view"), perm("docs.edit")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r1");
        let user = UserId::generate();
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: r1.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let resolved = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"docs.view"));
        assert!(names.contains(&"docs.edit"));
        assert_eq!(resolved.permissions.len(), 2);
    }

    #[test]
    fn resolve_is_realm_isolated() {
        let (engine, realm_a) = mk_engine();
        let realm_b = RealmId::generate();
        let r_a = engine
            .create_role(
                &realm_a,
                &CreateRoleRequest {
                    name: "only_in_a".to_string(),
                    description: None,
                    permissions: vec![perm("a.only")],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        let user = UserId::generate();
        engine
            .assign_role(
                &realm_a,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: r_a.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        // Resolve in OTHER realm — must be empty.
        let resolved = engine
            .resolve_permissions(&user, &realm_b, None, None)
            .expect("resolve b");
        assert!(resolved.permissions.is_empty());
        assert!(resolved.roles.is_empty());
    }

    #[test]
    fn seed_realm_runs_and_is_idempotent() {
        let (engine, realm) = mk_engine();
        engine.seed_realm(&realm).expect("seed 1");
        let first = engine
            .get_role_by_name(&realm, "realm.admin")
            .expect("get")
            .expect("some");
        engine.seed_realm(&realm).expect("seed 2");
        let second = engine
            .get_role_by_name(&realm, "realm.admin")
            .expect("get")
            .expect("some");
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn seeded_realm_admin_resolves_with_hearth_admin() {
        let (engine, realm) = mk_engine();
        engine.seed_realm(&realm).expect("seed");
        let role = engine
            .get_role_by_name(&realm, "realm.admin")
            .expect("get")
            .expect("some");

        let user = UserId::generate();
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let resolved = engine
            .resolve_permissions(&user, &realm, None, None)
            .expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"hearth.admin"));
        assert!(names.contains(&"realm.admin"));
    }

    #[test]
    fn list_role_members_returns_assigned_subjects() {
        let (engine, realm) = mk_engine();
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        let user = UserId::generate();
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");

        let page = engine
            .list_role_members(&realm, &role.id, None, 100)
            .expect("list");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0], RoleSubject::User(user));
    }

    #[test]
    fn delete_role_removes_name_index() {
        let (engine, realm) = mk_engine();
        let r = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "tmp".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        RbacEngine::delete_role(&engine, &realm, &r.id).expect("delete");
        assert!(RbacEngine::get_role(&engine, &realm, &r.id)
            .expect("get")
            .is_none());
        assert!(RbacEngine::get_role_by_name(&engine, &realm, "tmp")
            .expect("get by name")
            .is_none());
    }

    #[test]
    fn delete_group_cascades_members_and_assignments() {
        let (engine, realm) = mk_engine();
        let g = engine
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: "G".to_string(),
                    slug: "g".to_string(),
                    description: None,
                },
            )
            .expect("g");
        let user = UserId::generate();
        engine
            .add_group_member(&realm, &g.id, &GroupMember::User(user))
            .expect("add");
        let role = engine
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "r".to_string(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("r");
        engine
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::Group(g.id.clone()),
                    role_id: role.id.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign to group");

        engine.delete_group(&realm, &g.id).expect("delete");
        assert!(engine.get_group(&realm, &g.id).expect("get").is_none());
        assert!(engine
            .list_group_members(&realm, &g.id, None, 100)
            .expect("list")
            .items
            .is_empty());
        assert!(engine
            .list_group_assignments(&realm, &g.id)
            .expect("list asgn")
            .is_empty());
    }
}
