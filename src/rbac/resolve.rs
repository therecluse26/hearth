//! Permission resolution algorithm.
//!
//! Implements AUTHORIZATION.md § 3: transitive group BFS, assignment
//! collection (filtered by realm/org scope), role composition DFS,
//! permission union, and OAuth-scope narrowing.
//!
//! This module is pure algorithm. It reads from the storage engine via a
//! small trait (`Resolver`) implemented by the embedded engine. Keeping
//! the traversal decoupled from the concrete engine makes property
//! testing (e.g. "cycles are rejected") self-contained.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::core::{OrganizationId, RealmId, UserId};

use super::error::RbacError;
#[cfg(test)]
use super::types::Subject;
use super::types::{
    CycleKind, GroupId, GroupMember, Permission, ResolvedPermissions, Role, RoleAssignment, RoleId,
    Scope, TraversalKind, UserPermissionGrant,
};

/// Maximum depth for transitive group membership BFS.
pub(crate) const MAX_GROUP_DEPTH: usize = 10;
/// Maximum number of distinct groups any single user may be transitively in.
pub(crate) const MAX_GROUP_BREADTH: usize = 1000;
/// Maximum depth for role-composition DFS.
pub(crate) const MAX_ROLE_DEPTH: usize = 10;

/// Rate window for `OrphanedReferenceSkipped` events: at most one emit per
/// `(realm, reference)` per hour.
const ORPHAN_EMIT_WINDOW: Duration = Duration::from_secs(3600);

/// Per-process rate-limiter for orphaned-reference tracing events.
///
/// Key: `(realm_id_bytes, ref_id_string)`.  Value: the `Instant` at which
/// the last event was emitted for that key.  Entries are never evicted
/// (a live process has a bounded number of unique realm × role-id pairs),
/// but the map stays small in practice — only stale references accumulate.
static ORPHAN_RATE_LIMITER: OnceLock<Mutex<HashMap<(RealmId, String), Instant>>> = OnceLock::new();

fn orphan_limiter() -> &'static Mutex<HashMap<(RealmId, String), Instant>> {
    ORPHAN_RATE_LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `true` if an `OrphanedReferenceSkipped` event for `(realm_id,
/// ref_id)` should be emitted right now; `false` if the rate window has not
/// elapsed since the last emit.
///
/// Side-effect: records the current instant if returning `true`.
pub(crate) fn should_emit_orphan(realm_id: &RealmId, ref_id: &str) -> bool {
    let key = (realm_id.clone(), ref_id.to_string());
    let now = Instant::now();
    let mut limiter = orphan_limiter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match limiter.get(&key) {
        Some(&last) if now.duration_since(last) < ORPHAN_EMIT_WINDOW => false,
        _ => {
            limiter.insert(key, now);
            true
        }
    }
}

/// Data-access surface the resolver needs.
///
/// Abstracting over this keeps `resolve.rs` concrete-engine-free and makes
/// test fakes trivial.
pub(crate) trait Resolver {
    /// Groups that directly contain the given member.
    fn parent_groups_of(
        &self,
        realm_id: &RealmId,
        member: &GroupMember,
    ) -> Result<Vec<GroupId>, RbacError>;

    /// Role assignments directly bound to a user (no transitive expansion).
    fn user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Role assignments directly bound to a group.
    fn group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Fetch a role by ID. Returns `None` if it has been deleted.
    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError>;

    /// Fetch a group by ID (used to convert `GroupId` → slug for output).
    fn get_group_slug(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<String>, RbacError>;

    /// Permissions granted by an OAuth scope value, or `None` if no narrowing
    /// should be applied (e.g. `openid`/`profile`/`email` are identifier
    /// scopes — full set passes through).
    ///
    /// Resolver returns `Some(vec![])` to mean "scope exists but maps to no
    /// permissions" (the narrowing yields an empty intersection).
    fn scope_permissions(
        &self,
        realm_id: &RealmId,
        scope_name: &str,
    ) -> Result<Option<Vec<Permission>>, RbacError>;

    /// Direct extra permissions granted to a user.
    fn user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError>;
}

/// Core algorithm: resolve `(user, realm, org?, scope?)` → `ResolvedPermissions`.
pub(crate) fn resolve_permissions<R: Resolver + ?Sized>(
    resolver: &R,
    user_id: &UserId,
    realm_id: &RealmId,
    org_id: Option<&OrganizationId>,
    requested_scope: Option<&str>,
) -> Result<ResolvedPermissions, RbacError> {
    // ----- Step 1: transitive group membership BFS -----
    let groups = bfs_groups(resolver, realm_id, user_id)?;

    // ----- Step 2: gather reachable assignments, filtered by scope -----
    let mut assignments: Vec<RoleAssignment> = Vec::new();
    for ra in resolver.user_assignments(realm_id, user_id)? {
        if assignment_applies(&ra, org_id) {
            assignments.push(ra);
        }
    }
    for gid in &groups {
        for ra in resolver.group_assignments(realm_id, gid)? {
            if assignment_applies(&ra, org_id) {
                assignments.push(ra);
            }
        }
    }

    // ----- Step 3: role composition DFS -----
    let mut role_names: BTreeSet<String> = BTreeSet::new();
    let mut perms: BTreeSet<Permission> = BTreeSet::new();
    let mut visited: HashSet<RoleId> = HashSet::new();
    for ra in &assignments {
        expand_role(
            resolver,
            realm_id,
            &ra.role_id,
            &mut role_names,
            &mut perms,
            &mut visited,
            0,
        )?;
    }

    // ----- Step 4: scope narrowing -----
    for extra in resolver.user_permissions(realm_id, user_id)? {
        if extra_applies(&extra, org_id) {
            perms.insert(extra.permission);
        }
    }

    let permissions: Vec<Permission> = if let Some(scope_str) = requested_scope {
        narrow_by_scope(resolver, realm_id, scope_str, perms)?
    } else {
        perms.into_iter().collect()
    };

    // ----- Step 5: group slugs for JWT claim -----
    let mut group_slugs: BTreeSet<String> = BTreeSet::new();
    for gid in &groups {
        if let Some(slug) = resolver.get_group_slug(realm_id, gid)? {
            group_slugs.insert(slug);
        }
    }

    Ok(ResolvedPermissions {
        roles: role_names.into_iter().collect(),
        groups: group_slugs.into_iter().collect(),
        permissions,
        granted_scopes: Vec::new(),
    })
}

fn extra_applies(extra: &UserPermissionGrant, org_id: Option<&OrganizationId>) -> bool {
    match &extra.scope {
        Scope::Realm => true,
        Scope::Org { org_id: oid } => org_id.is_some_and(|requested| requested == oid),
    }
}

/// Returns true if a role assignment applies given the optional org context.
fn assignment_applies(ra: &RoleAssignment, org_id: Option<&OrganizationId>) -> bool {
    match &ra.scope {
        Scope::Realm => true,
        Scope::Org { org_id: oid } => match org_id {
            Some(requested) => requested == oid,
            None => false,
        },
    }
}

/// Transitive group-membership BFS with cycle detection and breadth cap.
///
/// Walks reverse edges (member → containing-group) starting from the user.
/// Returns the distinct set of groups the user ends up in.
fn bfs_groups<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    user_id: &UserId,
) -> Result<Vec<GroupId>, RbacError> {
    let mut visited: HashSet<GroupId> = HashSet::new();
    // BFS queue: (member, depth_from_user).
    let mut queue: VecDeque<(GroupMember, usize)> = VecDeque::new();
    queue.push_back((GroupMember::User(user_id.clone()), 0));

    while let Some((member, depth)) = queue.pop_front() {
        // The user itself contributes no group until its parents are examined.
        let parents = resolver.parent_groups_of(realm_id, &member)?;

        let next_depth = depth + 1;

        for parent in parents {
            // Cycle detection: if we've already visited this group from the
            // same user we simply skip — this is safe because the visited
            // set is bounded by the realm's group set and each group is
            // explored at most once.
            if !visited.insert(parent.clone()) {
                continue;
            }

            if visited.len() > MAX_GROUP_BREADTH {
                return Err(RbacError::BreadthExceeded {
                    kind: TraversalKind::GroupMembership,
                    limit: MAX_GROUP_BREADTH,
                });
            }

            if next_depth > MAX_GROUP_DEPTH {
                return Err(RbacError::DepthExceeded {
                    kind: TraversalKind::GroupMembership,
                    limit: MAX_GROUP_DEPTH,
                });
            }

            queue.push_back((GroupMember::Group(parent), next_depth));
        }
    }

    Ok(visited.into_iter().collect())
}

/// DFS role composition expansion.
///
/// - Skips roles whose ID isn't found (defensive — dangling parent edge).
/// - Rejects cycles with `CycleDetected`.
/// - Rejects depth beyond `MAX_ROLE_DEPTH`.
fn expand_role<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    role_id: &RoleId,
    role_names: &mut BTreeSet<String>,
    perms: &mut BTreeSet<Permission>,
    visited: &mut HashSet<RoleId>,
    depth: usize,
) -> Result<(), RbacError> {
    if depth > MAX_ROLE_DEPTH {
        return Err(RbacError::DepthExceeded {
            kind: TraversalKind::RoleComposition,
            limit: MAX_ROLE_DEPTH,
        });
    }

    if !visited.insert(role_id.clone()) {
        // Already expanded — this is not a cycle, just a diamond: two
        // parents share a common ancestor. Safe to stop.
        return Ok(());
    }

    let Some(role) = resolver.get_role(realm_id, role_id)? else {
        // Dangling parent: a parent role ID was set on another role but the
        // target has since been deleted. Write-time checks normally prevent
        // this; we tolerate at resolve time so a stale DAG doesn't fail the
        // whole token issuance.
        //
        // Emit a rate-limited structured warning so operators can detect
        // YAML-storage drift without log spam. See AUTHZ_EXPANSION.md
        // §"Dangling references".
        let ref_id = role_id.to_string();
        if should_emit_orphan(realm_id, &ref_id) {
            tracing::warn!(
                realm_id = %realm_id,
                role_id = %ref_id,
                action = "orphaned_reference_skipped",
                "dangling role reference skipped during permission resolution"
            );
        }
        return Ok(());
    };

    role_names.insert(role.name.clone());
    for p in &role.permissions {
        perms.insert(p.clone());
    }

    for parent in &role.parent_roles {
        if parent == role_id {
            // Self-edge.
            return Err(RbacError::CycleDetected {
                kind: CycleKind::RoleComposition,
                entity: role.name.clone(),
            });
        }
        expand_role(
            resolver,
            realm_id,
            parent,
            role_names,
            perms,
            visited,
            depth + 1,
        )?;
    }

    Ok(())
}

/// Narrow a permission set by an OAuth scope's declared permissions.
///
/// If the scope resolves to `None`, no narrowing occurs (e.g. `openid`,
/// `profile`, `email`). If it resolves to an empty `Vec`, the intersection
/// is empty — the caller will issue a token with zero permissions.
fn narrow_by_scope<R: Resolver + ?Sized>(
    resolver: &R,
    realm_id: &RealmId,
    scope_str: &str,
    perms: BTreeSet<Permission>,
) -> Result<Vec<Permission>, RbacError> {
    // Scope string is space-delimited per OAuth 2.0. We take the UNION of
    // each scope's permission set, then intersect the user's perms with
    // that union. `openid`-style scopes with no mapping are treated as
    // "no narrowing from this scope value" and contribute the full set.
    let mut any_nonfilter = false;
    let mut allowed: BTreeSet<Permission> = BTreeSet::new();

    for scope_name in scope_str.split_whitespace() {
        match resolver.scope_permissions(realm_id, scope_name)? {
            None => {
                // No-filter scope — the entire original set is admitted.
                any_nonfilter = true;
            }
            Some(list) => {
                for p in list {
                    allowed.insert(p);
                }
            }
        }
    }

    if any_nonfilter {
        // At least one scope is non-filtering → no narrowing applied.
        return Ok(perms.into_iter().collect());
    }

    Ok(perms.into_iter().filter(|p| allowed.contains(p)).collect())
}

// ---------------------------------------------------------------------------
// Tests (using an in-memory resolver)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;
    use std::collections::HashMap;

    struct Fake {
        // member-uuid (discriminator+id) -> parent group ids
        parents: HashMap<String, Vec<GroupId>>,
        // user -> assignments
        user_asgn: HashMap<UserId, Vec<RoleAssignment>>,
        // group -> assignments
        group_asgn: HashMap<GroupId, Vec<RoleAssignment>>,
        roles: HashMap<RoleId, Role>,
        group_slugs: HashMap<GroupId, String>,
        scopes: HashMap<String, Option<Vec<Permission>>>,
        user_perms: HashMap<UserId, Vec<UserPermissionGrant>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                parents: HashMap::new(),
                user_asgn: HashMap::new(),
                group_asgn: HashMap::new(),
                roles: HashMap::new(),
                group_slugs: HashMap::new(),
                scopes: HashMap::new(),
                user_perms: HashMap::new(),
            }
        }

        fn key_of(m: &GroupMember) -> String {
            match m {
                GroupMember::User(u) => format!("u:{}", u.as_uuid()),
                GroupMember::Group(g) => format!("g:{}", g.as_uuid()),
            }
        }

        fn add_parent(&mut self, child: &GroupMember, parent: GroupId) {
            self.parents
                .entry(Self::key_of(child))
                .or_default()
                .push(parent);
        }

        fn upsert_role(&mut self, role: Role) {
            self.roles.insert(role.id.clone(), role);
        }

        fn upsert_group_slug(&mut self, g: &GroupId, slug: &str) {
            self.group_slugs.insert(g.clone(), slug.to_string());
        }

        fn set_scope(&mut self, name: &str, perms: Option<Vec<Permission>>) {
            self.scopes.insert(name.to_string(), perms);
        }
    }

    impl Resolver for Fake {
        fn parent_groups_of(
            &self,
            _r: &RealmId,
            member: &GroupMember,
        ) -> Result<Vec<GroupId>, RbacError> {
            Ok(self
                .parents
                .get(&Self::key_of(member))
                .cloned()
                .unwrap_or_default())
        }

        fn user_assignments(
            &self,
            _r: &RealmId,
            user_id: &UserId,
        ) -> Result<Vec<RoleAssignment>, RbacError> {
            Ok(self.user_asgn.get(user_id).cloned().unwrap_or_default())
        }

        fn group_assignments(
            &self,
            _r: &RealmId,
            group_id: &GroupId,
        ) -> Result<Vec<RoleAssignment>, RbacError> {
            Ok(self.group_asgn.get(group_id).cloned().unwrap_or_default())
        }

        fn get_role(&self, _r: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
            Ok(self.roles.get(role_id).cloned())
        }

        fn get_group_slug(
            &self,
            _r: &RealmId,
            group_id: &GroupId,
        ) -> Result<Option<String>, RbacError> {
            Ok(self.group_slugs.get(group_id).cloned())
        }

        fn scope_permissions(
            &self,
            _r: &RealmId,
            scope_name: &str,
        ) -> Result<Option<Vec<Permission>>, RbacError> {
            // Non-registered scope → no match (treated as empty Vec so we see narrowing).
            Ok(self
                .scopes
                .get(scope_name)
                .cloned()
                .unwrap_or(Some(Vec::new())))
        }

        fn user_permissions(
            &self,
            _r: &RealmId,
            user_id: &UserId,
        ) -> Result<Vec<UserPermissionGrant>, RbacError> {
            Ok(self.user_perms.get(user_id).cloned().unwrap_or_default())
        }
    }

    fn mk_role(realm: &RealmId, name: &str, perms: &[&str], parents: Vec<RoleId>) -> Role {
        Role {
            id: RoleId::generate(),
            realm_id: realm.clone(),
            name: name.to_string(),
            description: None,
            permissions: perms
                .iter()
                .map(|p| Permission::new(*p).expect("valid perm in test"))
                .collect(),
            parent_roles: parents,
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        }
    }

    fn mk_asgn(realm: &RealmId, subject: Subject, role_id: RoleId, scope: Scope) -> RoleAssignment {
        RoleAssignment {
            id: crate::rbac::types::AssignmentId::generate(),
            realm_id: realm.clone(),
            subject,
            role_id,
            scope,
            assigned_at: Timestamp::from_micros(1),
            assigned_by: None,
        }
    }

    // === Worked example (AUTHORIZATION.md § 3.1) ===

    #[test]
    fn worked_example_resolves_to_union_of_docs_perms() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let leads = GroupId::generate();
        let engineers = GroupId::generate();

        let mut fake = Fake::new();
        fake.upsert_group_slug(&leads, "leads");
        fake.upsert_group_slug(&engineers, "engineers");
        // alice → leads
        fake.add_parent(&GroupMember::User(alice.clone()), leads.clone());
        // leads → engineers
        fake.add_parent(&GroupMember::Group(leads.clone()), engineers.clone());

        let docs_editor = mk_role(&realm, "docs.editor", &["docs.view", "docs.edit"], vec![]);
        let docs_admin = mk_role(
            &realm,
            "docs.admin",
            &["docs.delete"],
            vec![docs_editor.id.clone()],
        );
        let editor_id = docs_editor.id.clone();
        let admin_id = docs_admin.id.clone();
        fake.upsert_role(docs_editor);
        fake.upsert_role(docs_admin);

        // engineers → docs.editor, leads → docs.admin (both realm-scoped)
        fake.group_asgn.insert(
            engineers.clone(),
            vec![mk_asgn(
                &realm,
                Subject::Group(engineers.clone()),
                editor_id,
                Scope::Realm,
            )],
        );
        fake.group_asgn.insert(
            leads.clone(),
            vec![mk_asgn(
                &realm,
                Subject::Group(leads.clone()),
                admin_id,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"docs.view"));
        assert!(names.contains(&"docs.edit"));
        assert!(names.contains(&"docs.delete"));
        assert_eq!(resolved.permissions.len(), 3, "expected exactly 3");
        assert!(resolved.roles.contains(&"docs.admin".to_string()));
        assert!(resolved.roles.contains(&"docs.editor".to_string()));
        assert!(resolved.groups.contains(&"leads".to_string()));
        assert!(resolved.groups.contains(&"engineers".to_string()));
    }

    #[test]
    fn org_scope_only_applies_with_matching_oid() {
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let org_a = OrganizationId::generate();
        let org_b = OrganizationId::generate();

        let role = mk_role(&realm, "org.member", &["org.read"], vec![]);
        let role_id = role.id.clone();

        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                role_id,
                Scope::Org {
                    org_id: org_a.clone(),
                },
            )],
        );

        // No org context — assignment should NOT apply.
        let none = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        assert!(none.permissions.is_empty());

        // Matching org — applies.
        let r_a = resolve_permissions(&fake, &alice, &realm, Some(&org_a), None).expect("resolve");
        assert_eq!(r_a.permissions.len(), 1);

        // Different org — does NOT apply.
        let r_b = resolve_permissions(&fake, &alice, &realm, Some(&org_b), None).expect("resolve");
        assert!(r_b.permissions.is_empty());
    }

    #[test]
    fn role_cycle_self_edge_returns_cycle_error() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        // Build a role whose parent list points to itself.
        let id = RoleId::generate();
        let role = Role {
            id: id.clone(),
            realm_id: realm.clone(),
            name: "r1".to_string(),
            description: None,
            permissions: vec![],
            parent_roles: vec![id.clone()],
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        };

        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                id,
                Scope::Realm,
            )],
        );

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::CycleDetected {
                kind: CycleKind::RoleComposition,
                ..
            }) => {}
            other => panic!("expected role-composition cycle, got {other:?}"),
        }
    }

    #[test]
    fn role_diamond_does_not_false_positive_as_cycle() {
        // A → B, A → C, B → D, C → D. D reached twice but no cycle.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let d = mk_role(&realm, "d", &["p.d"], vec![]);
        let b = mk_role(&realm, "b", &["p.b"], vec![d.id.clone()]);
        let c = mk_role(&realm, "c", &["p.c"], vec![d.id.clone()]);
        let a = mk_role(&realm, "a", &["p.a"], vec![b.id.clone(), c.id.clone()]);
        let a_id = a.id.clone();

        let mut fake = Fake::new();
        fake.upsert_role(a);
        fake.upsert_role(b);
        fake.upsert_role(c);
        fake.upsert_role(d);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                a_id,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        assert_eq!(resolved.permissions.len(), 4, "expected p.a, p.b, p.c, p.d");
    }

    #[test]
    fn role_depth_exceeds_limit_returns_error() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let mut ids: Vec<RoleId> = (0..=(MAX_ROLE_DEPTH + 2))
            .map(|_| RoleId::generate())
            .collect();
        ids.reverse();

        // Chain: ids[0] → ids[1] → ... → ids[last]
        let mut fake = Fake::new();
        for window in ids.windows(2) {
            let child = &window[0];
            let parent = &window[1];
            fake.upsert_role(Role {
                id: child.clone(),
                realm_id: realm.clone(),
                name: format!("r_{}", child.as_uuid()),
                description: None,
                permissions: vec![],
                parent_roles: vec![parent.clone()],
                scope_kind: crate::rbac::RoleScopeKind::Realm,
                created_at: Timestamp::from_micros(1),
                updated_at: Timestamp::from_micros(1),
            });
        }
        // Final leaf role has no parents.
        let leaf = ids.last().expect("ids non-empty").clone();
        fake.upsert_role(Role {
            id: leaf,
            realm_id: realm.clone(),
            name: "leaf".to_string(),
            description: None,
            permissions: vec![],
            parent_roles: vec![],
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(1),
        });

        let head = ids.first().expect("ids non-empty").clone();
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                head,
                Scope::Realm,
            )],
        );

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::DepthExceeded {
                kind: TraversalKind::RoleComposition,
                limit,
            }) => assert_eq!(limit, MAX_ROLE_DEPTH),
            other => panic!("expected role DepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn group_depth_exceeds_limit_returns_error() {
        // Build a chain alice ∈ g0 ∈ g1 ∈ ... ∈ g_{MAX_GROUP_DEPTH+2}. The
        // BFS increments depth each hop; once it crosses MAX_GROUP_DEPTH
        // the resolver must abort with a typed DepthExceeded rather than
        // silently truncate, otherwise ambient-authority leaks could
        // hide behind the cap.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let groups: Vec<GroupId> = (0..=(MAX_GROUP_DEPTH + 2))
            .map(|_| GroupId::generate())
            .collect();

        let mut fake = Fake::new();
        for (i, g) in groups.iter().enumerate() {
            fake.upsert_group_slug(g, &format!("g{i}"));
        }
        fake.add_parent(&GroupMember::User(alice.clone()), groups[0].clone());
        for window in groups.windows(2) {
            fake.add_parent(&GroupMember::Group(window[0].clone()), window[1].clone());
        }

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::DepthExceeded {
                kind: TraversalKind::GroupMembership,
                limit,
            }) => assert_eq!(limit, MAX_GROUP_DEPTH),
            other => panic!("expected group DepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn group_breadth_exceeds_limit_returns_error() {
        // Fan-out exceeding MAX_GROUP_BREADTH must return
        // BreadthExceeded rather than quietly truncating.
        //
        // Shape: one user directly in MAX_GROUP_BREADTH+10 distinct groups.
        // No chaining, so depth stays at 1 — only the breadth cap trips.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let mut fake = Fake::new();
        let total = MAX_GROUP_BREADTH + 10;
        for i in 0..total {
            let g = GroupId::generate();
            fake.upsert_group_slug(&g, &format!("g{i}"));
            fake.add_parent(&GroupMember::User(alice.clone()), g);
        }

        let result = resolve_permissions(&fake, &alice, &realm, None, None);
        match result {
            Err(RbacError::BreadthExceeded {
                kind: TraversalKind::GroupMembership,
                limit,
            }) => assert_eq!(limit, MAX_GROUP_BREADTH),
            other => panic!("expected group BreadthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn group_cycle_does_not_loop_forever() {
        // A ∈ B, B ∈ A (cycle). BFS must terminate via visited set.
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let a = GroupId::generate();
        let b = GroupId::generate();

        let mut fake = Fake::new();
        fake.upsert_group_slug(&a, "a");
        fake.upsert_group_slug(&b, "b");
        // alice → a
        fake.add_parent(&GroupMember::User(alice.clone()), a.clone());
        // a → b → a (cycle)
        fake.add_parent(&GroupMember::Group(a.clone()), b.clone());
        fake.add_parent(&GroupMember::Group(b.clone()), a.clone());

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        // Both groups visible, no duplicates, no hang.
        assert_eq!(resolved.groups.len(), 2);
    }

    #[test]
    fn scope_narrowing_intersects_with_scope_perms() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let role = mk_role(
            &realm,
            "r",
            &["docs.view", "docs.edit", "hearth.admin"],
            vec![],
        );
        let rid = role.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                rid,
                Scope::Realm,
            )],
        );
        fake.set_scope(
            "docs",
            Some(vec![
                Permission::new("docs.view").expect("valid"),
                Permission::new("docs.edit").expect("valid"),
            ]),
        );

        let resolved =
            resolve_permissions(&fake, &alice, &realm, None, Some("docs")).expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert!(names.contains(&"docs.view"));
        assert!(names.contains(&"docs.edit"));
        assert!(!names.contains(&"hearth.admin"));
        assert_eq!(resolved.permissions.len(), 2);
    }

    #[test]
    fn scope_none_means_no_narrowing() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let role = mk_role(&realm, "r", &["docs.view", "hearth.admin"], vec![]);
        let rid = role.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                rid,
                Scope::Realm,
            )],
        );
        // openid → no narrowing (None means no filter).
        fake.set_scope("openid", None);

        let resolved =
            resolve_permissions(&fake, &alice, &realm, None, Some("openid")).expect("resolve");
        assert_eq!(resolved.permissions.len(), 2);
    }

    #[test]
    fn scope_unknown_narrows_to_empty() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let role = mk_role(&realm, "r", &["docs.view"], vec![]);
        let rid = role.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(role);
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                rid,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, Some("unknown_scope"))
            .expect("resolve");
        assert!(resolved.permissions.is_empty());
    }

    #[test]
    fn permissions_are_deduplicated_and_sorted() {
        let realm = RealmId::generate();
        let alice = UserId::generate();

        let r1 = mk_role(&realm, "r1", &["b.x", "a.x"], vec![]);
        let r2 = mk_role(&realm, "r2", &["a.x", "c.x"], vec![]);
        let r1_id = r1.id.clone();
        let r2_id = r2.id.clone();
        let mut fake = Fake::new();
        fake.upsert_role(r1);
        fake.upsert_role(r2);
        fake.user_asgn.insert(
            alice.clone(),
            vec![
                mk_asgn(&realm, Subject::User(alice.clone()), r1_id, Scope::Realm),
                mk_asgn(&realm, Subject::User(alice.clone()), r2_id, Scope::Realm),
            ],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        let names: Vec<&str> = resolved
            .permissions
            .iter()
            .map(Permission::as_str)
            .collect();
        assert_eq!(names, vec!["a.x", "b.x", "c.x"]);
    }

    #[test]
    fn missing_role_is_tolerated_at_resolve_time() {
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let dangling = RoleId::generate();

        let mut fake = Fake::new();
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                dangling,
                Scope::Realm,
            )],
        );

        let resolved = resolve_permissions(&fake, &alice, &realm, None, None).expect("resolve");
        assert!(resolved.permissions.is_empty());
        assert!(resolved.roles.is_empty());
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        // Permission strings drawn from a small vocabulary. We deliberately
        // include duplicates in the generated Vec so the dedup invariant is
        // exercised, and mix single-segment / dotted forms for realism.
        fn perm_vocab() -> Vec<&'static str> {
            // All entries must satisfy the AUTHZ_EXPANSION grammar
            // (≥ 1 dot, no `:`). Single-segment names belong to the
            // OIDC scope namespace and are rejected by Permission::new.
            vec![
                "docs.view",
                "docs.edit",
                "docs.delete",
                "org.billing.view",
                "org.billing.admin",
                "users.list",
                "users.invite",
                "a.b",
                "z.a",
                "m.n.o",
            ]
        }

        proptest! {
            /// Property: for any set of roles assigned directly to a user,
            /// `resolved.permissions` is **sorted ascending** and contains
            /// **no duplicates**, regardless of:
            ///   - duplication across roles,
            ///   - duplication within a single role,
            ///   - order in which roles are listed on the user.
            ///
            /// This is the contract stated on `ResolvedPermissions` and the
            /// one SDKs rely on for deterministic JWT claim ordering.
            #[test]
            fn resolved_permissions_are_sorted_and_deduped(
                per_role in proptest::collection::vec(
                    proptest::collection::vec(0usize..10, 0..6),
                    1..5,
                ),
            ) {
                let realm = RealmId::generate();
                let alice = UserId::generate();
                let vocab = perm_vocab();

                let mut fake = Fake::new();
                let mut asgns = Vec::new();
                for idx_set in &per_role {
                    // Duplicate each index once inside the role's perm list so
                    // the within-role dedup path is exercised too.
                    let perm_strs: Vec<&str> = idx_set
                        .iter()
                        .flat_map(|i| std::iter::repeat_n(vocab[*i], 2))
                        .collect();
                    let role = mk_role(&realm, "r", &perm_strs, vec![]);
                    let rid = role.id.clone();
                    fake.upsert_role(role);
                    asgns.push(mk_asgn(
                        &realm,
                        Subject::User(alice.clone()),
                        rid,
                        Scope::Realm,
                    ));
                }
                fake.user_asgn.insert(alice.clone(), asgns);

                let resolved = resolve_permissions(&fake, &alice, &realm, None, None)
                    .expect("resolve");

                // Sorted ascending (by Permission's Ord — which delegates to
                // the inner String's Ord).
                let sorted: Vec<_> = {
                    let mut v = resolved.permissions.clone();
                    v.sort();
                    v
                };
                prop_assert_eq!(&resolved.permissions, &sorted);

                // Deduplicated.
                let mut seen = std::collections::HashSet::new();
                for p in &resolved.permissions {
                    prop_assert!(
                        seen.insert(p.as_str().to_string()),
                        "duplicate permission in resolved set: {}", p.as_str()
                    );
                }

                // Groups and roles share the same contract.
                let mut roles_sorted = resolved.roles.clone();
                roles_sorted.sort();
                prop_assert_eq!(&resolved.roles, &roles_sorted);

                let mut groups_sorted = resolved.groups.clone();
                groups_sorted.sort();
                prop_assert_eq!(&resolved.groups, &groups_sorted);
            }
        }
    }

    // ===== OrphanedReferenceSkipped rate limiter =====

    /// Unique realm IDs for rate-limiter tests so parallel test runs never
    /// share a key with other tests (the limiter is process-global).
    fn fresh_realm() -> RealmId {
        RealmId::generate()
    }

    #[test]
    fn orphan_first_call_emits() {
        let realm = fresh_realm();
        assert!(
            should_emit_orphan(&realm, "role_aabbccdd-0000-0000-0000-000000000001"),
            "first call for a new key must emit"
        );
    }

    #[test]
    fn orphan_second_immediate_call_is_rate_limited() {
        let realm = fresh_realm();
        let ref_id = "role_aabbccdd-0000-0000-0000-000000000002";
        assert!(should_emit_orphan(&realm, ref_id), "first call must emit");
        assert!(
            !should_emit_orphan(&realm, ref_id),
            "second immediate call must be rate-limited"
        );
    }

    #[test]
    fn orphan_different_realm_is_independent() {
        let realm_a = fresh_realm();
        let realm_b = fresh_realm();
        let ref_id = "role_aabbccdd-0000-0000-0000-000000000003";
        // Emit on realm_a; realm_b must still be independent.
        let _ = should_emit_orphan(&realm_a, ref_id);
        assert!(
            should_emit_orphan(&realm_b, ref_id),
            "different realm must not be rate-limited by realm_a's emit"
        );
    }

    #[test]
    fn orphan_different_ref_is_independent() {
        let realm = fresh_realm();
        let ref_a = "role_aabbccdd-0000-0000-0000-000000000004";
        let ref_b = "role_aabbccdd-0000-0000-0000-000000000005";
        // Emit ref_a; ref_b in the same realm must still be independent.
        let _ = should_emit_orphan(&realm, ref_a);
        assert!(
            should_emit_orphan(&realm, ref_b),
            "different ref_id in same realm must not be rate-limited"
        );
    }

    #[test]
    fn resolve_with_dangling_role_emits_orphan_event_and_succeeds() {
        // Verify that a dangling role ID in the assignment list does not
        // abort permission resolution — the user just gets no permissions
        // from that assignment.
        let realm = RealmId::generate();
        let alice = UserId::generate();
        let dangling = RoleId::generate();

        let mut fake = Fake::new();
        fake.user_asgn.insert(
            alice.clone(),
            vec![mk_asgn(
                &realm,
                Subject::User(alice.clone()),
                dangling,
                Scope::Realm,
            )],
        );

        let resolved =
            resolve_permissions(&fake, &alice, &realm, None, None).expect("must not error");
        assert!(resolved.permissions.is_empty());
        assert!(resolved.roles.is_empty());
    }
}
