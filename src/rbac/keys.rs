//! Storage key encoding for RBAC records.
//!
//! All keys use the `rba:` prefix and are realm-scoped — either by
//! embedding the realm ID directly or by indirection through a record
//! that itself carries a `RealmId`. See AUTHORIZATION.md § 4.1.

use crate::core::{OrganizationId, RealmId, UserId};

use super::types::{AssignmentId, GroupId, GroupMember, RoleId, Scope};

pub(crate) const ROLE_PREFIX: &str = "rba:role:";
pub(crate) const ROLE_NAME_PREFIX: &str = "rba:role:name:";
pub(crate) const GROUP_PREFIX: &str = "rba:group:";
pub(crate) const GROUP_SLUG_PREFIX: &str = "rba:group:slug:";
pub(crate) const ASSIGN_USER_PREFIX: &str = "rba:assign:user:";
pub(crate) const ASSIGN_GROUP_PREFIX: &str = "rba:assign:group:";
pub(crate) const ASSIGN_ROLE_PREFIX: &str = "rba:assign:role:";
pub(crate) const ASSIGN_PRI_PREFIX: &str = "rba:assign:pri:";
pub(crate) const GM_GROUP_PREFIX: &str = "rba:gm:group:";
pub(crate) const GM_MEMBER_PREFIX: &str = "rba:gm:member:";
pub(crate) const PERM_PREFIX: &str = "rba:perm:";
pub(crate) const SCOPE_PREFIX: &str = "rba:scope:";
pub(crate) const USER_PERM_PREFIX: &str = "rba:user_perm:";
pub(crate) const USER_PERM_BY_PERM_PREFIX: &str = "rba:user_perm:by_perm:";
pub(crate) const ORG_ROLE_PREFIX: &str = "rba:org_role:";

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// `rba:role:{role_id}`
pub(crate) fn encode_role(role_id: &RoleId) -> Vec<u8> {
    format!("{ROLE_PREFIX}{}", role_id.as_uuid()).into_bytes()
}

/// `rba:role:name:{realm_id}:{name}`
pub(crate) fn encode_role_name(realm_id: &RealmId, name: &str) -> Vec<u8> {
    format!("{ROLE_NAME_PREFIX}{}:{name}", realm_id.as_uuid()).into_bytes()
}

/// Scan prefix for all role-name entries in a realm.
pub(crate) fn role_name_scan_prefix(realm_id: &RealmId) -> Vec<u8> {
    format!("{ROLE_NAME_PREFIX}{}:", realm_id.as_uuid()).into_bytes()
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// `rba:group:{group_id}`
pub(crate) fn encode_group(group_id: &GroupId) -> Vec<u8> {
    format!("{GROUP_PREFIX}{}", group_id.as_uuid()).into_bytes()
}

/// `rba:group:slug:{realm_id}:{slug}`
pub(crate) fn encode_group_slug(realm_id: &RealmId, slug: &str) -> Vec<u8> {
    format!("{GROUP_SLUG_PREFIX}{}:{slug}", realm_id.as_uuid()).into_bytes()
}

/// Scan prefix for all group-slug entries in a realm.
pub(crate) fn group_slug_scan_prefix(realm_id: &RealmId) -> Vec<u8> {
    format!("{GROUP_SLUG_PREFIX}{}:", realm_id.as_uuid()).into_bytes()
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

/// `rba:assign:pri:{assignment_id}`
pub(crate) fn encode_assignment(id: &AssignmentId) -> Vec<u8> {
    format!("{ASSIGN_PRI_PREFIX}{}", id.as_uuid()).into_bytes()
}

/// `rba:assign:user:{user_id}:{assignment_id}`
pub(crate) fn encode_assign_user(user_id: &UserId, id: &AssignmentId) -> Vec<u8> {
    format!("{ASSIGN_USER_PREFIX}{}:{}", user_id.as_uuid(), id.as_uuid()).into_bytes()
}

/// Scan prefix for `rba:assign:user:{user_id}:`.
pub(crate) fn assign_user_scan_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{ASSIGN_USER_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// `rba:assign:group:{group_id}:{assignment_id}`
pub(crate) fn encode_assign_group(group_id: &GroupId, id: &AssignmentId) -> Vec<u8> {
    format!(
        "{ASSIGN_GROUP_PREFIX}{}:{}",
        group_id.as_uuid(),
        id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for `rba:assign:group:{group_id}:`.
pub(crate) fn assign_group_scan_prefix(group_id: &GroupId) -> Vec<u8> {
    format!("{ASSIGN_GROUP_PREFIX}{}:", group_id.as_uuid()).into_bytes()
}

/// `rba:assign:role:{role_id}:{assignment_id}`
pub(crate) fn encode_assign_role(role_id: &RoleId, id: &AssignmentId) -> Vec<u8> {
    format!("{ASSIGN_ROLE_PREFIX}{}:{}", role_id.as_uuid(), id.as_uuid()).into_bytes()
}

/// Scan prefix for `rba:assign:role:{role_id}:`.
pub(crate) fn assign_role_scan_prefix(role_id: &RoleId) -> Vec<u8> {
    format!("{ASSIGN_ROLE_PREFIX}{}:", role_id.as_uuid()).into_bytes()
}

// ---------------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------------

/// Encodes a member's type discriminator and stable ID for use in membership keys.
fn member_parts(member: &GroupMember) -> (&'static str, String) {
    match member {
        GroupMember::User(u) => ("user", u.as_uuid().to_string()),
        GroupMember::Group(g) => ("group", g.as_uuid().to_string()),
    }
}

/// `rba:gm:group:{group_id}:member:{member_type}:{member_id}` (forward index)
pub(crate) fn encode_gm_forward(group_id: &GroupId, member: &GroupMember) -> Vec<u8> {
    let (mtype, mid) = member_parts(member);
    format!(
        "{GM_GROUP_PREFIX}{}:member:{mtype}:{mid}",
        group_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix over a group's forward members.
pub(crate) fn gm_forward_scan_prefix(group_id: &GroupId) -> Vec<u8> {
    format!("{GM_GROUP_PREFIX}{}:member:", group_id.as_uuid()).into_bytes()
}

/// `rba:gm:member:{member_type}:{member_id}:group:{group_id}` (reverse index)
pub(crate) fn encode_gm_reverse(member: &GroupMember, group_id: &GroupId) -> Vec<u8> {
    let (mtype, mid) = member_parts(member);
    format!(
        "{GM_MEMBER_PREFIX}{mtype}:{mid}:group:{}",
        group_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix over all groups containing the given member (reverse index).
pub(crate) fn gm_reverse_scan_prefix(member: &GroupMember) -> Vec<u8> {
    let (mtype, mid) = member_parts(member);
    format!("{GM_MEMBER_PREFIX}{mtype}:{mid}:group:").into_bytes()
}

// ---------------------------------------------------------------------------
// Permission registry & scopes
// ---------------------------------------------------------------------------

/// `rba:perm:{realm_id}:{permission}`
pub(crate) fn encode_permission(realm_id: &RealmId, permission: &str) -> Vec<u8> {
    format!("{PERM_PREFIX}{}:{permission}", realm_id.as_uuid()).into_bytes()
}

/// Scan prefix for all registered permissions in a realm.
#[allow(dead_code)]
pub(crate) fn permission_scan_prefix(realm_id: &RealmId) -> Vec<u8> {
    format!("{PERM_PREFIX}{}:", realm_id.as_uuid()).into_bytes()
}

/// `rba:scope:{realm_id}:{scope_name}`
pub(crate) fn encode_scope(realm_id: &RealmId, scope_name: &str) -> Vec<u8> {
    format!("{SCOPE_PREFIX}{}:{scope_name}", realm_id.as_uuid()).into_bytes()
}

/// Scan prefix for all scopes in a realm.
#[allow(dead_code)]
pub(crate) fn scope_scan_prefix(realm_id: &RealmId) -> Vec<u8> {
    format!("{SCOPE_PREFIX}{}:", realm_id.as_uuid()).into_bytes()
}

// ---------------------------------------------------------------------------
// Resource-scoped scope bundles
// ---------------------------------------------------------------------------

pub(crate) const RESOURCE_SCOPE_PREFIX: &str = "rba:res_scope:";

/// `rba:res_scope:{realm_id}:{sha256_12hex}:{scope_name}`
pub(crate) fn encode_resource_scope(
    realm_id: &RealmId,
    uri_hash: &str,
    scope_name: &str,
) -> Vec<u8> {
    format!("{RESOURCE_SCOPE_PREFIX}{}:{uri_hash}:{scope_name}", realm_id.as_uuid())
        .into_bytes()
}

/// Scan prefix for all resource-scope entries under a given URI hash.
pub(crate) fn resource_scope_scan_prefix(realm_id: &RealmId, uri_hash: &str) -> Vec<u8> {
    format!("{RESOURCE_SCOPE_PREFIX}{}:{uri_hash}:", realm_id.as_uuid()).into_bytes()
}

fn scope_key(scope: &Scope) -> String {
    match scope {
        Scope::Realm => "_realm".to_string(),
        Scope::Org { org_id } => org_id.as_uuid().to_string(),
    }
}

/// `rba:user_perm:{realm}:{user}:{scope_key}:{perm}`
pub(crate) fn encode_user_permission(
    realm_id: &RealmId,
    user_id: &UserId,
    scope: &Scope,
    permission: &str,
) -> Vec<u8> {
    format!(
        "{USER_PERM_PREFIX}{}:{}:{}:{permission}",
        realm_id.as_uuid(),
        user_id.as_uuid(),
        scope_key(scope)
    )
    .into_bytes()
}

/// `rba:user_perm:by_perm:{realm}:{perm}:{scope_key}:{user}`
pub(crate) fn encode_user_permission_by_perm(
    realm_id: &RealmId,
    permission: &str,
    scope: &Scope,
    user_id: &UserId,
) -> Vec<u8> {
    format!(
        "{USER_PERM_BY_PERM_PREFIX}{}:{permission}:{}:{}",
        realm_id.as_uuid(),
        scope_key(scope),
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for all extra permissions granted to a user in a realm.
pub(crate) fn user_permission_scan_prefix(realm_id: &RealmId, user_id: &UserId) -> Vec<u8> {
    format!(
        "{USER_PERM_PREFIX}{}:{}:",
        realm_id.as_uuid(),
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for users holding an extra permission at a given scope.
pub(crate) fn user_permission_by_perm_scan_prefix(
    realm_id: &RealmId,
    permission: &str,
    scope: &Scope,
) -> Vec<u8> {
    format!(
        "{USER_PERM_BY_PERM_PREFIX}{}:{permission}:{}:",
        realm_id.as_uuid(),
        scope_key(scope)
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Org extra roles
// ---------------------------------------------------------------------------

/// `rba:org_role:{realm_id}:{org_id}:{user_id}:{role_name}`
pub(crate) fn encode_org_extra_role(
    realm_id: &RealmId,
    org_id: &OrganizationId,
    user_id: &UserId,
    role_name: &str,
) -> Vec<u8> {
    format!(
        "{ORG_ROLE_PREFIX}{}:{}:{}:{role_name}",
        realm_id.as_uuid(),
        org_id.as_uuid(),
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for all extra org roles for a user within a specific org.
pub(crate) fn org_extra_role_scan_prefix(
    realm_id: &RealmId,
    org_id: &OrganizationId,
    user_id: &UserId,
) -> Vec<u8> {
    format!(
        "{ORG_ROLE_PREFIX}{}:{}:{}:",
        realm_id.as_uuid(),
        org_id.as_uuid(),
        user_id.as_uuid()
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Computes the exclusive end bound for a prefix scan.
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> RealmId {
        RealmId::generate()
    }

    #[test]
    fn role_key_has_correct_prefix() {
        let id = RoleId::generate();
        let k = encode_role(&id);
        let s = std::str::from_utf8(&k).expect("utf8");
        assert!(s.starts_with("rba:role:"));
        assert!(s.contains(&id.as_uuid().to_string()));
    }

    #[test]
    fn role_name_key_embeds_realm() {
        let r = rid();
        let k = encode_role_name(&r, "docs.admin");
        let s = std::str::from_utf8(&k).expect("utf8");
        assert!(s.starts_with("rba:role:name:"));
        assert!(s.contains(&r.as_uuid().to_string()));
        assert!(s.ends_with(":docs.admin"));
    }

    #[test]
    fn role_name_scan_prefix_matches_encoded_keys() {
        let r = rid();
        let prefix = role_name_scan_prefix(&r);
        let k = encode_role_name(&r, "docs.admin");
        assert!(k.starts_with(&prefix));
    }

    #[test]
    fn role_name_scan_bounded_to_realm() {
        // Different realm must NOT fall within the scan prefix.
        let r1 = rid();
        let r2 = rid();
        let prefix = role_name_scan_prefix(&r1);
        let k_other = encode_role_name(&r2, "docs.admin");
        assert!(!k_other.starts_with(&prefix));
    }

    #[test]
    fn group_key_and_slug_index() {
        let r = rid();
        let g = GroupId::generate();
        let k = encode_group(&g);
        let s = std::str::from_utf8(&k).expect("utf8");
        assert!(s.starts_with("rba:group:"));
        assert!(
            !s.starts_with("rba:group:slug:"),
            "slug has a separate prefix"
        );

        let kslug = encode_group_slug(&r, "engineering");
        let sslug = std::str::from_utf8(&kslug).expect("utf8");
        assert!(sslug.starts_with("rba:group:slug:"));
        assert!(sslug.ends_with(":engineering"));
    }

    #[test]
    fn group_slug_scan_prefix_matches() {
        let r = rid();
        let k = encode_group_slug(&r, "engineers");
        assert!(k.starts_with(&group_slug_scan_prefix(&r)));
    }

    #[test]
    fn assignment_keys_distinct_by_index() {
        let aid = AssignmentId::generate();
        let uid = UserId::generate();
        let gid = GroupId::generate();
        let rid = RoleId::generate();

        let pri = encode_assignment(&aid);
        let au = encode_assign_user(&uid, &aid);
        let ag = encode_assign_group(&gid, &aid);
        let ar = encode_assign_role(&rid, &aid);

        for k in [&pri, &au, &ag, &ar] {
            let s = std::str::from_utf8(k).expect("utf8");
            assert!(s.starts_with("rba:assign:"));
        }
        // All four encode distinct keys for the same assignment ID.
        assert_ne!(pri, au);
        assert_ne!(au, ag);
        assert_ne!(ag, ar);
        assert_ne!(pri, ar);
    }

    #[test]
    fn assign_user_scan_prefix_matches() {
        let uid = UserId::generate();
        let aid = AssignmentId::generate();
        let k = encode_assign_user(&uid, &aid);
        assert!(k.starts_with(&assign_user_scan_prefix(&uid)));
    }

    #[test]
    fn assign_group_scan_prefix_matches() {
        let gid = GroupId::generate();
        let aid = AssignmentId::generate();
        let k = encode_assign_group(&gid, &aid);
        assert!(k.starts_with(&assign_group_scan_prefix(&gid)));
    }

    #[test]
    fn assign_role_scan_prefix_matches() {
        let rid = RoleId::generate();
        let aid = AssignmentId::generate();
        let k = encode_assign_role(&rid, &aid);
        assert!(k.starts_with(&assign_role_scan_prefix(&rid)));
    }

    #[test]
    fn group_membership_forward_and_reverse_match_scans() {
        let gid = GroupId::generate();
        let uid = UserId::generate();
        let member = GroupMember::User(uid);

        let fwd = encode_gm_forward(&gid, &member);
        assert!(fwd.starts_with(&gm_forward_scan_prefix(&gid)));

        let rev = encode_gm_reverse(&member, &gid);
        assert!(rev.starts_with(&gm_reverse_scan_prefix(&member)));

        // Forward and reverse are different keys.
        assert_ne!(fwd, rev);

        // User vs Group discriminator differs.
        let other_member = GroupMember::Group(GroupId::generate());
        let rev2 = encode_gm_reverse(&other_member, &gid);
        assert_ne!(rev, rev2);
    }

    #[test]
    fn group_membership_reverse_discriminator_embedded() {
        let gid = GroupId::generate();
        let uid = UserId::generate();

        let user_member = GroupMember::User(uid);
        let rev = encode_gm_reverse(&user_member, &gid);
        let s = std::str::from_utf8(&rev).expect("utf8");
        assert!(s.starts_with("rba:gm:member:user:"));
        assert!(s.contains(":group:"));
    }

    #[test]
    fn permission_registry_key_embeds_realm() {
        let r = rid();
        let k = encode_permission(&r, "docs.edit");
        let s = std::str::from_utf8(&k).expect("utf8");
        assert!(s.starts_with("rba:perm:"));
        assert!(s.contains(&r.as_uuid().to_string()));
        assert!(s.ends_with(":docs.edit"));
        assert!(k.starts_with(&permission_scan_prefix(&r)));
    }

    #[test]
    fn scope_key_embeds_realm() {
        let r = rid();
        let k = encode_scope(&r, "docs");
        let s = std::str::from_utf8(&k).expect("utf8");
        assert!(s.starts_with("rba:scope:"));
        assert!(s.ends_with(":docs"));
        assert!(k.starts_with(&scope_scan_prefix(&r)));
    }

    #[test]
    fn prefix_end_is_strictly_greater() {
        let p = b"abc".to_vec();
        let e = prefix_end(&p);
        assert!(e > p);
    }

    #[test]
    fn keys_roundtrip_contain_entity_uuid() {
        // Primary role key contains UUID substring, useful as a very-loose
        // round-trip check without a parser.
        let rid = RoleId::generate();
        let k = encode_role(&rid);
        let s = std::str::from_utf8(&k).expect("utf8");
        assert!(s.contains(&rid.as_uuid().to_string()));
    }
}
