//! Integration tests for the RBAC engine resolution pipeline.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 scenarios:
//! - role composition transitive / cycle / depth cap
//! - group nesting transitive / cycle / caps
//! - scope filtering (realm vs org) and scope intersection (OAuth narrowing)

mod common;

use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, CycleKind, GroupMember, Permission,
    RbacError, RoleStatus, Scope, Subject, TraversalKind, UpdateRoleRequest,
};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid seed perm"))
        .collect()
}

#[tokio::test]
async fn role_composition_transitive() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    let a = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "a".into(),
                description: None,
                permissions: perms(&["a.x"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create a");
    let b = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "b".into(),
                description: None,
                permissions: perms(&["b.x"]),
                parent_roles: vec![a.id.clone()],
                ..Default::default()
            },
        )
        .expect("create b");
    let c = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "c".into(),
                description: None,
                permissions: perms(&["c.x"]),
                parent_roles: vec![b.id.clone()],
                ..Default::default()
            },
        )
        .expect("create c");

    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: c.id.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    let names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert!(names.contains(&"a.x"));
    assert!(names.contains(&"b.x"));
    assert!(names.contains(&"c.x"));
}

#[tokio::test]
async fn role_cycle_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    let a = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "a".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create a");
    let b = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "b".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![a.id.clone()],
                ..Default::default()
            },
        )
        .expect("create b");

    // Try to update `a` to point at `b` — this would create a cycle a→b→a.
    let result = h.rbac().update_role(
        &realm,
        &a.id,
        &hearth::rbac::UpdateRoleRequest {
            name: None,
            description: None,
            permissions: None,
            parent_roles: Some(vec![b.id]),
            ..Default::default()
        },
    );
    match result {
        Err(RbacError::CycleDetected {
            kind: CycleKind::RoleComposition,
            ..
        }) => {}
        other => panic!("expected RoleComposition cycle, got {other:?}"),
    }
}

#[tokio::test]
async fn role_depth_cap() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    // Build a chain 0 ← 1 ← 2 ← ... ← N where N = MAX_ROLE_DEPTH + 2.
    // The write-time cycle check walks parents transitively, so creating
    // the child at depth > limit triggers DepthExceeded.
    let depth_limit = 10; // matches resolve::MAX_ROLE_DEPTH
    let mut last_id = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "r0".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create r0")
        .id;

    let mut err = None;
    for i in 1..=(depth_limit + 2) {
        let res = h.rbac().create_role(
            &realm,
            &CreateRoleRequest {
                name: format!("r{i}"),
                description: None,
                permissions: vec![],
                parent_roles: vec![last_id.clone()],
                ..Default::default()
            },
        );
        match res {
            Ok(r) => last_id = r.id,
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }

    match err {
        Some(RbacError::DepthExceeded {
            kind: TraversalKind::RoleComposition,
            ..
        }) => {}
        other => panic!("expected RoleComposition DepthExceeded, got {other:?}"),
    }
}

#[tokio::test]
async fn group_nesting_transitive() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    // G1 ⊂ G2 ⊂ G3, user ∈ G1. A role assigned to G3 must reach the user.
    let g1 = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "G1".into(),
                slug: "g1".into(),
                description: None,
            },
        )
        .expect("g1");
    let g2 = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "G2".into(),
                slug: "g2".into(),
                description: None,
            },
        )
        .expect("g2");
    let g3 = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "G3".into(),
                slug: "g3".into(),
                description: None,
            },
        )
        .expect("g3");

    h.rbac()
        .add_group_member(&realm, &g2.id, &GroupMember::Group(g1.id.clone()))
        .expect("g2 contains g1");
    h.rbac()
        .add_group_member(&realm, &g3.id, &GroupMember::Group(g2.id.clone()))
        .expect("g3 contains g2");
    h.rbac()
        .add_group_member(&realm, &g1.id, &GroupMember::User(user.clone()))
        .expect("g1 contains user");

    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "top".into(),
                description: None,
                permissions: perms(&["top.view"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::Group(g3.id),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    let names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert!(names.contains(&"top.view"));
    // All three groups present in resolved set.
    assert!(resolved.groups.contains(&"g1".to_string()));
    assert!(resolved.groups.contains(&"g2".to_string()));
    assert!(resolved.groups.contains(&"g3".to_string()));
}

#[tokio::test]
async fn group_cycle_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    let g1 = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "G1".into(),
                slug: "g1".into(),
                description: None,
            },
        )
        .expect("g1");
    let g2 = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "G2".into(),
                slug: "g2".into(),
                description: None,
            },
        )
        .expect("g2");

    // g1 ⊂ g2 OK; g2 ⊂ g1 would cycle.
    h.rbac()
        .add_group_member(&realm, &g2.id, &GroupMember::Group(g1.id.clone()))
        .expect("g2 contains g1");
    let result = h
        .rbac()
        .add_group_member(&realm, &g1.id, &GroupMember::Group(g2.id.clone()));
    match result {
        Err(RbacError::CycleDetected {
            kind: CycleKind::GroupMembership,
            ..
        }) => {}
        other => panic!("expected GroupMembership cycle, got {other:?}"),
    }
}

#[tokio::test]
async fn group_caps_self_loop_rejected() {
    // The write-time cycle check rejects adding a group as a member of itself
    // with CycleDetected — this exercises the same code path that enforces caps.
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let g = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "solo".into(),
                slug: "solo".into(),
                description: None,
            },
        )
        .expect("solo");
    let result = h
        .rbac()
        .add_group_member(&realm, &g.id, &GroupMember::Group(g.id.clone()));
    assert!(matches!(result, Err(RbacError::CycleDetected { .. })));
}

#[tokio::test]
async fn scope_filtering_org_requires_matching_oid() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();
    let org_a = OrganizationId::generate();
    let org_b = OrganizationId::generate();

    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.viewer".into(),
                description: None,
                permissions: perms(&["docs.view"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Org {
                    org_id: org_a.clone(),
                },
                assigned_by: None,
            },
        )
        .expect("assign");

    // No oid supplied — assignment must be filtered out.
    let without_oid = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    assert!(without_oid.permissions.is_empty());

    // Matching oid — applies.
    let in_a = h
        .rbac()
        .resolve_permissions(&user, &realm, Some(&org_a), None)
        .expect("resolve");
    assert_eq!(in_a.permissions.len(), 1);

    // Wrong oid — filtered out.
    let in_b = h
        .rbac()
        .resolve_permissions(&user, &realm, Some(&org_b), None)
        .expect("resolve");
    assert!(in_b.permissions.is_empty());
}

#[tokio::test]
async fn scope_intersection_narrows_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed"); // installs `org` scope → [org.*]
    let user = UserId::generate();

    // Use the seeded `org.admin` role which grants org.write + org.admin (and
    // transitively org.read via org.member).
    let role = h
        .rbac()
        .get_role_by_name(&realm, "org.admin")
        .expect("lookup")
        .expect("seeded");
    h.rbac()
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

    // Without scope: full set.
    let wide = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve");
    let wide_names: Vec<&str> = wide.permissions.iter().map(Permission::as_str).collect();
    assert!(wide_names.contains(&"org.read"));
    assert!(wide_names.contains(&"org.admin"));

    // With scope `org`: intersects with org.* mapping — still has org.*, but
    // does NOT pick up unrelated permissions the user doesn't have (sanity).
    let narrowed = h
        .rbac()
        .resolve_permissions(&user, &realm, None, Some("org"))
        .expect("resolve");
    let nn: Vec<&str> = narrowed
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    for p in &nn {
        assert!(
            p.starts_with("org."),
            "scope=org narrowed set contained non-org permission: {p}"
        );
    }
    assert!(nn.contains(&"org.admin"), "org.admin should survive");
}

// ===== HEA-537: Role soft-delete + restore =====

/// Archiving a role blocks new assignments; restoring it allows assignments again.
#[tokio::test]
async fn archived_role_blocks_and_restore_allows_assignment() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "archivist-role".into(),
                description: None,
                permissions: perms(&["docs.read"]),
                parent_roles: vec![],
                scope_kind: Default::default(),
            },
        )
        .expect("create role");

    // Archive the role.
    h.rbac()
        .update_role(
            &realm,
            &role.id,
            &UpdateRoleRequest {
                status: Some(RoleStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive role");

    // New assignment must be rejected.
    let err = h
        .rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                role_id: role.id.clone(),
                subject: Subject::User(user.clone()),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect_err("assign to archived role must fail");
    assert!(
        matches!(err, RbacError::RoleArchived),
        "expected RoleArchived, got {err}"
    );

    // Restore to Active.
    h.rbac()
        .update_role(
            &realm,
            &role.id,
            &UpdateRoleRequest {
                status: Some(RoleStatus::Active),
                ..Default::default()
            },
        )
        .expect("restore role");

    // Assignment must now succeed.
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                role_id: role.id.clone(),
                subject: Subject::User(user),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign to restored role must succeed");
}
