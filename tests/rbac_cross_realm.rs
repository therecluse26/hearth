//! Integration test: RBAC data in realm A is invisible to queries scoped
//! to realm B — both at the engine level and through the public API.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — rbac_cross_realm:no_leak.

mod common;

use hearth::core::{RealmId, UserId};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

#[tokio::test]
async fn assignment_in_realm_a_not_visible_in_realm_b() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let role = h
        .rbac()
        .create_role(
            &realm_a,
            &CreateRoleRequest {
                name: "docs".into(),
                description: None,
                permissions: vec![Permission::new("docs.view").expect("valid")],
                parent_roles: vec![],
            },
        )
        .expect("create");
    let role_id = role.id.clone();

    let user = UserId::generate();
    h.rbac()
        .assign_role(
            &realm_a,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role_id.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign in A");

    // Resolve in realm A: sees the permission.
    let in_a = h
        .rbac()
        .resolve_permissions(&user, &realm_a, None, None)
        .expect("resolve A");
    assert!(!in_a.permissions.is_empty());

    // Resolve in realm B: must see nothing.
    let in_b = h
        .rbac()
        .resolve_permissions(&user, &realm_b, None, None)
        .expect("resolve B");
    assert!(in_b.permissions.is_empty());
    assert!(in_b.roles.is_empty());
    assert!(in_b.groups.is_empty());
}

#[tokio::test]
async fn role_lookup_by_id_does_not_cross_realms() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let role = h
        .rbac()
        .create_role(
            &realm_a,
            &CreateRoleRequest {
                name: "foreign".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
            },
        )
        .expect("create");

    // Looking it up in realm B via its ID must return None.
    let result = h.rbac().get_role(&realm_b, &role.id).expect("get");
    assert!(result.is_none(), "role must not be visible across realms");
}
