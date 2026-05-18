//! Integration test: first user created via onboarding receives the `realm.admin`
//! role and therefore the `hearth.admin` permission.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — onboarding_rbac:first_user_admin.
//! Exercises the RBAC side through the engine directly; the complete
//! onboarding HTTP/web flow is covered in `tests/onboarding.rs`.

mod common;

use hearth::identity::CreateUserRequest;
use hearth::rbac::{AssignRoleRequest, Permission, Scope, Subject};

#[tokio::test]
async fn first_user_gets_realm_admin_and_hearth_admin_permission() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    // Simulate onboarding: create a user and assign `realm.admin`.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "admin@example.com".into(),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");

    let resolved = h
        .rbac()
        .resolve_permissions(user.id(), &realm, None, None)
        .expect("resolve");
    let perms: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert!(
        perms.contains(&"hearth.admin"),
        "first user must carry hearth.admin permission"
    );
    assert!(resolved.roles.contains(&"realm.admin".to_string()));
}
