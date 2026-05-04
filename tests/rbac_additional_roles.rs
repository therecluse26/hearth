//! Integration tests for additional org-scoped roles on RBAC engine.
//!
//! Covers `add_additional_role`, `remove_additional_role`, and
//! `list_additional_roles` on `RbacEngine`, plus their interaction with
//! `resolve_permissions`.

mod common;

use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, RbacError, Scope, Subject};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a role with the given name and permissions in the realm.
fn make_role(
    h: &common::TestHarness,
    realm: &RealmId,
    name: &str,
    perm_names: &[&str],
) -> hearth::rbac::Role {
    h.rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: name.to_string(),
                description: None,
                permissions: perms(perm_names),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_additional_role_stores_role() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    make_role(&h, &realm, "editor", &["docs.read"]);

    h.rbac()
        .add_additional_role(&realm, &org, &user, "editor", None)
        .expect("add_additional_role");

    let roles = h
        .rbac()
        .list_additional_roles(&realm, &org, &user)
        .expect("list_additional_roles");
    assert_eq!(roles, vec!["editor".to_string()]);
}

#[tokio::test]
async fn remove_additional_role_removes_it() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    make_role(&h, &realm, "editor", &["docs.read"]);

    h.rbac()
        .add_additional_role(&realm, &org, &user, "editor", None)
        .expect("add");

    h.rbac()
        .remove_additional_role(&realm, &org, &user, "editor")
        .expect("remove");

    let roles = h
        .rbac()
        .list_additional_roles(&realm, &org, &user)
        .expect("list");
    assert!(roles.is_empty(), "list must be empty after remove");
}

#[tokio::test]
async fn list_additional_roles_empty_for_new_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    let roles = h
        .rbac()
        .list_additional_roles(&realm, &org, &user)
        .expect("list");
    assert!(roles.is_empty(), "new user should have no additional roles");
}

#[tokio::test]
async fn add_additional_role_nonexistent_role_fails() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    // "ghost" role does not exist in this realm.
    let result = h
        .rbac()
        .add_additional_role(&realm, &org, &user, "ghost", None);
    assert!(
        matches!(result, Err(RbacError::RoleNotFound)),
        "expected RoleNotFound, got {result:?}"
    );
}

#[tokio::test]
async fn additional_roles_included_in_resolve_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    // Create an org-scoped role and assign it to the user as an additional role.
    make_role(&h, &realm, "org.editor", &["docs.write"]);

    h.rbac()
        .add_additional_role(&realm, &org, &user, "org.editor", None)
        .expect("add");

    // Also verify there's no realm-level assignment — permissions come purely
    // from the additional role.
    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, Some(&org), None)
        .expect("resolve");

    let perm_names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert!(
        perm_names.contains(&"docs.write"),
        "docs.write from additional role must appear in resolved permissions; got {perm_names:?}"
    );
}

#[tokio::test]
async fn additional_roles_scoped_to_org() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org_a = OrganizationId::generate();
    let org_b = OrganizationId::generate();
    let user = UserId::generate();

    make_role(&h, &realm, "billing", &["billing.read"]);

    // Add the role only to org_a.
    h.rbac()
        .add_additional_role(&realm, &org_a, &user, "billing", None)
        .expect("add to org_a");

    // Verify it appears for org_a...
    let in_a = h
        .rbac()
        .list_additional_roles(&realm, &org_a, &user)
        .expect("list org_a");
    assert_eq!(in_a, vec!["billing".to_string()]);

    // ...but not for org_b.
    let in_b = h
        .rbac()
        .list_additional_roles(&realm, &org_b, &user)
        .expect("list org_b");
    assert!(
        in_b.is_empty(),
        "additional role must not bleed across orgs; org_b had: {in_b:?}"
    );
}

#[tokio::test]
async fn additional_roles_do_not_appear_without_org_context() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    make_role(&h, &realm, "support", &["tickets.view"]);

    h.rbac()
        .add_additional_role(&realm, &org, &user, "support", None)
        .expect("add");

    // Without passing an org_id, the additional role must not surface.
    let without_org = h
        .rbac()
        .resolve_permissions(&user, &realm, None, None)
        .expect("resolve without org");

    // Baseline: no realm-level assignments, so resolved permissions must be empty.
    assert!(
        without_org.permissions.is_empty(),
        "additional org role must not appear without org context; got {:?}",
        without_org.permissions
    );
}

#[tokio::test]
async fn add_multiple_additional_roles_all_listed() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    make_role(&h, &realm, "reader", &["docs.read"]);
    make_role(&h, &realm, "writer", &["docs.write"]);

    h.rbac()
        .add_additional_role(&realm, &org, &user, "reader", None)
        .expect("add reader");
    h.rbac()
        .add_additional_role(&realm, &org, &user, "writer", None)
        .expect("add writer");

    let mut roles = h
        .rbac()
        .list_additional_roles(&realm, &org, &user)
        .expect("list");
    roles.sort();
    assert_eq!(roles, vec!["reader".to_string(), "writer".to_string()]);
}

#[tokio::test]
async fn realm_level_and_additional_org_role_permissions_unioned() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let org = OrganizationId::generate();
    let user = UserId::generate();

    // Realm-level role.
    let base = make_role(&h, &realm, "base", &["base.read"]);
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: base.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign base");

    // Additional org-scoped role.
    make_role(&h, &realm, "org.editor", &["org.write"]);
    h.rbac()
        .add_additional_role(&realm, &org, &user, "org.editor", None)
        .expect("add org.editor");

    let resolved = h
        .rbac()
        .resolve_permissions(&user, &realm, Some(&org), None)
        .expect("resolve");

    let perm_names: Vec<&str> = resolved
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert!(
        perm_names.contains(&"base.read"),
        "realm-level perm must be present"
    );
    assert!(
        perm_names.contains(&"org.write"),
        "org additional role perm must be present"
    );
}
