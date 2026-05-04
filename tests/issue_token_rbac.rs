//! Integration tests for token issuance with RBAC claim population.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 scenarios:
//! - populates roles/groups/permissions claims at issue time
//! - size cap refuses issuance (currently unenforced — see comment)

mod common;

use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupMember, Permission, Scope,
    Subject,
};

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
}

#[tokio::test]
async fn populates_roles_groups_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Create a group and put the user in it.
    let group = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Engineers".into(),
                slug: "engineers".into(),
                description: None,
            },
        )
        .expect("group");
    h.rbac()
        .add_group_member(&realm, &group.id, &GroupMember::User(user.id().clone()))
        .expect("add member");

    // Role attached to the group.
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.editor".into(),
                description: None,
                permissions: perms(&["docs.view", "docs.edit"]),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::Group(group.id.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");

    // Issue a token via the public Identity API.
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue");

    let claims = h
        .identity()
        .validate_token(&realm, pair.access_token())
        .expect("validate");

    assert!(claims.roles.contains(&"docs.editor".to_string()));
    assert!(claims.groups.contains(&"engineers".to_string()));
    assert!(claims.permissions.contains(&"docs.view".to_string()));
    assert!(claims.permissions.contains(&"docs.edit".to_string()));
}

#[tokio::test]
async fn claims_empty_for_user_with_no_assignments() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue");
    let claims = h
        .identity()
        .validate_token(&realm, pair.access_token())
        .expect("validate");

    assert!(claims.roles.is_empty());
    assert!(claims.groups.is_empty());
    assert!(claims.permissions.is_empty());
}

// Size-cap enforcement in token issuance is not yet wired (see
// `src/identity/engine.rs::issue_tokens` — it resolves but does not call
// `RbacError::TokenSizeExceeded`). When enforcement lands, replace this
// scaffolding with a test that asserts issuance fails.
#[tokio::test]
#[ignore = "size cap enforcement pending — AUTHORIZATION.md § 5.4 / MIGRATE_TO_RBAC.md § 7"]
async fn size_cap_refuses_issuance() {
    // Placeholder: when implemented, assign 101+ permissions and assert
    // issue_tokens returns the documented TokenSizeExceeded / TokenTooLarge error.
}
