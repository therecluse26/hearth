//! Integration tests for token issuance with RBAC claim population.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 scenarios:
//! - populates roles/groups/permissions claims at issue time
//! - size cap refuses issuance (currently unenforced — see comment)

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateUserRequest, IdentityError,
    RegisterClientRequest, SessionContext, TokenExchangeRequest,
};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupMember, Permission, Scope,
    Subject,
};

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}
const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
}

#[tokio::test]
async fn populates_roles_groups_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
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
    let realm = h.create_realm();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
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

#[tokio::test]
async fn permissions_cap_refuses_issuance() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let many_perms: Vec<Permission> = (0..101)
        .map(|i| Permission::new(format!("perm.{i:03}")).expect("valid perm"))
        .collect();
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "big.role".into(),
                description: None,
                permissions: many_perms,
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
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

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let err = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect_err("should fail");

    match err {
        IdentityError::TokenTooLarge {
            limit,
            limit_value,
            actual,
        } => {
            assert_eq!(limit, "access_token_permissions_per_token");
            assert_eq!(limit_value, 100);
            assert_eq!(actual, 101);
        }
        other => panic!("expected TokenTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn roles_cap_refuses_issuance() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    for i in 0..51 {
        let role = h
            .rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("role.{i:03}"),
                    description: None,
                    permissions: perms(&["dummy.action"]),
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("role");
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
    }

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let err = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect_err("should fail");

    match err {
        IdentityError::TokenTooLarge {
            limit,
            limit_value,
            actual,
        } => {
            assert_eq!(limit, "access_token_roles_per_token");
            assert_eq!(limit_value, 50);
            assert_eq!(actual, 51);
        }
        other => panic!("expected TokenTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn groups_cap_refuses_issuance() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    for i in 0..51 {
        let group = h
            .rbac()
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: format!("grp-{i:03}"),
                    slug: format!("grp-{i:03}"),
                    description: None,
                },
            )
            .expect("group");
        h.rbac()
            .add_group_member(&realm, &group.id, &GroupMember::User(user.id().clone()))
            .expect("add member");
    }

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let err = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect_err("should fail");

    match err {
        IdentityError::TokenTooLarge {
            limit,
            limit_value,
            actual,
        } => {
            assert_eq!(limit, "access_token_groups_per_token");
            assert_eq!(limit_value, 50);
            assert_eq!(actual, 51);
        }
        other => panic!("expected TokenTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn exact_limit_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // 100 permissions in one role.
    let many_perms: Vec<Permission> = (0..100)
        .map(|i| Permission::new(format!("perm.{i:03}")).expect("valid perm"))
        .collect();
    let big_role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "big.role".into(),
                description: None,
                permissions: many_perms,
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: big_role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign big role");

    // 49 more roles (total 50).
    // Each small role re-uses a permission already in big_role so the
    // deduplicated permission count stays exactly 100.
    for i in 0..49 {
        let role = h
            .rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("role.{i:03}"),
                    description: None,
                    permissions: perms(&["perm.000"]),
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("role");
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
    }

    // 50 groups.
    for i in 0..50 {
        let group = h
            .rbac()
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: format!("grp-{i:03}"),
                    slug: format!("grp-{i:03}"),
                    description: None,
                },
            )
            .expect("group");
        h.rbac()
            .add_group_member(&realm, &group.id, &GroupMember::User(user.id().clone()))
            .expect("add member");
    }

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue at exact limit should succeed");

    let claims = h
        .identity()
        .validate_token(&realm, pair.access_token())
        .expect("validate");
    assert_eq!(claims.permissions.len(), 100);
    assert_eq!(claims.roles.len(), 50);
    assert_eq!(claims.groups.len(), 50);
}

#[tokio::test]
async fn byte_cap_refuses_issuance() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // 80 permissions at the max allowed length (128 chars) produce a JSON
    // payload well past the 8 KiB byte cap while staying under the 100-count
    // cap, exercising the bytes-per-token branch.
    let many_perms: Vec<Permission> = (0..80)
        .map(|i| {
            // Must contain '.' and be ≤128 chars.
            let name = format!("{i:03}.{}", "a".repeat(124));
            assert_eq!(name.len(), 128, "sanity: exactly 128 chars");
            Permission::new(&name).expect("valid perm")
        })
        .collect();
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "byte.role".into(),
                description: None,
                permissions: many_perms,
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
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

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let err = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect_err("should fail");

    match err {
        IdentityError::TokenTooLarge {
            limit,
            limit_value,
            actual,
        } => {
            assert_eq!(limit, "access_token_claims_bytes_per_token");
            assert_eq!(limit_value, 8192);
            assert!(actual > 8192, "expected actual > 8192, got {actual}");
        }
        other => panic!("expected TokenTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn oauth_path_permissions_cap_refuses_issuance() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // 101 permissions via role.
    let many_perms: Vec<Permission> = (0..101)
        .map(|i| Permission::new(format!("perm.{i:03}")).expect("valid perm"))
        .collect();
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "big.role".into(),
                description: None,
                permissions: many_perms,
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
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

    // Register a first-party OAuth client so the default claim profile
    // embeds roles/groups/permissions in the access token.
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "test-client".into(),
                redirect_uris: vec!["http://localhost/callback".into()],
                client_secret: None,
                grant_types: vec!["authorization_code".into()],
                require_consent: false,
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    // Authorize with two-word scope → scope_for_resolver = None → no narrowing.
    let auth_resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "http://localhost/callback".into(),
                scope: "openid profile".into(),
                state: "csrf".into(),
                response_type: "code".into(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
            },
        )
        .expect("authorize");

    // Exchange the code — access-token validation trips first.
    let err = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: "http://localhost/callback".into(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        )
        .expect_err("should fail");

    match err {
        IdentityError::TokenTooLarge {
            limit,
            limit_value,
            actual,
        } => {
            assert_eq!(limit, "access_token_permissions_per_token");
            assert_eq!(limit_value, 100);
            assert_eq!(actual, 101);
        }
        other => panic!("expected TokenTooLarge, got {other:?}"),
    }
}
