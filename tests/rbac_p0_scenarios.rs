//! P0 RBAC scenario tests.
//!
//! Covers `docs/specs/TEST_SCENARIOS.md` §"Authorization (RBAC) Engine":
//! - Unit: Permission string grammar (external test)
//! - Unit: Group caps (depth > 10)
//! - Adversarial: Invalid permission strings rejected at role creation
//! - Adversarial: Reserved namespace (`hearth.*`) rejected
//! - Adversarial: Token-size cap exceeded

mod common;

use hearth::core::{RealmId, UserId};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupMember, Permission, RbacError,
    Scope, Subject, TraversalKind, UpdateRoleRequest,
};

fn p(s: &str) -> Permission {
    Permission::new(s).expect("valid perm in test")
}

// ---------------------------------------------------------------------------
// Unit: Permission string grammar
// ---------------------------------------------------------------------------

#[test]
fn permission_grammar_basic_dotted_accepted() {
    assert!(Permission::new("docs.read").is_ok());
    assert!(Permission::new("org.billing.view").is_ok());
    assert!(Permission::new("a.b.c.d").is_ok());
}

#[test]
fn permission_grammar_empty_rejected() {
    assert!(
        Permission::new("").is_err(),
        "empty string must be rejected"
    );
}

#[test]
fn permission_grammar_no_dot_rejected() {
    // A permission must contain at least one `.` namespace separator.
    assert!(Permission::new("docs").is_err());
    assert!(Permission::new("nodot").is_err());
}

#[test]
fn permission_grammar_delimiter_chars_rejected() {
    assert!(Permission::new("docs read").is_err(), "space");
    assert!(Permission::new("docs/read").is_err(), "slash");
    assert!(Permission::new("docs:read").is_err(), "colon");
}

#[test]
fn permission_grammar_length_over_128_rejected() {
    // Build a string longer than 128 chars with a valid dot.
    let seg = "a".repeat(65);
    let long = format!("{seg}.{seg}"); // 131 chars
    assert!(long.len() > 128);
    assert!(
        Permission::new(&long).is_err(),
        "length > 128 must be rejected"
    );
}

#[test]
fn permission_grammar_max_128_accepted() {
    // 63 + '.' + 63 = 127 chars — must be accepted.
    let seg = "a".repeat(63);
    let s = format!("{seg}.{seg}");
    assert_eq!(s.len(), 127);
    assert!(
        Permission::new(&s).is_ok(),
        "length == 127 must be accepted"
    );
}

// ---------------------------------------------------------------------------
// Unit: Group caps — depth > 10
// ---------------------------------------------------------------------------

#[tokio::test]
async fn group_depth_cap_exceeded() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    // Chain: user ∈ g0 ⊂ g1 ⊂ ... ⊂ g12. Adding g12 as parent of g11 must
    // trigger DepthExceeded once depth > MAX_GROUP_DEPTH (10).
    let g0 = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "g0".into(),
                slug: "g0".into(),
                description: None,
            },
        )
        .expect("g0");
    h.rbac()
        .add_group_member(&realm, &g0.id, &GroupMember::User(user.clone()))
        .expect("user in g0");

    let mut last_id = g0.id;
    let mut depth_err = None;
    for i in 1..=12 {
        let g = h
            .rbac()
            .create_group(
                &realm,
                &CreateGroupRequest {
                    name: format!("g{i}"),
                    slug: format!("g{i}"),
                    description: None,
                },
            )
            .expect("create group");
        match h
            .rbac()
            .add_group_member(&realm, &g.id, &GroupMember::Group(last_id.clone()))
        {
            Ok(_) => last_id = g.id,
            Err(e) => {
                depth_err = Some(e);
                break;
            }
        }
    }

    match depth_err {
        Some(RbacError::DepthExceeded {
            kind: TraversalKind::GroupMembership,
            ..
        }) => {}
        other => panic!("expected GroupMembership DepthExceeded, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Adversarial: invalid permission strings rejected at role creation
// ---------------------------------------------------------------------------

#[test]
fn invalid_permission_grammar_rejected_at_construction() {
    // Permission is a validated newtype. These must all fail at the type boundary
    // before reaching the engine, guaranteeing no invalid permission ever enters.
    assert!(Permission::new("").is_err(), "empty");
    assert!(Permission::new("no-dot").is_err(), "no namespace separator");
    assert!(Permission::new("has space.x").is_err(), "whitespace");
    assert!(Permission::new("slash/x.y").is_err(), "slash");
    assert!(Permission::new("colon:x.y").is_err(), "colon");
    let long = format!("a.{}", "z".repeat(130));
    assert!(Permission::new(&long).is_err(), "too long");
}

// ---------------------------------------------------------------------------
// Adversarial: reserved namespace (hearth.*) rejected at create_role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_role_rejects_hearth_namespace_permission() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    let result = h.rbac().create_role(
        &realm,
        &CreateRoleRequest {
            name: "evil-role".into(),
            description: None,
            permissions: vec![Permission::new("hearth.admin").expect("valid grammar")],
            parent_roles: vec![],
            ..Default::default()
        },
    );
    assert!(
        matches!(result, Err(RbacError::ReservedNamespace { .. })),
        "hearth.* permission must be rejected at create_role; got {result:?}"
    );
}

#[tokio::test]
async fn update_role_rejects_hearth_namespace_permission() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "safe-role".into(),
                description: None,
                permissions: vec![p("docs.read")],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create");

    let result = h.rbac().update_role(
        &realm,
        &role.id,
        &UpdateRoleRequest {
            permissions: Some(vec![
                Permission::new("hearth.internal").expect("valid grammar")
            ]),
            ..Default::default()
        },
    );
    assert!(
        matches!(result, Err(RbacError::ReservedNamespace { .. })),
        "hearth.* permission must be rejected at update_role; got {result:?}"
    );
}

#[tokio::test]
async fn multiple_hearth_namespace_permissions_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    let result = h.rbac().create_role(
        &realm,
        &CreateRoleRequest {
            name: "multi-evil".into(),
            description: None,
            permissions: vec![
                p("docs.read"),
                Permission::new("hearth.scope.impersonate").expect("valid grammar"),
            ],
            parent_roles: vec![],
            ..Default::default()
        },
    );
    assert!(
        matches!(result, Err(RbacError::ReservedNamespace { .. })),
        "any hearth.* permission must cause ReservedNamespace; got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: token-size cap exceeded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_size_cap_permissions_exceeded() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    // MAX_PERMISSIONS_PER_TOKEN = 100. Spread 101 unique permissions across
    // 11 roles (10 per role, last role adds 1) and assign all to the user.
    for batch in 0..11usize {
        let count = if batch < 10 { 10 } else { 1 };
        let batch_perms: Vec<Permission> =
            (0..count).map(|i| p(&format!("ns{batch}.p{i}"))).collect();
        let role = h
            .rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("bulk-{batch}"),
                    description: None,
                    permissions: batch_perms,
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create bulk role");
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
            .expect("assign bulk role");
    }

    let result = h.rbac().resolve_permissions(&user, &realm, None, None);
    assert!(
        matches!(
            result,
            Err(RbacError::TokenSizeExceeded { ref limit, .. }) if limit == "permissions_per_token"
        ),
        "expected TokenSizeExceeded(permissions_per_token), got {result:?}"
    );
}

#[tokio::test]
async fn token_size_cap_roles_exceeded() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    // MAX_ROLES_PER_TOKEN = 50. Assign 51 distinct roles (each with a unique
    // permission so they don't collapse) to the user.
    for i in 0..51usize {
        let role = h
            .rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("role-{i}"),
                    description: None,
                    permissions: vec![p(&format!("r{i}.act"))],
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create role");
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
            .expect("assign role");
    }

    let result = h.rbac().resolve_permissions(&user, &realm, None, None);
    assert!(
        matches!(
            result,
            Err(RbacError::TokenSizeExceeded { ref limit, .. })
                if limit == "roles_per_token" || limit == "permissions_per_token"
        ),
        "expected TokenSizeExceeded for roles or permissions, got {result:?}"
    );
}

#[tokio::test]
async fn token_size_within_cap_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = UserId::generate();

    // 5 roles with 5 permissions each = 25 total. Well under every cap.
    for i in 0..5usize {
        let role = h
            .rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: format!("small-{i}"),
                    description: None,
                    permissions: (0..5).map(|j| p(&format!("s{i}.p{j}"))).collect(),
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create");
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
    }

    let result = h.rbac().resolve_permissions(&user, &realm, None, None);
    assert!(
        result.is_ok(),
        "under-cap resolution must succeed; got {result:?}"
    );
    assert_eq!(result.expect("ok").permissions.len(), 25);
}
