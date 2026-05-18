//! Tests for `RealmPermissionRegistry::validate()`.
//!
//! Layer: unit tests exercising registry cross-reference and structural rules
//! defined in `docs/specs/AUTHZ_EXPANSION.md` §"Registry validators".

use hearth::core::{RealmId, Timestamp};
use hearth::identity::claims_config::{ClaimMapping, ClaimProfile, ClaimSource};
use hearth::rbac::registry::{RealmPermissionRegistry, RegistryError};
use hearth::rbac::{
    Permission, PermissionDefinition, ProtectedResource, Role, RoleId, RoleScopeKind, RoleStatus,
    ScopeBundle,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn perm_def(name: &str) -> PermissionDefinition {
    PermissionDefinition {
        name: Permission::new(name).expect("valid permission in test"),
        display_name: name.to_string(),
        description: None,
        category: None,
    }
}

fn make_role(id: RoleId, name: &str, perms: &[&str], parents: Vec<RoleId>) -> Role {
    Role {
        id,
        realm_id: RealmId::new(Uuid::nil()),
        name: name.to_string(),
        description: None,
        permissions: perms
            .iter()
            .map(|p| Permission::new(*p).expect("valid permission in test"))
            .collect(),
        parent_roles: parents,
        scope_kind: RoleScopeKind::Realm,
        status: RoleStatus::Active,
        yaml_managed: false,
        created_at: Timestamp::from_micros(0),
        updated_at: Timestamp::from_micros(0),
    }
}

fn make_bundle(name: &str, perms: &[&str]) -> ScopeBundle {
    ScopeBundle {
        name: name.to_string(),
        display_name: name.to_string(),
        description: None,
        permissions: perms
            .iter()
            .map(|p| Permission::new(*p).expect("valid permission in test"))
            .collect(),
    }
}

fn minimal_mapping(claim: &str) -> ClaimMapping {
    ClaimMapping {
        claim: claim.to_string(),
        source: ClaimSource::Omit,
        include_in_access_token: true,
        include_in_id_token: false,
        include_in_userinfo: false,
        first_party_only: false,
        required_scopes: None,
        allowed_clients: None,
    }
}

// ---------------------------------------------------------------------------
// Valid registry
// ---------------------------------------------------------------------------

#[test]
fn valid_registry_passes() {
    let role_id = RoleId::generate();
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read"), perm_def("docs.write")],
        roles: vec![make_role(
            role_id,
            "editor",
            &["docs.read", "docs.write"],
            vec![],
        )],
        scopes: vec![make_bundle("read:docs", &["docs.read"])],
        protected_resources: vec![],
        claim_profile: None,
    };
    reg.validate().expect("valid registry must pass");
}

#[test]
fn empty_registry_passes() {
    let reg = RealmPermissionRegistry::default();
    reg.validate().expect("empty registry must pass validation");
}

// ---------------------------------------------------------------------------
// Scope bundle name grammar
// ---------------------------------------------------------------------------

#[test]
fn bundle_name_with_dot_fails() {
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read")],
        scopes: vec![make_bundle("read.docs", &["docs.read"])], // `.` instead of `:`
        ..Default::default()
    };
    let errs = reg.validate().expect_err("dot in bundle name must fail");
    assert!(
        errs.iter().any(|e| matches!(e, RegistryError::InvalidScopeBundleName { name, .. } if name == "read.docs")),
        "expected InvalidScopeBundleName for 'read.docs', got {errs:?}"
    );
}

#[test]
fn bundle_name_without_colon_fails() {
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read")],
        scopes: vec![make_bundle("readdocs", &["docs.read"])], // no separator
        ..Default::default()
    };
    let errs = reg.validate().expect_err("bare-word bundle name must fail");
    assert!(
        errs.iter().any(|e| matches!(e, RegistryError::InvalidScopeBundleName { name, .. } if name == "readdocs")),
        "got {errs:?}"
    );
}

#[test]
fn bundle_name_valid_colon_passes() {
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read")],
        scopes: vec![make_bundle("read:docs", &["docs.read"])],
        ..Default::default()
    };
    reg.validate()
        .expect("bundle name with colon separator must pass validation");
}

#[test]
fn bundle_name_nested_colons_passes() {
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read")],
        scopes: vec![make_bundle("mcp:tools:invoke", &["docs.read"])],
        ..Default::default()
    };
    reg.validate()
        .expect("bundle name with nested colons must pass validation");
}

// ---------------------------------------------------------------------------
// Undeclared permission references
// ---------------------------------------------------------------------------

#[test]
fn role_references_undeclared_permission_fails() {
    let role_id = RoleId::generate();
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read")],
        roles: vec![make_role(
            role_id,
            "editor",
            &["docs.read", "docs.write"],
            vec![],
        )],
        // docs.write not declared!
        ..Default::default()
    };
    let errs = reg
        .validate()
        .expect_err("undeclared perm in role must fail");
    assert!(
        errs.iter().any(|e| matches!(e,
            RegistryError::UndeclaredPermissionInRole { role_name, permission }
            if role_name == "editor" && permission == "docs.write"
        )),
        "got {errs:?}"
    );
}

#[test]
fn bundle_references_undeclared_permission_fails() {
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("docs.read")],
        scopes: vec![make_bundle("read:docs", &["docs.read", "docs.list"])],
        // docs.list not declared!
        ..Default::default()
    };
    let errs = reg
        .validate()
        .expect_err("undeclared perm in bundle must fail");
    assert!(
        errs.iter().any(|e| matches!(e,
            RegistryError::UndeclaredPermissionInBundle { bundle_name, permission }
            if bundle_name == "read:docs" && permission == "docs.list"
        )),
        "got {errs:?}"
    );
}

#[test]
fn protected_resource_bundle_references_undeclared_permission_fails() {
    let reg = RealmPermissionRegistry {
        permissions: vec![perm_def("mcp.invoke")],
        protected_resources: vec![ProtectedResource {
            resource_uri: "https://mcp.example.com".to_string(),
            display_name: "MCP Server".to_string(),
            scopes: vec![make_bundle("mcp:invoke", &["mcp.invoke", "mcp.list"])],
            // mcp.list not declared!
        }],
        ..Default::default()
    };
    let errs = reg
        .validate()
        .expect_err("undeclared perm in protected resource bundle must fail");
    assert!(
        errs.iter().any(|e| matches!(e,
            RegistryError::UndeclaredPermissionInBundle { bundle_name, permission }
            if bundle_name == "mcp:invoke" && permission == "mcp.list"
        )),
        "got {errs:?}"
    );
}

// ---------------------------------------------------------------------------
// Role parent references
// ---------------------------------------------------------------------------

#[test]
fn role_with_undeclared_parent_id_fails() {
    let dangling_id = RoleId::generate();
    let role_id = RoleId::generate();
    let reg = RealmPermissionRegistry {
        permissions: vec![],
        roles: vec![make_role(role_id, "editor", &[], vec![dangling_id.clone()])],
        ..Default::default()
    };
    let errs = reg.validate().expect_err("dangling parent ID must fail");
    assert!(
        errs.iter().any(|e| matches!(e,
            RegistryError::UndeclaredParentRole { role_name, .. }
            if role_name == "editor"
        )),
        "got {errs:?}"
    );
}

// ---------------------------------------------------------------------------
// Role parent cycle detection
// ---------------------------------------------------------------------------

#[test]
fn role_self_cycle_fails() {
    let id = RoleId::generate();
    // Role whose parent list contains itself.
    let reg = RealmPermissionRegistry {
        roles: vec![make_role(id.clone(), "cycler", &[], vec![id.clone()])],
        ..Default::default()
    };
    let errs = reg.validate().expect_err("self-cycle must fail");
    assert!(
        errs.iter().any(
            |e| matches!(e, RegistryError::RoleParentCycle { role_name } if role_name == "cycler")
        ),
        "got {errs:?}"
    );
}

#[test]
fn role_two_node_cycle_fails() {
    let id_a = RoleId::generate();
    let id_b = RoleId::generate();
    let reg = RealmPermissionRegistry {
        roles: vec![
            make_role(id_a.clone(), "a", &[], vec![id_b.clone()]),
            make_role(id_b.clone(), "b", &[], vec![id_a.clone()]),
        ],
        ..Default::default()
    };
    let errs = reg.validate().expect_err("two-node cycle must fail");
    assert!(
        errs.iter()
            .any(|e| matches!(e, RegistryError::RoleParentCycle { .. })),
        "got {errs:?}"
    );
}

#[test]
fn role_diamond_no_cycle_passes() {
    // A → B, A → C, B → D, C → D (diamond, not a cycle)
    let id_a = RoleId::generate();
    let id_b = RoleId::generate();
    let id_c = RoleId::generate();
    let id_d = RoleId::generate();
    let reg = RealmPermissionRegistry {
        roles: vec![
            make_role(id_a, "a", &[], vec![id_b.clone(), id_c.clone()]),
            make_role(id_b, "b", &[], vec![id_d.clone()]),
            make_role(id_c, "c", &[], vec![id_d.clone()]),
            make_role(id_d, "d", &[], vec![]),
        ],
        ..Default::default()
    };
    reg.validate()
        .expect("diamond-shaped DAG must pass validation");
}

#[test]
fn role_parent_chain_exceeds_depth_fails() {
    // Build a chain of MAX_ROLE_PARENT_DEPTH + 2 roles: r0 → r1 → … → r_n
    const LIMIT: usize = 10;
    let ids: Vec<RoleId> = (0..=(LIMIT + 2)).map(|_| RoleId::generate()).collect();
    let mut roles = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let parent = if i + 1 < ids.len() {
            vec![ids[i + 1].clone()]
        } else {
            vec![]
        };
        roles.push(make_role(id.clone(), &format!("r{i}"), &[], parent));
    }
    let reg = RealmPermissionRegistry {
        roles,
        ..Default::default()
    };
    let errs = reg.validate().expect_err("depth-exceeded chain must fail");
    assert!(
        errs.iter()
            .any(|e| matches!(e, RegistryError::RoleParentDepthExceeded { .. })),
        "got {errs:?}"
    );
}

// ---------------------------------------------------------------------------
// Claim profile: Tier 1 forbidden targets
// ---------------------------------------------------------------------------

fn reg_with_claim(claim: &str) -> RealmPermissionRegistry {
    RealmPermissionRegistry {
        claim_profile: Some(ClaimProfile {
            mappings: vec![minimal_mapping(claim)],
            updated_at: None,
        }),
        ..Default::default()
    }
}

#[test]
fn tier1_claim_iss_rejected() {
    let errs = reg_with_claim("iss").validate().expect_err("iss is Tier 1");
    assert!(errs
        .iter()
        .any(|e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "iss")));
}

#[test]
fn tier1_claim_sub_rejected() {
    let errs = reg_with_claim("sub").validate().expect_err("sub is Tier 1");
    assert!(errs
        .iter()
        .any(|e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "sub")));
}

#[test]
fn tier1_claim_oid_rejected() {
    let errs = reg_with_claim("oid").validate().expect_err("oid is Tier 1");
    assert!(errs
        .iter()
        .any(|e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "oid")));
}

#[test]
fn tier1_claim_permissions_rejected() {
    let errs = reg_with_claim("permissions")
        .validate()
        .expect_err("permissions is Tier 1");
    assert!(errs.iter().any(
        |e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "permissions")
    ));
}

#[test]
fn tier1_claim_email_verified_rejected() {
    let errs = reg_with_claim("email_verified")
        .validate()
        .expect_err("email_verified is Tier 1");
    assert!(errs.iter().any(
        |e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "email_verified")
    ));
}

#[test]
fn tier2_claim_roles_allowed() {
    assert!(
        reg_with_claim("roles").validate().is_ok(),
        "roles is Tier 2, allowed"
    );
}

#[test]
fn tier2_claim_email_allowed() {
    assert!(
        reg_with_claim("email").validate().is_ok(),
        "email is Tier 2, allowed"
    );
}

#[test]
fn tier3_short_claim_allowed() {
    assert!(
        reg_with_claim("department").validate().is_ok(),
        "short snake_case custom claim is Tier 3, allowed"
    );
}

#[test]
fn tier3_https_claim_allowed() {
    assert!(
        reg_with_claim("https://acme.com/department")
            .validate()
            .is_ok(),
        "HTTPS-namespaced custom claim is Tier 3, allowed"
    );
}

// ---------------------------------------------------------------------------
// Additional Tier 1 / Tier 3 tests (spec §"Registry validation tests")
// ---------------------------------------------------------------------------

/// Tier 1 claim `sub` must be rejected as a mapper target.
#[test]
fn tier1_claim_rejected_as_mapper_target() {
    let errs = reg_with_claim("sub").validate().expect_err("sub is Tier 1");
    assert!(
        errs.iter()
            .any(|e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "sub")),
        "expected ForbiddenClaimTarget for 'sub'; got {errs:?}"
    );
}

/// Tier 3 short identifier `employee_id` must be accepted.
#[test]
fn tier3_short_claim_accepted() {
    assert!(
        reg_with_claim("employee_id").validate().is_ok(),
        "short snake_case 'employee_id' is Tier 3 and must be accepted"
    );
}

/// Tier 3 HTTPS-namespaced `https://example.com/dept` must be accepted.
#[test]
fn tier3_https_claim_accepted() {
    assert!(
        reg_with_claim("https://example.com/dept")
            .validate()
            .is_ok(),
        "HTTPS-namespaced claim must be accepted as Tier 3"
    );
}

/// Tier 1 claim `exp` must be rejected as a mapper target.
#[test]
fn tier1_claim_exp_rejected() {
    let errs = reg_with_claim("exp").validate().expect_err("exp is Tier 1");
    assert!(
        errs.iter()
            .any(|e| matches!(e, RegistryError::ForbiddenClaimTarget { claim } if claim == "exp")),
        "expected ForbiddenClaimTarget for 'exp'; got {errs:?}"
    );
}
