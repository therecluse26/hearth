#![allow(clippy::unwrap_used)]
//! Integration tests for YAML-driven RBAC reconciliation.
//!
//! Verifies that `RbacEngine::reconcile_permissions`, `reconcile_roles`, and
//! `reconcile_scopes` upsert per-realm RBAC state by name and are idempotent
//! across re-runs (so server restarts converge on YAML-declared state without
//! duplication or drift).

mod common;

use hearth::core::RealmId;
use hearth::rbac::{Permission, RoleScopeKind, RoleSpec, ScopeSpec};

#[tokio::test]
async fn reconcile_creates_yaml_role_referencing_seed_parent() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    h.rbac()
        .reconcile_permissions(
            &realm,
            &["billing.read".to_string(), "billing.write".to_string()],
        )
        .expect("reconcile perms");

    let specs = vec![RoleSpec {
        name: "org.billing_admin".to_string(),
        description: Some("Manages billing".to_string()),
        permissions: vec!["billing.read".to_string(), "billing.write".to_string()],
        // org.admin is a SEED role — reconcile must resolve it by name.
        parent_names: vec!["org.admin".to_string()],
        scope_kind: RoleScopeKind::Organization,
    }];
    h.rbac()
        .reconcile_roles(&realm, &specs)
        .expect("reconcile roles");

    let role = h
        .rbac()
        .get_role_by_name(&realm, "org.billing_admin")
        .expect("lookup")
        .expect("custom role created");

    assert_eq!(role.scope_kind, RoleScopeKind::Organization);
    let perm_names: Vec<&str> = role.permissions.iter().map(Permission::as_str).collect();
    assert!(perm_names.contains(&"billing.read"));
    assert!(perm_names.contains(&"billing.write"));
    assert_eq!(
        role.parent_roles.len(),
        1,
        "parent name must resolve to a single role id"
    );

    // The resolved parent must point to the seed org.admin role.
    let org_admin = h
        .rbac()
        .get_role_by_name(&realm, "org.admin")
        .expect("lookup")
        .expect("seeded");
    assert_eq!(role.parent_roles[0], org_admin.id);
}

#[tokio::test]
async fn reconcile_is_idempotent_and_repairs_drift() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    h.rbac()
        .reconcile_permissions(&realm, &["billing.read".to_string()])
        .expect("perms #1");
    let specs_v1 = vec![RoleSpec {
        name: "support.agent".to_string(),
        description: Some("v1 desc".to_string()),
        permissions: vec!["billing.read".to_string()],
        parent_names: vec![],
        scope_kind: RoleScopeKind::Realm,
    }];
    h.rbac()
        .reconcile_roles(&realm, &specs_v1)
        .expect("roles #1");

    let id_v1 = h
        .rbac()
        .get_role_by_name(&realm, "support.agent")
        .expect("lookup")
        .expect("created")
        .id;

    // Second run: same spec → must not change the role ID (no duplicate
    // create) and must keep the description.
    h.rbac()
        .reconcile_roles(&realm, &specs_v1)
        .expect("roles #2 idempotent");
    let after_idempotent = h
        .rbac()
        .get_role_by_name(&realm, "support.agent")
        .expect("lookup")
        .expect("present");
    assert_eq!(after_idempotent.id, id_v1, "role id must be stable");

    // Third run: change description and add a permission → drift repair
    // updates the existing role in place (still same ID).
    h.rbac()
        .reconcile_permissions(&realm, &["reports.export".to_string()])
        .expect("perms #2");
    let specs_v2 = vec![RoleSpec {
        name: "support.agent".to_string(),
        description: Some("v2 desc".to_string()),
        permissions: vec!["billing.read".to_string(), "reports.export".to_string()],
        parent_names: vec![],
        scope_kind: RoleScopeKind::Realm,
    }];
    h.rbac()
        .reconcile_roles(&realm, &specs_v2)
        .expect("roles #3 drift");
    let after_drift = h
        .rbac()
        .get_role_by_name(&realm, "support.agent")
        .expect("lookup")
        .expect("still present");
    assert_eq!(after_drift.id, id_v1, "drift repair must reuse role id");
    assert_eq!(after_drift.description.as_deref(), Some("v2 desc"));
    let names: Vec<&str> = after_drift
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    assert!(names.contains(&"reports.export"));
}

#[tokio::test]
async fn reconcile_unknown_parent_errors() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    let specs = vec![RoleSpec {
        name: "broken.role".to_string(),
        description: None,
        permissions: vec![],
        parent_names: vec!["does.not.exist".to_string()],
        scope_kind: RoleScopeKind::Realm,
    }];
    let err = h.rbac().reconcile_roles(&realm, &specs).unwrap_err();
    assert!(
        err.to_string().contains("does.not.exist"),
        "error must name the missing parent: {err}"
    );
}

#[tokio::test]
async fn reconcile_scopes_persists_bundle() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    h.rbac()
        .reconcile_permissions(
            &realm,
            &["billing.read".to_string(), "billing.write".to_string()],
        )
        .expect("perms");

    let specs = vec![ScopeSpec {
        name: "billing:manage".to_string(),
        permissions: Some(vec![
            "billing.read".to_string(),
            "billing.write".to_string(),
        ]),
    }];
    h.rbac()
        .reconcile_scopes(&realm, &specs)
        .expect("scopes reconcile");

    // Re-running the same spec must not error or duplicate.
    h.rbac()
        .reconcile_scopes(&realm, &specs)
        .expect("scopes idempotent");
}

#[tokio::test]
async fn reconcile_does_not_leak_across_realms() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();
    h.rbac().seed_realm(&realm_a).expect("seed a");
    h.rbac().seed_realm(&realm_b).expect("seed b");

    h.rbac()
        .reconcile_permissions(&realm_a, &["a.only".to_string()])
        .expect("perms a");
    let specs = vec![RoleSpec {
        name: "a.role".to_string(),
        description: None,
        permissions: vec!["a.only".to_string()],
        parent_names: vec![],
        scope_kind: RoleScopeKind::Realm,
    }];
    h.rbac().reconcile_roles(&realm_a, &specs).expect("roles a");

    // Realm B must not see realm A's custom role.
    let leaked = h
        .rbac()
        .get_role_by_name(&realm_b, "a.role")
        .expect("lookup");
    assert!(leaked.is_none(), "custom role leaked across realms");
}
