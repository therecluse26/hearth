//! Integration tests for realm RBAC seeding.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 scenarios:
//! - fresh realm has seed roles + permissions installed
//! - seed is idempotent

mod common;

use hearth::core::RealmId;
use hearth::rbac::Permission;

const SEED_ROLE_NAMES: &[&str] = &[
    "realm.admin",
    "realm.member",
    "org.member",
    "org.admin",
    "org.owner",
];

#[tokio::test]
async fn fresh_realm_has_seed_roles() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    for name in SEED_ROLE_NAMES {
        let role = h
            .rbac()
            .get_role_by_name(&realm, name)
            .expect("lookup")
            .unwrap_or_else(|| panic!("missing seed role: {name}"));
        assert_eq!(role.realm_id, realm);
    }
}

#[tokio::test]
async fn realm_admin_role_has_hearth_admin_permission() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed");

    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    let names: Vec<&str> = role.permissions.iter().map(Permission::as_str).collect();
    assert!(
        names.contains(&"hearth.admin"),
        "realm.admin must carry hearth.admin to gate admin endpoints"
    );
}

#[tokio::test]
async fn seed_is_idempotent() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    h.rbac().seed_realm(&realm).expect("seed #1");
    // Capture role IDs after the first seed.
    let before: Vec<(String, _)> = SEED_ROLE_NAMES
        .iter()
        .map(|n| {
            let r = h
                .rbac()
                .get_role_by_name(&realm, n)
                .expect("lookup")
                .expect("seeded");
            ((*n).to_string(), r.id)
        })
        .collect();
    h.rbac().seed_realm(&realm).expect("seed #2 idempotent");
    // IDs must be stable across re-seed — proves no duplication.
    for (name, id) in before {
        let r = h
            .rbac()
            .get_role_by_name(&realm, &name)
            .expect("lookup")
            .expect("seeded");
        assert_eq!(r.id, id, "role id changed across reseed: {name}");
    }
}
