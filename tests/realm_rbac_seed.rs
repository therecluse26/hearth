//! Integration tests for realm RBAC seeding.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 scenarios:
//! - fresh realm has seed roles + permissions installed
//! - seed is idempotent
//! - startup reconciliation repairs unseeded realms

mod common;

use hearth::core::RealmId;
use hearth::identity::CreateRealmRequest;
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

/// Verifies that `reconcile_rbac_seeds` repairs realms that were created
/// without seeding — i.e. the "silent failure" scenario this bug describes.
#[tokio::test]
async fn reconcile_rbac_seeds_repairs_unseeded_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");

    // Create a realm WITHOUT calling seed_realm — simulates a creation-time
    // seed failure that was previously only warn!()-logged.
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("unseeded-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    // Confirm no seed roles exist yet.
    let before = h
        .rbac()
        .get_role_by_name(&realm_id, "realm.admin")
        .expect("lookup");
    assert!(before.is_none(), "realm.admin should not exist before reconcile");

    // Run startup reconciliation.
    hearth::identity::reconcile::reconcile_rbac_seeds(h.identity(), h.rbac());

    // Seed roles must now be present.
    for name in SEED_ROLE_NAMES {
        let role = h
            .rbac()
            .get_role_by_name(&realm_id, name)
            .expect("lookup after reconcile")
            .unwrap_or_else(|| panic!("missing seed role after reconcile: {name}"));
        assert_eq!(role.realm_id, realm_id);
    }
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
