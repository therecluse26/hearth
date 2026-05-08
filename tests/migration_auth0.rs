//! Integration tests for the Auth0 → Hearth migration importer.
//!
//! The fixture ships a `__BCRYPT_HUNTER2_HASH__` placeholder because bcrypt
//! salts are non-deterministic and we want the round-trip verify test to
//! assert a real hash-against-plaintext match. `build_bundle_bytes()` computes
//! a fresh bcrypt hash for `"hunter2"` at cost 4 and substitutes it in.
//!
//! Fixture shape (3 users / 1 client / 1 org / 2 roles) is documented in
//! `tests/fixtures/auth0/tenant-export.json`.
//!
//! Tests intentionally avoid asserting on internal RBAC key layouts —
//! observable behaviour (via `authz.check`, `identity.get_user_by_email`,
//! `identity.list_members`, `identity.verify_password`) is the contract.

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::migration::{Auth0ImportOptions, Auth0Importer};
use hearth::identity::{
    CleartextPassword, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    OrganizationRole, UserStatus,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const BUNDLE_TEMPLATE: &str = include_str!("fixtures/auth0/tenant-export.json");

/// Returns the fixture JSON with a freshly computed bcrypt hash of
/// `"hunter2"` substituted for the `__BCRYPT_HUNTER2_HASH__` placeholder.
fn build_bundle_bytes() -> Vec<u8> {
    let hash = bcrypt::hash("hunter2", 4).expect("bcrypt hash");
    BUNDLE_TEMPLATE
        .replace("__BCRYPT_HUNTER2_HASH__", &hash)
        .into_bytes()
}

fn build_engines() -> (
    Arc<dyn IdentityEngine>,
    Arc<dyn RbacEngine>,
    tempfile::TempDir,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage: Arc<dyn StorageEngine> = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("storage"),
    );
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let authz: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let identity: Arc<dyn IdentityEngine> = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&audit),
        )
        .expect("identity"),
    );
    (identity, authz, temp)
}

// ===== 1. Happy-path counts =====

#[tokio::test]
async fn imports_minimal_bundle_and_reports_correct_counts() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");

    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions::default())
        .expect("import_bundle");

    let realm_id = report.realm_id.clone().expect("realm_id in report");
    assert_eq!(
        realm_id.as_uuid().to_string(),
        "9a000000-0000-4000-8000-000000000001"
    );

    assert_eq!(report.users_imported, 3);
    // Bob's md5 is unsupported; he still imports but without a credential.
    assert_eq!(report.users_with_skipped_credentials, 1);
    assert_eq!(report.clients_imported, 1);
    // Roles: alice→admin, alice→engineer, carol→engineer = 3 tuples.
    // Organization roles live on org objects, not realm objects — counted separately.
    assert_eq!(report.role_assignments_written, 3);

    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("md5") && w.contains("bob@acme.test")),
        "expected warning about bob's md5 hash: {:?}",
        report.warnings,
    );
}

// ===== 2. Bcrypt password verifies round-trip =====

#[tokio::test]
async fn bcrypt_custom_password_hash_verifies_natively_after_import() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");
    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions::default())
        .expect("import");
    let realm_id = report.realm_id.expect("realm_id");

    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup")
        .expect("alice exists");

    let ok = identity
        .verify_password(
            &realm_id,
            alice.id(),
            &CleartextPassword::from_string("hunter2".to_string()),
        )
        .expect("verify_password");
    assert!(ok, "imported bcrypt hash must verify the original password");

    let wrong = identity
        .verify_password(
            &realm_id,
            alice.id(),
            &CleartextPassword::from_string("wrong".to_string()),
        )
        .expect("verify_password");
    assert!(!wrong, "wrong password must not verify");
}

// ===== 3. Auth0 roles → RBAC assignments =====

#[tokio::test]
async fn auth0_role_assignments_become_rbac_assignments() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");
    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions::default())
        .expect("import");
    let realm_id = report.realm_id.expect("realm_id");

    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup")
        .expect("alice exists");
    let bob = identity
        .get_user_by_email(&realm_id, "bob@acme.test")
        .expect("lookup")
        .expect("bob exists");
    let carol = identity
        .get_user_by_email(&realm_id, "carol@acme.test")
        .expect("lookup")
        .expect("carol exists");

    let admin_role = authz
        .get_role_by_name(&realm_id, "admin")
        .expect("lookup")
        .expect("admin role");
    let eng_role = authz
        .get_role_by_name(&realm_id, "engineer")
        .expect("lookup")
        .expect("engineer role");
    let alice_assignments = authz
        .list_user_assignments(&realm_id, alice.id())
        .expect("list alice");
    let bob_assignments = authz
        .list_user_assignments(&realm_id, bob.id())
        .expect("list bob");
    let carol_assignments = authz
        .list_user_assignments(&realm_id, carol.id())
        .expect("list carol");
    assert!(
        alice_assignments.iter().any(|a| a.role_id == admin_role.id),
        "alice should have admin role"
    );
    assert!(
        !bob_assignments.iter().any(|a| a.role_id == admin_role.id),
        "bob was not assigned admin"
    );
    assert!(
        alice_assignments.iter().any(|a| a.role_id == eng_role.id),
        "alice should have engineer role"
    );
    assert!(
        carol_assignments.iter().any(|a| a.role_id == eng_role.id),
        "carol should have engineer role"
    );
}

// ===== 4. `blocked: true` → Disabled =====

#[tokio::test]
async fn blocked_user_imports_as_disabled() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");
    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions::default())
        .expect("import");
    let realm_id = report.realm_id.expect("realm_id");

    let bob = identity
        .get_user_by_email(&realm_id, "bob@acme.test")
        .expect("lookup")
        .expect("bob exists");
    assert_eq!(bob.status(), UserStatus::Disabled);

    // Carol has email_verified=false → PendingVerification.
    let carol = identity
        .get_user_by_email(&realm_id, "carol@acme.test")
        .expect("lookup")
        .expect("carol exists");
    assert_eq!(carol.status(), UserStatus::PendingVerification);

    // Alice has email_verified=true and blocked=false → Active.
    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup")
        .expect("alice exists");
    assert_eq!(alice.status(), UserStatus::Active);
}

// ===== 5. `--dry-run` semantics =====

#[tokio::test]
async fn dry_run_does_not_mutate_storage() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");

    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions { dry_run: true })
        .expect("dry-run import");

    let realm_id = report
        .realm_id
        .clone()
        .expect("dry-run still reports hinted realm id");

    // No realm actually created — lookup must not find any fixture user.
    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .ok()
        .flatten();
    assert!(alice.is_none(), "dry-run must not write users");

    assert_eq!(report.users_imported, 3);
    assert!(
        report.warnings.iter().any(|w| w.contains("dry-run")),
        "dry-run must surface a warning"
    );
}

// ===== 6. Unsupported algorithm → warning + no credential =====

#[tokio::test]
async fn unsupported_password_algorithm_imports_user_without_credential() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");
    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions::default())
        .expect("import");
    let realm_id = report.realm_id.expect("realm_id");

    let bob = identity
        .get_user_by_email(&realm_id, "bob@acme.test")
        .expect("lookup")
        .expect("bob still imported despite md5");

    let result = identity.verify_password(
        &realm_id,
        bob.id(),
        &CleartextPassword::from_string("password".to_string()),
    );
    assert!(
        result.is_err(),
        "bob has no stored credential → verify_password must error, got {result:?}"
    );
}

// ===== 7. Organization members + roles =====

#[tokio::test]
async fn organization_members_assigned_correct_roles() {
    let (identity, authz, _tmp) = build_engines();
    let importer = Auth0Importer::new(Arc::clone(&identity), Arc::clone(&authz));
    let bundle = Auth0Importer::parse(&build_bundle_bytes()).expect("parse bundle");
    let report = importer
        .import_bundle(&bundle, None, &Auth0ImportOptions::default())
        .expect("import");
    let realm_id = report.realm_id.expect("realm_id");

    let org = identity
        .get_organization_by_slug(&realm_id, "acme-eng")
        .expect("lookup org")
        .expect("acme-eng exists");
    assert_eq!(org.name(), "Acme Engineering");

    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup")
        .expect("alice exists");
    let bob = identity
        .get_user_by_email(&realm_id, "bob@acme.test")
        .expect("lookup")
        .expect("bob exists");

    let alice_membership = identity
        .get_membership(&realm_id, org.id(), alice.id())
        .expect("lookup membership")
        .expect("alice is member");
    assert_eq!(alice_membership.role(), OrganizationRole::Admin);

    let bob_membership = identity
        .get_membership(&realm_id, org.id(), bob.id())
        .expect("lookup membership")
        .expect("bob is member");
    assert_eq!(bob_membership.role(), OrganizationRole::Member);
}
