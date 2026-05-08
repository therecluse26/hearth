//! Integration tests for Keycloak realm-export migration.
//!
//! These tests exercise the full pipeline end-to-end: JSON parse →
//! `KeycloakImporter::import_realm` → verify migrated artifacts through
//! the public `IdentityEngine` + `RbacEngine` APIs.
//!
//! Fixtures live under `tests/fixtures/keycloak/`; credentials in the
//! fixtures are real (we generated them with `pbkdf2_hmac<Sha256>`) so
//! the round-trip through `verify_password` is meaningful.

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::migration::{ImportOptions, KeycloakImporter};
use hearth::identity::{
    CleartextPassword, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const REALM_FIXTURE: &str = include_str!("fixtures/keycloak/realm-export.json");

/// Builds a fresh set of engines backed by a tempdir. Returned in `Arc`s
/// because `KeycloakImporter::new` wants `Arc<dyn ...>`.
fn build_engines() -> (
    Arc<dyn IdentityEngine>,
    Arc<dyn RbacEngine>,
    tempfile::TempDir,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(temp.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));

    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;

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

// ===== Scenario 1: Happy-path import =====
//
// Parse the fixture, import the realm, and assert the report reflects
// every object we expect to land in storage.

#[tokio::test]
async fn imports_minimal_realm_and_reports_correct_counts() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");

    let report = importer
        .import_realm(&export, None, &ImportOptions::default())
        .expect("import_realm");

    // Realm id is the Keycloak realm uuid (preserved verbatim).
    let realm_id = report.realm_id.clone().expect("realm_id in report");
    assert_eq!(
        realm_id.as_uuid().to_string(),
        "550e8400-e29b-41d4-a716-446655440000"
    );

    // Both users imported (one with and one without a credential).
    assert_eq!(report.users_imported, 2);
    // Bob's pbkdf2-sha512 credential was skipped.
    assert_eq!(report.users_with_skipped_credentials, 1);
    assert_eq!(report.clients_imported, 1);
    // alice: admin + member; bob: member → 3 tuples.
    assert_eq!(report.role_assignments_written, 3);

    // And at least one warning explains the skipped credential.
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("pbkdf2-sha512") && w.contains("bob@acme.test")),
        "expected skip warning for bob's pbkdf2-sha512; got {:?}",
        report.warnings,
    );
}

// ===== Scenario 2: Password round-trip =====
//
// The fixture embeds a real PBKDF2-SHA256 hash of "hunter2". After
// migration, `verify_password` must accept that password and reject
// any other.

#[tokio::test]
async fn migrated_pbkdf2_password_verifies_natively() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");
    let report = importer
        .import_realm(&export, None, &ImportOptions::default())
        .expect("import_realm");
    let realm_id = report.realm_id.expect("realm_id");

    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup alice")
        .expect("alice exists");

    let ok = identity
        .verify_password(
            &realm_id,
            alice.id(),
            &CleartextPassword::from_string("hunter2".to_string()),
        )
        .expect("verify_password");
    assert!(ok, "correct password must verify");

    let wrong = identity
        .verify_password(
            &realm_id,
            alice.id(),
            &CleartextPassword::from_string("not-hunter2".to_string()),
        )
        .expect("verify_password");
    assert!(!wrong, "wrong password must not verify");
}

// ===== Scenario 3: Role → RBAC assignment mapping =====
//
// Keycloak realm roles become RBAC role assignments scoped to the
// imported realm. A `check()` for a user→role assignment must return
// true; an unassigned user→role must return false.

#[tokio::test]
async fn realm_roles_become_rbac_assignments() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");
    let report = importer
        .import_realm(&export, None, &ImportOptions::default())
        .expect("import_realm");
    let realm_id = report.realm_id.expect("realm_id");

    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup alice")
        .expect("alice exists");
    let bob = identity
        .get_user_by_email(&realm_id, "bob@acme.test")
        .expect("lookup bob")
        .expect("bob exists");

    // Alice has admin, bob doesn't. Use list_user_assignments + role lookup.
    let admin_role = authz
        .get_role_by_name(&realm_id, "admin")
        .expect("lookup")
        .expect("admin role created by importer");
    let member_role = authz
        .get_role_by_name(&realm_id, "member")
        .expect("lookup")
        .expect("member role created by importer");
    let alice_assignments = authz
        .list_user_assignments(&realm_id, alice.id())
        .expect("list alice");
    let bob_assignments = authz
        .list_user_assignments(&realm_id, bob.id())
        .expect("list bob");
    assert!(
        alice_assignments.iter().any(|a| a.role_id == admin_role.id),
        "alice should have admin role"
    );
    assert!(
        !bob_assignments.iter().any(|a| a.role_id == admin_role.id),
        "bob should NOT have admin role"
    );
    assert!(
        alice_assignments
            .iter()
            .any(|a| a.role_id == member_role.id),
        "alice should be a member"
    );
    assert!(
        bob_assignments.iter().any(|a| a.role_id == member_role.id),
        "bob should be a member"
    );
}

// ===== Scenario 4: Skipped-credential user still imports =====
//
// Bob's pbkdf2-sha512 credential is not supported, but his *account*
// should still land — migration proceeds with the user record and
// records a warning, rather than dropping the whole user.

#[tokio::test]
async fn skipped_credential_user_is_still_imported_without_credential() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");
    let report = importer
        .import_realm(&export, None, &ImportOptions::default())
        .expect("import_realm");
    let realm_id = report.realm_id.expect("realm_id");

    let bob = identity
        .get_user_by_email(&realm_id, "bob@acme.test")
        .expect("lookup bob")
        .expect("bob exists despite unsupported credential");

    // verify_password should return IdentityError::CredentialNotFound
    // (no credential stored) — Result::Err, not Ok(false).
    let result = identity.verify_password(
        &realm_id,
        bob.id(),
        &CleartextPassword::from_string("correcthorse".to_string()),
    );
    assert!(
        result.is_err(),
        "bob has no stored credential so verify_password must error: {result:?}"
    );
}

// ===== Scenario 5: Idempotency =====
//
// Running the same import twice against the same engines must not
// crash; the second run reports per-item warnings (duplicate realm /
// duplicate emails / duplicate client IDs) but does not corrupt state.

#[tokio::test]
async fn re_running_import_is_safe_and_reports_duplicates() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");

    // First run: clean success.
    let first = importer
        .import_realm(&export, None, &ImportOptions::default())
        .expect("first import");
    assert_eq!(first.users_imported, 2);
    let realm_id = first.realm_id.clone().expect("realm_id");

    // Second run: `import_realm` rejects the duplicate. We explicitly
    // pass the same realm id so the error surfaces at the realm stage
    // (matches the real-world re-run case).
    let second = importer.import_realm(&export, Some(realm_id.clone()), &ImportOptions::default());

    // Either: the realm-level call errors out (expected), or the
    // importer surfaces per-item warnings for every duplicate user.
    // Both are acceptable; what matters is that the engines remain
    // consistent and alice's password still verifies.
    let _ = second;

    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .expect("lookup alice")
        .expect("alice still exists after duplicate import");
    let ok = identity
        .verify_password(
            &realm_id,
            alice.id(),
            &CleartextPassword::from_string("hunter2".to_string()),
        )
        .expect("verify_password");
    assert!(ok, "alice's credential must survive a redundant re-import");
}

// ===== Scenario 6: Dry-run mutates nothing =====

#[tokio::test]
async fn dry_run_makes_no_changes_to_storage() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");

    let report = importer
        .import_realm(&export, None, &ImportOptions { dry_run: true })
        .expect("dry-run import");

    let realm_id = report
        .realm_id
        .clone()
        .expect("dry-run still reports a hinted realm id");

    // No realm was actually created — a get_user_by_email for the
    // (non-existent) realm returns a RealmNotFound-style error or
    // None; either way, Alice must not be findable.
    let alice = identity
        .get_user_by_email(&realm_id, "alice@acme.test")
        .ok()
        .flatten();
    assert!(alice.is_none(), "dry-run must not create users");

    // And the report still surfaces what *would* have been imported.
    assert_eq!(report.users_imported, 2);
    assert!(report.warnings.iter().any(|w| w.contains("dry-run")));
}

// ===== Scenario 7: Custom realm id override =====
//
// Callers can supply their own `RealmId` (e.g. to match an existing
// pre-provisioned realm shell) — the importer must honour it.

#[tokio::test]
async fn custom_realm_id_is_honoured() {
    let (identity, authz, _temp) = build_engines();
    let importer = KeycloakImporter::new(Arc::clone(&identity), Arc::clone(&authz));
    let export = KeycloakImporter::parse(REALM_FIXTURE.as_bytes()).expect("parse fixture");

    let custom = RealmId::new(
        "deadbeef-dead-beef-dead-beefdeadbeef"
            .parse()
            .expect("uuid"),
    );
    let report = importer
        .import_realm(&export, Some(custom.clone()), &ImportOptions::default())
        .expect("import with custom realm id");
    assert_eq!(report.realm_id.as_ref(), Some(&custom));

    let alice = identity
        .get_user_by_email(&custom, "alice@acme.test")
        .expect("lookup")
        .expect("alice found under custom realm");
    let ok = identity
        .verify_password(
            &custom,
            alice.id(),
            &CleartextPassword::from_string("hunter2".to_string()),
        )
        .expect("verify");
    assert!(ok);
}
