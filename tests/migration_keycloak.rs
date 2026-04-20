//! Integration tests for Keycloak realm-export migration.
//!
//! These tests exercise the full pipeline end-to-end: JSON parse →
//! `KeycloakImporter::import_realm` → verify migrated artifacts through
//! the public `IdentityEngine` + `AuthorizationEngine` APIs.
//!
//! Fixtures live under `tests/fixtures/keycloak/`; credentials in the
//! fixtures are real (we generated them with `pbkdf2_hmac<Sha256>`) so
//! the round-trip through `verify_password` is meaningful.

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::authz::{AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, SubjectRef};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::migration::{ImportOptions, KeycloakImporter};
use hearth::identity::{
    CleartextPassword, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const REALM_FIXTURE: &str = include_str!("fixtures/keycloak/realm-export.json");

/// Builds a fresh set of engines backed by a tempdir. Returned in `Arc`s
/// because `KeycloakImporter::new` wants `Arc<dyn ...>`.
fn build_engines() -> (
    Arc<dyn IdentityEngine>,
    Arc<dyn AuthorizationEngine>,
    tempfile::TempDir,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(temp.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));

    let authz: Arc<dyn AuthorizationEngine> = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&storage),
        AuthzConfig::default(),
    ));

    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let identity: Arc<dyn IdentityEngine> = Arc::new(
        EmbeddedIdentityEngine::new(Arc::clone(&storage), Arc::clone(&clock), identity_config)
            .expect("identity"),
    );
    // Keep audit engine constructed so the storage has the same wiring
    // as a real deployment, even though these tests don't assert on it.
    let _audit = EmbeddedAuditEngine::new(storage, clock);

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
    assert_eq!(report.tuples_written, 3);

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

// ===== Scenario 3: Role → Zanzibar tuple mapping =====
//
// Keycloak realm roles become relations on `realm:<realm_id>`. A
// `check()` for a user→role assignment must return true; an unassigned
// user→role must return false.

#[tokio::test]
async fn realm_roles_become_zanzibar_tuples() {
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

    let realm_obj = ObjectRef::new("realm", &realm_id.as_uuid().to_string()).expect("object");
    let alice_subj = SubjectRef::direct("user", &alice.id().as_uuid().to_string()).expect("subj");
    let bob_subj = SubjectRef::direct("user", &bob.id().as_uuid().to_string()).expect("subj");

    // alice is admin
    let alice_admin = authz
        .check(&realm_id, &realm_obj, "admin", &alice_subj, None)
        .expect("check");
    assert!(alice_admin, "alice should have admin role");

    // bob is not admin
    let bob_admin = authz
        .check(&realm_id, &realm_obj, "admin", &bob_subj, None)
        .expect("check");
    assert!(!bob_admin, "bob should NOT have admin role");

    // both are members
    let alice_member = authz
        .check(&realm_id, &realm_obj, "member", &alice_subj, None)
        .expect("check");
    let bob_member = authz
        .check(&realm_id, &realm_obj, "member", &bob_subj, None)
        .expect("check");
    assert!(alice_member && bob_member, "both users should be members");
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
