//! Cross-realm migration crash-recovery simulation.
//!
//! Oracle invariant: a crash at any point during cross-realm migration
//! leaves the system in a state that can be safely resumed on the next
//! startup, with no users lost and no users duplicated.
//!
//! The crash state we test is: 50 of 100 users were fully migrated
//! (destination write, source delete, and progress marker all committed to
//! WAL), the process then crashed before the remaining 50 users were touched
//! and before the overall `completed` marker was written.
//!
//! On restart `execute_cross_realm_migration` must:
//! - Skip the 50 already-marked users.
//! - Migrate the remaining 50 users.
//! - Write the `completed` marker at the end.
//! - Leave the destination with all 100 users and the source empty.
//!
//! Rather than injecting faults into the I/O layer, we construct the
//! post-crash durable state directly — the same approach used in
//! `realm_crash.rs` and `audit_crash.rs`.

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::config::MigrateConflictPolicy;
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::migration::cross_realm::{CrossRealmMigrateOptions, execute_cross_realm_migration};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ---------------------------------------------------------------------------
// Infrastructure
// ---------------------------------------------------------------------------

const SRC_SLUG: &str = "sim-crash-src";
const N_USERS: usize = 100;
const CRASH_AFTER: usize = 50;

fn sys_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn user_primary_key(user_uuid: uuid::Uuid) -> Vec<u8> {
    format!("usr:id:{user_uuid}").into_bytes()
}

fn user_email_key(email: &str) -> Vec<u8> {
    format!("usr:email:{email}").into_bytes()
}

fn progress_key(src_slug: &str, user_uuid: uuid::Uuid) -> Vec<u8> {
    format!("config:migration:progress:{src_slug}:{user_uuid}").into_bytes()
}

fn completed_key(src_slug: &str) -> Vec<u8> {
    format!("config:migration:completed:{src_slug}").into_bytes()
}

/// Reopens storage + identity + RBAC from an existing data directory.
/// Calling this a second time on the same path simulates a process restart
/// with WAL recovery.
fn open_engines(
    dir: &std::path::Path,
) -> (
    Arc<EmbeddedStorageEngine>,
    EmbeddedIdentityEngine,
    EmbeddedRbacEngine,
) {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("identity engine");
    let rbac = EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    );
    (storage, identity, rbac)
}

/// Counts `usr:id:` entries in a realm.
fn count_users_in_realm(storage: &dyn StorageEngine, realm: &RealmId) -> usize {
    let start = b"usr:id:".to_vec();
    let mut end = start.clone();
    *end.last_mut().expect("non-empty") += 1;
    storage
        .scan(realm, &start, &end)
        .expect("scan users")
        .len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verifies that a mid-migration crash is safely resumed on the next startup.
///
/// Crash state: first 50 users fully migrated (destination written, source
/// deleted, per-user progress markers committed). No `completed` marker.
#[test]
fn simulation_crash_mid_migration_resumes_correctly() {
    let dir = tempfile::tempdir().expect("tempdir");

    // --- Phase 1: Seed users and simulate post-crash state ---
    let (storage, identity, _rbac) = open_engines(dir.path());

    let src = identity
        .create_realm(&CreateRealmRequest {
            name: SRC_SLUG.to_string(),
            config: None,
        })
        .expect("create src realm")
        .id()
        .clone();

    let dst = identity
        .create_realm(&CreateRealmRequest {
            name: "sim-crash-dst".to_string(),
            config: None,
        })
        .expect("create dst realm")
        .id()
        .clone();

    // Seed N_USERS users in source realm.
    let mut users: Vec<(uuid::Uuid, String)> = Vec::new();
    for i in 0..N_USERS {
        let email = format!("simuser-{i}@crash.example.com");
        let user = identity
            .create_user(
                &src,
                &CreateUserRequest {
                    email: email.clone(),
                    display_name: format!("Sim User {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
        users.push((*user.id().as_uuid(), email));
    }

    // Simulate the durable state after "crash following N users successfully
    // migrated." For each of the first CRASH_AFTER users:
    //   1. Copy primary record + email index to destination (destination write).
    //   2. Delete from source (source deletion).
    //   3. Write per-user progress marker (final step before process dies).
    //
    // No `completed` marker is written — the crash happened before all users
    // were processed.
    let sys = sys_realm_id();
    for (user_uuid, email) in &users[..CRASH_AFTER] {
        let pk = user_primary_key(*user_uuid);
        let ek = user_email_key(email);

        // 1. Copy to destination.
        let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if let Some(v) = storage.get(&src, &pk).expect("get primary") {
            batch.push((pk.clone(), v));
        }
        if let Some(v) = storage.get(&src, &ek).expect("get email") {
            batch.push((ek.clone(), v));
        }
        storage.put_batch(&dst, &batch).expect("copy to dst");

        // 2. Delete from source.
        storage.delete(&src, &pk).expect("delete src primary");
        storage.delete(&src, &ek).expect("delete src email");

        // 3. Write progress marker.
        storage
            .put(&sys, &progress_key(SRC_SLUG, *user_uuid), b"done")
            .expect("write progress marker");
    }

    // Sanity: source has CRASH_AFTER fewer users, destination has CRASH_AFTER.
    assert_eq!(count_users_in_realm(&*storage, &src), N_USERS - CRASH_AFTER);
    assert_eq!(count_users_in_realm(&*storage, &dst), CRASH_AFTER);
    // No completed marker yet.
    assert!(
        storage
            .get(&sys, &completed_key(SRC_SLUG))
            .expect("check completed")
            .is_none()
    );

    // Drop engines → simulate crash and WAL flush.
    drop(identity);
    drop(storage);

    // --- Phase 2: Restart and resume migration ---
    let (storage, identity, rbac) = open_engines(dir.path());

    let opts = CrossRealmMigrateOptions {
        move_semantics: true,
        users: true,
        orgs: true,
        on_conflict: MigrateConflictPolicy::Error,
    };

    let report = execute_cross_realm_migration(
        &identity as &dyn IdentityEngine,
        &rbac as &dyn RbacEngine,
        &*storage as &dyn StorageEngine,
        &src,
        &dst,
        SRC_SLUG,
        &opts,
    )
    .expect("resumed migration must not fail");

    // The resumed run migrates the remaining N_USERS - CRASH_AFTER users.
    assert_eq!(
        report.migrated,
        (N_USERS - CRASH_AFTER) as u64,
        "resumed run should migrate only the unfinished users"
    );

    // All N_USERS users must be in destination.
    assert_eq!(
        count_users_in_realm(&*storage, &dst),
        N_USERS,
        "destination must contain all {N_USERS} users after resume"
    );

    // Source must be empty (move semantics applied to remaining users).
    assert_eq!(
        count_users_in_realm(&*storage, &src),
        0,
        "source must be empty after move-semantics migration completes"
    );

    // Completed marker must now be present.
    assert!(
        storage
            .get(&sys_realm_id(), &completed_key(SRC_SLUG))
            .expect("check completed")
            .is_some(),
        "completed marker must be written after full resume"
    );
}

/// Verifies that the migration is a complete no-op when the `completed`
/// marker is already present — covers the "server restarted after a
/// successful migration" case without re-running any migration logic.
#[test]
fn simulation_crash_mid_migration_record_intact() {
    let dir = tempfile::tempdir().expect("tempdir");

    let (storage, identity, rbac) = open_engines(dir.path());

    let src = identity
        .create_realm(&CreateRealmRequest {
            name: "sim-noop-src".to_string(),
            config: None,
        })
        .expect("create src realm")
        .id()
        .clone();

    let dst = identity
        .create_realm(&CreateRealmRequest {
            name: "sim-noop-dst".to_string(),
            config: None,
        })
        .expect("create dst realm")
        .id()
        .clone();

    for i in 0..10 {
        identity
            .create_user(
                &src,
                &CreateUserRequest {
                    email: format!("noop-{i}@crash.example.com"),
                    display_name: format!("Noop {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
    }

    let opts = CrossRealmMigrateOptions {
        move_semantics: true,
        users: true,
        orgs: true,
        on_conflict: MigrateConflictPolicy::Error,
    };

    // First run: successful migration.
    let r1 = execute_cross_realm_migration(
        &identity as &dyn IdentityEngine,
        &rbac as &dyn RbacEngine,
        &*storage as &dyn StorageEngine,
        &src,
        &dst,
        "sim-noop-src",
        &opts,
    )
    .expect("first migration");
    assert_eq!(r1.migrated, 10);

    // Simulate restart.
    drop(identity);
    drop(storage);
    let (storage, identity, rbac) = open_engines(dir.path());

    // Second run: completed marker present → no-op.
    let r2 = execute_cross_realm_migration(
        &identity as &dyn IdentityEngine,
        &rbac as &dyn RbacEngine,
        &*storage as &dyn StorageEngine,
        &src,
        &dst,
        "sim-noop-src",
        &opts,
    )
    .expect("second migration (no-op)");

    assert_eq!(r2.migrated, 0, "no-op run must report zero migrated");

    // Destination still intact.
    assert_eq!(count_users_in_realm(&*storage, &dst), 10);
}
