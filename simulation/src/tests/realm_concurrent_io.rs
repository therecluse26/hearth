//! Concurrent realm ops under simulated I/O delays and faults.
//!
//! Oracle invariant (from `TEST_SCENARIOS.md` § Multi-Tenancy — Simulation):
//! "Concurrent realm operations under simulated I/O delays produce no data
//!  corruption."
//!
//! This module exercises three properties of Hearth's realm lifecycle:
//!
//!   1. Atomicity — a `create_realm` that races with an injected write
//!      fault either lands both the realm record AND its per-realm
//!      signing key, or neither (no orphaned realms with no JWKS).
//!   2. Concurrency safety — interleaved create/update/delete across many
//!      threads never panics, poisons a mutex, or leaves the store in a
//!      partially-updated state.
//!   3. Recoverability — after a process restart (close + reopen storage),
//!      WAL replay reconstructs identical invariants.
//!
//! The tests stay on real tokio + `FaultFs` to match the pattern used by
//! `realm_crash.rs`; `madsim` is not required here because the
//! concurrency we need is native thread-level.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateRealmRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

use crate::FaultFs;

/// System realm id — mirrors `identity::keys::system_realm_id`, which is
/// crate-private. Must stay in sync.
fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn realm_record_key(realm_id: &RealmId) -> Vec<u8> {
    format!("realm:id:{}", realm_id.as_uuid()).into_bytes()
}

fn realm_signing_key_key(realm_id: &RealmId) -> Vec<u8> {
    format!("realm:key:{}", realm_id.as_uuid()).into_bytes()
}

/// Opens an engine stack with the given `Fs` implementation.
fn open_engines_with_fs(
    dir: &Path,
    fs: Arc<dyn hearth::storage::fs::Fs>,
) -> (Arc<dyn StorageEngine>, Arc<EmbeddedIdentityEngine>) {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open_with_fs(config, fs).expect("open storage"))
        as Arc<dyn StorageEngine>;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            IdentityConfig::default(),
        )
        .expect("identity engine"),
    );
    (storage, identity)
}

/// Opens an engine stack on `RealFs` — used for post-recovery verification.
fn open_engines_real(dir: &Path) -> (Arc<dyn StorageEngine>, Arc<EmbeddedIdentityEngine>) {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"))
        as Arc<dyn StorageEngine>;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            IdentityConfig::default(),
        )
        .expect("identity engine"),
    );
    (storage, identity)
}

/// For every live realm, asserts that both the realm record AND the
/// per-realm signing key are present — the atomicity invariant.
fn assert_live_realm_invariants(
    storage: &dyn StorageEngine,
    identity: &EmbeddedIdentityEngine,
    realms: &[RealmId],
) {
    let sys = system_realm_id();
    for tid in realms {
        let has_record = storage
            .get(&sys, &realm_record_key(tid))
            .expect("get realm record")
            .is_some();
        let has_key = storage
            .get(&sys, &realm_signing_key_key(tid))
            .expect("get realm signing key")
            .is_some();
        // Atomicity: both must be present for any live realm. The record
        // alone = orphaned realm; the key alone = leaked key material.
        assert_eq!(
            has_record, has_key,
            "realm {tid} atomicity violation: record={has_record} key={has_key}"
        );
        if has_record {
            // Live realm must yield a valid JWKS document (exercises the
            // lazy key-loading path that depends on the signing key).
            let jwks = identity.realm_jwks(tid).expect("realm_jwks must succeed");
            assert!(
                !jwks.keys.is_empty(),
                "realm {tid} JWKS must contain at least one key"
            );
        }
    }
}

/// Scans the system realm's `realm:id:` prefix and returns all live ids.
fn list_live_realm_ids(storage: &dyn StorageEngine) -> Vec<RealmId> {
    let start = b"realm:id:".to_vec();
    let mut end = start.clone();
    if let Some(b) = end.last_mut() {
        *b = b.saturating_add(1);
    }
    let entries = storage
        .scan(&system_realm_id(), &start, &end)
        .expect("scan realms");
    entries
        .into_iter()
        .filter_map(|e| {
            let suffix = std::str::from_utf8(&e.key[start.len()..]).ok()?;
            let uuid = uuid::Uuid::parse_str(suffix).ok()?;
            Some(RealmId::new(uuid))
        })
        .collect()
}

/// Phase 1: no-delay warm-up seed. Returns the seeded realm ids.
fn seed_realms(identity: &EmbeddedIdentityEngine, n: usize) -> Vec<RealmId> {
    (0..n)
        .map(|i| {
            let t = identity
                .create_realm(&CreateRealmRequest {
                    name: format!("seed-realm-{i}"),
                    config: None,
                })
                .expect("seed create_realm");
            t.id().clone()
        })
        .collect()
}

/// Drives a mix of create/update/delete across `n_tasks` worker threads,
/// using `std::thread::spawn` so we avoid pulling in a tokio test runtime.
/// Each task performs one op against one realm chosen from `pool`.
fn run_mixed_ops(
    identity: Arc<EmbeddedIdentityEngine>,
    existing: Vec<RealmId>,
    n_tasks: usize,
) -> Vec<Option<RealmId>> {
    let mut handles = Vec::with_capacity(n_tasks);
    for i in 0..n_tasks {
        let identity = Arc::clone(&identity);
        let pool = existing.clone();
        let handle = std::thread::spawn(move || -> Option<RealmId> {
            match i % 3 {
                // Create: new realm. A write-fault mid-batch here is the
                // core atomicity case the test exercises.
                0 => identity
                    .create_realm(&CreateRealmRequest {
                        name: format!("concurrent-new-{i}"),
                        config: None,
                    })
                    .ok()
                    .map(|t| t.id().clone()),
                // Update: mutate an existing seeded realm's config. Does
                // not require atomicity but must not poison the key cache.
                1 if !pool.is_empty() => {
                    let tid = pool[i % pool.len()].clone();
                    let _ = identity.update_realm(
                        &tid,
                        &UpdateRealmRequest {
                            name: Some(format!("updated-{i}")),
                            status: None,
                            config: None,
                        },
                    );
                    Some(tid)
                }
                // Delete: cascade a seeded realm. delete_realm is
                // idempotent per the Step 19 P0 fix, so duplicate deletes
                // are safe.
                _ if !pool.is_empty() => {
                    let tid = pool[i % pool.len()].clone();
                    let _ = identity.delete_realm(&tid);
                    None
                }
                _ => None,
            }
        });
        handles.push(handle);
    }

    handles
        .into_iter()
        .map(|h| h.join().expect("worker thread panicked"))
        .collect()
}

/// Test 1 — pure concurrency with I/O delays.
///
/// No fault injection; just write/sync latency + jitter. Every successful
/// op must leave realms in a consistent state, both immediately and after
/// a process restart.
#[test]
fn simulation_concurrent_realm_ops_under_io_delay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path: PathBuf = dir.path().to_path_buf();

    // Phase 1: seed 8 realms with no latency.
    let seed = {
        let (_storage, identity) = open_engines_real(&dir_path);
        seed_realms(&identity, 8)
    };

    // Phase 2: reopen with latency-injecting FaultFs and run mixed ops.
    let fault = FaultFs::new();
    // write=200µs base, sync=500µs base, jitter up to 150µs. These numbers
    // are small enough to keep the test under a second on CI but large
    // enough to scramble thread interleavings.
    fault.config.set_latency(0, 200, 500, 150, 0x00C0_FFEE);
    let fault = Arc::new(fault);

    let leftover_after_concurrent = {
        let (storage, identity) = open_engines_with_fs(&dir_path, Arc::clone(&fault) as Arc<_>);

        // 24 tasks is enough to produce contention on the key cache mutex
        // plus multiple WAL appends per scheduling quantum.
        run_mixed_ops(Arc::clone(&identity), seed.clone(), 24);

        let live = list_live_realm_ids(storage.as_ref());
        assert_live_realm_invariants(storage.as_ref(), identity.as_ref(), &live);
        live
    };

    // Phase 3: reopen on RealFs and re-verify that WAL replay restored
    // exactly the same invariants — no lost writes, no orphaned keys.
    let (storage, identity) = open_engines_real(&dir_path);
    let live_after_reopen = list_live_realm_ids(storage.as_ref());
    assert_live_realm_invariants(storage.as_ref(), identity.as_ref(), &live_after_reopen);

    // The set of live realms must be identical across the reopen.
    let mut a = leftover_after_concurrent;
    let mut b = live_after_reopen;
    a.sort_by_key(|t| t.as_uuid().as_bytes().to_vec());
    b.sort_by_key(|t| t.as_uuid().as_bytes().to_vec());
    assert_eq!(
        a, b,
        "WAL replay did not reconstruct the same live realm set"
    );
}

/// Test 2 — concurrency + mid-run write fault.
///
/// Before the `create_realm` → `put_batch` refactor, a write fault between
/// the realm-record `put()` and the signing-key `put()` would leave an
/// orphaned realm record with no key — `realm_jwks()` would then error,
/// violating the invariant. With `put_batch`, that window does not exist:
/// both entries land atomically or neither does.
#[test]
fn simulation_concurrent_realm_ops_with_write_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path: PathBuf = dir.path().to_path_buf();

    let seed = {
        let (_storage, identity) = open_engines_real(&dir_path);
        seed_realms(&identity, 6)
    };

    let fault = FaultFs::new();
    // Light latency so the fault has time to race with in-flight ops on
    // other threads.
    fault.config.set_latency(0, 100, 200, 80, 0xDEAD);
    // Arm a fault after 16 successful writes — guaranteed to land somewhere
    // in the middle of create/update/delete activity below.
    fault.config.fail_write_after(16);
    let fault = Arc::new(fault);

    {
        let (storage, identity) = open_engines_with_fs(&dir_path, Arc::clone(&fault) as Arc<_>);
        run_mixed_ops(Arc::clone(&identity), seed.clone(), 24);

        // After the run, disable further faults so invariant checks can
        // read freely.
        fault.config.reset();

        let live = list_live_realm_ids(storage.as_ref());
        assert_live_realm_invariants(storage.as_ref(), identity.as_ref(), &live);
    }

    // Process restart: WAL replay must converge to the same invariants.
    let (storage, identity) = open_engines_real(&dir_path);
    let live = list_live_realm_ids(storage.as_ref());
    assert_live_realm_invariants(storage.as_ref(), identity.as_ref(), &live);
}
