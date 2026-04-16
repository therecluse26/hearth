//! Concurrent tenant ops under simulated I/O delays and faults.
//!
//! Oracle invariant (from `TEST_SCENARIOS.md` § Multi-Tenancy — Simulation):
//! "Concurrent tenant operations under simulated I/O delays produce no data
//!  corruption."
//!
//! This module exercises three properties of Hearth's tenant lifecycle:
//!
//!   1. Atomicity — a `create_tenant` that races with an injected write
//!      fault either lands both the tenant record AND its per-tenant
//!      signing key, or neither (no orphaned tenants with no JWKS).
//!   2. Concurrency safety — interleaved create/update/delete across many
//!      threads never panics, poisons a mutex, or leaves the store in a
//!      partially-updated state.
//!   3. Recoverability — after a process restart (close + reopen storage),
//!      WAL replay reconstructs identical invariants.
//!
//! The tests stay on real tokio + `FaultFs` to match the pattern used by
//! `tenant_crash.rs`; `madsim` is not required here because the
//! concurrency we need is native thread-level.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hearth::core::{Clock, SystemClock, TenantId};
use hearth::identity::{
    CreateTenantRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    UpdateTenantRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

use crate::FaultFs;

/// System tenant id — mirrors `identity::keys::system_tenant_id`, which is
/// crate-private. Must stay in sync.
fn system_tenant_id() -> TenantId {
    TenantId::new(uuid::Uuid::nil())
}

fn tenant_record_key(tenant_id: &TenantId) -> Vec<u8> {
    format!("tenant:id:{}", tenant_id.as_uuid()).into_bytes()
}

fn tenant_signing_key_key(tenant_id: &TenantId) -> Vec<u8> {
    format!("tenant:key:{}", tenant_id.as_uuid()).into_bytes()
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

/// For every live tenant, asserts that both the tenant record AND the
/// per-tenant signing key are present — the atomicity invariant.
fn assert_live_tenant_invariants(
    storage: &dyn StorageEngine,
    identity: &EmbeddedIdentityEngine,
    tenants: &[TenantId],
) {
    let sys = system_tenant_id();
    for tid in tenants {
        let has_record = storage
            .get(&sys, &tenant_record_key(tid))
            .expect("get tenant record")
            .is_some();
        let has_key = storage
            .get(&sys, &tenant_signing_key_key(tid))
            .expect("get tenant signing key")
            .is_some();
        // Atomicity: both must be present for any live tenant. The record
        // alone = orphaned tenant; the key alone = leaked key material.
        assert_eq!(
            has_record, has_key,
            "tenant {tid} atomicity violation: record={has_record} key={has_key}"
        );
        if has_record {
            // Live tenant must yield a valid JWKS document (exercises the
            // lazy key-loading path that depends on the signing key).
            let jwks = identity.tenant_jwks(tid).expect("tenant_jwks must succeed");
            assert!(
                !jwks.keys.is_empty(),
                "tenant {tid} JWKS must contain at least one key"
            );
        }
    }
}

/// Scans the system tenant's `tenant:id:` prefix and returns all live ids.
fn list_live_tenant_ids(storage: &dyn StorageEngine) -> Vec<TenantId> {
    let start = b"tenant:id:".to_vec();
    let mut end = start.clone();
    if let Some(b) = end.last_mut() {
        *b = b.saturating_add(1);
    }
    let entries = storage
        .scan(&system_tenant_id(), &start, &end)
        .expect("scan tenants");
    entries
        .into_iter()
        .filter_map(|e| {
            let suffix = std::str::from_utf8(&e.key[start.len()..]).ok()?;
            let uuid = uuid::Uuid::parse_str(suffix).ok()?;
            Some(TenantId::new(uuid))
        })
        .collect()
}

/// Phase 1: no-delay warm-up seed. Returns the seeded tenant ids.
fn seed_tenants(identity: &EmbeddedIdentityEngine, n: usize) -> Vec<TenantId> {
    (0..n)
        .map(|i| {
            let t = identity
                .create_tenant(&CreateTenantRequest {
                    name: format!("seed-tenant-{i}"),
                    config: None,
                })
                .expect("seed create_tenant");
            t.id().clone()
        })
        .collect()
}

/// Drives a mix of create/update/delete across `n_tasks` worker threads,
/// using `std::thread::spawn` so we avoid pulling in a tokio test runtime.
/// Each task performs one op against one tenant chosen from `pool`.
fn run_mixed_ops(
    identity: Arc<EmbeddedIdentityEngine>,
    existing: Vec<TenantId>,
    n_tasks: usize,
) -> Vec<Option<TenantId>> {
    let mut handles = Vec::with_capacity(n_tasks);
    for i in 0..n_tasks {
        let identity = Arc::clone(&identity);
        let pool = existing.clone();
        let handle = std::thread::spawn(move || -> Option<TenantId> {
            match i % 3 {
                // Create: new tenant. A write-fault mid-batch here is the
                // core atomicity case the test exercises.
                0 => identity
                    .create_tenant(&CreateTenantRequest {
                        name: format!("concurrent-new-{i}"),
                        config: None,
                    })
                    .ok()
                    .map(|t| t.id().clone()),
                // Update: mutate an existing seeded tenant's config. Does
                // not require atomicity but must not poison the key cache.
                1 if !pool.is_empty() => {
                    let tid = pool[i % pool.len()].clone();
                    let _ = identity.update_tenant(
                        &tid,
                        &UpdateTenantRequest {
                            name: Some(format!("updated-{i}")),
                            status: None,
                            config: None,
                        },
                    );
                    Some(tid)
                }
                // Delete: cascade a seeded tenant. delete_tenant is
                // idempotent per the Step 19 P0 fix, so duplicate deletes
                // are safe.
                _ if !pool.is_empty() => {
                    let tid = pool[i % pool.len()].clone();
                    let _ = identity.delete_tenant(&tid);
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
/// op must leave tenants in a consistent state, both immediately and after
/// a process restart.
#[test]
fn simulation_concurrent_tenant_ops_under_io_delay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path: PathBuf = dir.path().to_path_buf();

    // Phase 1: seed 8 tenants with no latency.
    let seed = {
        let (_storage, identity) = open_engines_real(&dir_path);
        seed_tenants(&identity, 8)
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

        let live = list_live_tenant_ids(storage.as_ref());
        assert_live_tenant_invariants(storage.as_ref(), identity.as_ref(), &live);
        live
    };

    // Phase 3: reopen on RealFs and re-verify that WAL replay restored
    // exactly the same invariants — no lost writes, no orphaned keys.
    let (storage, identity) = open_engines_real(&dir_path);
    let live_after_reopen = list_live_tenant_ids(storage.as_ref());
    assert_live_tenant_invariants(storage.as_ref(), identity.as_ref(), &live_after_reopen);

    // The set of live tenants must be identical across the reopen.
    let mut a = leftover_after_concurrent;
    let mut b = live_after_reopen;
    a.sort_by_key(|t| t.as_uuid().as_bytes().to_vec());
    b.sort_by_key(|t| t.as_uuid().as_bytes().to_vec());
    assert_eq!(
        a, b,
        "WAL replay did not reconstruct the same live tenant set"
    );
}

/// Test 2 — concurrency + mid-run write fault.
///
/// Before the `create_tenant` → `put_batch` refactor, a write fault between
/// the tenant-record `put()` and the signing-key `put()` would leave an
/// orphaned tenant record with no key — `tenant_jwks()` would then error,
/// violating the invariant. With `put_batch`, that window does not exist:
/// both entries land atomically or neither does.
#[test]
fn simulation_concurrent_tenant_ops_with_write_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path: PathBuf = dir.path().to_path_buf();

    let seed = {
        let (_storage, identity) = open_engines_real(&dir_path);
        seed_tenants(&identity, 6)
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

        let live = list_live_tenant_ids(storage.as_ref());
        assert_live_tenant_invariants(storage.as_ref(), identity.as_ref(), &live);
    }

    // Process restart: WAL replay must converge to the same invariants.
    let (storage, identity) = open_engines_real(&dir_path);
    let live = list_live_tenant_ids(storage.as_ref());
    assert_live_tenant_invariants(storage.as_ref(), identity.as_ref(), &live);
}
