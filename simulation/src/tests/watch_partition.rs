//! Watch API partition/resume simulation tests.
//!
//! Oracle invariant: a watcher that disconnects (simulated by dropping the
//! live receiver) and later reconnects with a `resume_from` zookie MUST
//! receive every event emitted during its absence, in monotonic sequence
//! order and correctly scoped to its tenant.
//!
//! This covers `TEST_SCENARIOS.md` § Zanzibar Full — Simulation:
//! "Watch API under network partition (resume / resync)".

use std::sync::Arc;

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite, WatchFilter,
};
use hearth::core::TenantId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

/// Builds an authz engine on a fresh tempdir.
fn setup_engine() -> (tempfile::TempDir, Arc<EmbeddedAuthzEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open storage");
    let engine = EmbeddedAuthzEngine::new(Arc::new(storage), AuthzConfig::default());
    (dir, Arc::new(engine))
}

/// Synthesises a deterministic tuple from a seed.
fn make_tuple(seed: u32) -> RelationshipTuple {
    let obj = ObjectRef::new("document", &format!("doc{seed}")).expect("valid object");
    let subj = SubjectRef::direct("user", &format!("user{seed}")).expect("valid subject");
    RelationshipTuple::new(obj, "viewer", subj).expect("valid tuple")
}

/// Simulated partition: W1 disconnects, 50 writes happen across 3 tenants,
/// W2 reconnects with `resume_from` and must receive every missed event
/// scoped to its tenant.
#[test]
fn simulation_watch_partition_replay_delivers_all_missed_events() {
    let seed = 61u64;
    let _ = seed;

    const WRITES_PER_TENANT: u32 = 50;

    let (_dir, engine) = setup_engine();

    // Three distinct tenants — guarantees per-tenant isolation of the
    // replay buffer.
    let tenants: Vec<TenantId> = (0..3).map(|_| TenantId::generate()).collect();

    // Phase 1: anchor each tenant with one initial write. The returned
    // zookie marks the "last seen" point from W1's perspective — every
    // write with sequence > this version should land in W2's replay.
    let mut anchor_zookies = Vec::with_capacity(tenants.len());
    for tenant in &tenants {
        let zookie = engine
            .write_tuples(tenant, &[TupleWrite::Touch(make_tuple(0))])
            .expect("write anchor");
        anchor_zookies.push(zookie);
    }

    // Phase 2: simulate partition. W1 is "disconnected" — we simply never
    // hold a subscriber during this window. The broadcast channel would
    // drop live events with no receivers; persisted events are what
    // makes replay possible.
    for (i, tenant) in tenants.iter().enumerate() {
        for seq in 1..=WRITES_PER_TENANT {
            // Unique seed per (tenant, seq) so duplicate-suppression in
            // `write_tuples` doesn't collapse them into a single event.
            #[allow(clippy::cast_possible_truncation)]
            let marker = (i as u32) * 1_000 + seq;
            engine
                .write_tuples(tenant, &[TupleWrite::Touch(make_tuple(marker))])
                .expect("write during partition");
        }
    }

    // Phase 3: W2 reconnects with the anchor zookie. Each tenant's W2
    // MUST observe exactly WRITES_PER_TENANT replay events tagged with
    // its own tenant id.
    for (i, tenant) in tenants.iter().enumerate() {
        let mut rx = engine
            .watch(
                tenant,
                &WatchFilter { object_type: None },
                Some(&anchor_zookies[i]),
            )
            .expect("reconnect watch");

        let mut drained = Vec::new();
        while let Some(event) = rx.drain_replay() {
            drained.push(event);
        }

        assert_eq!(
            drained.len(),
            WRITES_PER_TENANT as usize,
            "tenant {i}: reconnected watcher must receive all {WRITES_PER_TENANT} missed events (seed={seed})",
        );

        // Sequence numbers must be strictly increasing (monotonic delivery).
        for window in drained.windows(2) {
            assert!(
                window[1].sequence > window[0].sequence,
                "tenant {i}: replay events must be in monotonic sequence order (seed={seed})",
            );
        }

        // Every replayed event must be tagged with the right tenant — the
        // `load_events_since` scan is bounded to this tenant's keyspace,
        // so a leak here would mean a storage-level isolation breach.
        for event in &drained {
            assert_eq!(
                event.tenant_id,
                tenant.to_string(),
                "tenant {i}: replay event leaked across tenant boundary (seed={seed})",
            );
        }

        // Every replayed sequence must be strictly greater than the
        // anchor zookie — no double-delivery of the anchor event.
        for event in &drained {
            assert!(
                event.sequence > anchor_zookies[i].version(),
                "tenant {i}: replay event sequence {} must exceed anchor {}",
                event.sequence,
                anchor_zookies[i].version(),
            );
        }
    }
}

/// Zookie taken AFTER the partition's writes should replay nothing — the
/// watcher is already caught up. Catches off-by-one bugs in
/// `load_events_since`.
#[test]
fn simulation_watch_resume_from_latest_replays_nothing() {
    let seed = 62u64;
    let _ = seed;

    let (_dir, engine) = setup_engine();
    let tenant = TenantId::generate();

    // Emit a small burst of events.
    let mut last_zookie = None;
    for i in 0..5 {
        let zookie = engine
            .write_tuples(&tenant, &[TupleWrite::Touch(make_tuple(i))])
            .expect("write");
        last_zookie = Some(zookie);
    }
    let anchor = last_zookie.expect("anchor");

    // Reconnect AT the latest point — no events should be in replay.
    let mut rx = engine
        .watch(&tenant, &WatchFilter { object_type: None }, Some(&anchor))
        .expect("reconnect");

    assert!(
        rx.drain_replay().is_none(),
        "watcher at current zookie should have empty replay (seed={seed})",
    );
}
