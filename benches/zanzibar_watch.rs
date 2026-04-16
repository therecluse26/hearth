//! Criterion benchmark for Zanzibar watch event delivery latency.
//!
//! Targets (per `TEST_SCENARIOS.md` § Zanzibar Full — Benchmark and
//! `VISION.md` § 7.1):
//! - Watch event delivery: p50 < 1 ms, p99 < 10 ms end-to-end from
//!   `write_tuples()` dispatch to the subscriber observing `rx.recv()`.
//!
//! The harness opens one subscriber, then repeatedly issues a single-tuple
//! write and awaits the corresponding event on the subscriber, measuring the
//! full round-trip. A dedicated tokio runtime is created once so the cost of
//! runtime construction does not enter the measured window.

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite, WatchFilter, WatchReceiver,
};
use hearth::core::TenantId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tokio::runtime::Runtime;

fn setup() -> (
    tempfile::TempDir,
    Arc<EmbeddedAuthzEngine>,
    TenantId,
    Runtime,
    WatchReceiver,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open storage");
    let engine = Arc::new(EmbeddedAuthzEngine::new(
        Arc::new(storage),
        AuthzConfig::default(),
    ));
    let tenant = TenantId::generate();

    let rt = Runtime::new().expect("runtime");
    let rx = engine
        .watch(&tenant, &WatchFilter { object_type: None }, None)
        .expect("watch");
    (dir, engine, tenant, rt, rx)
}

fn make_tuple(seed: u64) -> RelationshipTuple {
    let obj = ObjectRef::new("document", &format!("doc{seed}")).expect("valid object");
    let subj = SubjectRef::direct("user", &format!("user{seed}")).expect("valid subject");
    RelationshipTuple::new(obj, "viewer", subj).expect("valid tuple")
}

fn bench_watch_event_delivery(c: &mut Criterion) {
    let (_dir, engine, tenant, rt, mut rx) = setup();

    // Counter ensures every iteration dispatches a unique tuple so namespace
    // dedup logic cannot short-circuit the write.
    let mut i: u64 = 0;

    c.bench_function("watch_event_delivery", |b| {
        b.iter(|| {
            i += 1;
            let tuple = make_tuple(i);
            engine
                .write_tuples(&tenant, &[TupleWrite::Touch(tuple)])
                .expect("write");

            // Block the current thread on the tokio runtime until the event
            // lands. Using block_on here is the standard criterion pattern for
            // driving an async op inside a sync benchmark iteration.
            rt.block_on(async {
                rx.recv().await.expect("event");
            });
        });
    });
}

criterion_group!(benches, bench_watch_event_delivery);
criterion_main!(benches);
