//! Criterion benchmark for the Audit query path (Step 31.5).
//!
//! Targets (per `TEST_SCENARIOS.md` § Phase 1 cross-cutting):
//! - Audit time-range query: p50 < 10 ms, p99 < 100 ms.
//!
//! The benchmark pre-populates a realm with 100,000 audit events
//! spanning a synthetic time range and queries a ~1 % slice by actor.

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::audit::AuditAction;
use hearth::audit::{AuditEngine, AuditQuery, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const EVENT_COUNT: usize = 100_000;

/// Sets up an audit engine pre-loaded with `EVENT_COUNT` events.
fn setup_audit() -> (tempfile::TempDir, EmbeddedAuditEngine, RealmId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let engine = EmbeddedAuditEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    );

    let realm_id = RealmId::generate();

    // Cycle through a small pool of actors so a filter by actor matches
    // approximately 1 % of the dataset — aligned with the query budget.
    let actors: [&str; 100] = std::array::from_fn(|i| {
        let s = Box::leak(format!("actor-{i:03}").into_boxed_str());
        s as &str
    });

    for i in 0..EVENT_COUNT {
        let actor = actors[i % actors.len()];
        engine
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: actor.to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: format!("user-{i}"),
                metadata: None,
            })
            .expect("append");
    }

    (dir, engine, realm_id)
}

/// Benchmarks a scoped audit query filtered by actor.
///
/// The filter selects ~1 % of events (one actor out of 100), modelling
/// a typical admin "what did this user do?" lookup.
fn bench_audit_query_by_actor(c: &mut Criterion) {
    let (_dir, engine, realm_id) = setup_audit();

    c.bench_function("audit_query_by_actor", |b| {
        b.iter(|| {
            let query = AuditQuery {
                realm_id: realm_id.clone(),
                start_time: None,
                end_time: None,
                actor: Some("actor-042".to_string()),
                action: None,
                limit: Some(2000),
            };
            let events = engine.query(&query).expect("query");
            assert!(!events.is_empty(), "actor should have events");
        });
    });
}

/// Benchmarks an unbounded (realm-only) audit query — worst case.
fn bench_audit_query_all(c: &mut Criterion) {
    let (_dir, engine, realm_id) = setup_audit();

    c.bench_function("audit_query_all_limited", |b| {
        b.iter(|| {
            let query = AuditQuery {
                realm_id: realm_id.clone(),
                start_time: None,
                end_time: None,
                actor: None,
                action: None,
                limit: Some(1000),
            };
            let events = engine.query(&query).expect("query");
            assert!(!events.is_empty());
        });
    });
}

criterion_group!(benches, bench_audit_query_by_actor, bench_audit_query_all);
criterion_main!(benches);
