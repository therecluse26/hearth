//! Criterion benchmarks for session management.
//!
//! Covers `TEST_SCENARIOS.md` § Session Management — Benchmark:
//! 1. Session lookup by ID: p50 < 10 μs, p99 < 100 μs
//! 2. Session creation throughput: > 50,000 ops/sec/core

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::core::{Clock, SystemClock, TenantId};
use hearth::identity::{CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an identity engine with a user and an active session.
fn setup_session() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    TenantId,
    hearth::core::SessionId,
    hearth::core::UserId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        clock,
        IdentityConfig::default(),
    )
    .expect("engine creation");
    let tenant = TenantId::generate();

    let user = engine
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "bench-session@example.com".to_string(),
                display_name: "Bench Session User".to_string(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(
            &tenant,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Read the session once to ensure it's in the hot tier
    let _ = engine.get_session(&tenant, session.id());

    (dir, engine, tenant, session.id().clone(), user.id().clone())
}

/// Benchmarks session lookup by ID (hot path).
fn bench_session_lookup_by_id(c: &mut Criterion) {
    let (_dir, engine, tenant, session_id, _user_id) = setup_session();

    c.bench_function("session_lookup_by_id", |b| {
        b.iter(|| {
            let result = engine.get_session(&tenant, &session_id).expect("get");
            assert!(result.is_some());
        });
    });
}

/// Benchmarks session creation throughput.
fn bench_session_creation(c: &mut Criterion) {
    let (_dir, engine, tenant, _session_id, user_id) = setup_session();

    c.bench_function("session_creation", |b| {
        b.iter(|| {
            let result = engine.create_session(
                &tenant,
                &user_id,
                &hearth::identity::SessionContext::default(),
            );
            assert!(result.is_ok());
        });
    });
}

criterion_group!(benches, bench_session_lookup_by_id, bench_session_creation);
criterion_main!(benches);
