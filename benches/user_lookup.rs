//! Criterion benchmarks for the identity engine.
//!
//! Covers `TEST_SCENARIOS.md` § Identity Engine — Benchmark:
//! 1. User lookup by ID: p50 < 20 μs, p99 < 200 μs
//! 2. User lookup by email: p50 < 20 μs, p99 < 200 μs

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::core::{Clock, SystemClock, TenantId};
use hearth::identity::{CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an identity engine with a single user for benchmarking.
fn setup_user() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    TenantId,
    hearth::core::UserId,
    String,
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
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create");

    let user_id = user.id().clone();
    let email = user.email().to_string();

    (dir, engine, tenant, user_id, email)
}

fn bench_user_lookup_by_id(c: &mut Criterion) {
    let (_dir, engine, tenant, user_id, _email) = setup_user();

    c.bench_function("identity_user_lookup_by_id", |b| {
        b.iter(|| {
            let result = engine.get_user(&tenant, &user_id).expect("get");
            assert!(result.is_some());
        });
    });
}

fn bench_user_lookup_by_email(c: &mut Criterion) {
    let (_dir, engine, tenant, _user_id, email) = setup_user();

    c.bench_function("identity_user_lookup_by_email", |b| {
        b.iter(|| {
            let result = engine.get_user_by_email(&tenant, &email).expect("get");
            assert!(result.is_some());
        });
    });
}

criterion_group!(benches, bench_user_lookup_by_id, bench_user_lookup_by_email);
criterion_main!(benches);
