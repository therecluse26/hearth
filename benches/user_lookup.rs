//! Criterion benchmarks for the identity engine.
//!
//! Covers `TEST_SCENARIOS.md` § Identity Engine — Benchmark:
//! 1. User lookup by ID: p50 < 20 μs, p99 < 200 μs
//! 2. User lookup by email: p50 < 20 μs, p99 < 200 μs
//! 3. User creation with Argon2id: p50 < 50 ms, p99 < 100 ms

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CleartextPassword, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an identity engine with a single user for benchmarking.
fn setup_user() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    RealmId,
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
    let realm = RealmId::generate();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
            },
        )
        .expect("create");

    let user_id = user.id().clone();
    let email = user.email().to_string();

    (dir, engine, realm, user_id, email)
}

fn bench_user_lookup_by_id(c: &mut Criterion) {
    let (_dir, engine, realm, user_id, _email) = setup_user();

    c.bench_function("identity_user_lookup_by_id", |b| {
        b.iter(|| {
            let result = engine.get_user(&realm, &user_id).expect("get");
            assert!(result.is_some());
        });
    });
}

fn bench_user_lookup_by_email(c: &mut Criterion) {
    let (_dir, engine, realm, _user_id, email) = setup_user();

    c.bench_function("identity_user_lookup_by_email", |b| {
        b.iter(|| {
            let result = engine.get_user_by_email(&realm, &email).expect("get");
            assert!(result.is_some());
        });
    });
}

fn bench_user_creation(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    // Use default config (full Argon2id parameters, NOT fast_for_testing)
    // to measure real-world password hashing performance.
    let engine = EmbeddedIdentityEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        clock,
        IdentityConfig::default(),
    )
    .expect("engine creation");
    let realm = RealmId::generate();

    let mut group = c.benchmark_group("identity_user_creation");
    // Argon2id is intentionally slow (~50ms per op), so reduce sample count.
    group.sample_size(10);

    let mut counter = 0u64;
    group.bench_function(BenchmarkId::new("create_user_with_argon2id", ""), |b| {
        b.iter(|| {
            counter += 1;
            let email = format!("bench-user-{counter}@example.com");
            let user = engine
                .create_user(
                    &realm,
                    &CreateUserRequest {
                        email: email.clone(),
                        display_name: "Bench User".to_string(),
                    },
                )
                .expect("create");
            let password = CleartextPassword::from_string("BenchmarkP@ssw0rd!".to_string());
            engine
                .set_password(&realm, user.id(), &password)
                .expect("set_password");
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_user_lookup_by_id,
    bench_user_lookup_by_email,
    bench_user_creation
);
criterion_main!(benches);
