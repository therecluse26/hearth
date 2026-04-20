//! Criterion benchmark for the Admin API user listing path (Step 31.4).
//!
//! Targets (per `TEST_SCENARIOS.md` § Phase 1 cross-cutting):
//! - Admin user listing: p50 < 5 ms, p99 < 50 ms per page.
//!
//! The benchmark pre-populates a realm with 10,000 users and then
//! repeatedly pages through them using the public `list_users` API.

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const USER_COUNT: usize = 10_000;
const PAGE_SIZE: usize = 100;

/// Sets up an engine with a realm and `USER_COUNT` users.
fn setup_admin() -> (tempfile::TempDir, EmbeddedIdentityEngine, RealmId) {
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

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "bench-admin-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    for i in 0..USER_COUNT {
        engine
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email: format!("user-{i:05}@bench.example.com"),
                    display_name: format!("Bench User {i}"),
                },
            )
            .expect("create user");
    }

    (dir, engine, realm_id)
}

/// Benchmarks a single page of `list_users` at the middle of the dataset.
///
/// We measure a single-page read (not the whole cursor walk) so criterion
/// reports per-page latency directly, matching the target budget.
fn bench_admin_list_users_page(c: &mut Criterion) {
    let (_dir, engine, realm_id) = setup_admin();

    // Walk forward to a mid-dataset cursor so we benchmark a steady-state
    // page read rather than the first page (which is always the hottest).
    let mut cursor: Option<String> = None;
    for _ in 0..(USER_COUNT / PAGE_SIZE / 2) {
        let page = engine
            .list_users(&realm_id, cursor.as_deref(), PAGE_SIZE)
            .expect("list_users");
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    let mid_cursor = cursor;

    c.bench_function("admin_list_users_page_mid", |b| {
        b.iter(|| {
            let page = engine
                .list_users(&realm_id, mid_cursor.as_deref(), PAGE_SIZE)
                .expect("list_users");
            assert_eq!(page.items.len(), PAGE_SIZE);
        });
    });
}

/// Benchmarks the full paginated walk through all `USER_COUNT` users.
///
/// Exposes amortized per-page cost across the whole dataset.
fn bench_admin_list_users_full_walk(c: &mut Criterion) {
    let (_dir, engine, realm_id) = setup_admin();

    c.bench_function("admin_list_users_full_walk", |b| {
        b.iter(|| {
            let mut cursor: Option<String> = None;
            let mut total = 0usize;
            loop {
                let page = engine
                    .list_users(&realm_id, cursor.as_deref(), PAGE_SIZE)
                    .expect("list_users");
                total += page.items.len();
                match page.next_cursor {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            assert_eq!(total, USER_COUNT);
        });
    });
}

criterion_group!(
    benches,
    bench_admin_list_users_page,
    bench_admin_list_users_full_walk
);
criterion_main!(benches);
