//! CI threshold gates for storage hot-path latency targets.
//!
//! Enforces the p50 and p99 latency targets documented in
//! `src/storage/tiered.rs` and `docs/specs/TEST_SCENARIOS.md`.
//!
//! # CI Threshold Gates
//!
//! Two percentile gates run at binary startup (before Criterion sampling).
//! The bench binary exits non-zero if any limit is breached, causing
//! `make bench-gate` — and therefore `make ci-standard` — to fail.
//!
//! | Gate | p50 limit | p99 limit |
//! |------|-----------|-----------|
//! | `storage_hot_tier_lookup` | 10 μs | 100 μs |
//! | `session_lookup_by_id`    | 10 μs | 100 μs |
//! | `user_lookup_by_id`       | 20 μs | 200 μs |
//! | `user_lookup_by_email`    | 20 μs | 200 μs |
//!
//! Gates collect [`GATE_SAMPLES`] measurements after [`GATE_WARMUP`] discard
//! iterations, then assert p50 (`samples[len/2]`) and p99
//! (`samples[len*99/100]`). Panicking here causes non-zero exit.
//!
//! Thresholds derive from `docs/specs/ARCHITECTURE.md` § Hot Path Rules and
//! `TEST_SCENARIOS.md` § Storage Tiered Hot/Cold + Session Management +
//! Identity Engine Benchmark scenarios.

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, Criterion};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Threshold constants ───────────────────────────────────────────────────────

/// Hard p50 limit for storage hot-tier key lookup.
const STORAGE_HOT_P50: Duration = Duration::from_micros(10);
/// Hard p99 limit for storage hot-tier key lookup.
const STORAGE_HOT_P99: Duration = Duration::from_micros(100);

/// Hard p50 limit for session lookup by ID (the `lookup_session` hot path).
const SESSION_LOOKUP_P50: Duration = Duration::from_micros(10);
/// Hard p99 limit for session lookup by ID.
const SESSION_LOOKUP_P99: Duration = Duration::from_micros(100);

/// Hard p50 limit for user lookup by ID or email index.
const USER_LOOKUP_P50: Duration = Duration::from_micros(20);
/// Hard p99 limit for user lookup by ID or email index.
const USER_LOOKUP_P99: Duration = Duration::from_micros(200);

/// Samples collected per gate for percentile estimation.
const GATE_SAMPLES: usize = 10_000;

/// Warm-up iterations discarded before gate measurement begins.
const GATE_WARMUP: usize = 200;

// ── Shared setup ──────────────────────────────────────────────────────────────

/// Creates an identity engine backed by a fresh temporary directory.
///
/// Returns the `TempDir` handle so the caller can keep it alive for the
/// duration of the benchmark.
fn make_identity_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine, RealmId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("engine");
    let realm = RealmId::generate();
    (dir, engine, realm)
}

// ── Gate helper ───────────────────────────────────────────────────────────────

/// Sort `samples`, then panic if p50 or p99 exceeds their respective limits.
fn assert_percentiles(
    samples: &mut [Duration],
    gate: &str,
    p50_limit: Duration,
    p99_limit: Duration,
) {
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    assert!(
        p50 <= p50_limit,
        "{gate} p50 {p50:?} exceeds CI limit {p50_limit:?} \
         — see benches/storage_gate.rs for threshold rationale"
    );
    assert!(
        p99 <= p99_limit,
        "{gate} p99 {p99:?} exceeds CI limit {p99_limit:?} \
         — see benches/storage_gate.rs for threshold rationale"
    );
}

// ── Gate functions ────────────────────────────────────────────────────────────

/// Assert `EmbeddedStorageEngine::get()` hot-tier p50 ≤ 10 μs and p99 ≤ 100 μs.
///
/// Keys are pre-populated and promoted to the hot tier via a read pass before
/// measurement begins, matching the steady-state `lookup_session` invariant.
fn gate_storage_hot_tier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine =
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open");
    let realm = RealmId::generate();

    // Pre-compute keys to avoid allocator noise inside the measurement loop.
    let keys: Vec<Vec<u8>> = (0..1_000_usize)
        .map(|i| format!("sess:{i:08}").into_bytes())
        .collect();

    for (i, key) in keys.iter().enumerate() {
        let value = format!("session-data-{i:08}-padding-to-realistic-size-xxxxxxxxxxxxx");
        engine.put(&realm, key, value.as_bytes()).expect("put");
    }
    // Promote every key to the hot tier before measuring.
    for key in &keys {
        let _ = engine.get(&realm, key);
    }

    for i in 0..GATE_WARMUP {
        black_box(
            engine
                .get(&realm, black_box(&keys[i % 1_000]))
                .expect("get"),
        );
    }

    let mut samples = Vec::with_capacity(GATE_SAMPLES);
    for i in 0..GATE_SAMPLES {
        let key = &keys[i % 1_000];
        let start = Instant::now();
        black_box(engine.get(&realm, black_box(key)).expect("get"));
        samples.push(start.elapsed());
    }

    assert_percentiles(
        &mut samples,
        "storage_hot_tier_lookup",
        STORAGE_HOT_P50,
        STORAGE_HOT_P99,
    );
    drop(dir);
}

/// Assert `get_session` by ID p50 ≤ 10 μs and p99 ≤ 100 μs.
fn gate_session_lookup() {
    let (_dir, engine, realm) = make_identity_engine();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "gate-session@example.com".to_string(),
                display_name: "Gate Session".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let session_id = session.id().clone();

    // Warm-up also promotes the session to the hot tier.
    for _ in 0..GATE_WARMUP {
        black_box(
            engine
                .get_session(&realm, black_box(&session_id))
                .expect("get"),
        );
    }

    let mut samples = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        black_box(
            engine
                .get_session(&realm, black_box(&session_id))
                .expect("get"),
        );
        samples.push(start.elapsed());
    }

    assert_percentiles(
        &mut samples,
        "session_lookup_by_id",
        SESSION_LOOKUP_P50,
        SESSION_LOOKUP_P99,
    );
}

/// Assert `get_user` by ID p50 ≤ 20 μs and p99 ≤ 200 μs.
fn gate_user_lookup_by_id() {
    let (_dir, engine, realm) = make_identity_engine();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "gate-user-id@example.com".to_string(),
                display_name: "Gate User ID".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let user_id = user.id().clone();

    for _ in 0..GATE_WARMUP {
        black_box(engine.get_user(&realm, black_box(&user_id)).expect("get"));
    }

    let mut samples = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        black_box(engine.get_user(&realm, black_box(&user_id)).expect("get"));
        samples.push(start.elapsed());
    }

    assert_percentiles(
        &mut samples,
        "user_lookup_by_id",
        USER_LOOKUP_P50,
        USER_LOOKUP_P99,
    );
}

/// Assert `get_user_by_email` p50 ≤ 20 μs and p99 ≤ 200 μs.
fn gate_user_lookup_by_email() {
    let (_dir, engine, realm) = make_identity_engine();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "gate-user-email@example.com".to_string(),
                display_name: "Gate User Email".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let email = user.email().to_string();

    for _ in 0..GATE_WARMUP {
        black_box(
            engine
                .get_user_by_email(&realm, black_box(email.as_str()))
                .expect("get"),
        );
    }

    let mut samples = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        black_box(
            engine
                .get_user_by_email(&realm, black_box(email.as_str()))
                .expect("get"),
        );
        samples.push(start.elapsed());
    }

    assert_percentiles(
        &mut samples,
        "user_lookup_by_email",
        USER_LOOKUP_P50,
        USER_LOOKUP_P99,
    );
}

// ── Criterion benchmarks ──────────────────────────────────────────────────────
// These generate HTML reports and baseline data complementary to the hard gates.

fn bench_storage_hot_tier(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine =
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open");
    let realm = RealmId::generate();

    let keys: Vec<Vec<u8>> = (0..1_000_usize)
        .map(|i| format!("sess:{i:08}").into_bytes())
        .collect();
    for (i, key) in keys.iter().enumerate() {
        let value = format!("session-data-{i:08}-padding-to-realistic-size-xxxxxxxxxxxxx");
        engine.put(&realm, key, value.as_bytes()).expect("put");
    }
    for key in &keys {
        let _ = engine.get(&realm, key);
    }

    c.bench_function("storage_gate_hot_tier_lookup", |b| {
        let mut i = 0_usize;
        b.iter(|| {
            let r = engine.get(&realm, &keys[i % 1_000]).expect("get");
            assert!(r.is_some());
            i += 1;
        });
    });
    // Keep dir alive until Criterion finishes sampling.
    drop(dir);
}

fn bench_session_lookup(c: &mut Criterion) {
    let (_dir, engine, realm) = make_identity_engine();
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench-gate-session@example.com".to_string(),
                display_name: "Bench Gate Session".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let session_id = session.id().clone();
    let _ = engine.get_session(&realm, &session_id); // promote to hot tier

    c.bench_function("storage_gate_session_lookup", |b| {
        b.iter(|| {
            let r = engine.get_session(&realm, &session_id).expect("get");
            assert!(r.is_some());
        });
    });
}

fn bench_user_lookup_by_id(c: &mut Criterion) {
    let (_dir, engine, realm) = make_identity_engine();
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench-gate-user-id@example.com".to_string(),
                display_name: "Bench Gate User ID".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let user_id = user.id().clone();

    c.bench_function("storage_gate_user_lookup_by_id", |b| {
        b.iter(|| {
            let r = engine.get_user(&realm, &user_id).expect("get");
            assert!(r.is_some());
        });
    });
}

fn bench_user_lookup_by_email(c: &mut Criterion) {
    let (_dir, engine, realm) = make_identity_engine();
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench-gate-user-email@example.com".to_string(),
                display_name: "Bench Gate User Email".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let email = user.email().to_string();

    c.bench_function("storage_gate_user_lookup_by_email", |b| {
        b.iter(|| {
            let r = engine.get_user_by_email(&realm, &email).expect("get");
            assert!(r.is_some());
        });
    });
}

criterion_group!(
    benches,
    bench_storage_hot_tier,
    bench_session_lookup,
    bench_user_lookup_by_id,
    bench_user_lookup_by_email,
);

// Custom main: run hard threshold gates before Criterion sampling.
// Panicking here causes non-zero exit, which fails `make bench-gate`.
fn main() {
    gate_storage_hot_tier();
    gate_session_lookup();
    gate_user_lookup_by_id();
    gate_user_lookup_by_email();

    benches();
}
