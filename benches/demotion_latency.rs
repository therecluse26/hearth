//! Hot/cold demotion-cycle latency benchmark.
//!
//! Measures p99 read latency across three phases of a hot-tier demotion cycle
//! to confirm that eviction does not cause read-latency spikes:
//!
//! - **Pre-demotion** — hot tier at capacity; all reads are lock-free `ArcSwap` loads.
//! - **During demotion** — interleaved writes force clock-sweep evictions; reads
//!   that miss the hot tier fall through to the memtable.
//! - **Post-demotion** — evicted entries re-promoted on first re-read; subsequent
//!   reads return to the lock-free hot-tier path.
//!
//! The named Criterion group `demotion_cycle` contains two bench functions:
//! `pre_demotion_read` and `post_demotion_read`. These are the canonical
//! regression-tracking scenarios for demotion latency (see HEA-335).
//!
//! ## Phase ceilings
//!
//! | Phase | p99 limit |
//! |-------|-----------|
//! | Pre-demotion read | 500 µs |
//! | During-demotion read | 500 µs |
//! | Post-demotion read | 500 µs |
//!
//! The 500 µs ceiling is intentionally generous relative to the 100 µs
//! steady-state gate in `storage_gate.rs` to tolerate the memtable fallback
//! path during eviction churn without false-positive CI failures.

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, Criterion};

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Small hot tier capacity to trigger demotion without a large dataset.
const HOT_TIER_CAPACITY: usize = 200;

/// Number of "hot" keys that fill the tier to capacity.
const ENTRY_COUNT: usize = HOT_TIER_CAPACITY;

/// Value size matching a realistic session-token payload.
const VALUE_BYTES: usize = 128;

/// Raw samples per phase for p99 estimation.
const PHASE_SAMPLES: usize = 4_000;

/// Discarded warm-up iterations before measurement.
const PHASE_WARMUP: usize = 100;

/// Absolute p99 ceiling for all three demotion phases.
const P99_CEILING: Duration = Duration::from_micros(500);

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_engine() -> (tempfile::TempDir, EmbeddedStorageEngine, RealmId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::production(
        dir.path().to_path_buf(),
        64 * 1024 * 1024, // 64 MiB WAL
        false,            // no fsync in bench
        64 * 1024 * 1024, // 64 MiB memtable flush threshold
        HOT_TIER_CAPACITY,
    );
    let engine = EmbeddedStorageEngine::open(config).expect("open");
    let realm = RealmId::generate();
    (dir, engine, realm)
}

fn make_keys(count: usize, prefix: &str) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| format!("{prefix}:{i:08}").into_bytes())
        .collect()
}

fn sorted_p99(samples: &mut Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() * 99 / 100]
}

// ── Hard gate ─────────────────────────────────────────────────────────────────

/// Three-phase demotion gate: panics (→ non-zero exit) if any phase exceeds
/// the p99 ceiling. Called before Criterion sampling in `main()`.
fn gate_demotion_latency() {
    let (_dir, engine, realm) = make_engine();
    let value: Vec<u8> = vec![0xAB; VALUE_BYTES];
    let hot_keys = make_keys(ENTRY_COUNT, "hot");

    // Populate and warm all keys into the hot tier.
    for key in &hot_keys {
        engine.put(&realm, key, &value).expect("put");
    }
    for key in &hot_keys {
        let _ = engine.get(&realm, key);
    }

    // Discard warm-up samples.
    for i in 0..PHASE_WARMUP {
        black_box(engine.get(&realm, &hot_keys[i % ENTRY_COUNT]).expect("get"));
    }

    // Phase 1: pre-demotion — all keys in hot tier.
    let mut pre = Vec::with_capacity(PHASE_SAMPLES);
    for i in 0..PHASE_SAMPLES {
        let key = &hot_keys[i % ENTRY_COUNT];
        let t = Instant::now();
        black_box(engine.get(&realm, black_box(key)).expect("get"));
        pre.push(t.elapsed());
    }
    let pre_p99 = sorted_p99(&mut pre);

    // Phase 2: during demotion — interleaved writes evict original entries.
    let cold_keys = make_keys(ENTRY_COUNT, "cold");
    let mut mid = Vec::with_capacity(PHASE_SAMPLES);
    for i in 0..PHASE_SAMPLES {
        // Write a displacement key every 4 iterations to spread eviction pressure
        // across the measurement window without flooding it with write latency.
        if i % 4 == 0 {
            engine
                .put(&realm, &cold_keys[i % ENTRY_COUNT], &value)
                .expect("put cold");
        }
        let key = &hot_keys[i % ENTRY_COUNT];
        let t = Instant::now();
        black_box(engine.get(&realm, black_box(key)).expect("get"));
        mid.push(t.elapsed());
    }
    let mid_p99 = sorted_p99(&mut mid);

    // Phase 3: post-demotion — evicted keys re-promoted on re-read.
    let mut post = Vec::with_capacity(PHASE_SAMPLES);
    for i in 0..PHASE_SAMPLES {
        let key = &hot_keys[i % ENTRY_COUNT];
        let t = Instant::now();
        black_box(engine.get(&realm, black_box(key)).expect("get"));
        post.push(t.elapsed());
    }
    let post_p99 = sorted_p99(&mut post);

    assert!(
        pre_p99 <= P99_CEILING,
        "demotion pre-phase p99 {pre_p99:?} exceeds ceiling {P99_CEILING:?} \
         — see benches/demotion_latency.rs for threshold rationale"
    );
    assert!(
        mid_p99 <= P99_CEILING,
        "demotion mid-phase p99 {mid_p99:?} exceeds ceiling {P99_CEILING:?} \
         — see benches/demotion_latency.rs for threshold rationale"
    );
    assert!(
        post_p99 <= P99_CEILING,
        "demotion post-phase p99 {post_p99:?} exceeds ceiling {P99_CEILING:?} \
         — see benches/demotion_latency.rs for threshold rationale"
    );
}

// ── Criterion benchmarks ──────────────────────────────────────────────────────

/// Criterion throughput for steady-state hot-tier reads (pre-demotion baseline).
fn bench_pre_demotion_read(c: &mut Criterion) {
    let (_dir, engine, realm) = make_engine();
    let keys = make_keys(ENTRY_COUNT, "hot");
    let value: Vec<u8> = vec![0xAB; VALUE_BYTES];

    for key in &keys {
        engine.put(&realm, key, &value).expect("put");
    }
    for key in &keys {
        let _ = engine.get(&realm, key); // promote to hot tier
    }

    let mut group = c.benchmark_group("demotion_cycle");
    group.bench_function("pre_demotion_read", |b| {
        let mut i = 0usize;
        b.iter(|| {
            black_box(engine.get(&realm, black_box(&keys[i % ENTRY_COUNT])).expect("get"));
            i += 1;
        });
    });
    group.finish();
}

/// Criterion throughput for reads after a full demotion cycle (post-promotion).
fn bench_post_demotion_read(c: &mut Criterion) {
    let (_dir, engine, realm) = make_engine();
    let keys = make_keys(ENTRY_COUNT, "hot");
    let cold_keys = make_keys(ENTRY_COUNT, "cold");
    let value: Vec<u8> = vec![0xAB; VALUE_BYTES];

    // Populate and warm original set.
    for key in &keys {
        engine.put(&realm, key, &value).expect("put");
    }
    for key in &keys {
        let _ = engine.get(&realm, key);
    }
    // Displace originals: fills tier with cold set, evicting hot keys.
    for key in &cold_keys {
        engine.put(&realm, key, &value).expect("put cold");
        let _ = engine.get(&realm, key); // promote cold key to hot tier
    }
    // Re-read originals once to trigger cold→hot promotion.
    for key in &keys {
        let _ = engine.get(&realm, key);
    }

    let mut group = c.benchmark_group("demotion_cycle");
    group.bench_function("post_demotion_read", |b| {
        let mut i = 0usize;
        b.iter(|| {
            black_box(engine.get(&realm, black_box(&keys[i % ENTRY_COUNT])).expect("get"));
            i += 1;
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pre_demotion_read, bench_post_demotion_read);

// Custom main: run hard p99 gate before Criterion sampling.
// A panicking gate exits non-zero, failing `make bench-gate`.
fn main() {
    gate_demotion_latency();
    benches();
}
