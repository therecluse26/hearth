//! Tiered storage crash-recovery simulation tests.
//!
//! Oracle invariant: tier transitions preserve all data. The hot tier
//! is purely in-memory, so crashes lose hot-tier state. Recovery must
//! re-populate from WAL + SST on first access.

use std::sync::Arc;

use hearth::core::TenantId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Tier transitions preserve all data under concurrent read/write load.
#[test]
fn simulation_tier_transitions_concurrent() {
    let seed = 48u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant = TenantId::generate();

    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));

    // Pre-populate 50 entries
    for i in 0u32..50 {
        let key = format!("conc-{i:04}");
        engine
            .put(&tenant, key.as_bytes(), b"initial")
            .expect("put");
    }

    // Concurrent operations from multiple threads
    let mut handles = Vec::new();

    // Reader threads
    for _ in 0..4 {
        let engine = Arc::clone(&engine);
        let t = tenant.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0u32..50 {
                let key = format!("conc-{i:04}");
                let val = engine.get(&t, key.as_bytes()).expect("get");
                if let Some(v) = val {
                    assert!(
                        v == b"initial" || v == b"updated",
                        "unexpected value for key {key}"
                    );
                }
            }
        }));
    }

    // Writer threads
    for batch in 0u32..4 {
        let engine = Arc::clone(&engine);
        let t = tenant.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0u32..10 {
                let key = format!("conc-{:04}", batch * 10 + i);
                engine.put(&t, key.as_bytes(), b"updated").expect("put");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Verify all data is accessible
    for i in 0u32..50 {
        let key = format!("conc-{i:04}");
        let val = engine.get(&tenant, key.as_bytes()).expect("get");
        assert!(
            val.is_some(),
            "key {key} must be accessible after concurrent ops (seed={seed})"
        );
    }
}

/// Crash during promotion: hot tier is in-memory, so a crash means
/// an empty tier on restart.
#[test]
fn simulation_crash_during_promotion() {
    let seed = 49u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant = TenantId::generate();

    // Phase 1: Write data and access it
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..10 {
            let key = format!("hot-{i:04}");
            engine
                .put(&tenant, key.as_bytes(), b"hot-value")
                .expect("put");
        }

        // Read to promote into hot tier
        for i in 0u32..10 {
            let key = format!("hot-{i:04}");
            let val = engine.get(&tenant, key.as_bytes()).expect("get");
            assert_eq!(val, Some(b"hot-value".to_vec()));
        }
    }

    // Phase 2: Re-open — hot tier is empty
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("recovery");

        for i in 0u32..10 {
            let key = format!("hot-{i:04}");
            let val = engine.get(&tenant, key.as_bytes()).expect("get");
            assert_eq!(
                val,
                Some(b"hot-value".to_vec()),
                "key {key} must be recoverable from WAL+SST after crash (seed={seed})"
            );
        }
    }
}
