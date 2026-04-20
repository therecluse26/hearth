//! SST crash-recovery simulation tests.
//!
//! Oracle invariant: after crash during flush or compaction, recovery
//! from WAL + valid SSTs produces correct state. Corrupt SSTs are
//! detected and skipped.

use std::io::Write;

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Crash during memtable flush: a corrupt SST is detected and
/// discarded on recovery; WAL replay recovers all committed data.
#[test]
fn simulation_crash_during_memtable_flush() {
    let seed = 45u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Write data through the engine (WAL is the durable copy)
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        engine.put(&realm, b"flush-key-1", b"val-1").expect("put");
        engine.put(&realm, b"flush-key-2", b"val-2").expect("put");
    }

    // Inject a corrupt SST file
    {
        let corrupt_sst_path = dir.path().join("000001.sst");
        let mut file = std::fs::File::create(&corrupt_sst_path).expect("create corrupt sst");
        file.write_all(b"HSST").expect("magic");
        file.write_all(&[0x01]).expect("version");
        file.write_all(&2u32.to_le_bytes()).expect("count");
        file.write_all(&[0u8; 3]).expect("reserved");
        file.sync_all().expect("sync");
    }

    // Re-open: engine should skip corrupt SST and recover from WAL
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("recovery");

        assert_eq!(
            engine.get(&realm, b"flush-key-1").expect("get"),
            Some(b"val-1".to_vec()),
            "data must survive crash during flush via WAL replay (seed={seed})"
        );
        assert_eq!(
            engine.get(&realm, b"flush-key-2").expect("get"),
            Some(b"val-2".to_vec()),
            "data must survive crash during flush via WAL replay (seed={seed})"
        );
    }
}

/// Crash during compaction: source SSTs remain intact when the
/// output SST is corrupt/incomplete.
#[test]
fn simulation_crash_during_compaction() {
    let seed = 46u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Write data in two phases
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        engine.put(&realm, b"key-a", b"val-a").expect("put");
        engine.put(&realm, b"key-b", b"val-b").expect("put");
    }

    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen");
        engine.put(&realm, b"key-c", b"val-c").expect("put");
        engine.put(&realm, b"key-d", b"val-d").expect("put");
    }

    // Simulate crash during compaction: create a corrupt output SST
    {
        let compacted_path = dir.path().join("999999.sst");
        let mut file = std::fs::File::create(&compacted_path).expect("create");
        file.write_all(b"HSST").expect("magic");
        file.write_all(&[0x01]).expect("version");
        file.write_all(&4u32.to_le_bytes()).expect("count");
        file.write_all(&[0u8; 3]).expect("reserved");
        file.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).expect("data");
        file.write_all(&[0xFF; 4]).expect("bad crc");
        file.write_all(b"HEND").expect("footer magic");
        file.sync_all().expect("sync");
    }

    // Re-open: engine should skip corrupt SST and recover from WAL
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("recovery");
        assert_eq!(
            engine.get(&realm, b"key-a").expect("get"),
            Some(b"val-a".to_vec()),
            "data must survive crash during compaction (seed={seed})"
        );
        assert_eq!(
            engine.get(&realm, b"key-b").expect("get"),
            Some(b"val-b".to_vec()),
        );
        assert_eq!(
            engine.get(&realm, b"key-c").expect("get"),
            Some(b"val-c".to_vec()),
        );
        assert_eq!(
            engine.get(&realm, b"key-d").expect("get"),
            Some(b"val-d".to_vec()),
        );
    }
}

/// Power-loss simulation: WAL replay + SST recovery produces correct
/// state after simulated power loss that corrupts the WAL tail.
#[test]
fn simulation_power_loss() {
    let seed = 47u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: Write data
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..10 {
            let key = format!("power-{i:04}");
            let val = format!("val-{i:04}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
                .expect("put");
        }
    }

    // Phase 2: Simulate power loss — corrupt the WAL tail
    {
        let wal_path = dir.path().join("hearth.wal");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal for corruption");
        file.write_all(b"POWER_LOSS_GARBAGE_PARTIAL_RECORD")
            .expect("corrupt wal tail");
        file.sync_all().expect("sync");
    }

    // Phase 3: Recovery
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("recovery after power loss");

        for i in 0u32..10 {
            let key = format!("power-{i:04}");
            let expected = format!("val-{i:04}");
            let actual = engine.get(&realm, key.as_bytes()).expect("get");
            assert_eq!(
                actual,
                Some(expected.into_bytes()),
                "key {key} must survive power-loss recovery (seed={seed})"
            );
        }
    }
}
