//! SST compaction crash-recovery simulation tests.
//!
//! Oracle invariant: after crash during compaction (between rename and
//! old-file deletion), the engine recovers correctly with both old and
//! new SSTs on disk. Newer SST entries take priority.

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Crash after rename, before old-file deletion: both old and new SSTs
/// coexist on disk. Recovery must produce correct state — the newer
/// compacted SST takes priority for duplicate keys.
#[test]
fn simulation_compaction_leaked_files_after_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: write data, generate >=2 SSTs, compact, then restore old
    // SSTs to simulate a crash between rename and old-file deletion.
    {
        let mut config = StorageConfig::production(
            dir.path().to_path_buf(),
            64 * 1024 * 1024, // wal_max_size_bytes
            false,            // fsync: false (test)
            50,               // memtable_flush_bytes: small → forces flushes
            100,              // hot_tier_capacity
        );
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..30 {
            engine
                .put(
                    &realm,
                    format!("cr-{i:04}").as_bytes(),
                    format!("va-{i:04}").as_bytes(),
                )
                .expect("put");
        }

        // Verify we have >=2 SSTs before compaction
        let sst_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(sst_count >= 2, "expected >=2 SSTs, got {sst_count}");

        // Save copies of SSTs before compaction deletes them
        let tmp_save = tempfile::tempdir().expect("tempdir for sst backups");
        for entry in std::fs::read_dir(dir.path()).expect("read_dir").flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "sst") {
                let save_path = tmp_save.path().join(entry.file_name());
                std::fs::copy(entry.path(), &save_path).expect("copy sst backup");
            }
        }

        // Run compaction — this creates a merged SST and deletes old ones
        let compacted = engine.compact_ssts(2).expect("compact");
        assert!(compacted > 0, "compaction should have merged SSTs");

        // Simulate crash-after-rename: restore old SSTs alongside the new one
        for entry in std::fs::read_dir(tmp_save.path())
            .expect("read_dir")
            .flatten()
        {
            let restore_path = dir.path().join(entry.file_name());
            std::fs::copy(entry.path(), &restore_path).expect("restore old sst");
        }
    }

    // Phase 2: reopen with both old and new SSTs on disk
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen after leaked files");

        // All keys must be readable — newer compacted SST wins for duplicates
        for i in 0u32..30 {
            let key = format!("cr-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(format!("va-{i:04}").into_bytes()),
                "key {key} must survive compaction crash with leaked SST files"
            );
        }
    }
}
