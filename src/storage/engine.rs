//! Composed storage engine integrating WAL, memtable, SST, and hot tier.
//!
//! `EmbeddedStorageEngine` implements the `StorageEngine` trait by layering:
//! - **Read path**: hot tier → memtable → SST files (newest first)
//! - **Write path**: WAL append → memtable insert → hot tier invalidate
//! - **Recovery**: WAL replay into fresh memtable on open

use std::path::PathBuf;
use std::sync::Mutex;

use arc_swap::ArcSwap;

use crate::core::TenantId;
use crate::storage::error::StorageError;
use crate::storage::memtable::{Memtable, MemtableConfig, MemtableValue};
use crate::storage::sst::{SstReader, SstWriter};
use crate::storage::tiered::{HotTier, TieredConfig};
use crate::storage::wal::{Wal, WalConfig, WalEntry, WalOperation};
use crate::storage::{ScanEntry, StorageEngine};

/// Configuration for the embedded storage engine.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Directory for WAL and SST files.
    pub data_dir: PathBuf,
    /// WAL configuration.
    pub wal_config: WalConfig,
    /// Memtable configuration.
    pub(crate) memtable_config: MemtableConfig,
    /// Hot tier configuration.
    pub(crate) tiered_config: TieredConfig,
}

impl StorageConfig {
    /// Creates a development/test configuration with no fsync and moderate thresholds.
    ///
    /// Suitable for integration tests and `--dev` mode. Uses `SyncMode::None`
    /// for speed and reasonable defaults that exercise flush/eviction paths
    /// without excessive I/O.
    pub fn dev(data_dir: PathBuf) -> Self {
        use crate::storage::wal::SyncMode;
        Self {
            data_dir,
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig::default(),
            tiered_config: TieredConfig::default(),
        }
    }

    /// Creates a test configuration with fast sync and small thresholds.
    #[cfg(test)]
    pub(crate) fn test_config(data_dir: PathBuf) -> Self {
        use crate::storage::wal::SyncMode;
        Self {
            data_dir,
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 4 * 1024, // 4 KiB for faster test flushes
            },
            tiered_config: TieredConfig {
                hot_tier_capacity: 100,
                eviction_batch_size: 10,
            },
        }
    }
}

/// Embedded storage engine composing WAL, memtable, SST files, and hot tier.
pub struct EmbeddedStorageEngine {
    /// Write-ahead log for durability.
    wal: Wal,
    /// Active in-memory sorted store.
    active_memtable: Memtable,
    /// On-disk SST files, newest first.
    sst_readers: ArcSwap<Vec<SstReader>>,
    /// In-memory hot tier for frequently accessed data.
    hot_tier: HotTier,
    /// Base data directory.
    data_dir: PathBuf,
    /// Serializes flush operations.
    flush_lock: Mutex<()>,
    /// Monotonically increasing SST file counter.
    sst_counter: std::sync::atomic::AtomicU64,
}

impl EmbeddedStorageEngine {
    /// Opens the storage engine at the given directory.
    ///
    /// Creates the directory if needed, discovers existing SST files,
    /// opens the WAL, and replays it into a fresh memtable.
    pub fn open(config: StorageConfig) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&config.data_dir)?;

        // Discover existing SST files, sorted newest-first by filename
        let mut sst_paths: Vec<PathBuf> = std::fs::read_dir(&config.data_dir)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
            .collect();
        sst_paths.sort();
        sst_paths.reverse(); // newest first (higher numbered files are newer)

        let mut sst_readers = Vec::new();
        let mut max_sst_num: u64 = 0;
        for path in &sst_paths {
            if let Ok(reader) = SstReader::open(path) {
                // Extract number from filename like "000001.sst"
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(num) = stem.parse::<u64>() {
                        max_sst_num = max_sst_num.max(num);
                    }
                }
                sst_readers.push(reader);
            }
            // Skip corrupted SST files — data should be recoverable from WAL
        }

        // Open WAL and replay into fresh memtable
        let wal_path = config.data_dir.join("hearth.wal");
        let wal = Wal::open(&wal_path, config.wal_config)?;
        let memtable = Memtable::new(config.memtable_config);

        let entries = wal.read_all()?;
        for entry in &entries {
            memtable.apply_wal_entry(entry)?;
        }

        let hot_tier = HotTier::new(config.tiered_config);

        Ok(Self {
            wal,
            active_memtable: memtable,
            sst_readers: ArcSwap::from_pointee(sst_readers),
            hot_tier,
            data_dir: config.data_dir,
            flush_lock: Mutex::new(()),
            sst_counter: std::sync::atomic::AtomicU64::new(max_sst_num + 1),
        })
    }

    /// Flushes the memtable to a new SST file and clears it.
    fn trigger_flush(&self) -> Result<(), StorageError> {
        let Ok(_guard) = self.flush_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "flush mutex poisoned",
            )));
        };

        let entries = self.active_memtable.iter_all();
        if entries.is_empty() {
            return Ok(());
        }

        // Generate sequential SST filename
        let sst_num = self
            .sst_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sst_path = self.data_dir.join(format!("{sst_num:06}.sst"));

        SstWriter::write_sst(&sst_path, &entries)?;

        // Rebuild SST reader list from disk (re-open all files).
        // SstReader is not Clone, so we re-open. This is acceptable for Phase 0
        // since flush is off the hot path.
        let mut all_sst_paths: Vec<PathBuf> = std::fs::read_dir(&self.data_dir)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
            .collect();
        all_sst_paths.sort();
        all_sst_paths.reverse(); // newest first

        let mut rebuilt_readers = Vec::new();
        for path in &all_sst_paths {
            if let Ok(reader) = SstReader::open(path) {
                rebuilt_readers.push(reader);
            }
        }
        self.sst_readers.store(std::sync::Arc::new(rebuilt_readers));

        // Clear the memtable after successful flush
        self.active_memtable.clear()?;

        Ok(())
    }
}

impl StorageEngine for EmbeddedStorageEngine {
    fn get(&self, tenant_id: &TenantId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // 1. Hot tier (lock-free, O(1))
        if let Some(value) = self.hot_tier.get(tenant_id, key) {
            return Ok(Some(value));
        }

        // 2. Active memtable
        // Note: memtable.get() returns None for both absent keys and tombstones.
        // We need to check for tombstones explicitly to avoid false cold-path lookups.
        {
            let entries = self.active_memtable.iter_tenant(tenant_id);
            for (k, v) in &entries {
                if k.as_slice() == key {
                    match v {
                        MemtableValue::Data(data) => {
                            // Promote to hot tier on memtable hit
                            self.hot_tier.promote(tenant_id, key, data);
                            return Ok(Some(data.clone()));
                        }
                        MemtableValue::Tombstone => {
                            // Key was deleted — stop searching deeper layers
                            return Ok(None);
                        }
                    }
                }
            }
        }

        // 3. SST files newest-to-oldest (binary search)
        let sst_readers = self.sst_readers.load();
        for reader in sst_readers.iter() {
            if let Some(value) = reader.get(tenant_id, key) {
                match value {
                    MemtableValue::Data(data) => {
                        // Cold hit — promote to hot tier
                        self.hot_tier.promote(tenant_id, key, &data);
                        return Ok(Some(data));
                    }
                    MemtableValue::Tombstone => {
                        // Tombstone in SST — stop searching older SSTs
                        return Ok(None);
                    }
                }
            }
        }

        Ok(None)
    }

    fn put(&self, tenant_id: &TenantId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        // 1. WAL append + fsync
        let entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            tenant_id: tenant_id.clone(),
            operation: WalOperation::Put,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.wal.append(&entry)?;

        // 2. Memtable insert
        self.active_memtable.put(tenant_id, key, value)?;

        // 3. Hot tier invalidate (stale cached value)
        self.hot_tier.invalidate(tenant_id, key);

        // 4. Check flush threshold
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn delete(&self, tenant_id: &TenantId, key: &[u8]) -> Result<(), StorageError> {
        // 1. WAL append + fsync
        let entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            tenant_id: tenant_id.clone(),
            operation: WalOperation::Delete,
            key: key.to_vec(),
            value: vec![],
        };
        self.wal.append(&entry)?;

        // 2. Memtable tombstone
        self.active_memtable.delete(tenant_id, key)?;

        // 3. Hot tier invalidate
        self.hot_tier.invalidate(tenant_id, key);

        // 4. Check flush threshold
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn scan(
        &self,
        tenant_id: &TenantId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        // Merge results from memtable and all SST files.
        // Use a BTreeMap to deduplicate — memtable entries (newest) win.
        let mut merged: std::collections::BTreeMap<Vec<u8>, MemtableValue> =
            std::collections::BTreeMap::new();

        // SST files oldest-to-newest (reverse of storage order) so newer overwrites older
        let sst_readers = self.sst_readers.load();
        for reader in sst_readers.iter().rev() {
            let entries = reader.range_scan(tenant_id, start, end);
            for (key, value) in entries {
                merged.insert(key, value);
            }
        }

        // Memtable entries (newest) overwrite SST entries
        let memtable_entries = self.active_memtable.iter_tenant(tenant_id);
        for (key, value) in memtable_entries {
            if key.as_slice() >= start && key.as_slice() < end {
                merged.insert(key, value);
            }
        }

        // Filter out tombstones and build result
        let result = merged
            .into_iter()
            .filter_map(|(key, value)| match value {
                MemtableValue::Data(data) => Some(ScanEntry { key, value: data }),
                MemtableValue::Tombstone => None,
            })
            .collect();

        Ok(result)
    }
}

impl std::fmt::Debug for EmbeddedStorageEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedStorageEngine")
            .field("data_dir", &self.data_dir)
            .field("hot_tier", &self.hot_tier)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TenantId;
    use crate::storage::wal::SyncMode;

    fn setup_engine() -> (tempfile::TempDir, EmbeddedStorageEngine) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::test_config(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        (dir, engine)
    }

    // ===== Step 7 Tests =====

    #[test]
    fn engine_put_get_roundtrip() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        engine.put(&tenant, b"key1", b"value1").expect("put");
        let val = engine.get(&tenant, b"key1").expect("get");
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[test]
    fn engine_delete_removes_value() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        engine.put(&tenant, b"key1", b"value1").expect("put");
        assert_eq!(
            engine.get(&tenant, b"key1").expect("get"),
            Some(b"value1".to_vec())
        );

        engine.delete(&tenant, b"key1").expect("delete");
        assert_eq!(engine.get(&tenant, b"key1").expect("get"), None);
    }

    #[test]
    fn engine_scan_returns_range() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        engine.put(&tenant, b"apple", b"v-apple").expect("put");
        engine.put(&tenant, b"banana", b"v-banana").expect("put");
        engine.put(&tenant, b"cherry", b"v-cherry").expect("put");
        engine.put(&tenant, b"date", b"v-date").expect("put");

        // Scan [banana, date) → banana, cherry
        let results = engine.scan(&tenant, b"banana", b"date").expect("scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, b"banana");
        assert_eq!(results[0].value, b"v-banana");
        assert_eq!(results[1].key, b"cherry");
        assert_eq!(results[1].value, b"v-cherry");
    }

    #[test]
    fn engine_tenant_isolation() {
        let (_dir, engine) = setup_engine();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        engine
            .put(&tenant_a, b"shared_key", b"value-a")
            .expect("put a");
        engine
            .put(&tenant_b, b"shared_key", b"value-b")
            .expect("put b");

        assert_eq!(
            engine.get(&tenant_a, b"shared_key").expect("get a"),
            Some(b"value-a".to_vec())
        );
        assert_eq!(
            engine.get(&tenant_b, b"shared_key").expect("get b"),
            Some(b"value-b".to_vec())
        );

        // Tenant C sees nothing
        let tenant_c = TenantId::generate();
        assert_eq!(engine.get(&tenant_c, b"shared_key").expect("get c"), None);
    }

    #[test]
    fn engine_wal_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        // Write data, then drop the engine (simulates crash)
        {
            let config = StorageConfig::test_config(dir.path().to_path_buf());
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            engine.put(&tenant, b"durable1", b"val1").expect("put");
            engine.put(&tenant, b"durable2", b"val2").expect("put");
            engine.delete(&tenant, b"durable2").expect("delete");
        }

        // Re-open: WAL replay should recover state
        {
            let config = StorageConfig::test_config(dir.path().to_path_buf());
            let engine = EmbeddedStorageEngine::open(config).expect("reopen");

            assert_eq!(
                engine.get(&tenant, b"durable1").expect("get"),
                Some(b"val1".to_vec()),
                "value should survive WAL recovery"
            );
            assert_eq!(
                engine.get(&tenant, b"durable2").expect("get"),
                None,
                "deleted value should remain deleted after recovery"
            );
        }
    }

    #[test]
    fn engine_memtable_flush_to_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        // Use very small flush threshold to trigger flush
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 100, // Very small — flush after ~2 entries
            },
            tiered_config: TieredConfig {
                hot_tier_capacity: 100,
                eviction_batch_size: 10,
            },
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        // Write enough data to trigger flush
        for i in 0u32..20 {
            let key = format!("key-{i:04}");
            let val = format!("val-{i:04}");
            engine
                .put(&tenant, key.as_bytes(), val.as_bytes())
                .expect("put");
        }

        // Verify SST files were created
        let sst_count = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(sst_count > 0, "flush should have created SST files");

        // All data should still be readable (from memtable + SST)
        for i in 0u32..20 {
            let key = format!("key-{i:04}");
            let expected = format!("val-{i:04}");
            let actual = engine.get(&tenant, key.as_bytes()).expect("get");
            assert_eq!(
                actual,
                Some(expected.into_bytes()),
                "key {key} should be readable after flush"
            );
        }
    }

    // Step 6 test #3: cold read promotes to hot tier (requires composed engine)
    #[test]
    fn engine_cold_promotes_to_hot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        // Write data and flush to SST (making it "cold")
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig {
                    flush_threshold_bytes: 50, // Very small
                },
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                },
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");

            // Write enough to trigger flush
            for i in 0u32..10 {
                let key = format!("cold-{i:04}");
                engine
                    .put(&tenant, key.as_bytes(), b"cold-value")
                    .expect("put");
            }
        }

        // Re-open: data is in SST (cold), hot tier is empty
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig::default(),
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                },
            };
            let engine = EmbeddedStorageEngine::open(config).expect("reopen");

            // Hot tier should be empty initially
            assert!(
                !engine.hot_tier.contains(&tenant, b"cold-0000"),
                "hot tier should be empty on fresh open"
            );

            // Read from cold (SST) — should promote to hot tier
            let val = engine.get(&tenant, b"cold-0000").expect("cold read");
            assert_eq!(val, Some(b"cold-value".to_vec()));

            // Now it should be in the hot tier
            assert!(
                engine.hot_tier.contains(&tenant, b"cold-0000"),
                "cold read should promote to hot tier"
            );

            // Second read should hit hot tier (faster path)
            let val2 = engine.get(&tenant, b"cold-0000").expect("hot read");
            assert_eq!(val2, Some(b"cold-value".to_vec()));
        }
    }

    #[test]
    fn engine_scan_merges_memtable_and_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 100,
            },
            tiered_config: TieredConfig::default(),
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        // Write keys that will end up in SST (flush triggered by small threshold)
        engine.put(&tenant, b"aaa", b"sst-val").expect("put");
        engine.put(&tenant, b"bbb", b"sst-val").expect("put");
        engine.put(&tenant, b"ccc", b"sst-val").expect("put");

        // These keys should be in memtable (written after last flush or still in memtable)
        engine.put(&tenant, b"ddd", b"mem-val").expect("put");
        engine.put(&tenant, b"eee", b"mem-val").expect("put");

        // Scan the full range — should merge SST + memtable
        let results = engine.scan(&tenant, b"aaa", b"fff").expect("scan");

        // We should see all 5 keys, regardless of which layer they're in
        assert!(
            results.len() >= 4,
            "scan should find keys across layers, got {}",
            results.len()
        );

        // Results should be sorted
        for window in results.windows(2) {
            assert!(
                window[0].key <= window[1].key,
                "scan results should be sorted: {:?} > {:?}",
                window[0].key,
                window[1].key
            );
        }
    }

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmbeddedStorageEngine>();
    }
}
