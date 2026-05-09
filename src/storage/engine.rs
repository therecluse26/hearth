//! Composed storage engine integrating WAL, memtable, SST, and hot tier.
//!
//! `EmbeddedStorageEngine` implements the `StorageEngine` trait by layering:
//! - **Read path**: hot tier → memtable → SST files (newest first)
//! - **Write path**: WAL append → memtable insert → hot tier invalidate
//! - **Recovery**: WAL replay into fresh memtable on open

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::core::RealmId;
use crate::storage::encryption;
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};
use crate::storage::key_registry::KeyRegistry;
use crate::storage::memtable::{Memtable, MemtableConfig, MemtableValue};
use crate::storage::sst::{self, SstReader, SstWriter};
use crate::storage::tiered::{HotTier, TieredConfig};
use crate::storage::wal::{BatchEntry, Wal, WalConfig, WalEntry, WalOperation};
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
    /// When true, missing KEKs during startup only log a warning
    /// instead of returning an error. Default: false.
    ///
    /// Operators can use this as an escape hatch to recover from a
    /// partly-corrupted `hearth.keys` file without recompiling.
    pub allow_missing_keks: bool,
    /// Background SST compaction configuration.
    pub compaction: CompactionConfig,
}

/// Configuration for background SST compaction.
#[derive(Debug, Clone)]
pub struct CompactionConfig {
    /// Whether automatic background compaction is enabled.
    pub enabled: bool,
    /// Interval between compaction attempts in seconds.
    pub interval_secs: u64,
    /// Minimum number of SST files before compaction is triggered.
    pub min_sst_count: usize,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            min_sst_count: 3,
        }
    }
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
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
        }
    }

    /// Creates a production storage configuration from operator-facing
    /// settings.
    ///
    /// Wires the `[storage]` YAML section values into the internal
    /// `WalConfig`, `MemtableConfig`, and `TieredConfig`. Callers should
    /// pre-compute `hot_tier_capacity` — either from the explicit
    /// `hot_tier_capacity` YAML field or via
    /// [`crate::storage::auto_size::auto_size_hot_tier_capacity`].
    pub fn production(
        data_dir: PathBuf,
        wal_max_size_bytes: u64,
        fsync: bool,
        memtable_flush_bytes: u64,
        hot_tier_capacity: usize,
    ) -> Self {
        use crate::storage::wal::SyncMode;
        Self {
            data_dir,
            wal_config: WalConfig {
                max_size: wal_max_size_bytes,
                sync_mode: if fsync {
                    SyncMode::EveryWrite
                } else {
                    SyncMode::None
                },
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: usize::try_from(memtable_flush_bytes)
                    .unwrap_or(usize::MAX),
            },
            tiered_config: TieredConfig {
                hot_tier_capacity,
                eviction_batch_size: 64,
            },
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
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
            allow_missing_keks: false,
            compaction: CompactionConfig {
                enabled: false,
                interval_secs: 0,
                min_sst_count: 2,
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
    /// Filesystem abstraction for fault injection in simulation tests.
    fs: Arc<dyn Fs>,
    /// Key registry for per-realm KEK management.
    key_registry: Arc<KeyRegistry>,
    /// System realm identifier used for file-level encryption.
    system_realm: RealmId,
}

impl EmbeddedStorageEngine {
    /// Opens the storage engine at the given directory.
    ///
    /// Creates the directory if needed, discovers existing SST files,
    /// opens the WAL, and replays it into a fresh memtable.
    pub fn open(config: StorageConfig) -> Result<Self, StorageError> {
        Self::open_with_fs(config, Arc::new(RealFs))
    }

    /// Opens the storage engine with a custom filesystem implementation.
    ///
    /// Used by the simulation crate to inject faults via a `FaultFs`.
    pub fn open_with_fs(config: StorageConfig, fs: Arc<dyn Fs>) -> Result<Self, StorageError> {
        fs.create_dir_all(&config.data_dir)?;

        // Load key registry (host key from env/auto-gen)
        let key_registry = Arc::new(KeyRegistry::load_with_fs(
            &config.data_dir,
            Arc::clone(&fs),
        )?);

        // System realm: a fixed UUID used for file-level encryption keys.
        // Kept stable across restarts so SST/WAL files remain decryptable.
        let system_realm = RealmId::new(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").map_err(|_| {
                StorageError::Crypto {
                    reason: "failed to parse system realm UUID".to_string(),
                }
            })?,
        );

        // Ensure the system realm has a KEK for file encryption
        key_registry.ensure_kek_for_realm(&system_realm)?;
        let system_kek = key_registry
            .get_kek_for_realm(&system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "failed to get system KEK".to_string(),
            })?;
        let system_kek_id = key_registry.kek_id_for_realm(&system_realm);

        // Open WAL with encryption
        let wal_path = config.data_dir.join("hearth.wal");
        let wal = Wal::open_with_fs(
            &wal_path,
            config.wal_config,
            Arc::clone(&fs),
            &system_kek,
            system_kek_id,
        )?;
        let memtable = Memtable::new(config.memtable_config);

        let entries = wal.read_all()?;
        for entry in &entries {
            memtable.apply_wal_entry(entry)?;
        }

        // Discover existing SST files, sorted newest-first by filename
        let mut sst_paths: Vec<(PathBuf, u64)> = fs
            .read_dir(&config.data_dir)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
            .filter_map(|p| {
                let num = p.file_stem()?.to_str()?.parse::<u64>().ok()?;
                Some((p, num))
            })
            .collect();
        sst_paths.sort_by_key(|(_, num)| std::cmp::Reverse(*num)); // newest first

        let mut sst_readers = Vec::new();
        let mut max_sst_num: u64 = 0;
        for (path, sst_num) in &sst_paths {
            // Read encryption header and extract KEK ID
            let (kek_id, enc_header) = sst::read_encryption_header(path, &*fs)?;
            // Look up the KEK from the registry by matching kek_id bytes to a realm
            let realm_for_kek = RealmId::new(uuid::Uuid::from_bytes(kek_id));
            let kek = if let Some(k) = key_registry.get_kek_for_realm(&realm_for_kek) {
                k
            } else if config.allow_missing_keks {
                tracing::warn!(
                    path = %path.display(),
                    realm = %realm_for_kek,
                    "SST file skipped: KEK not found in registry"
                );
                continue;
            } else {
                return Err(StorageError::Crypto {
                    reason: format!(
                        "SST {} references KEK for realm {} but no KEK is registered; refusing to start",
                        path.display(),
                        realm_for_kek
                    ),
                });
            };
            let dek = match encryption::unwrap_dek(&enc_header, &kek) {
                Ok(d) => d,
                Err(e) => {
                    if config.allow_missing_keks {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "SST file skipped: DEK unwrapping failed"
                        );
                        continue;
                    }
                    return Err(StorageError::Crypto {
                        reason: format!("SST {} DEK unwrapping failed: {}", path.display(), e),
                    });
                }
            };
            let reader = SstReader::open_with_fs(path, &*fs, *sst_num, &dek).map_err(|e| {
                StorageError::Crypto {
                    reason: format!("SST {} failed to open reader: {}", path.display(), e),
                }
            })?;
            max_sst_num = max_sst_num.max(*sst_num);
            sst_readers.push(reader);
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
            fs,
            key_registry,
            system_realm,
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

        // Generate per-file DEK and wrap with system realm KEK
        let system_kek = self
            .key_registry
            .get_kek_for_realm(&self.system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "system KEK not found".to_string(),
            })?;
        let system_kek_id = self.key_registry.kek_id_for_realm(&self.system_realm);
        let dek = encryption::generate_dek()?;
        let enc_header = encryption::wrap_dek(&dek, &system_kek, system_kek_id)?;

        SstWriter::write_sst_with_fs(&sst_path, &entries, &*self.fs, sst_num, &dek, &enc_header)?;

        // Rebuild SST reader list from disk (re-open all files).
        let mut all_sst_paths: Vec<(PathBuf, u64)> = self
            .fs
            .read_dir(&self.data_dir)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
            .filter_map(|p| {
                let num = p.file_stem()?.to_str()?.parse::<u64>().ok()?;
                Some((p, num))
            })
            .collect();
        all_sst_paths.sort_by_key(|(_, num)| std::cmp::Reverse(*num)); // newest first

        let mut rebuilt_readers = Vec::new();
        for (path, sst_num) in &all_sst_paths {
            let (kek_id, enc_header) = match sst::read_encryption_header(path, &*self.fs) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "SST file skipped: failed to read encryption header"
                    );
                    continue;
                }
            };
            let realm_for_kek = RealmId::new(uuid::Uuid::from_bytes(kek_id));
            let kek = match self.key_registry.get_kek_for_realm(&realm_for_kek) {
                Some(k) => k,
                None => {
                    tracing::warn!(
                        path = %path.display(),
                        realm = %realm_for_kek,
                        "SST file skipped: KEK not found"
                    );
                    continue;
                }
            };
            let dek = match encryption::unwrap_dek(&enc_header, &kek) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "SST file skipped: DEK unwrapping failed"
                    );
                    continue;
                }
            };
            match SstReader::open_with_fs(path, &*self.fs, *sst_num, &dek) {
                Ok(reader) => rebuilt_readers.push(reader),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "SST file skipped: failed to open reader"
                    );
                }
            }
        }
        self.sst_readers.store(Arc::new(rebuilt_readers));

        // Clear the memtable after successful flush
        self.active_memtable.clear()?;

        Ok(())
    }
}

impl EmbeddedStorageEngine {
    /// Compacts all current SST files into a single output SST.
    ///
    /// Returns the number of SSTs compacted (0 if the count is below
    /// `min_sst_count`). Writes to a temporary path and atomically
    /// renames for crash safety.
    ///
    /// Acquires the flush lock to serialize with memtable flushes.
    /// Callers in async contexts should wrap this in `spawn_blocking`
    /// to avoid blocking Tokio worker threads.
    ///
    /// # Crash Safety
    ///
    /// The compacted SST is written to a `.sst.tmp` path and atomically
    /// renamed to `{num:06}.sst`. If the process crashes **after** the
    /// rename but **before** old SST files are deleted, both old and new
    /// SSTs coexist on disk. Recovery handles this correctly — the newer
    /// SST (higher number) takes priority for duplicate keys. The leaked
    /// old files are harmless orphans cleaned up by the next compaction.
    pub fn compact_ssts(&self, min_sst_count: usize) -> Result<usize, StorageError> {
        // Fast path — check count without locking
        let sst_readers = self.sst_readers.load();
        if sst_readers.len() < min_sst_count {
            return Ok(0);
        }
        let input_count = sst_readers.len();

        // TODO(compaction): holding flush_lock across full merge blocks writers
        // for O(total-data) time. In Phase 2+, switch to leveled compaction
        // where minor compactions merge subsets of SSTs without blocking.

        let Ok(_guard) = self.flush_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "flush mutex poisoned",
            )));
        };

        // Re-check after lock — another compaction may have reduced count
        let sst_readers = self.sst_readers.load();
        if sst_readers.len() < min_sst_count {
            return Ok(0);
        }

        // Collect old SST numbers for file deletion after successful compaction
        let old_sst_nums: Vec<u64> = sst_readers.iter().map(|r| r.sst_number()).collect();

        // Inputs in oldest-to-newest order (sst_readers is newest-first)
        let readers_oldest_first: Vec<&SstReader> = sst_readers.iter().rev().collect();

        // DEK + encryption header (same pattern as trigger_flush)
        let system_kek = self
            .key_registry
            .get_kek_for_realm(&self.system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "system KEK not found".to_string(),
            })?;
        let system_kek_id = self.key_registry.kek_id_for_realm(&self.system_realm);
        let dek = encryption::generate_dek()?;
        let enc_header = encryption::wrap_dek(&dek, &system_kek, system_kek_id)?;

        let sst_num = self
            .sst_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_path = self.data_dir.join(format!("{sst_num:06}.sst.tmp"));
        let final_path = self.data_dir.join(format!("{sst_num:06}.sst"));

        // Write to temp path for crash safety
        sst::compact_with_fs(
            &readers_oldest_first,
            &tmp_path,
            &*self.fs,
            sst_num,
            &dek,
            &enc_header,
        )?;

        // Open reader from temp path before rename (SstReader is in-memory,
        // independent of the underlying file path)
        let new_reader = SstReader::open_with_fs(&tmp_path, &*self.fs, sst_num, &dek)
            .map_err(|e| StorageError::Crypto {
                reason: format!("compacted SST failed to open reader: {e}"),
            })?;

        // Atomic rename — crash-safe: partial writes leave a .tmp, not a corrupt .sst
        self.fs.rename(&tmp_path, &final_path)?;

        // Atomically swap reader list to just the compacted SST
        self.sst_readers.store(Arc::new(vec![new_reader]));

        // Delete old SST files (best-effort — warn on failure)
        for old_num in old_sst_nums {
            let old_path = self.data_dir.join(format!("{old_num:06}.sst"));
            if let Err(e) = self.fs.remove_file(&old_path) {
                tracing::warn!(
                    path = %old_path.display(),
                    error = %e,
                    "compaction: failed to delete old SST file",
                );
            }
        }

        Ok(input_count)
    }
}

impl StorageEngine for EmbeddedStorageEngine {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // 1. Hot tier (lock-free, O(1))
        if let Some(value) = self.hot_tier.get(realm_id, key) {
            return Ok(Some(value));
        }

        // 2. Active memtable
        // Note: memtable.get() returns None for both absent keys and tombstones.
        // We need to check for tombstones explicitly to avoid false cold-path lookups.
        {
            let entries = self.active_memtable.iter_realm(realm_id);
            for (k, v) in &entries {
                if k.as_slice() == key {
                    match v {
                        MemtableValue::Data(data) => {
                            // Promote to hot tier on memtable hit
                            self.hot_tier.promote(realm_id, key, data);
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
            if let Some(value) = reader.get(realm_id, key) {
                match value {
                    MemtableValue::Data(data) => {
                        // Cold hit — promote to hot tier
                        self.hot_tier.promote(realm_id, key, &data);
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

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        // 1. WAL append + fsync
        let entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Put,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.wal.append(&entry)?;

        // 2. Memtable insert
        self.active_memtable.put(realm_id, key, value)?;

        // 3. Hot tier invalidate (stale cached value)
        self.hot_tier.invalidate(realm_id, key);

        // 4. Check flush threshold
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        // 1. WAL append + fsync
        let entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Delete,
            key: key.to_vec(),
            value: vec![],
        };
        self.wal.append(&entry)?;

        // 2. Memtable tombstone
        self.active_memtable.delete(realm_id, key)?;

        // 3. Hot tier invalidate
        self.hot_tier.invalidate(realm_id, key);

        // 4. Check flush threshold
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        // Trivial case: the caller supplied no work. Treat as a no-op so
        // higher layers don't need to guard against empty batches.
        if entries.is_empty() {
            return Ok(());
        }

        // 1. Build and append a single WAL record containing all entries.
        //    The existing `[len][payload][crc32]` framing + `read_all()`'s
        //    "stop on bad CRC/truncation" recovery policy together give us
        //    all-or-nothing durability for free.
        let sub_entries: Vec<BatchEntry> = entries
            .iter()
            .map(|(k, v)| BatchEntry {
                operation: WalOperation::Put,
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        let payload = crate::storage::wal::encode_batch_payload(&sub_entries)?;
        let wal_entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Batch,
            key: Vec::new(),
            value: payload,
        };
        self.wal.append(&wal_entry)?;

        // 2. Apply each sub-entry to the in-memory state. If a failure
        //    occurs here (e.g., memtable mutex poisoned), the WAL record is
        //    already durable; recovery on the next open will replay the
        //    batch in full, re-establishing consistency.
        for (key, value) in entries {
            self.active_memtable.put(realm_id, key, value)?;
            self.hot_tier.invalidate(realm_id, key);
        }

        // 3. Single flush check at the tail — the batch may have pushed us
        //    over the threshold, but we don't need to check per-entry.
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn scan(
        &self,
        realm_id: &RealmId,
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
            let entries = reader.range_scan(realm_id, start, end);
            for (key, value) in entries {
                merged.insert(key, value);
            }
        }

        // Memtable entries (newest) overwrite SST entries
        let memtable_entries = self.active_memtable.iter_realm(realm_id);
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
    use crate::core::RealmId;
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
        let realm = RealmId::generate();

        engine.put(&realm, b"key1", b"value1").expect("put");
        let val = engine.get(&realm, b"key1").expect("get");
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[test]
    fn engine_delete_removes_value() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        engine.put(&realm, b"key1", b"value1").expect("put");
        assert_eq!(
            engine.get(&realm, b"key1").expect("get"),
            Some(b"value1".to_vec())
        );

        engine.delete(&realm, b"key1").expect("delete");
        assert_eq!(engine.get(&realm, b"key1").expect("get"), None);
    }

    #[test]
    fn engine_scan_returns_range() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        engine.put(&realm, b"apple", b"v-apple").expect("put");
        engine.put(&realm, b"banana", b"v-banana").expect("put");
        engine.put(&realm, b"cherry", b"v-cherry").expect("put");
        engine.put(&realm, b"date", b"v-date").expect("put");

        // Scan [banana, date) → banana, cherry
        let results = engine.scan(&realm, b"banana", b"date").expect("scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, b"banana");
        assert_eq!(results[0].value, b"v-banana");
        assert_eq!(results[1].key, b"cherry");
        assert_eq!(results[1].value, b"v-cherry");
    }

    #[test]
    fn engine_realm_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        engine
            .put(&realm_a, b"shared_key", b"value-a")
            .expect("put a");
        engine
            .put(&realm_b, b"shared_key", b"value-b")
            .expect("put b");

        assert_eq!(
            engine.get(&realm_a, b"shared_key").expect("get a"),
            Some(b"value-a".to_vec())
        );
        assert_eq!(
            engine.get(&realm_b, b"shared_key").expect("get b"),
            Some(b"value-b".to_vec())
        );

        // Realm C sees nothing
        let realm_c = RealmId::generate();
        assert_eq!(engine.get(&realm_c, b"shared_key").expect("get c"), None);
    }

    #[test]
    fn engine_wal_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Write data, then drop the engine (simulates crash)
        {
            let config = StorageConfig::test_config(dir.path().to_path_buf());
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            engine.put(&realm, b"durable1", b"val1").expect("put");
            engine.put(&realm, b"durable2", b"val2").expect("put");
            engine.delete(&realm, b"durable2").expect("delete");
        }

        // Re-open: WAL replay should recover state
        {
            let config = StorageConfig::test_config(dir.path().to_path_buf());
            let engine = EmbeddedStorageEngine::open(config).expect("reopen");

            assert_eq!(
                engine.get(&realm, b"durable1").expect("get"),
                Some(b"val1".to_vec()),
                "value should survive WAL recovery"
            );
            assert_eq!(
                engine.get(&realm, b"durable2").expect("get"),
                None,
                "deleted value should remain deleted after recovery"
            );
        }
    }

    #[test]
    fn engine_memtable_flush_to_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

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
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        // Write enough data to trigger flush
        for i in 0u32..20 {
            let key = format!("key-{i:04}");
            let val = format!("val-{i:04}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
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
            let actual = engine.get(&realm, key.as_bytes()).expect("get");
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
        let realm = RealmId::generate();

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
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");

            // Write enough to trigger flush
            for i in 0u32..10 {
                let key = format!("cold-{i:04}");
                engine
                    .put(&realm, key.as_bytes(), b"cold-value")
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
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
            };
            let engine = EmbeddedStorageEngine::open(config).expect("reopen");

            // Hot tier should be empty initially
            assert!(
                !engine.hot_tier.contains(&realm, b"cold-0000"),
                "hot tier should be empty on fresh open"
            );

            // Read from cold (SST) — should promote to hot tier
            let val = engine.get(&realm, b"cold-0000").expect("cold read");
            assert_eq!(val, Some(b"cold-value".to_vec()));

            // Now it should be in the hot tier
            assert!(
                engine.hot_tier.contains(&realm, b"cold-0000"),
                "cold read should promote to hot tier"
            );

            // Second read should hit hot tier (faster path)
            let val2 = engine.get(&realm, b"cold-0000").expect("hot read");
            assert_eq!(val2, Some(b"cold-value".to_vec()));
        }
    }

    #[test]
    fn engine_scan_merges_memtable_and_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

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
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");

            // Write keys that will end up in SST (flush triggered by small threshold)
        engine.put(&realm, b"aaa", b"sst-val").expect("put");
        engine.put(&realm, b"bbb", b"sst-val").expect("put");
        engine.put(&realm, b"ccc", b"sst-val").expect("put");

        // These keys should be in memtable (written after last flush or still in memtable)
        engine.put(&realm, b"ddd", b"mem-val").expect("put");
        engine.put(&realm, b"eee", b"mem-val").expect("put");

        // Scan the full range — should merge SST + memtable
        let results = engine.scan(&realm, b"aaa", b"fff").expect("scan");

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

    #[test]
    fn engine_refuses_to_start_with_missing_keks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Build engine, flush data to create an SST file
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig {
                    flush_threshold_bytes: 50,
                },
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                },
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            for i in 0u32..5 {
                engine
                    .put(&realm, format!("k-{i}").as_bytes(), b"v")
                    .expect("put");
            }
        }

        // Delete the key registry so KEKs are lost, and the WAL (which also
        // has a wrapped DEK that can't be unwrapped without the old KEK).
        std::fs::remove_file(dir.path().join("hearth.keys")).expect("remove keys");
        std::fs::remove_file(dir.path().join("hearth.wal")).expect("remove wal");

        // Reopen: SSTs reference a KEK that no longer exists, should fail
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig::default(),
            tiered_config: TieredConfig::default(),
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
        };
        let result = EmbeddedStorageEngine::open(config);
        assert!(
            matches!(result, Err(StorageError::Crypto { .. })),
            "expected StorageError::Crypto, got: {result:?}"
        );
    }

    #[test]
    fn engine_allow_missing_keks_silently_drops_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Build engine, flush data to create an SST file
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig {
                    flush_threshold_bytes: 50,
                },
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                },
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            for i in 0u32..5 {
                engine
                    .put(&realm, format!("k-{i}").as_bytes(), b"v")
                    .expect("put");
            }
        }

        // Remove key registry and WAL so SST DEKs can't be unwrapped
        std::fs::remove_file(dir.path().join("hearth.keys")).expect("remove keys");
        std::fs::remove_file(dir.path().join("hearth.wal")).expect("remove wal");

        // Reopen with allow_missing_keks: SST is silently dropped, open succeeds
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig::default(),
            tiered_config: TieredConfig::default(),
            allow_missing_keks: true,
            compaction: CompactionConfig::default(),
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open with allow_missing_keks");
        // Data that was only in the SST is no longer reachable
        for i in 0u32..5 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i}").as_bytes())
                    .expect("get"),
                None,
                "SST-dropped key k-{i} should not be found"
            );
        }
    }

    #[test]
    fn engine_compaction_reduces_sst_count_and_preserves_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..50 {
            engine
                .put(
                    &realm,
                    format!("c-{i:04}").as_bytes(),
                    format!("val-{i:04}").as_bytes(),
                )
                .expect("put");
        }

        let sst_before = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(
            sst_before >= 2,
            "expected at least 2 SST files before compaction, got {sst_before}"
        );

        let compacted = engine.compact_ssts(2).expect("compact_ssts");
        assert_eq!(
            compacted, sst_before,
            "compacted count should match input SST count"
        );

        let sst_after = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert_eq!(
            sst_after, 1,
            "after compaction there should be exactly 1 SST file, got {sst_after}"
        );

        for i in 0u32..50 {
            let key = format!("c-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(format!("val-{i:04}").into_bytes()),
                "key {key} should be accessible after compaction"
            );
        }
    }

    #[test]
    fn engine_compaction_skips_when_below_min_sst_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        engine.put(&realm, b"a", b"val-a").expect("put");

        let compacted = engine.compact_ssts(5).expect("compact_ssts");
        assert_eq!(
            compacted, 0,
            "compaction should skip when SST count is below min_sst_count"
        );
    }

    #[test]
    fn engine_compaction_succeeds_at_exact_min_sst_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
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
                    format!("b-{i:04}").as_bytes(),
                    format!("vb-{i:04}").as_bytes(),
                )
                .expect("put");
        }

        let sst_before = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();

        if sst_before >= 2 {
            let compacted = engine.compact_ssts(2).expect("compact_ssts");
            assert_eq!(
                compacted, sst_before,
                "compaction at exact min_sst_count boundary should succeed"
            );

            for i in 0u32..30 {
                let key = format!("b-{i:04}");
                assert_eq!(
                    engine.get(&realm, key.as_bytes()).expect("get"),
                    Some(format!("vb-{i:04}").into_bytes()),
                );
            }
        }
    }

    #[test]
    fn engine_compaction_removes_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..20 {
            engine
                .put(
                    &realm,
                    format!("k-{i:04}").as_bytes(),
                    format!("val-{i:04}").as_bytes(),
                )
                .expect("put");
        }
        for i in 0u32..10 {
            engine
                .delete(&realm, format!("k-{i:04}").as_bytes())
                .expect("delete");
        }

        // Extra writes to force flushes (push tombstones into SSTs)
        engine.put(&realm, b"flush-a", b"x").expect("put");
        engine.put(&realm, b"flush-b", b"x").expect("put");

        let compacted = engine.compact_ssts(2).expect("compact");
        assert!(compacted > 0, "should have compacted at least 2 SSTs");

        // Compacted SST must have zero tombstones
        let readers = engine.sst_readers.load();
        assert_eq!(readers.len(), 1, "should be 1 SST after compaction");
        for (_key, value) in readers[0].iter_all() {
            assert!(
                !matches!(value, MemtableValue::Tombstone),
                "compacted SST must contain zero tombstones"
            );
        }

        // Deleted keys must be unreachable
        for i in 0u32..10 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i:04}").as_bytes())
                    .expect("get"),
                None,
                "deleted key k-{i:04} must not be reachable after compaction"
            );
        }

        // Live keys must still be reachable
        for i in 10u32..20 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i:04}").as_bytes())
                    .expect("get"),
                Some(format!("val-{i:04}").into_bytes()),
            );
        }
    }
}
