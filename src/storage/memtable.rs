//! In-memory sorted key-value store for recent writes.
//!
//! The memtable accepts writes and provides lock-free reads via `ArcSwap`.
//! When it reaches its configured size threshold, it signals readiness for
//! flushing to an SST (Step 5). Writes are serialized behind a `Mutex`;
//! reads are wait-free through `ArcSwap::load()`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::core::TenantId;
use crate::storage::error::StorageError;
use crate::storage::wal::{WalEntry, WalOperation};

/// Composite key combining tenant identity with a data key.
///
/// Ordered by tenant UUID bytes first, then by key bytes (lexicographic).
/// This ensures tenant-scoped ordering and makes cross-tenant reads
/// structurally impossible without providing a different `TenantId`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CompositeKey {
    /// The tenant that owns this key.
    tenant_id: TenantId,
    /// The raw key bytes.
    key: Vec<u8>,
}

impl CompositeKey {
    /// Creates a new composite key from a tenant ID and raw key bytes.
    pub(crate) fn new(tenant_id: TenantId, key: Vec<u8>) -> Self {
        Self { tenant_id, key }
    }

    /// Returns a reference to the tenant ID.
    pub(crate) fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns a reference to the raw key bytes.
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Value stored in the memtable, supporting tombstone markers for deletes.
///
/// Tombstones are preserved until SST flush and compaction (Step 5+).
/// The `get()` method returns `None` for both absent keys and tombstones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MemtableValue {
    /// A live key-value entry.
    Data(Vec<u8>),
    /// A deletion marker.
    Tombstone,
}

/// Configuration for the memtable.
#[derive(Debug, Clone)]
pub(crate) struct MemtableConfig {
    /// Byte threshold at which the memtable signals readiness for flush.
    pub flush_threshold_bytes: usize,
}

impl Default for MemtableConfig {
    fn default() -> Self {
        Self {
            flush_threshold_bytes: 4 * 1024 * 1024, // 4 MiB
        }
    }
}

/// In-memory sorted key-value store with lock-free reads.
///
/// Uses `ArcSwap<BTreeMap>` for wait-free read access and a `Mutex`
/// to serialize writes (clone-mutate-swap pattern). Writes are off the
/// hot path, so the allocation from cloning is acceptable.
pub(crate) struct Memtable {
    /// The sorted key-value data, swapped atomically on writes.
    data: ArcSwap<BTreeMap<CompositeKey, MemtableValue>>,
    /// Serializes write operations (put, delete, clear).
    write_lock: Mutex<()>,
    /// Approximate total byte size of all entries.
    approximate_size: AtomicUsize,
    /// Configuration (flush threshold).
    config: MemtableConfig,
}

impl Memtable {
    /// Creates a new empty memtable with the given configuration.
    pub(crate) fn new(config: MemtableConfig) -> Self {
        Self {
            data: ArcSwap::from_pointee(BTreeMap::new()),
            write_lock: Mutex::new(()),
            approximate_size: AtomicUsize::new(0),
            config,
        }
    }

    /// Inserts or updates a key-value pair for the given tenant.
    ///
    /// If the key already exists, its value is overwritten. Size tracking
    /// is updated to reflect the delta.
    pub(crate) fn put(
        &self,
        tenant_id: &TenantId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        let composite = CompositeKey {
            tenant_id: tenant_id.clone(),
            key: key.to_vec(),
        };
        let new_value = MemtableValue::Data(value.to_vec());

        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let current = self.data.load_full();
        let mut new_map = (*current).clone();

        let new_entry_size = Self::entry_size(key, &new_value);
        let old_entry_size = new_map
            .get(&composite)
            .map_or(0, |old_val| Self::entry_size(key, old_val));

        new_map.insert(composite, new_value);
        self.data.store(Arc::new(new_map));

        self.update_size(old_entry_size, new_entry_size);

        Ok(())
    }

    /// Inserts a tombstone for the given key, marking it as deleted.
    ///
    /// Subsequent `get()` calls return `None`. The tombstone is preserved
    /// for SST flush so downstream compaction can remove the key.
    pub(crate) fn delete(&self, tenant_id: &TenantId, key: &[u8]) -> Result<(), StorageError> {
        let composite = CompositeKey {
            tenant_id: tenant_id.clone(),
            key: key.to_vec(),
        };
        let new_value = MemtableValue::Tombstone;

        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let current = self.data.load_full();
        let mut new_map = (*current).clone();

        let new_entry_size = Self::entry_size(key, &new_value);
        let old_entry_size = new_map
            .get(&composite)
            .map_or(0, |old_val| Self::entry_size(key, old_val));

        new_map.insert(composite, new_value);
        self.data.store(Arc::new(new_map));

        self.update_size(old_entry_size, new_entry_size);

        Ok(())
    }

    /// Retrieves a value by tenant and key. Returns `None` for both
    /// absent keys and tombstones. This is a lock-free read.
    pub(crate) fn get(&self, tenant_id: &TenantId, key: &[u8]) -> Option<Vec<u8>> {
        let composite = CompositeKey {
            tenant_id: tenant_id.clone(),
            key: key.to_vec(),
        };
        let snapshot = self.data.load();
        match snapshot.get(&composite) {
            Some(MemtableValue::Data(v)) => Some(v.clone()),
            Some(MemtableValue::Tombstone) | None => None,
        }
    }

    /// Returns whether the memtable has reached its flush threshold.
    pub(crate) fn should_flush(&self) -> bool {
        self.approximate_size.load(Ordering::Relaxed) >= self.config.flush_threshold_bytes
    }

    /// Returns the approximate byte size of all entries in the memtable.
    pub(crate) fn approximate_size(&self) -> usize {
        self.approximate_size.load(Ordering::Relaxed)
    }

    /// Returns all entries for a given tenant, sorted by key.
    ///
    /// Includes tombstones. The returned keys are the raw data keys
    /// (without the tenant prefix).
    pub(crate) fn iter_tenant(&self, tenant_id: &TenantId) -> Vec<(Vec<u8>, MemtableValue)> {
        let snapshot = self.data.load();
        let start = CompositeKey {
            tenant_id: tenant_id.clone(),
            key: vec![],
        };
        snapshot
            .range(start..)
            .take_while(|(k, _)| k.tenant_id == *tenant_id)
            .map(|(k, v)| (k.key.clone(), v.clone()))
            .collect()
    }

    /// Returns all entries across all tenants, sorted by composite key.
    ///
    /// Used for flushing to SST files. Includes tombstones.
    pub(crate) fn iter_all(&self) -> Vec<(CompositeKey, MemtableValue)> {
        let snapshot = self.data.load();
        snapshot
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Applies a WAL entry to the memtable (for crash recovery replay).
    pub(crate) fn apply_wal_entry(&self, entry: &WalEntry) -> Result<(), StorageError> {
        match entry.operation {
            WalOperation::Put => self.put(&entry.tenant_id, &entry.key, &entry.value),
            WalOperation::Delete => self.delete(&entry.tenant_id, &entry.key),
            WalOperation::Batch => {
                // The outer record's CRC already guarantees atomicity — a
                // corrupt or truncated batch is dropped by the reader before
                // reaching here. If decoding still fails, treat it as a
                // malformed record and stop replay rather than applying a
                // partial batch.
                let sub_entries = crate::storage::wal::decode_batch_payload(&entry.value)?;
                for sub in &sub_entries {
                    match sub.operation {
                        WalOperation::Put => self.put(&entry.tenant_id, &sub.key, &sub.value)?,
                        WalOperation::Delete => self.delete(&entry.tenant_id, &sub.key)?,
                        WalOperation::Batch => {
                            return Err(StorageError::DeserializationFailed {
                                reason: "nested batch in WAL replay".to_string(),
                            });
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Clears all data and resets size tracking. Used after flushing to SST.
    pub(crate) fn clear(&self) -> Result<(), StorageError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        self.data.store(Arc::new(BTreeMap::new()));
        self.approximate_size.store(0, Ordering::Relaxed);

        Ok(())
    }

    /// Estimates the byte size of a single entry.
    ///
    /// Accounts for 16 bytes of UUID, key length, and value length.
    fn entry_size(key: &[u8], value: &MemtableValue) -> usize {
        16 + key.len()
            + match value {
                MemtableValue::Data(v) => v.len(),
                MemtableValue::Tombstone => 0,
            }
    }

    /// Updates the approximate size atomically given old and new entry sizes.
    fn update_size(&self, old_size: usize, new_size: usize) {
        if new_size >= old_size {
            self.approximate_size
                .fetch_add(new_size - old_size, Ordering::Relaxed);
        } else {
            self.approximate_size
                .fetch_sub(old_size - new_size, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for Memtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memtable")
            .field(
                "approximate_size",
                &self.approximate_size.load(Ordering::Relaxed),
            )
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{TenantId, Timestamp};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::AtomicBool;

    // ===== Phase A: P0 Fast Unit Tests =====
    // TEST_SCENARIOS.md: "Insert and retrieve key-value pairs (single and multiple)"

    #[test]
    fn insert_and_retrieve_single_key() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"value1").expect("put");

        assert_eq!(mt.get(&tenant, b"key1"), Some(b"value1".to_vec()));
    }

    #[test]
    fn insert_and_retrieve_multiple_keys() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"val1").expect("put 1");
        mt.put(&tenant, b"key2", b"val2").expect("put 2");
        mt.put(&tenant, b"key3", b"val3").expect("put 3");

        assert_eq!(mt.get(&tenant, b"key1"), Some(b"val1".to_vec()));
        assert_eq!(mt.get(&tenant, b"key2"), Some(b"val2".to_vec()));
        assert_eq!(mt.get(&tenant, b"key3"), Some(b"val3".to_vec()));
    }

    #[test]
    fn get_nonexistent_key_returns_none() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        assert_eq!(mt.get(&tenant, b"missing"), None);
    }

    // TEST_SCENARIOS.md: "Update existing key overwrites value"

    #[test]
    fn update_overwrites_value() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"original").expect("put 1");
        assert_eq!(mt.get(&tenant, b"key1"), Some(b"original".to_vec()));

        mt.put(&tenant, b"key1", b"updated").expect("put 2");
        assert_eq!(mt.get(&tenant, b"key1"), Some(b"updated".to_vec()));
    }

    // TEST_SCENARIOS.md: "Delete key removes entry; subsequent lookup returns None"

    #[test]
    fn delete_key_returns_none_on_lookup() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"value1").expect("put");
        assert_eq!(mt.get(&tenant, b"key1"), Some(b"value1".to_vec()));

        mt.delete(&tenant, b"key1").expect("delete");
        assert_eq!(mt.get(&tenant, b"key1"), None);
    }

    #[test]
    fn delete_nonexistent_key_succeeds() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.delete(&tenant, b"missing").expect("delete");
        assert_eq!(mt.get(&tenant, b"missing"), None);
    }

    #[test]
    fn delete_inserts_tombstone_visible_in_iterator() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"value1").expect("put");
        mt.delete(&tenant, b"key1").expect("delete");

        let entries = mt.iter_tenant(&tenant);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (b"key1".to_vec(), MemtableValue::Tombstone));
    }

    // TEST_SCENARIOS.md: "Flush threshold triggers when memtable reaches configured byte size"

    #[test]
    fn flush_threshold_triggers_at_configured_size() {
        let config = MemtableConfig {
            flush_threshold_bytes: 100,
        };
        let mt = Memtable::new(config);
        let tenant = TenantId::generate();

        assert!(!mt.should_flush());
        assert_eq!(mt.approximate_size(), 0);

        // Each entry: 16 (UUID) + key.len() + value.len()
        // First put: 16 + 4 + 32 = 52
        mt.put(&tenant, b"key1", &[0u8; 32]).expect("put 1");
        assert!(!mt.should_flush());

        // Second put: 16 + 4 + 32 = 52, total ~104 > 100
        mt.put(&tenant, b"key2", &[0u8; 32]).expect("put 2");
        assert!(mt.should_flush());
    }

    #[test]
    fn size_tracking_accounts_for_updates() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", &[0u8; 100]).expect("put large");
        let size_after_large = mt.approximate_size();

        // Overwrite with smaller value — size should decrease
        mt.put(&tenant, b"key1", &[0u8; 10]).expect("put small");
        let size_after_small = mt.approximate_size();

        assert!(
            size_after_small < size_after_large,
            "size should decrease on smaller update: {size_after_small} vs {size_after_large}"
        );
    }

    // TEST_SCENARIOS.md: "Iterator returns entries in sorted key order"

    #[test]
    fn iterator_returns_sorted_key_order() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        // Insert in non-sorted order
        mt.put(&tenant, b"charlie", b"3").expect("put");
        mt.put(&tenant, b"alpha", b"1").expect("put");
        mt.put(&tenant, b"delta", b"4").expect("put");
        mt.put(&tenant, b"bravo", b"2").expect("put");

        let entries = mt.iter_tenant(&tenant);
        let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(
            keys,
            vec![
                b"alpha".as_slice(),
                b"bravo".as_slice(),
                b"charlie".as_slice(),
                b"delta".as_slice(),
            ]
        );
    }

    // ===== Supplementary Unit Tests (architecture requirements) =====

    #[test]
    fn tenant_isolation_no_cross_tenant_reads() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        mt.put(&tenant_a, b"shared_key", b"value-a").expect("put a");
        mt.put(&tenant_b, b"shared_key", b"value-b").expect("put b");
        mt.put(&tenant_a, b"only-a", b"exclusive").expect("put a2");

        // Each tenant sees only their own data
        assert_eq!(mt.get(&tenant_a, b"shared_key"), Some(b"value-a".to_vec()));
        assert_eq!(mt.get(&tenant_b, b"shared_key"), Some(b"value-b".to_vec()));
        assert_eq!(mt.get(&tenant_b, b"only-a"), None);

        // Tenant iterators are scoped
        let entries_a = mt.iter_tenant(&tenant_a);
        assert_eq!(entries_a.len(), 2);
        let entries_b = mt.iter_tenant(&tenant_b);
        assert_eq!(entries_b.len(), 1);
    }

    #[test]
    fn apply_wal_entry_put_and_delete() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        let put_entry = WalEntry {
            timestamp: Timestamp::from_micros(1_000_000),
            tenant_id: tenant.clone(),
            operation: WalOperation::Put,
            key: b"key1".to_vec(),
            value: b"value1".to_vec(),
        };
        mt.apply_wal_entry(&put_entry).expect("apply put");
        assert_eq!(mt.get(&tenant, b"key1"), Some(b"value1".to_vec()));

        let delete_entry = WalEntry {
            timestamp: Timestamp::from_micros(2_000_000),
            tenant_id: tenant.clone(),
            operation: WalOperation::Delete,
            key: b"key1".to_vec(),
            value: vec![],
        };
        mt.apply_wal_entry(&delete_entry).expect("apply delete");
        assert_eq!(mt.get(&tenant, b"key1"), None);
    }

    #[test]
    fn clear_resets_data_and_size() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"value1").expect("put 1");
        mt.put(&tenant, b"key2", b"value2").expect("put 2");
        assert!(mt.approximate_size() > 0);

        mt.clear().expect("clear");

        assert_eq!(mt.get(&tenant, b"key1"), None);
        assert_eq!(mt.get(&tenant, b"key2"), None);
        assert_eq!(mt.approximate_size(), 0);
        assert!(mt.iter_tenant(&tenant).is_empty());
        assert!(mt.iter_all().is_empty());
    }

    #[test]
    fn iter_all_returns_entries_across_tenants() {
        let mt = Memtable::new(MemtableConfig::default());
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        mt.put(&tenant_a, b"a1", b"va1").expect("put");
        mt.put(&tenant_b, b"b1", b"vb1").expect("put");

        let all = mt.iter_all();
        assert_eq!(all.len(), 2);

        // All entries should be sorted by CompositeKey
        assert!(all[0].0 < all[1].0, "iter_all should return sorted entries");
    }

    #[test]
    fn memtable_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Memtable>();
    }

    // ===== Phase B: P0 Extended Property Tests =====

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum TestOp {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
    }

    fn arb_test_op() -> impl Strategy<Value = TestOp> {
        prop_oneof![
            (
                prop::collection::vec(any::<u8>(), 1..32),
                prop::collection::vec(any::<u8>(), 0..64),
            )
                .prop_map(|(k, v)| TestOp::Put(k, v)),
            prop::collection::vec(any::<u8>(), 1..32).prop_map(TestOp::Delete),
        ]
    }

    proptest! {
        /// TEST_SCENARIOS.md: "Random insert/update/delete sequences maintain correct key set"
        #[test]
        fn proptest_random_ops_maintain_correct_key_set(
            ops in prop::collection::vec(arb_test_op(), 1..200)
        ) {
            let mt = Memtable::new(MemtableConfig::default());
            let tenant = TenantId::generate();
            let mut oracle: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

            for op in &ops {
                match op {
                    TestOp::Put(key, value) => {
                        mt.put(&tenant, key, value).expect("put");
                        oracle.insert(key.clone(), value.clone());
                    }
                    TestOp::Delete(key) => {
                        mt.delete(&tenant, key).expect("delete");
                        oracle.remove(key);
                    }
                }
            }

            // Verify all oracle entries exist in memtable
            for (key, expected) in &oracle {
                let actual = mt.get(&tenant, key);
                prop_assert_eq!(
                    actual.as_deref(),
                    Some(expected.as_slice()),
                    "key {:?} mismatch",
                    key
                );
            }

            // Verify memtable has no extra live entries
            let entries = mt.iter_tenant(&tenant);
            let live_entries: Vec<_> = entries
                .into_iter()
                .filter(|(_, v)| matches!(v, MemtableValue::Data(_)))
                .collect();
            let memtable_keys: HashSet<Vec<u8>> =
                live_entries.iter().map(|(k, _)| k.clone()).collect();
            let oracle_keys: HashSet<Vec<u8>> = oracle.keys().cloned().collect();
            prop_assert_eq!(memtable_keys, oracle_keys);
        }
    }

    /// `TEST_SCENARIOS.md`: "Concurrent reads during writes see consistent snapshots"
    #[test]
    fn concurrent_reads_during_writes_see_consistent_snapshots() {
        let mt = Arc::new(Memtable::new(MemtableConfig::default()));
        let tenant = TenantId::generate();
        let done = Arc::new(AtomicBool::new(false));

        std::thread::scope(|s| {
            // Writer: inserts keys 0..1000
            let mt_w = &mt;
            let t_w = &tenant;
            let done_w = &done;
            s.spawn(move || {
                for i in 0u32..1000 {
                    mt_w.put(t_w, &i.to_be_bytes(), &i.to_be_bytes())
                        .expect("put");
                }
                done_w.store(true, Ordering::Release);
            });

            // Readers: continuously snapshot and verify sorted order
            for _ in 0..4 {
                let mt_r = &mt;
                let t_r = &tenant;
                let done_r = &done;
                s.spawn(move || {
                    let mut iterations = 0u64;
                    while !done_r.load(Ordering::Acquire) {
                        let entries = mt_r.iter_tenant(t_r);
                        // Every snapshot must be sorted
                        for window in entries.windows(2) {
                            assert!(
                                window[0].0 <= window[1].0,
                                "snapshot not sorted at iteration {iterations}"
                            );
                        }
                        iterations += 1;
                    }
                    // Ensure readers actually ran
                    assert!(iterations > 0, "reader thread never ran");
                });
            }
        });

        // Final consistency check: all 1000 keys should be present
        for i in 0u32..1000 {
            assert_eq!(
                mt.get(&tenant, &i.to_be_bytes()),
                Some(i.to_be_bytes().to_vec()),
                "key {i} missing after concurrent writes"
            );
        }
    }
}
