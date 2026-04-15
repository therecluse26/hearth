//! Write-ahead log for durable storage of mutations.
//!
//! Binary format per record:
//! ```text
//! [4 bytes: payload length (u32 LE)]
//! [N bytes: payload]
//! [4 bytes: CRC32 of payload]
//! ```
//!
//! Payload layout:
//! ```text
//! [8 bytes: timestamp i64 LE]
//! [16 bytes: tenant UUID]
//! [1 byte: operation (0=Put, 1=Delete)]
//! [4 bytes: key length u32 LE]
//! [N bytes: key]
//! [4 bytes: value length u32 LE]
//! [M bytes: value]
//! ```

use crate::core::{TenantId, Timestamp};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, FsFile, RealFs};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// The type of mutation in a WAL entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalOperation {
    /// Insert or update a key-value pair.
    Put,
    /// Remove a key.
    Delete,
}

/// A single entry in the write-ahead log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    /// When this mutation occurred.
    pub timestamp: Timestamp,
    /// Which tenant owns this data.
    pub tenant_id: TenantId,
    /// The type of mutation.
    pub operation: WalOperation,
    /// The key being mutated.
    pub key: Vec<u8>,
    /// The value (empty for Delete operations).
    pub value: Vec<u8>,
}

impl WalEntry {
    /// Serializes this entry into its binary payload representation.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 16 + 1 + 4 + self.key.len() + 4 + self.value.len());

        // Timestamp: i64 LE
        buf.extend_from_slice(&self.timestamp.as_micros().to_le_bytes());

        // Tenant UUID: 16 bytes
        buf.extend_from_slice(self.tenant_id.as_uuid().as_bytes());

        // Operation: 1 byte
        let op_byte: u8 = match self.operation {
            WalOperation::Put => 0,
            WalOperation::Delete => 1,
        };
        buf.push(op_byte);

        // Key: length-prefixed
        #[allow(clippy::cast_possible_truncation)]
        let key_len = self.key.len() as u32;
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend_from_slice(&self.key);

        // Value: length-prefixed
        #[allow(clippy::cast_possible_truncation)]
        let val_len = self.value.len() as u32;
        buf.extend_from_slice(&val_len.to_le_bytes());
        buf.extend_from_slice(&self.value);

        buf
    }

    /// Deserializes a binary payload into a `WalEntry`.
    ///
    /// Returns `Err` for any malformed or truncated input. This function
    /// is guaranteed not to panic on arbitrary input.
    pub fn deserialize(data: &[u8]) -> Result<Self, StorageError> {
        // Minimum size: 8 (ts) + 16 (uuid) + 1 (op) + 4 (key_len) + 4 (val_len) = 33
        if data.len() < 33 {
            return Err(StorageError::DeserializationFailed {
                reason: format!("payload too short: {} bytes", data.len()),
            });
        }

        let mut pos = 0;

        // Timestamp
        let ts_bytes: [u8; 8] =
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid timestamp bytes".to_string(),
                })?;
        let timestamp = Timestamp::from_micros(i64::from_le_bytes(ts_bytes));
        pos += 8;

        // Tenant UUID
        let uuid_bytes: [u8; 16] =
            data[pos..pos + 16]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid UUID bytes".to_string(),
                })?;
        let tenant_id = TenantId::new(Uuid::from_bytes(uuid_bytes));
        pos += 16;

        // Operation
        let operation = match data[pos] {
            0 => WalOperation::Put,
            1 => WalOperation::Delete,
            other => {
                return Err(StorageError::DeserializationFailed {
                    reason: format!("unknown operation byte: {other}"),
                })
            }
        };
        pos += 1;

        // Key
        if data.len() < pos + 4 {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated key length".to_string(),
            });
        }
        let key_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid key length bytes".to_string(),
                })?;
        let key_len = u32::from_le_bytes(key_len_bytes) as usize;
        pos += 4;

        if data.len() < pos + key_len {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated key data".to_string(),
            });
        }
        let key = data[pos..pos + key_len].to_vec();
        pos += key_len;

        // Value
        if data.len() < pos + 4 {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated value length".to_string(),
            });
        }
        let val_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid value length bytes".to_string(),
                })?;
        let val_len = u32::from_le_bytes(val_len_bytes) as usize;
        pos += 4;

        if data.len() < pos + val_len {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated value data".to_string(),
            });
        }
        let value = data[pos..pos + val_len].to_vec();

        Ok(WalEntry {
            timestamp,
            tenant_id,
            operation,
            key,
            value,
        })
    }
}

/// Controls when the WAL fsyncs to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncMode {
    /// Fsync after every write (production default).
    EveryWrite,
    /// No fsync — faster but unsafe. For development/testing only.
    None,
}

/// Configuration for the write-ahead log.
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Maximum WAL file size in bytes before rotation.
    pub max_size: u64,
    /// Fsync policy.
    pub sync_mode: SyncMode,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            max_size: 64 * 1024 * 1024, // 64 MiB
            sync_mode: SyncMode::EveryWrite,
        }
    }
}

/// Write-ahead log providing durable, ordered storage of mutations.
///
/// Thread-safe via `std::sync::Mutex`. WAL writes are blocking I/O and
/// should be called from `tokio::task::spawn_blocking`.
pub struct Wal {
    file: Mutex<Box<dyn FsFile>>,
    path: PathBuf,
    config: WalConfig,
    /// Retained for potential re-open after rotation in future phases.
    #[allow(dead_code)]
    fs: Arc<dyn Fs>,
}

impl Wal {
    /// Opens or creates a WAL file at the given path using the default filesystem.
    pub fn open(path: &Path, config: WalConfig) -> Result<Self, StorageError> {
        Self::open_with_fs(path, config, Arc::new(RealFs))
    }

    /// Opens or creates a WAL file at the given path using a custom filesystem.
    ///
    /// Used by the simulation crate to inject faults via a `FaultFs`.
    pub fn open_with_fs(
        path: &Path,
        config: WalConfig,
        fs: Arc<dyn Fs>,
    ) -> Result<Self, StorageError> {
        let file = fs.open_append(path)?;

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            config,
            fs,
        })
    }

    /// Appends an entry to the WAL.
    ///
    /// Serializes the entry, writes `[length][payload][crc32]`, and optionally fsyncs.
    pub fn append(&self, entry: &WalEntry) -> Result<(), StorageError> {
        let payload = entry.serialize();
        let crc = crc32fast::hash(&payload);

        let mut file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;

        // Check if rotation is needed
        let file_size = file.seek(SeekFrom::End(0))?;
        #[allow(clippy::cast_possible_truncation)]
        let record_size = 4 + payload.len() as u64 + 4;
        if self.config.max_size > 0 && file_size + record_size > self.config.max_size {
            self.rotate_locked(&mut **file)?;
        }

        // Write: [payload_length: u32 LE][payload][crc32: u32 LE]
        #[allow(clippy::cast_possible_truncation)]
        let payload_len = payload.len() as u32;
        file.write_all(&payload_len.to_le_bytes())?;
        file.write_all(&payload)?;
        file.write_all(&crc.to_le_bytes())?;

        if self.config.sync_mode == SyncMode::EveryWrite {
            file.sync_all()?;
        }

        Ok(())
    }

    /// Reads all valid entries from the WAL.
    ///
    /// Stops at the first corrupted or incomplete record, returning only
    /// the valid prefix. This is the expected recovery behavior.
    pub fn read_all(&self) -> Result<Vec<WalEntry>, StorageError> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;

        file.seek(SeekFrom::Start(0))?;

        let mut all_data = Vec::new();
        file.read_to_end(&mut all_data)?;

        let mut entries = Vec::new();
        let mut pos: usize = 0;

        while pos + 4 <= all_data.len() {
            // Read payload length
            let len_bytes: [u8; 4] = match all_data[pos..pos + 4].try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let payload_len = u32::from_le_bytes(len_bytes) as usize;
            pos += 4;

            // Check we have enough data for payload + CRC
            if pos + payload_len + 4 > all_data.len() {
                break; // Incomplete record — stop
            }

            let payload = &all_data[pos..pos + payload_len];
            pos += payload_len;

            // Read and verify CRC
            let crc_bytes: [u8; 4] = match all_data[pos..pos + 4].try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let stored_crc = u32::from_le_bytes(crc_bytes);
            let computed_crc = crc32fast::hash(payload);
            pos += 4;

            if stored_crc != computed_crc {
                break; // Corrupted record — stop, return valid prefix
            }

            match WalEntry::deserialize(payload) {
                Ok(entry) => entries.push(entry),
                Err(_) => break, // Deserialization failure — stop
            }
        }

        Ok(entries)
    }

    /// Forces an fsync of the WAL file.
    pub fn sync(&self) -> Result<(), StorageError> {
        let file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;
        file.sync_all()?;
        Ok(())
    }

    /// Rotates the WAL file by truncating the current file.
    ///
    /// In a full implementation this would rename and create a new segment.
    /// For Phase 0, rotation truncates the file to start fresh.
    fn rotate_locked(&self, file: &mut dyn FsFile) -> Result<(), StorageError> {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        if self.config.sync_mode == SyncMode::EveryWrite {
            file.sync_all()?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wal")
            .field("path", &self.path)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TenantId;
    use proptest::prelude::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    /// Helper to create a test WAL entry.
    fn make_entry(key: &[u8], value: &[u8], op: WalOperation) -> WalEntry {
        WalEntry {
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            tenant_id: TenantId::new(Uuid::new_v4()),
            operation: op,
            key: key.to_vec(),
            value: value.to_vec(),
        }
    }

    // --- Serialization tests ---

    #[test]
    fn wal_entry_put_serde_round_trip() {
        let entry = make_entry(b"users/alice", b"data-here", WalOperation::Put);
        let bytes = entry.serialize();
        let decoded = WalEntry::deserialize(&bytes).expect("deserialize");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn wal_entry_delete_serde_round_trip() {
        let entry = make_entry(b"users/bob", b"", WalOperation::Delete);
        let bytes = entry.serialize();
        let decoded = WalEntry::deserialize(&bytes).expect("deserialize");
        assert_eq!(entry, decoded);
    }

    // --- P0 fast unit tests ---

    #[test]
    fn empty_wal_returns_no_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = Wal::open(&wal_path, WalConfig::default()).expect("open");
        let entries = wal.read_all().expect("read");
        assert!(entries.is_empty());
    }

    #[test]
    fn append_single_entry_and_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = Wal::open(&wal_path, WalConfig::default()).expect("open");

        let entry = make_entry(b"key1", b"value1", WalOperation::Put);
        wal.append(&entry).expect("append");

        let entries = wal.read_all().expect("read");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }

    #[test]
    fn append_multiple_preserves_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = Wal::open(&wal_path, WalConfig::default()).expect("open");

        let mut expected = Vec::new();
        for i in 0..10 {
            let entry = make_entry(
                format!("key{i}").as_bytes(),
                format!("val{i}").as_bytes(),
                WalOperation::Put,
            );
            wal.append(&entry).expect("append");
            expected.push(entry);
        }

        let entries = wal.read_all().expect("read");
        assert_eq!(entries.len(), 10);
        assert_eq!(entries, expected);
    }

    #[test]
    fn wal_fsync_durability_across_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry = make_entry(b"durable-key", b"durable-val", WalOperation::Put);

        // Write and drop (simulates process exit)
        {
            let wal = Wal::open(
                &wal_path,
                WalConfig {
                    sync_mode: SyncMode::EveryWrite,
                    ..WalConfig::default()
                },
            )
            .expect("open");
            wal.append(&entry).expect("append");
        }

        // Re-open and verify data persisted
        {
            let wal = Wal::open(&wal_path, WalConfig::default()).expect("reopen");
            let entries = wal.read_all().expect("read");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0], entry);
        }
    }

    #[test]
    fn wal_recovery_stops_at_corruption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry1 = make_entry(b"good1", b"val1", WalOperation::Put);
        let entry2 = make_entry(b"good2", b"val2", WalOperation::Put);

        // Write two valid entries
        {
            let wal = Wal::open(&wal_path, WalConfig::default()).expect("open");
            wal.append(&entry1).expect("append 1");
            wal.append(&entry2).expect("append 2");
        }

        // Append garbage bytes to simulate corruption
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&wal_path)
                .expect("open for corruption");
            file.write_all(b"GARBAGE_CORRUPT_DATA_HERE")
                .expect("write garbage");
            file.sync_all().expect("sync");
        }

        // Re-open: should get both valid entries, garbage ignored
        {
            let wal = Wal::open(&wal_path, WalConfig::default()).expect("reopen");
            let entries = wal.read_all().expect("read");
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0], entry1);
            assert_eq!(entries[1], entry2);
        }
    }

    // --- P1 fast ---

    #[test]
    fn wal_rotation_at_size_threshold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        // Very small max_size to trigger rotation quickly
        let config = WalConfig {
            max_size: 100,
            sync_mode: SyncMode::None,
        };
        let wal = Wal::open(&wal_path, config).expect("open");

        // Write entries until rotation occurs
        for i in 0..10 {
            let entry = make_entry(
                format!("key-{i}").as_bytes(),
                format!("value-{i}").as_bytes(),
                WalOperation::Put,
            );
            wal.append(&entry).expect("append");
        }

        // After rotation, the WAL should contain fewer entries than written
        // because rotation truncates the file
        let entries = wal.read_all().expect("read");
        assert!(
            entries.len() < 10,
            "expected rotation to truncate, got {} entries",
            entries.len()
        );
    }

    // --- P0 extended property tests ---

    /// Strategy for generating arbitrary `WalEntry` values.
    fn arb_wal_entry() -> impl Strategy<Value = WalEntry> {
        (
            any::<i64>(),                               // timestamp micros
            any::<[u8; 16]>(),                          // tenant uuid bytes
            prop_oneof![Just(0u8), Just(1u8)],          // operation
            prop::collection::vec(any::<u8>(), 0..256), // key
            prop::collection::vec(any::<u8>(), 0..256), // value
        )
            .prop_map(|(ts, uuid_bytes, op_byte, key, value)| {
                let operation = if op_byte == 0 {
                    WalOperation::Put
                } else {
                    WalOperation::Delete
                };
                WalEntry {
                    timestamp: Timestamp::from_micros(ts),
                    tenant_id: TenantId::new(Uuid::from_bytes(uuid_bytes)),
                    operation,
                    key,
                    value,
                }
            })
    }

    // ===== Phase C: Simulation tests — see simulation/ crate =====

    // ===== Phase D: Property tests =====

    proptest! {
        #[test]
        fn proptest_entry_serde_round_trip(entry in arb_wal_entry()) {
            let bytes = entry.serialize();
            let decoded = WalEntry::deserialize(&bytes).expect("deserialize");
            prop_assert_eq!(entry, decoded);
        }

        #[test]
        fn proptest_random_writes_maintain_order(
            entries in prop::collection::vec(arb_wal_entry(), 1..50)
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let wal_path = dir.path().join("test.wal");
            let config = WalConfig {
                max_size: u64::MAX, // no rotation
                sync_mode: SyncMode::None,
            };
            let wal = Wal::open(&wal_path, config).expect("open");

            for entry in &entries {
                wal.append(entry).expect("append");
            }

            let read_back = wal.read_all().expect("read");
            prop_assert_eq!(entries, read_back);
        }

        #[test]
        fn proptest_wal_replay_prefix_consistency(
            entries in prop::collection::vec(arb_wal_entry(), 1..30)
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let wal_path = dir.path().join("test.wal");
            let config = WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::None,
            };

            // Write all entries
            {
                let wal = Wal::open(&wal_path, config.clone()).expect("open");
                for entry in &entries {
                    wal.append(entry).expect("append");
                }
            }

            // Re-open and verify all entries survive
            {
                let wal = Wal::open(&wal_path, config).expect("reopen");
                let read_back = wal.read_all().expect("read");
                prop_assert_eq!(entries, read_back);
            }
        }
    }
}
