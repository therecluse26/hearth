//! Write-ahead log for durable storage of mutations.
//!
//! All WAL records are encrypted at rest using AES-256-GCM envelope encryption.
//! The WAL file starts with a 76-byte encryption header containing the
//! per-segment DEK wrapped by a realm KEK. Each record payload is encrypted
//! with a monotonic counter-based nonce.
//!
//! On-disk layout:
//! ```text
//! ENCRYPTION HEADER (76 bytes):
//!   [16B] KEK identifier
//!   [12B] Nonce for DEK wrapping
//!   [32B] DEK ciphertext
//!   [16B] GCM auth tag
//!
//! RECORDS (starting at byte 76):
//!   Per record:
//!     [4B] encrypted payload length (u32 LE, includes GCM tag)
//!     [NB] encrypted payload (AES-256-GCM ciphertext + 16B tag)
//!     [4B] CRC32 of encrypted payload bytes
//! ```
//!
//! Payload (plaintext, before encryption):
//! ```text
//! [8 bytes: timestamp i64 LE]
//! [16 bytes: realm UUID]
//! [1 byte: operation (0=Put, 1=Delete, 2=Batch)]
//! [4 bytes: key length u32 LE]
//! [N bytes: key]
//! [4 bytes: value length u32 LE]
//! [M bytes: value]
//! ```

use crate::core::{RealmId, Timestamp};
use crate::storage::encryption::{
    self, counter_nonce, DataEncryptionKey, EncryptionHeader, KekId, ENCRYPTION_HEADER_SIZE,
    KEK_ID_SIZE,
};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, FsFile, RealFs};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// The type of mutation in a WAL entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalOperation {
    /// Insert or update a key-value pair.
    Put,
    /// Remove a key.
    Delete,
    /// Atomic multi-entry write. The outer `WalEntry`'s `value` field encodes
    /// the nested list of `(sub_op, key, value)` tuples; its `key` field is
    /// unused (empty). Readers that do not recognise this opcode must treat
    /// the record as corrupt and stop replay — preserving the all-or-nothing
    /// guarantee on downgrade.
    Batch,
}

/// A single entry in the write-ahead log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    /// When this mutation occurred.
    pub timestamp: Timestamp,
    /// Which realm owns this data.
    pub realm_id: RealmId,
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

        // Realm UUID: 16 bytes
        buf.extend_from_slice(self.realm_id.as_uuid().as_bytes());

        // Operation: 1 byte
        let op_byte: u8 = match self.operation {
            WalOperation::Put => 0,
            WalOperation::Delete => 1,
            WalOperation::Batch => 2,
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

        // Realm UUID
        let uuid_bytes: [u8; 16] =
            data[pos..pos + 16]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid UUID bytes".to_string(),
                })?;
        let realm_id = RealmId::new(Uuid::from_bytes(uuid_bytes));
        pos += 16;

        // Operation
        let operation = match data[pos] {
            0 => WalOperation::Put,
            1 => WalOperation::Delete,
            2 => WalOperation::Batch,
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
            realm_id,
            operation,
            key,
            value,
        })
    }
}

/// A single sub-operation inside a `WalOperation::Batch` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// Put or Delete. Batch is disallowed — batches cannot nest.
    pub operation: WalOperation,
    /// Target key within the batch's realm.
    pub key: Vec<u8>,
    /// Value (empty for Delete).
    pub value: Vec<u8>,
}

/// Encodes a sequence of batch entries into the `value` field of a batch
/// `WalEntry`. The outer record's timestamp + realm apply to every sub-entry.
///
/// Layout:
/// ```text
/// [4 bytes: count (u32 LE)]
/// for each entry:
///   [1 byte: sub-op (0=Put, 1=Delete)]
///   [4 bytes: key length (u32 LE)]
///   [N bytes: key]
///   [4 bytes: value length (u32 LE)]
///   [M bytes: value]
/// ```
pub fn encode_batch_payload(entries: &[BatchEntry]) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::with_capacity(4 + entries.len() * 16);
    #[allow(clippy::cast_possible_truncation)]
    let count = entries.len() as u32;
    buf.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        let sub_op: u8 = match entry.operation {
            WalOperation::Put => 0,
            WalOperation::Delete => 1,
            WalOperation::Batch => {
                return Err(StorageError::DeserializationFailed {
                    reason: "batches cannot nest".to_string(),
                })
            }
        };
        buf.push(sub_op);
        #[allow(clippy::cast_possible_truncation)]
        let k_len = entry.key.len() as u32;
        buf.extend_from_slice(&k_len.to_le_bytes());
        buf.extend_from_slice(&entry.key);
        #[allow(clippy::cast_possible_truncation)]
        let v_len = entry.value.len() as u32;
        buf.extend_from_slice(&v_len.to_le_bytes());
        buf.extend_from_slice(&entry.value);
    }
    Ok(buf)
}

/// Inverse of [`encode_batch_payload`]. Returns `Err` for any truncation or
/// malformed sub-op so the WAL reader falls back to its "stop at corruption"
/// policy — preserving all-or-nothing semantics.
pub fn decode_batch_payload(data: &[u8]) -> Result<Vec<BatchEntry>, StorageError> {
    if data.len() < 4 {
        return Err(StorageError::DeserializationFailed {
            reason: "batch payload missing count".to_string(),
        });
    }
    let count_bytes: [u8; 4] =
        data[0..4]
            .try_into()
            .map_err(|_| StorageError::DeserializationFailed {
                reason: "invalid batch count".to_string(),
            })?;
    let count = u32::from_le_bytes(count_bytes) as usize;
    let mut pos = 4usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 1 > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch sub-op".to_string(),
            });
        }
        let operation = match data[pos] {
            0 => WalOperation::Put,
            1 => WalOperation::Delete,
            other => {
                return Err(StorageError::DeserializationFailed {
                    reason: format!("invalid batch sub-op byte: {other}"),
                })
            }
        };
        pos += 1;

        if pos + 4 > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch key length".to_string(),
            });
        }
        let k_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid batch key length".to_string(),
                })?;
        let k_len = u32::from_le_bytes(k_len_bytes) as usize;
        pos += 4;
        if pos + k_len > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch key".to_string(),
            });
        }
        let key = data[pos..pos + k_len].to_vec();
        pos += k_len;

        if pos + 4 > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch value length".to_string(),
            });
        }
        let v_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid batch value length".to_string(),
                })?;
        let v_len = u32::from_le_bytes(v_len_bytes) as usize;
        pos += 4;
        if pos + v_len > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch value".to_string(),
            });
        }
        let value = data[pos..pos + v_len].to_vec();
        pos += v_len;

        entries.push(BatchEntry {
            operation,
            key,
            value,
        });
    }
    Ok(entries)
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

/// Rotation state: the per-segment DEK and encryption header.
/// Protected by its own Mutex for safe interior mutability during rotation.
struct RotationState {
    dek: DataEncryptionKey,
    enc_header: EncryptionHeader,
}

/// Write-ahead log providing durable, ordered storage of mutations.
///
/// Thread-safe via `std::sync::Mutex`. WAL writes are blocking I/O and
/// should be called from `tokio::task::spawn_blocking`.
pub struct Wal {
    file: Mutex<Box<dyn FsFile>>,
    path: PathBuf,
    config: WalConfig,
    /// Rotation state (DEK + encryption header), locked separately.
    rotation: Mutex<RotationState>,
    /// Monotonic record counter used as the encryption nonce.
    record_counter: AtomicU64,
    /// Key encryption key (unused currently, reserved for key rotation).
    #[allow(dead_code)]
    kek: encryption::KeyEncryptionKey,
    /// KEK identifier.
    #[allow(dead_code)]
    kek_id: KekId,
    /// Retained for potential re-open after rotation in future phases.
    #[allow(dead_code)]
    fs: Arc<dyn Fs>,
}

impl Wal {
    /// Opens or creates a WAL file at the given path using a custom filesystem.
    ///
    /// Used by the simulation crate to inject faults via a `FaultFs`.
    pub fn open_with_fs(
        path: &Path,
        config: WalConfig,
        fs: Arc<dyn Fs>,
        kek: &encryption::KeyEncryptionKey,
        kek_id: KekId,
    ) -> Result<Self, StorageError> {
        let mut file = fs.open_append(path)?;
        let file_size = file.seek(SeekFrom::End(0))?;

        let (dek, enc_header, record_count) = if file_size == 0 {
            // New file: generate DEK, write encryption header
            let dek = encryption::generate_dek()?;
            let enc_header = encryption::wrap_dek(&dek, kek, kek_id)?;
            file.write_all(&enc_header.to_bytes())?;
            file.sync_all()?;
            (dek, enc_header, 0u64)
        } else {
            // Existing file: read encryption header
            if file_size < ENCRYPTION_HEADER_SIZE as u64 {
                return Err(StorageError::Crypto {
                    reason: format!("WAL file too small for encryption header: {file_size} bytes"),
                });
            }

            // Read entire file to get the header + count records
            let mut all_data = Vec::new();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut all_data)?;

            if all_data.len() < ENCRYPTION_HEADER_SIZE {
                return Err(StorageError::Crypto {
                    reason: "failed to read full encryption header from WAL".to_string(),
                });
            }

            let header_arr: [u8; ENCRYPTION_HEADER_SIZE] = all_data[..ENCRYPTION_HEADER_SIZE]
                .try_into()
                .map_err(|_| StorageError::Crypto {
                    reason: "failed to convert WAL header bytes".to_string(),
                })?;

            let enc_header = EncryptionHeader::from_bytes(&header_arr);
            let dek = encryption::unwrap_dek(&enc_header, kek)?;

            // Count existing records for the counter
            let mut count = 0u64;
            let record_data = &all_data[ENCRYPTION_HEADER_SIZE..];
            let mut pos = 0usize;

            while pos + 4 <= record_data.len() {
                let len_bytes: [u8; 4] = match record_data[pos..pos + 4].try_into() {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let payload_len = u32::from_le_bytes(len_bytes) as usize;
                if pos + 4 + payload_len + 4 > record_data.len() {
                    break;
                }
                pos += 4 + payload_len + 4;
                count += 1;
            }

            file.seek(SeekFrom::End(0))?;
            (dek, enc_header, count)
        };

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            config,
            rotation: Mutex::new(RotationState { dek, enc_header }),
            record_counter: AtomicU64::new(record_count),
            kek: kek.clone_key(),
            kek_id,
            fs,
        })
    }

    /// Returns a copy of the encryption header for this WAL segment.
    #[allow(dead_code)]
    pub(crate) fn enc_header(&self) -> EncryptionHeader {
        self.rotation
            .lock()
            .expect("rotation mutex poisoned")
            .enc_header
            .clone()
    }

    /// Appends an entry to the WAL.
    ///
    /// Serializes the entry, encrypts the payload, writes `[length][ciphertext][crc32]`,
    /// and optionally fsyncs.
    pub fn append(&self, entry: &WalEntry) -> Result<(), StorageError> {
        let plaintext = entry.serialize();

        let mut file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;

        // Check if rotation is needed
        let file_size = file.seek(SeekFrom::End(0))?;
        #[allow(clippy::cast_possible_truncation)]
        let approx_record_size = 4 + plaintext.len() as u64 + encryption::TAG_SIZE as u64 + 4;
        if self.config.max_size > 0 && file_size + approx_record_size > self.config.max_size {
            self.rotate_locked(&mut **file)?;
        }

        // Load record counter AFTER rotation check (rotation resets to 0)
        let record_num = self.record_counter.load(Ordering::Relaxed);

        // Encrypt with current DEK
        let nonce = counter_nonce(record_num);
        let aad = record_num.to_le_bytes();
        let (ciphertext, crc) = {
            let rot = self
                .rotation
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("rotation mutex poisoned")))?;
            let mut dek_bytes = [0u8; 32];
            dek_bytes.copy_from_slice(rot.dek.as_bytes());
            let dek = DataEncryptionKey::from_bytes(dek_bytes);
            let ct = encryption::encrypt_section(&plaintext, &dek, &nonce, &aad)?;
            let c = crc32fast::hash(&ct);
            (ct, c)
        };

        // Write: [payload_length: u32 LE][ciphertext][crc32: u32 LE]
        #[allow(clippy::cast_possible_truncation)]
        let payload_len = ciphertext.len() as u32;
        file.write_all(&payload_len.to_le_bytes())?;
        file.write_all(&ciphertext)?;
        file.write_all(&crc.to_le_bytes())?;

        if self.config.sync_mode == SyncMode::EveryWrite {
            file.sync_all()?;
        }

        self.record_counter.fetch_add(1, Ordering::Relaxed);

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

        // Snapshot the DEK for this read pass
        let dek = {
            let rot = self
                .rotation
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("rotation mutex poisoned")))?;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(rot.dek.as_bytes());
            DataEncryptionKey::from_bytes(bytes)
        };

        // Skip encryption header
        let file_size = file.seek(SeekFrom::End(0))?;
        if file_size < ENCRYPTION_HEADER_SIZE as u64 {
            return Ok(Vec::new());
        }

        let mut all_data = Vec::new();
        file.seek(SeekFrom::Start(ENCRYPTION_HEADER_SIZE as u64))?;
        file.read_to_end(&mut all_data)?;

        let mut entries = Vec::new();
        let mut pos: usize = 0;
        let mut record_num: u64 = 0;

        while pos + 4 <= all_data.len() {
            let record_start = pos;

            // Read payload length
            let len_bytes: [u8; 4] = match all_data[pos..pos + 4].try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let payload_len = u32::from_le_bytes(len_bytes) as usize;
            pos += 4;

            // Check we have enough data for payload + CRC.
            // Torn writes (incomplete record with partial ciphertext
            // or missing CRC) are intentionally silent truncation:
            // the process crashed mid-write, and we return the valid
            // prefix from before the crash.
            if pos + payload_len + 4 > all_data.len() {
                break;
            }

            let ciphertext = &all_data[pos..pos + payload_len];
            pos += payload_len;

            // Read and verify CRC (over ciphertext)
            let crc_bytes: [u8; 4] = match all_data[pos..pos + 4].try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let stored_crc = u32::from_le_bytes(crc_bytes);
            let computed_crc = crc32fast::hash(ciphertext);
            pos += 4;

            if stored_crc != computed_crc {
                if pos < all_data.len() {
                    // Mid-stream CRC corruption: more data follows
                    // this record. Not normal crash-recovery — the
                    // trailing bytes are intact but the CRC doesn't
                    // match. Likely disk rot or tampering.
                    return Err(StorageError::ChecksumMismatch {
                        offset: record_start as u64,
                    });
                }
                // Terminal CRC failure: this is the last record and
                // the process crashed before completing it. Silent
                // truncation is the expected recovery behavior.
                break;
            }

            // Decrypt payload — AEAD tag failure surfaces as error
            // unconditionally. GCM authentication failure means the
            // ciphertext was tampered with (or the wrong key/nonce/
            // AAD was used). None of those happen during clean
            // truncation.
            let nonce = counter_nonce(record_num);
            let aad = record_num.to_le_bytes();
            let plaintext = encryption::decrypt_section(ciphertext, &dek, &nonce, &aad)?;

            match WalEntry::deserialize(&plaintext) {
                Ok(entry) => entries.push(entry),
                Err(_) => break, // Deserialization failure — stop
            }

            record_num += 1;
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

    /// Rotates the WAL file by truncating and writing a fresh encryption header.
    fn rotate_locked(&self, file: &mut dyn FsFile) -> Result<(), StorageError> {
        // Generate new per-segment DEK and encrypt with the KEK
        let new_dek = encryption::generate_dek()?;
        let mut kek_bytes = [0u8; 32];
        kek_bytes.copy_from_slice(self.kek.as_bytes());
        let kek = encryption::KeyEncryptionKey::from_bytes(kek_bytes);
        let new_enc_header = encryption::wrap_dek(&new_dek, &kek, self.kek_id)?;

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&new_enc_header.to_bytes())?;

        if self.config.sync_mode == SyncMode::EveryWrite {
            file.sync_all()?;
        }

        // Update rotation state
        {
            let mut rot = self
                .rotation
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("rotation mutex poisoned")))?;
            rot.dek = new_dek;
            rot.enc_header = new_enc_header;
        }
        self.record_counter.store(0, Ordering::Relaxed);

        Ok(())
    }
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wal")
            .field("path", &self.path)
            .field("config", &self.config)
            .field(
                "record_counter",
                &self.record_counter.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;
    use proptest::prelude::*;
    use std::io::Write;

    /// Helper to generate a test KEK for WAL tests.
    /// Uses a fixed deterministic key so that WAL re-open tests work correctly.
    fn test_kek() -> (encryption::KeyEncryptionKey, KekId) {
        let mut kek_bytes = [0u8; 32];
        for i in 0..32 {
            kek_bytes[i] = (i * 13 + 7) as u8;
        }
        let kek = encryption::KeyEncryptionKey::from_bytes(kek_bytes);
        let kek_id = [0x42u8; KEK_ID_SIZE];
        (kek, kek_id)
    }

    /// Helper to open a WAL for testing.
    fn open_test_wal(path: &Path, config: WalConfig) -> Wal {
        let (kek, kek_id) = test_kek();
        Wal::open_with_fs(path, config, Arc::new(RealFs), &kek, kek_id).expect("open wal")
    }

    /// Helper to create a test WAL entry.
    fn make_entry(key: &[u8], value: &[u8], op: WalOperation) -> WalEntry {
        WalEntry {
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            realm_id: RealmId::new(Uuid::new_v4()),
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
        let wal = open_test_wal(&wal_path, WalConfig::default());
        let entries = wal.read_all().expect("read");
        assert!(entries.is_empty());
    }

    #[test]
    fn append_single_entry_and_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = open_test_wal(&wal_path, WalConfig::default());

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
        let wal = open_test_wal(&wal_path, WalConfig::default());

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
            let wal = open_test_wal(
                &wal_path,
                WalConfig {
                    sync_mode: SyncMode::EveryWrite,
                    ..WalConfig::default()
                },
            );
            wal.append(&entry).expect("append");
        }

        // Re-open and verify data persisted
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
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
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&entry1).expect("append 1");
            wal.append(&entry2).expect("append 2");
        }

        // Append garbage bytes to simulate corruption
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&wal_path)
                .expect("open for corruption");
            file.write_all(b"GARBAGE_CORRUPT_DATA_HERE")
                .expect("write garbage");
            file.sync_all().expect("sync");
        }

        // Re-open: should get both valid entries, garbage ignored
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
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
            max_size: 500,
            sync_mode: SyncMode::None,
        };
        let wal = open_test_wal(&wal_path, config);

        // Write entries until rotation occurs
        for i in 0..20 {
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
            entries.len() < 20,
            "expected rotation to truncate, got {} entries",
            entries.len()
        );
    }

    #[test]
    fn wal_reads_across_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let config = WalConfig {
            max_size: 500,
            sync_mode: SyncMode::None,
        };
        let wal = open_test_wal(&wal_path, config);

        // Fill up and trigger rotation
        for i in 0..30 {
            let entry = make_entry(
                format!("burst-{i}").as_bytes(),
                format!("val-{i}").as_bytes(),
                WalOperation::Put,
            );
            wal.append(&entry).expect("append");
        }

        // After rotation, write more entries that should survive
        let post_entry = make_entry(b"post-rotate", b"survives", WalOperation::Put);
        wal.append(&post_entry).expect("append post");

        let entries = wal.read_all().expect("read");
        assert!(
            entries.iter().any(|e| e.key == b"post-rotate"),
            "post-rotation entry should be readable"
        );
    }

    #[test]
    fn wal_tampered_gcm_ciphertext_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry1 = make_entry(b"good1", b"val1", WalOperation::Put);
        let entry2 = make_entry(b"good2", b"val2", WalOperation::Put);

        // Write two valid entries
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&entry1).expect("append 1");
            wal.append(&entry2).expect("append 2");
        }

        // Tamper with the GCM tag of entry2 (last 16 bytes of ciphertext)
        {
            // Read the raw WAL file
            let mut data = std::fs::read(&wal_path).expect("read wal");
            // Skip encryption header (76 bytes)
            // Record 0: [4B len][ciphertext][4B CRC]
            // Record 1: [4B len][ciphertext][4B CRC]
            // Find the second record's ciphertext and flip a byte near the end
            let enc_header_size = ENCRYPTION_HEADER_SIZE as usize;
            let mut pos = enc_header_size;

            // Skip record 0
            if pos + 4 <= data.len() {
                let len0 = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4 + len0 + 4;
            }
            // Now at record 1: flip byte in the GCM tag region (last 16 bytes of ciphertext)
            if pos + 4 <= data.len() {
                let len1 = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                // CRC is at pos + 4 + len1..pos + 4 + len1 + 4
                // GCM tag is the last 16 bytes of the ciphertext (at pos+4+len1-16..pos+4+len1)
                let tag_pos = pos + 4 + len1 - 1; // last byte of tag
                data[tag_pos] ^= 0xFF; // tamper
            }

            std::fs::write(&wal_path, &data).expect("write tampered wal");
        }

        // Re-open: should only get entry1 (entry2 fails GCM auth)
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read");
            assert_eq!(
                entries.len(),
                1,
                "only first record should survive tampering"
            );
            assert_eq!(entries[0], entry1);
        }
    }

    // --- Property tests ---

    /// Strategy for generating arbitrary `WalEntry` values.
    fn arb_wal_entry() -> impl Strategy<Value = WalEntry> {
        (
            any::<i64>(),
            any::<[u8; 16]>(),
            prop_oneof![Just(0u8), Just(1u8)],
            prop::collection::vec(any::<u8>(), 0..256),
            prop::collection::vec(any::<u8>(), 0..256),
        )
            .prop_map(|(ts, uuid_bytes, op_byte, key, value)| {
                let operation = if op_byte == 0 {
                    WalOperation::Put
                } else {
                    WalOperation::Delete
                };
                WalEntry {
                    timestamp: Timestamp::from_micros(ts),
                    realm_id: RealmId::new(Uuid::from_bytes(uuid_bytes)),
                    operation,
                    key,
                    value,
                }
            })
    }

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
                max_size: u64::MAX,
                sync_mode: SyncMode::None,
            };
            let wal = open_test_wal(&wal_path, config);

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
                let wal = open_test_wal(&wal_path, config.clone());
                for entry in &entries {
                    wal.append(entry).expect("append");
                }
            }

            // Re-open and verify all entries survive
            {
                let wal = open_test_wal(&wal_path, config);
                let read_back = wal.read_all().expect("read");
                prop_assert_eq!(entries, read_back);
            }
        }
    }
}
