//! Sorted String Table (SST) persistence for memtable flushes.
//!
//! All SST files are encrypted at rest using AES-256-GCM envelope encryption.
//!
//! Binary format:
//! ```text
//! BASE HEADER (12 bytes):
//!   [4B] magic    = b"HSST"
//!   [4B] entry_count (u32 LE)
//!   [4B] CRC32 of the plaintext data section
//!
//! ENCRYPTION HEADER (76 bytes):
//!   [16B] KEK identifier (realm UUID bytes)
//!   [12B] Nonce used for DEK wrapping
//!   [32B] DEK ciphertext (AES-256-GCM output)
//!   [16B] GCM authentication tag for DEK wrapping
//!
//! ENCRYPTED DATA SECTION (variable):
//!   [NB] AES-256-GCM ciphertext of the serialized data section
//!        (includes appended 16B GCM tag)
//! ```
//!
//! Per-file DEKs are randomly generated. The data nonce is derived from
//! the SST file number via `counter_nonce()`.

use std::path::Path;

use uuid::Uuid;

use crate::core::RealmId;
use crate::storage::encryption::{self, counter_nonce, DataEncryptionKey, EncryptionHeader, KekId};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};
use crate::storage::memtable::{CompositeKey, MemtableValue};

/// SST file magic bytes.
const SST_MAGIC: &[u8; 4] = b"HSST";

/// Size of the base header: magic(4) + entry_count(4) + crc32(4).
const BASE_HEADER_SIZE: usize = 12;

/// Total header size: base(12) + encryption(76).
pub(crate) const TOTAL_HEADER_SIZE: usize = BASE_HEADER_SIZE + encryption::ENCRYPTION_HEADER_SIZE;

/// Metadata about a written SST file.
#[derive(Debug, Clone)]
pub(crate) struct SstMetadata {
    /// Number of entries written.
    pub entry_count: u32,
    /// Total file size in bytes.
    pub file_size: u64,
}

/// Writes sorted entries to an SST file on disk.
pub(crate) struct SstWriter;

impl SstWriter {
    /// Writes a sorted slice of entries to an SST file at the given path.
    ///
    /// Entries MUST be pre-sorted by `CompositeKey`. The writer does not
    /// re-sort — it trusts the caller (memtable iteration is already sorted).
    pub(crate) fn write_sst(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError> {
        Self::write_sst_with_fs(path, entries, &RealFs, sst_number, dek, enc_header)
    }

    /// Writes an SST file using a custom filesystem implementation.
    pub(crate) fn write_sst_with_fs(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError> {
        let mut file = fs.create(path)?;

        // --- Serialize entries to plaintext ---
        let plaintext = Self::serialize_entries(entries);
        let crc = crc32fast::hash(&plaintext);

        // --- Write base header ---
        #[allow(clippy::cast_possible_truncation)]
        let entry_count = entries.len() as u32;
        file.write_all(SST_MAGIC)?;
        file.write_all(&entry_count.to_le_bytes())?;
        file.write_all(&crc.to_le_bytes())?;

        // --- Write encryption header ---
        file.write_all(&enc_header.to_bytes())?;

        // --- Encrypt and write data section ---
        let data_nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let ciphertext = encryption::encrypt_section(&plaintext, dek, &data_nonce, &aad)?;
        file.write_all(&ciphertext)?;

        file.sync_all()?;

        let file_size = TOTAL_HEADER_SIZE as u64 + ciphertext.len() as u64;

        Ok(SstMetadata {
            entry_count,
            file_size,
        })
    }

    /// Serializes entries into the data section binary format.
    fn serialize_entries(entries: &[(CompositeKey, MemtableValue)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (key, value) in entries {
            Self::serialize_entry(&mut buf, key, value);
        }
        buf
    }

    /// Serializes a single entry into the buffer.
    fn serialize_entry(buf: &mut Vec<u8>, key: &CompositeKey, value: &MemtableValue) {
        match value {
            MemtableValue::Data(_) => buf.push(0x00),
            MemtableValue::Tombstone => buf.push(0x01),
        }

        // Realm UUID (16 bytes)
        buf.extend_from_slice(key.realm_id().as_uuid().as_bytes());

        // Key: length-prefixed
        #[allow(clippy::cast_possible_truncation)]
        let key_len = key.key().len() as u32;
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend_from_slice(key.key());

        // Value: length-prefixed (0 for tombstone)
        match value {
            MemtableValue::Data(v) => {
                #[allow(clippy::cast_possible_truncation)]
                let val_len = v.len() as u32;
                buf.extend_from_slice(&val_len.to_le_bytes());
                buf.extend_from_slice(v);
            }
            MemtableValue::Tombstone => {
                buf.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }
}

/// Reads entries from an SST file on disk.
#[derive(Debug)]
pub(crate) struct SstReader {
    /// All entries loaded from the SST, sorted by `CompositeKey`.
    entries: Vec<(CompositeKey, MemtableValue)>,
    /// Number of entries as declared in the header.
    entry_count: u32,
}

impl SstReader {
    /// Opens and validates an SST file, decrypting and loading all entries.
    pub(crate) fn open(
        path: &Path,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        Self::open_with_fs(path, &RealFs, sst_number, dek)
    }

    /// Opens an SST file using a custom filesystem implementation.
    pub(crate) fn open_with_fs(
        path: &Path,
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        let data = fs.read(path)?;

        // Minimum file size: base header + encryption header
        if data.len() < TOTAL_HEADER_SIZE {
            return Err(StorageError::InvalidSstFormat {
                reason: format!("file too small: {} bytes", data.len()),
            });
        }

        // --- Parse base header ---
        if &data[0..4] != SST_MAGIC {
            return Err(StorageError::InvalidSstFormat {
                reason: "invalid magic bytes".to_string(),
            });
        }
        let entry_count = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid entry count bytes".to_string(),
            }
        })?);
        let stored_crc = u32::from_le_bytes(data[8..12].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid CRC bytes".to_string(),
            }
        })?);

        // --- Parse encryption header (validate it parseable) ---
        let enc_bytes: &[u8; encryption::ENCRYPTION_HEADER_SIZE] = data
            [BASE_HEADER_SIZE..TOTAL_HEADER_SIZE]
            .try_into()
            .map_err(|_| StorageError::InvalidSstFormat {
                reason: "truncated encryption header".to_string(),
            })?;
        let _enc_header = EncryptionHeader::from_bytes(enc_bytes);

        // --- Decrypt data section ---
        let ciphertext = &data[TOTAL_HEADER_SIZE..];
        let data_nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let plaintext = encryption::decrypt_section(ciphertext, dek, &data_nonce, &aad)?;

        // --- Verify CRC ---
        let computed_crc = crc32fast::hash(&plaintext);
        if stored_crc != computed_crc {
            return Err(StorageError::ChecksumMismatch {
                offset: TOTAL_HEADER_SIZE as u64,
            });
        }

        // --- Parse entries ---
        let entries = Self::deserialize_entries(&plaintext, entry_count)?;

        Ok(Self {
            entries,
            entry_count,
        })
    }

    /// Returns all entries in sorted order.
    pub(crate) fn iter_all(&self) -> &[(CompositeKey, MemtableValue)] {
        &self.entries
    }

    /// Returns all entries for a specific realm, with raw keys (no realm prefix).
    pub(crate) fn iter_realm(&self, realm_id: &RealmId) -> Vec<(Vec<u8>, MemtableValue)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.realm_id() == realm_id)
            .map(|(k, v)| (k.key().to_vec(), v.clone()))
            .collect()
    }

    /// Point lookup for a specific realm and key.
    pub(crate) fn get(&self, realm_id: &RealmId, key: &[u8]) -> Option<MemtableValue> {
        let target = CompositeKey::new(realm_id.clone(), key.to_vec());
        self.entries
            .binary_search_by(|(k, _)| k.cmp(&target))
            .ok()
            .map(|idx| self.entries[idx].1.clone())
    }

    /// Range scan within a single realm's key space.
    ///
    /// Returns entries where `start_key <= key < end_key` (half-open interval).
    pub(crate) fn range_scan(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Vec<(Vec<u8>, MemtableValue)> {
        let start = CompositeKey::new(realm_id.clone(), start_key.to_vec());
        let end = CompositeKey::new(realm_id.clone(), end_key.to_vec());

        self.entries
            .iter()
            .filter(|(k, _)| *k >= start && *k < end)
            .map(|(k, v)| (k.key().to_vec(), v.clone()))
            .collect()
    }

    /// Returns the entry count as declared in the SST header.
    pub(crate) fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// Deserializes the data section into entries.
    fn deserialize_entries(
        data: &[u8],
        expected_count: u32,
    ) -> Result<Vec<(CompositeKey, MemtableValue)>, StorageError> {
        let mut entries = Vec::with_capacity(expected_count as usize);
        let mut pos = 0;

        while pos < data.len() {
            if pos >= data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing type byte".to_string(),
                });
            }
            let entry_type = data[pos];
            pos += 1;

            // Realm UUID (16 bytes)
            if pos + 16 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing realm UUID".to_string(),
                });
            }
            let uuid_bytes: [u8; 16] =
                data[pos..pos + 16]
                    .try_into()
                    .map_err(|_| StorageError::InvalidSstFormat {
                        reason: "invalid UUID bytes".to_string(),
                    })?;
            let realm_id = RealmId::new(Uuid::from_bytes(uuid_bytes));
            pos += 16;

            // Key length + key data
            if pos + 4 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing key length".to_string(),
                });
            }
            let key_len = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
                StorageError::InvalidSstFormat {
                    reason: "invalid key length bytes".to_string(),
                }
            })?) as usize;
            pos += 4;

            if pos + key_len > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing key data".to_string(),
                });
            }
            let key = data[pos..pos + key_len].to_vec();
            pos += key_len;

            // Value length + value data
            if pos + 4 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing value length".to_string(),
                });
            }
            let val_len = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
                StorageError::InvalidSstFormat {
                    reason: "invalid value length bytes".to_string(),
                }
            })?) as usize;
            pos += 4;

            if pos + val_len > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing value data".to_string(),
                });
            }
            let value_data = data[pos..pos + val_len].to_vec();
            pos += val_len;

            let composite_key = CompositeKey::new(realm_id, key);
            let value = match entry_type {
                0x00 => MemtableValue::Data(value_data),
                0x01 => MemtableValue::Tombstone,
                other => {
                    return Err(StorageError::InvalidSstFormat {
                        reason: format!("unknown entry type: {other:#x}"),
                    })
                }
            };

            entries.push((composite_key, value));
        }

        #[allow(clippy::cast_possible_truncation)]
        let actual_count = entries.len() as u32;
        if actual_count != expected_count {
            return Err(StorageError::InvalidSstFormat {
                reason: format!(
                    "entry count mismatch: header says {expected_count}, found {actual_count}"
                ),
            });
        }

        Ok(entries)
    }
}

/// Compacts multiple SST files into a single output SST.
///
/// Input SSTs are ordered oldest-to-newest. For duplicate keys, the newest
/// value wins. Tombstones are removed entirely during compaction (they have
/// served their purpose of shadowing older values).
pub(crate) fn compact(
    input_ssts: &[&SstReader],
    output_path: &Path,
    output_sst_number: u64,
    dek: &DataEncryptionKey,
    enc_header: &EncryptionHeader,
) -> Result<SstMetadata, StorageError> {
    compact_with_fs(
        input_ssts,
        output_path,
        &RealFs,
        output_sst_number,
        dek,
        enc_header,
    )
}

/// Compacts SST files using a custom filesystem implementation.
pub(crate) fn compact_with_fs(
    input_ssts: &[&SstReader],
    output_path: &Path,
    fs: &dyn Fs,
    output_sst_number: u64,
    dek: &DataEncryptionKey,
    enc_header: &EncryptionHeader,
) -> Result<SstMetadata, StorageError> {
    let mut merged = std::collections::BTreeMap::new();
    for sst in input_ssts {
        for (key, value) in sst.iter_all() {
            merged.insert(key.clone(), value.clone());
        }
    }

    let live_entries: Vec<(CompositeKey, MemtableValue)> = merged
        .into_iter()
        .filter(|(_, v)| !matches!(v, MemtableValue::Tombstone))
        .collect();

    SstWriter::write_sst_with_fs(
        output_path,
        &live_entries,
        fs,
        output_sst_number,
        dek,
        enc_header,
    )
}

/// Reads the encryption header from an SST file without decrypting the data.
///
/// Returns the `(KekId, EncryptionHeader)` so callers can look up the
/// appropriate KEK before fully opening the file.
pub(crate) fn read_encryption_header(
    path: &Path,
    fs: &dyn Fs,
) -> Result<(KekId, EncryptionHeader), StorageError> {
    let data = fs.read(path)?;
    if data.len() < TOTAL_HEADER_SIZE {
        return Err(StorageError::InvalidSstFormat {
            reason: format!("file too small for header: {} bytes", data.len()),
        });
    }

    if &data[0..4] != SST_MAGIC {
        return Err(StorageError::InvalidSstFormat {
            reason: "invalid magic bytes".to_string(),
        });
    }

    let enc_bytes: &[u8; encryption::ENCRYPTION_HEADER_SIZE] = data
        [BASE_HEADER_SIZE..TOTAL_HEADER_SIZE]
        .try_into()
        .map_err(|_| StorageError::InvalidSstFormat {
            reason: "truncated encryption header".to_string(),
        })?;

    let enc_header = EncryptionHeader::from_bytes(enc_bytes);
    let kek_id = enc_header.kek_id;

    Ok((kek_id, enc_header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;
    use crate::storage::encryption;
    use crate::storage::memtable::{Memtable, MemtableConfig};

    /// Helper to create encryption context for tests.
    fn test_encryption_context() -> (DataEncryptionKey, EncryptionHeader) {
        let dek = encryption::generate_dek().expect("dek");
        let kek = encryption::generate_kek().expect("kek");
        let kek_id = [0x42u8; encryption::KEK_ID_SIZE];
        let enc_header = encryption::wrap_dek(&dek, &kek, kek_id).expect("wrap");
        (dek, enc_header)
    }

    #[test]
    fn flush_memtable_to_sst_produces_valid_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("test.sst");

        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"value1").expect("put");
        mt.put(&realm, b"key2", b"value2").expect("put");
        mt.put(&realm, b"key3", b"value3").expect("put");

        let entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        let metadata =
            SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        assert_eq!(metadata.entry_count, 3);
        assert!(metadata.file_size > 0);

        // Verify raw file structure
        let raw = std::fs::read(&sst_path).expect("read file");
        assert!(raw.len() >= TOTAL_HEADER_SIZE);
        assert_eq!(&raw[0..4], b"HSST");
        assert_eq!(u32::from_le_bytes(raw[4..8].try_into().expect("bytes")), 3);
    }

    #[test]
    fn read_sst_matches_original_memtable_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("test.sst");

        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"alpha", b"val-a").expect("put");
        mt.put(&realm, b"bravo", b"val-b").expect("put");
        mt.delete(&realm, b"charlie").expect("delete");
        mt.put(&realm, b"delta", b"val-d").expect("put");

        let original_entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &original_entries, 1, &dek, &enc_header)
            .expect("write_sst");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let read_entries = reader.iter_all();

        assert_eq!(read_entries.len(), original_entries.len());
        for (orig, read) in original_entries.iter().zip(read_entries.iter()) {
            assert_eq!(orig, read);
        }
    }

    #[test]
    fn compaction_merges_deduplicates_and_removes_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // SST 1 (older): key1=v1, key2=v2, key3=v3
        let sst1_path = dir.path().join("sst1.sst");
        let entries1 = vec![
            (
                CompositeKey::new(realm.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1-old".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key2".to_vec()),
                MemtableValue::Data(b"v2".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        let (dek1, enc1) = test_encryption_context();
        SstWriter::write_sst(&sst1_path, &entries1, 1, &dek1, &enc1).expect("write sst1");

        // SST 2 (newer): key1=v1-new (overwrite), key3=tombstone (delete)
        let sst2_path = dir.path().join("sst2.sst");
        let entries2 = vec![
            (
                CompositeKey::new(realm.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1-new".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key3".to_vec()),
                MemtableValue::Tombstone,
            ),
        ];
        let (dek2, enc2) = test_encryption_context();
        SstWriter::write_sst(&sst2_path, &entries2, 2, &dek2, &enc2).expect("write sst2");

        // Compact (oldest first, newest last)
        let reader1 = SstReader::open(&sst1_path, 1, &dek1).expect("open sst1");
        let reader2 = SstReader::open(&sst2_path, 2, &dek2).expect("open sst2");
        let output_path = dir.path().join("compacted.sst");
        let (dek_out, enc_out) = test_encryption_context();
        let metadata =
            compact(&[&reader1, &reader2], &output_path, 3, &dek_out, &enc_out).expect("compact");

        assert_eq!(metadata.entry_count, 2);

        let compacted = SstReader::open(&output_path, 3, &dek_out).expect("open compacted");
        let all = compacted.iter_all();

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.key(), b"key1");
        assert_eq!(all[0].1, MemtableValue::Data(b"v1-new".to_vec()));
        assert_eq!(all[1].0.key(), b"key2");
        assert_eq!(all[1].1, MemtableValue::Data(b"v2".to_vec()));
    }

    #[test]
    fn empty_memtable_flush_produces_valid_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("empty.sst");

        let entries: Vec<(CompositeKey, MemtableValue)> = vec![];
        let (dek, enc_header) = test_encryption_context();
        let metadata =
            SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        assert_eq!(metadata.entry_count, 0);

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        assert_eq!(reader.entry_count(), 0);
        assert!(reader.iter_all().is_empty());
    }

    #[test]
    fn wrong_dek_fails_decryption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("wrong_dek.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        // Try to open with a different DEK
        let wrong_dek = encryption::generate_dek().expect("wrong dek");
        let result = SstReader::open(&sst_path, 1, &wrong_dek);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_sst_number_fails_decryption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("wrong_num.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 42, &dek, &enc_header).expect("write_sst");

        // Try to open with wrong SST number (changes nonce + AAD)
        let result = SstReader::open(&sst_path, 99, &dek);

        assert!(result.is_err());
    }

    #[test]
    fn corruption_in_ciphertext_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("corrupt.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        // Corrupt a byte in the ciphertext
        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[TOTAL_HEADER_SIZE + 1] ^= 0xFF;
        std::fs::write(&sst_path, &raw).expect("write corrupt");

        let result = SstReader::open(&sst_path, 1, &dek);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_magic_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("bad_magic.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"k".to_vec()),
            MemtableValue::Data(b"v".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[0..4].copy_from_slice(b"BAAD");
        std::fs::write(&sst_path, &raw).expect("write");

        let result = SstReader::open(&sst_path, 1, &dek);
        assert!(matches!(result, Err(StorageError::InvalidSstFormat { .. })));
    }

    #[test]
    fn realm_isolation_in_reader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("multi_realm.sst");

        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let mt = Memtable::new(MemtableConfig::default());
        mt.put(&realm_a, b"a-key1", b"a-val1").expect("put");
        mt.put(&realm_a, b"a-key2", b"a-val2").expect("put");
        mt.put(&realm_b, b"b-key1", b"b-val1").expect("put");

        let entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        let a_entries = reader.iter_realm(&realm_a);
        assert_eq!(a_entries.len(), 2);
        for (k, _) in &a_entries {
            assert!(k.starts_with(b"a-key"), "unexpected key: {k:?}");
        }

        let b_entries = reader.iter_realm(&realm_b);
        assert_eq!(b_entries.len(), 1);
        assert_eq!(b_entries[0].0, b"b-key1".to_vec());

        let ghost = RealmId::generate();
        assert!(reader.iter_realm(&ghost).is_empty());
    }

    #[test]
    fn compaction_all_tombstones_produces_empty_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let sst_path = dir.path().join("tombstones.sst");
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"k1".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(realm, b"k2".to_vec()),
                MemtableValue::Tombstone,
            ),
        ];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let output_path = dir.path().join("compacted.sst");
        let (dek_out, enc_out) = test_encryption_context();
        let metadata = compact(&[&reader], &output_path, 2, &dek_out, &enc_out).expect("compact");

        assert_eq!(metadata.entry_count, 0);
        let compacted = SstReader::open(&output_path, 2, &dek_out).expect("open compacted");
        assert!(compacted.iter_all().is_empty());
    }

    #[test]
    fn compaction_single_sst_input_preserves_live_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let sst_path = dir.path().join("single.sst");
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"k1".to_vec()),
                MemtableValue::Data(b"v1".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"k2".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(realm, b"k3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let output_path = dir.path().join("compacted.sst");
        let (dek_out, enc_out) = test_encryption_context();
        let metadata = compact(&[&reader], &output_path, 2, &dek_out, &enc_out).expect("compact");

        assert_eq!(metadata.entry_count, 2);
        let compacted = SstReader::open(&output_path, 2, &dek_out).expect("open compacted");
        let all = compacted.iter_all();
        assert_eq!(all[0].0.key(), b"k1");
        assert_eq!(all[1].0.key(), b"k3");
    }

    #[test]
    fn point_lookup_and_range_scan_over_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("lookup.sst");
        let realm = RealmId::generate();

        let mt = Memtable::new(MemtableConfig::default());
        mt.put(&realm, b"apple", b"v-apple").expect("put");
        mt.put(&realm, b"banana", b"v-banana").expect("put");
        mt.put(&realm, b"cherry", b"v-cherry").expect("put");
        mt.put(&realm, b"date", b"v-date").expect("put");
        mt.put(&realm, b"elderberry", b"v-elder").expect("put");
        mt.delete(&realm, b"fig").expect("delete");

        let entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        assert_eq!(
            reader.get(&realm, b"banana"),
            Some(MemtableValue::Data(b"v-banana".to_vec()))
        );
        assert_eq!(reader.get(&realm, b"grape"), None);
        assert_eq!(reader.get(&realm, b"fig"), Some(MemtableValue::Tombstone));

        let range = reader.range_scan(&realm, b"banana", b"date");
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].0, b"banana".to_vec());
        assert_eq!(range[1].0, b"cherry".to_vec());

        let ghost = RealmId::generate();
        assert!(reader.range_scan(&ghost, b"a", b"z").is_empty());
        assert_eq!(reader.get(&ghost, b"apple"), None);

        let realm_entries = reader.iter_realm(&realm);
        assert_eq!(realm_entries.len(), 6);
    }

    #[test]
    fn read_encryption_header_extracts_kek_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("enc_header.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let (kek_id, _) = read_encryption_header(&sst_path, &RealFs).expect("read header");
        assert_eq!(kek_id, enc_header.kek_id);
    }
}
