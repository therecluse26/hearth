//! Sorted String Table (SST) persistence for memtable flushes.
//!
//! Binary format (v1):
//! ```text
//! HEADER (12 bytes):
//!   [4B] magic    = b"HSST"
//!   [1B] version  = 0x01
//!   [4B] entry_count (u32 LE)
//!   [3B] reserved = 0x00
//!
//! DATA SECTION (variable, entries sorted by CompositeKey):
//!   Per entry:
//!     [1B]  type (0x00=Data, 0x01=Tombstone)
//!     [16B] tenant UUID
//!     [4B]  key length (u32 LE)
//!     [NB]  key bytes
//!     [4B]  value length (u32 LE, 0 for tombstone)
//!     [MB]  value bytes
//!
//! FOOTER (8 bytes):
//!   [4B] CRC32 of entire data section
//!   [4B] footer magic = b"HEND"
//! ```

use std::path::Path;

use uuid::Uuid;

use crate::core::TenantId;
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};
use crate::storage::memtable::{CompositeKey, MemtableValue};

/// SST file magic bytes.
const SST_MAGIC: &[u8; 4] = b"HSST";

/// SST format version.
const SST_VERSION: u8 = 0x01;

/// Footer magic bytes.
const FOOTER_MAGIC: &[u8; 4] = b"HEND";

/// Header size in bytes: 4 (magic) + 1 (version) + 4 (count) + 3 (reserved).
const HEADER_SIZE: usize = 12;

/// Footer size in bytes: 4 (CRC32) + 4 (footer magic).
const FOOTER_SIZE: usize = 8;

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
    ) -> Result<SstMetadata, StorageError> {
        Self::write_sst_with_fs(path, entries, &RealFs)
    }

    /// Writes an SST file using a custom filesystem implementation.
    pub(crate) fn write_sst_with_fs(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        fs: &dyn Fs,
    ) -> Result<SstMetadata, StorageError> {
        let mut file = fs.create(path)?;

        // --- Header ---
        file.write_all(SST_MAGIC)?;
        file.write_all(&[SST_VERSION])?;
        #[allow(clippy::cast_possible_truncation)]
        let entry_count = entries.len() as u32;
        file.write_all(&entry_count.to_le_bytes())?;
        file.write_all(&[0u8; 3])?; // reserved

        // --- Data Section ---
        let data_section = Self::serialize_entries(entries);
        file.write_all(&data_section)?;

        // --- Footer ---
        let crc = crc32fast::hash(&data_section);
        file.write_all(&crc.to_le_bytes())?;
        file.write_all(FOOTER_MAGIC)?;

        file.sync_all()?;

        let file_size = HEADER_SIZE as u64 + data_section.len() as u64 + FOOTER_SIZE as u64;

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
        // Type byte
        match value {
            MemtableValue::Data(_) => buf.push(0x00),
            MemtableValue::Tombstone => buf.push(0x01),
        }

        // Tenant UUID (16 bytes)
        buf.extend_from_slice(key.tenant_id().as_uuid().as_bytes());

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
    /// Opens and validates an SST file, loading all entries into memory.
    pub(crate) fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_fs(path, &RealFs)
    }

    /// Opens an SST file using a custom filesystem implementation.
    pub(crate) fn open_with_fs(path: &Path, fs: &dyn Fs) -> Result<Self, StorageError> {
        let data = fs.read(path)?;

        // Minimum file size: header + footer
        if data.len() < HEADER_SIZE + FOOTER_SIZE {
            return Err(StorageError::InvalidSstFormat {
                reason: format!("file too small: {} bytes", data.len()),
            });
        }

        // --- Validate header ---
        if &data[0..4] != SST_MAGIC {
            return Err(StorageError::InvalidSstFormat {
                reason: "invalid magic bytes".to_string(),
            });
        }
        if data[4] != SST_VERSION {
            return Err(StorageError::InvalidSstFormat {
                reason: format!("unsupported version: {}", data[4]),
            });
        }
        let entry_count = u32::from_le_bytes(data[5..9].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid entry count bytes".to_string(),
            }
        })?);

        // --- Validate footer ---
        let footer_start = data.len() - FOOTER_SIZE;
        if &data[footer_start + 4..] != FOOTER_MAGIC {
            return Err(StorageError::InvalidSstFormat {
                reason: "invalid footer magic".to_string(),
            });
        }

        let stored_crc = u32::from_le_bytes(
            data[footer_start..footer_start + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidSstFormat {
                    reason: "invalid CRC bytes".to_string(),
                })?,
        );

        // --- Validate CRC ---
        let data_section = &data[HEADER_SIZE..footer_start];
        let computed_crc = crc32fast::hash(data_section);
        if stored_crc != computed_crc {
            return Err(StorageError::ChecksumMismatch {
                offset: footer_start as u64,
            });
        }

        // --- Parse entries ---
        let entries = Self::deserialize_entries(data_section, entry_count)?;

        Ok(Self {
            entries,
            entry_count,
        })
    }

    /// Returns all entries in sorted order.
    pub(crate) fn iter_all(&self) -> &[(CompositeKey, MemtableValue)] {
        &self.entries
    }

    /// Returns all entries for a specific tenant, with raw keys (no tenant prefix).
    pub(crate) fn iter_tenant(&self, tenant_id: &TenantId) -> Vec<(Vec<u8>, MemtableValue)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.tenant_id() == tenant_id)
            .map(|(k, v)| (k.key().to_vec(), v.clone()))
            .collect()
    }

    /// Point lookup for a specific tenant and key.
    pub(crate) fn get(&self, tenant_id: &TenantId, key: &[u8]) -> Option<MemtableValue> {
        let target = CompositeKey::new(tenant_id.clone(), key.to_vec());
        self.entries
            .binary_search_by(|(k, _)| k.cmp(&target))
            .ok()
            .map(|idx| self.entries[idx].1.clone())
    }

    /// Range scan within a single tenant's key space.
    ///
    /// Returns entries where `start_key <= key < end_key` (half-open interval).
    pub(crate) fn range_scan(
        &self,
        tenant_id: &TenantId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Vec<(Vec<u8>, MemtableValue)> {
        let start = CompositeKey::new(tenant_id.clone(), start_key.to_vec());
        let end = CompositeKey::new(tenant_id.clone(), end_key.to_vec());

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
            // Type byte
            if pos >= data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing type byte".to_string(),
                });
            }
            let entry_type = data[pos];
            pos += 1;

            // Tenant UUID (16 bytes)
            if pos + 16 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing tenant UUID".to_string(),
                });
            }
            let uuid_bytes: [u8; 16] =
                data[pos..pos + 16]
                    .try_into()
                    .map_err(|_| StorageError::InvalidSstFormat {
                        reason: "invalid UUID bytes".to_string(),
                    })?;
            let tenant_id = TenantId::new(Uuid::from_bytes(uuid_bytes));
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

            let composite_key = CompositeKey::new(tenant_id, key);
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
) -> Result<SstMetadata, StorageError> {
    compact_with_fs(input_ssts, output_path, &RealFs)
}

/// Compacts SST files using a custom filesystem implementation.
pub(crate) fn compact_with_fs(
    input_ssts: &[&SstReader],
    output_path: &Path,
    fs: &dyn Fs,
) -> Result<SstMetadata, StorageError> {
    // Merge all entries, newest-last wins for duplicates
    let mut merged = std::collections::BTreeMap::new();
    for sst in input_ssts {
        for (key, value) in sst.iter_all() {
            merged.insert(key.clone(), value.clone());
        }
    }

    // Remove tombstones — they've shadowed older values
    let live_entries: Vec<(CompositeKey, MemtableValue)> = merged
        .into_iter()
        .filter(|(_, v)| !matches!(v, MemtableValue::Tombstone))
        .collect();

    SstWriter::write_sst_with_fs(output_path, &live_entries, fs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TenantId;
    use crate::storage::memtable::{Memtable, MemtableConfig};
    // ===== Phase A: P0 Fast Unit Tests =====

    // TEST_SCENARIOS.md: "Flush memtable to SST produces valid binary format"

    #[test]
    fn flush_memtable_to_sst_produces_valid_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("test.sst");

        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"key1", b"value1").expect("put");
        mt.put(&tenant, b"key2", b"value2").expect("put");
        mt.put(&tenant, b"key3", b"value3").expect("put");

        let entries = mt.iter_all();
        let metadata = SstWriter::write_sst(&sst_path, &entries).expect("write_sst");

        assert_eq!(metadata.entry_count, 3);
        assert!(metadata.file_size > 0);

        // Verify raw file structure
        let raw = std::fs::read(&sst_path).expect("read file");

        // Header: magic
        assert_eq!(&raw[0..4], b"HSST");
        // Header: version
        assert_eq!(raw[4], 0x01);
        // Header: entry count
        assert_eq!(u32::from_le_bytes(raw[5..9].try_into().expect("bytes")), 3);
        // Header: reserved
        assert_eq!(&raw[9..12], &[0u8; 3]);

        // Footer: last 4 bytes are HEND
        let footer_end = raw.len();
        assert_eq!(&raw[footer_end - 4..], b"HEND");

        // Footer: CRC32 of data section
        let data_section = &raw[HEADER_SIZE..footer_end - FOOTER_SIZE];
        let expected_crc = crc32fast::hash(data_section);
        let stored_crc = u32::from_le_bytes(
            raw[footer_end - 8..footer_end - 4]
                .try_into()
                .expect("crc bytes"),
        );
        assert_eq!(stored_crc, expected_crc);
    }

    // TEST_SCENARIOS.md: "Read SST back matches original memtable contents"

    #[test]
    fn read_sst_matches_original_memtable_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("test.sst");

        let mt = Memtable::new(MemtableConfig::default());
        let tenant = TenantId::generate();

        mt.put(&tenant, b"alpha", b"val-a").expect("put");
        mt.put(&tenant, b"bravo", b"val-b").expect("put");
        mt.delete(&tenant, b"charlie").expect("delete");
        mt.put(&tenant, b"delta", b"val-d").expect("put");

        let original_entries = mt.iter_all();
        SstWriter::write_sst(&sst_path, &original_entries).expect("write_sst");

        let reader = SstReader::open(&sst_path).expect("open");
        let read_entries = reader.iter_all();

        assert_eq!(read_entries.len(), original_entries.len());
        for (orig, read) in original_entries.iter().zip(read_entries.iter()) {
            assert_eq!(orig, read);
        }
    }

    // TEST_SCENARIOS.md: "Compaction merges, deduplicates, and removes tombstones"

    #[test]
    fn compaction_merges_deduplicates_and_removes_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        // SST 1 (older): key1=v1, key2=v2, key3=v3
        let sst1_path = dir.path().join("sst1.sst");
        let entries1 = vec![
            (
                CompositeKey::new(tenant.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1-old".to_vec()),
            ),
            (
                CompositeKey::new(tenant.clone(), b"key2".to_vec()),
                MemtableValue::Data(b"v2".to_vec()),
            ),
            (
                CompositeKey::new(tenant.clone(), b"key3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        SstWriter::write_sst(&sst1_path, &entries1).expect("write sst1");

        // SST 2 (newer): key1=v1-new (overwrite), key3=tombstone (delete)
        let sst2_path = dir.path().join("sst2.sst");
        let entries2 = vec![
            (
                CompositeKey::new(tenant.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1-new".to_vec()),
            ),
            (
                CompositeKey::new(tenant.clone(), b"key3".to_vec()),
                MemtableValue::Tombstone,
            ),
        ];
        SstWriter::write_sst(&sst2_path, &entries2).expect("write sst2");

        // Compact (oldest first, newest last)
        let reader1 = SstReader::open(&sst1_path).expect("open sst1");
        let reader2 = SstReader::open(&sst2_path).expect("open sst2");
        let output_path = dir.path().join("compacted.sst");
        let metadata = compact(&[&reader1, &reader2], &output_path).expect("compact");

        // Should have 2 entries: key1 (updated) and key2 (unchanged). key3 tombstoned → removed.
        assert_eq!(metadata.entry_count, 2);

        let compacted = SstReader::open(&output_path).expect("open compacted");
        let all = compacted.iter_all();

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.key(), b"key1");
        assert_eq!(all[0].1, MemtableValue::Data(b"v1-new".to_vec()));
        assert_eq!(all[1].0.key(), b"key2");
        assert_eq!(all[1].1, MemtableValue::Data(b"v2".to_vec()));
    }

    // ===== Supplementary P0 Fast Tests =====

    #[test]
    fn empty_memtable_flush_produces_valid_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("empty.sst");

        let entries: Vec<(CompositeKey, MemtableValue)> = vec![];
        let metadata = SstWriter::write_sst(&sst_path, &entries).expect("write_sst");

        assert_eq!(metadata.entry_count, 0);

        let reader = SstReader::open(&sst_path).expect("open");
        assert_eq!(reader.entry_count(), 0);
        assert!(reader.iter_all().is_empty());
    }

    #[test]
    fn crc_corruption_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("corrupt.sst");

        let tenant = TenantId::generate();
        let entries = vec![(
            CompositeKey::new(tenant, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        SstWriter::write_sst(&sst_path, &entries).expect("write_sst");

        // Corrupt a byte in the data section
        let mut raw = std::fs::read(&sst_path).expect("read");
        let data_start = HEADER_SIZE;
        raw[data_start + 1] ^= 0xFF; // flip a byte in the tenant UUID area
        std::fs::write(&sst_path, &raw).expect("write corrupt");

        let result = SstReader::open(&sst_path);
        assert!(result.is_err());
        match result.expect_err("should fail") {
            StorageError::ChecksumMismatch { .. } => {} // expected
            other => panic!("expected ChecksumMismatch, got: {other}"),
        }
    }

    #[test]
    fn invalid_magic_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("bad_magic.sst");

        let tenant = TenantId::generate();
        let entries = vec![(
            CompositeKey::new(tenant, b"k".to_vec()),
            MemtableValue::Data(b"v".to_vec()),
        )];
        SstWriter::write_sst(&sst_path, &entries).expect("write_sst");

        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[0..4].copy_from_slice(b"BAAD");
        std::fs::write(&sst_path, &raw).expect("write");

        let result = SstReader::open(&sst_path);
        assert!(matches!(result, Err(StorageError::InvalidSstFormat { .. })));
    }

    #[test]
    fn tenant_isolation_in_reader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("multi_tenant.sst");

        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        // Ensure deterministic ordering: use iter_all from a memtable
        let mt = Memtable::new(MemtableConfig::default());
        mt.put(&tenant_a, b"a-key1", b"a-val1").expect("put");
        mt.put(&tenant_a, b"a-key2", b"a-val2").expect("put");
        mt.put(&tenant_b, b"b-key1", b"b-val1").expect("put");

        let entries = mt.iter_all();
        SstWriter::write_sst(&sst_path, &entries).expect("write_sst");

        let reader = SstReader::open(&sst_path).expect("open");

        // Tenant A sees only their keys
        let a_entries = reader.iter_tenant(&tenant_a);
        assert_eq!(a_entries.len(), 2);
        for (k, _) in &a_entries {
            assert!(k.starts_with(b"a-key"), "unexpected key: {k:?}");
        }

        // Tenant B sees only their key
        let b_entries = reader.iter_tenant(&tenant_b);
        assert_eq!(b_entries.len(), 1);
        assert_eq!(b_entries[0].0, b"b-key1".to_vec());

        // Non-existent tenant sees nothing
        let ghost = TenantId::generate();
        assert!(reader.iter_tenant(&ghost).is_empty());
    }

    #[test]
    fn compaction_all_tombstones_produces_empty_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        let sst_path = dir.path().join("tombstones.sst");
        let entries = vec![
            (
                CompositeKey::new(tenant.clone(), b"k1".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(tenant, b"k2".to_vec()),
                MemtableValue::Tombstone,
            ),
        ];
        SstWriter::write_sst(&sst_path, &entries).expect("write");

        let reader = SstReader::open(&sst_path).expect("open");
        let output_path = dir.path().join("compacted.sst");
        let metadata = compact(&[&reader], &output_path).expect("compact");

        assert_eq!(metadata.entry_count, 0);
        let compacted = SstReader::open(&output_path).expect("open compacted");
        assert!(compacted.iter_all().is_empty());
    }

    #[test]
    fn compaction_single_sst_input_preserves_live_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant = TenantId::generate();

        let sst_path = dir.path().join("single.sst");
        let entries = vec![
            (
                CompositeKey::new(tenant.clone(), b"k1".to_vec()),
                MemtableValue::Data(b"v1".to_vec()),
            ),
            (
                CompositeKey::new(tenant.clone(), b"k2".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(tenant, b"k3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        SstWriter::write_sst(&sst_path, &entries).expect("write");

        let reader = SstReader::open(&sst_path).expect("open");
        let output_path = dir.path().join("compacted.sst");
        let metadata = compact(&[&reader], &output_path).expect("compact");

        // k2 (tombstone) removed, k1 and k3 survive
        assert_eq!(metadata.entry_count, 2);
        let compacted = SstReader::open(&output_path).expect("open compacted");
        let all = compacted.iter_all();
        assert_eq!(all[0].0.key(), b"k1");
        assert_eq!(all[1].0.key(), b"k3");
    }

    // ===== Phase A continued: P1 Fast =====

    // TEST_SCENARIOS.md: "Point lookup and range scan over SST"

    #[test]
    fn point_lookup_and_range_scan_over_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("lookup.sst");
        let tenant = TenantId::generate();

        let mt = Memtable::new(MemtableConfig::default());
        mt.put(&tenant, b"apple", b"v-apple").expect("put");
        mt.put(&tenant, b"banana", b"v-banana").expect("put");
        mt.put(&tenant, b"cherry", b"v-cherry").expect("put");
        mt.put(&tenant, b"date", b"v-date").expect("put");
        mt.put(&tenant, b"elderberry", b"v-elder").expect("put");
        mt.delete(&tenant, b"fig").expect("delete");

        let entries = mt.iter_all();
        SstWriter::write_sst(&sst_path, &entries).expect("write");

        let reader = SstReader::open(&sst_path).expect("open");

        // Point lookup: hit
        assert_eq!(
            reader.get(&tenant, b"banana"),
            Some(MemtableValue::Data(b"v-banana".to_vec()))
        );

        // Point lookup: miss
        assert_eq!(reader.get(&tenant, b"grape"), None);

        // Point lookup: tombstone (returns Some(Tombstone), caller decides behavior)
        assert_eq!(reader.get(&tenant, b"fig"), Some(MemtableValue::Tombstone));

        // Range scan: [banana, date) = banana, cherry
        let range = reader.range_scan(&tenant, b"banana", b"date");
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].0, b"banana".to_vec());
        assert_eq!(range[1].0, b"cherry".to_vec());

        // Range scan: tenant isolation
        let ghost = TenantId::generate();
        assert!(reader.range_scan(&ghost, b"a", b"z").is_empty());
        assert_eq!(reader.get(&ghost, b"apple"), None);

        // iter_tenant returns correct subset
        let tenant_entries = reader.iter_tenant(&tenant);
        assert_eq!(tenant_entries.len(), 6); // 5 data + 1 tombstone
    }

    // ===== Phase B: P0 Extended (proptest) =====

    use proptest::prelude::*;

    /// Strategy for a (key, value) pair within a single tenant.
    fn arb_kv() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
        (
            prop::collection::vec(any::<u8>(), 1..64),
            prop::collection::vec(any::<u8>(), 0..128),
        )
    }

    // TEST_SCENARIOS.md: "proptest write-flush-read integrity"
    proptest! {
        #[test]
        fn proptest_write_flush_read_integrity(
            kvs in prop::collection::vec(arb_kv(), 1..100)
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let sst_path = dir.path().join("prop.sst");
            let mt = Memtable::new(MemtableConfig::default());
            let tenant = TenantId::generate();

            // Apply all ops to memtable (some keys may be overwritten)
            let mut oracle = std::collections::BTreeMap::new();
            for (k, v) in &kvs {
                mt.put(&tenant, k, v).expect("put");
                oracle.insert(k.clone(), v.clone());
            }

            // Flush to SST
            let entries = mt.iter_all();
            SstWriter::write_sst(&sst_path, &entries).expect("write");

            // Read back
            let reader = SstReader::open(&sst_path).expect("open");
            let tenant_entries = reader.iter_tenant(&tenant);

            // All live entries should match oracle
            let read_map: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = tenant_entries
                .into_iter()
                .filter_map(|(k, v)| match v {
                    MemtableValue::Data(d) => Some((k, d)),
                    MemtableValue::Tombstone => None,
                })
                .collect();

            prop_assert_eq!(oracle, read_map);
        }
    }

    /// Strategy for compaction test operations.
    #[derive(Debug, Clone)]
    enum CompactOp {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
    }

    fn arb_compact_op() -> impl Strategy<Value = CompactOp> {
        prop_oneof![
            (
                prop::collection::vec(any::<u8>(), 1..32),
                prop::collection::vec(any::<u8>(), 0..64),
            )
                .prop_map(|(k, v)| CompactOp::Put(k, v)),
            prop::collection::vec(any::<u8>(), 1..32).prop_map(CompactOp::Delete),
        ]
    }

    // TEST_SCENARIOS.md: "proptest compaction preserves live, removes tombstones"
    proptest! {
        #[test]
        fn proptest_compaction_preserves_live_removes_tombstones(
            ops1 in prop::collection::vec(arb_compact_op(), 1..50),
            ops2 in prop::collection::vec(arb_compact_op(), 1..50),
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let tenant = TenantId::generate();

            // Build SST 1 (older)
            let mt1 = Memtable::new(MemtableConfig::default());
            let mut oracle = std::collections::BTreeMap::new();
            for op in &ops1 {
                match op {
                    CompactOp::Put(k, v) => {
                        mt1.put(&tenant, k, v).expect("put");
                        oracle.insert(k.clone(), Some(v.clone()));
                    }
                    CompactOp::Delete(k) => {
                        mt1.delete(&tenant, k).expect("delete");
                        oracle.insert(k.clone(), None);
                    }
                }
            }
            let sst1_path = dir.path().join("sst1.sst");
            SstWriter::write_sst(&sst1_path, &mt1.iter_all()).expect("write sst1");

            // Build SST 2 (newer — overwrites win)
            let mt2 = Memtable::new(MemtableConfig::default());
            for op in &ops2 {
                match op {
                    CompactOp::Put(k, v) => {
                        mt2.put(&tenant, k, v).expect("put");
                        oracle.insert(k.clone(), Some(v.clone()));
                    }
                    CompactOp::Delete(k) => {
                        mt2.delete(&tenant, k).expect("delete");
                        oracle.insert(k.clone(), None);
                    }
                }
            }
            let sst2_path = dir.path().join("sst2.sst");
            SstWriter::write_sst(&sst2_path, &mt2.iter_all()).expect("write sst2");

            // Compact
            let reader1 = SstReader::open(&sst1_path).expect("open sst1");
            let reader2 = SstReader::open(&sst2_path).expect("open sst2");
            let output_path = dir.path().join("compacted.sst");
            compact(&[&reader1, &reader2], &output_path).expect("compact");

            // Verify against oracle
            let compacted = SstReader::open(&output_path).expect("open compacted");
            let compacted_entries = compacted.iter_tenant(&tenant);
            let compacted_map: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = compacted_entries
                .into_iter()
                .filter_map(|(k, v)| match v {
                    MemtableValue::Data(d) => Some((k, d)),
                    MemtableValue::Tombstone => None,
                })
                .collect();

            // Oracle: keep only live entries
            let oracle_live: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = oracle
                .into_iter()
                .filter_map(|(k, v)| v.map(|val| (k, val)))
                .collect();

            prop_assert_eq!(oracle_live, compacted_map);
        }
    }

    // ===== Phase C: Simulation tests — see simulation/ crate =====
}
