//! WAL crash-recovery simulation tests.
//!
//! Oracle invariant: after crash recovery, all committed WAL entries survive.
//! No partial entries appear in the recovered log.
//!
//! Seeds are documented per-test for deterministic replay when madsim is
//! enabled via `RUSTFLAGS='--cfg madsim'` in a future phase.

use std::io::Write;
use std::sync::Arc;

use hearth::core::{RealmId, Timestamp};
use hearth::storage::encryption;
use hearth::storage::error::StorageError;
use hearth::storage::fs::RealFs;
use hearth::storage::wal::{SyncMode, Wal, WalConfig, WalEntry, WalOperation};

/// Deterministic test KEK for WAL crash tests.
fn test_kek() -> (encryption::KeyEncryptionKey, encryption::KekId) {
    let mut kek_bytes = [0u8; 32];
    for i in 0..32 {
        kek_bytes[i] = (i * 13 + 7) as u8;
    }
    let kek = encryption::KeyEncryptionKey::from_bytes(kek_bytes);
    let kek_id = [0x42u8; encryption::KEK_ID_SIZE];
    (kek, kek_id)
}

/// Helper to open a WAL for crash tests.
fn open_test_wal(path: &std::path::Path, config: WalConfig) -> Wal {
    let (kek, kek_id) = test_kek();
    Wal::open_with_fs(path, config, Arc::new(RealFs), &kek, kek_id).expect("open wal")
}

/// Helper to create a test WAL entry.
fn make_entry(key: &[u8], value: &[u8]) -> WalEntry {
    WalEntry {
        timestamp: Timestamp::from_micros(1_700_000_000_000_000),
        realm_id: RealmId::generate(),
        operation: WalOperation::Put,
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

/// Crash mid-write: WAL recovers to last fully committed entry.
///
/// Simulates a process crash during `write_all` by truncating the
/// file mid-record. The WAL reader must return only the valid prefix.
#[test]
fn simulation_crash_mid_write() {
    let seed = 42u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");
    let config = WalConfig {
        max_size: u64::MAX,
        sync_mode: SyncMode::None,
    };

    let entry1 = make_entry(b"committed-1", b"value-1");
    let entry2 = make_entry(b"committed-2", b"value-2");
    let entry3 = make_entry(b"in-flight", b"never-committed");

    // Write two valid entries normally
    {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&entry1).expect("append 1");
        wal.append(&entry2).expect("append 2");
    }

    // Now manually write a partial third record (simulate crash mid-write).
    // Record format: [4B length][payload][4B CRC]
    // We write the length header and half the payload, then stop.
    {
        let payload = entry3.serialize();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open for partial write");

        #[allow(clippy::cast_possible_truncation)]
        let payload_len = payload.len() as u32;
        file.write_all(&payload_len.to_le_bytes())
            .expect("write length");

        // Write only half the payload — simulates crash mid-write
        let half = payload.len() / 2;
        file.write_all(&payload[..half])
            .expect("write partial payload");

        file.sync_all().expect("sync");
    }

    // Recovery: should return only the 2 committed entries
    {
        let wal = open_test_wal(&wal_path, config);
        let entries = wal.read_all().expect("read");
        assert_eq!(
            entries.len(),
            2,
            "crash mid-write: only committed entries should survive (seed={seed})"
        );
        assert_eq!(entries[0], entry1);
        assert_eq!(entries[1], entry2);
    }
}

/// Crash mid-fsync: recovery produces valid state without corruption.
///
/// Simulates a crash where the payload was written but the CRC was
/// only partially flushed (corrupt CRC bytes). The WAL reader must
/// discard the record with the bad CRC and return the valid prefix.
#[test]
fn simulation_crash_mid_fsync() {
    let seed = 43u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");
    let config = WalConfig {
        max_size: u64::MAX,
        sync_mode: SyncMode::None,
    };

    let entry1 = make_entry(b"safe-key", b"safe-value");

    // Write one valid entry
    {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&entry1).expect("append 1");
    }

    // Write a second record with correct payload but corrupt CRC
    {
        let payload = make_entry(b"unsafe-key", b"unsafe-val").serialize();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open for corrupt write");

        #[allow(clippy::cast_possible_truncation)]
        let payload_len = payload.len() as u32;
        file.write_all(&payload_len.to_le_bytes())
            .expect("write length");
        file.write_all(&payload).expect("write payload");
        file.write_all(&[0xFF, 0xFE, 0xFD, 0xFC])
            .expect("write bad CRC");
        file.sync_all().expect("sync");
    }

    // Recovery: corrupt CRC causes the second record to be discarded
    {
        let wal = open_test_wal(&wal_path, config);
        let entries = wal.read_all().expect("read");
        assert_eq!(
            entries.len(),
            1,
            "crash mid-fsync: record with bad CRC must be discarded (seed={seed})"
        );
        assert_eq!(entries[0], entry1);
    }
}

/// Simulated disk I/O failure during append: partial writes do not
/// corrupt subsequent recovery.
#[test]
fn simulation_disk_io_failure() {
    let seed = 44u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");
    let config = WalConfig {
        max_size: u64::MAX,
        sync_mode: SyncMode::None,
    };

    let entry1 = make_entry(b"before-failure", b"val");

    // Write a valid entry
    {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&entry1).expect("append");
    }

    // Inject a partial record: write only the 4-byte length header
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open for injection");
        file.write_all(&100u32.to_le_bytes())
            .expect("write orphan length");
        file.sync_all().expect("sync");
    }

    // Recovery: partial record must be discarded
    {
        let wal = open_test_wal(&wal_path, config);
        let entries = wal.read_all().expect("read after failure");
        assert_eq!(
            entries.len(),
            1,
            "partial record from I/O failure must be discarded (seed={seed})"
        );
        assert_eq!(entries[0], entry1);
    }
}

/// Mid-record truncation: file is cut at an exact mid-record byte boundary.
///
/// Uses `set_len()` to simulate a truncation at the OS level (e.g. a crash
/// during `write()` on a file system without atomic append). The WAL reader
/// must discard the truncated record and return only intact predecessors.
#[test]
fn simulation_wal_mid_record_truncation() {
    let seed = 45u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");
    let config = WalConfig {
        max_size: u64::MAX,
        sync_mode: SyncMode::None,
    };

    let entry1 = make_entry(b"trunc-committed", b"survives");
    let entry2 = make_entry(b"trunc-inflight", b"lost");

    // Write one valid entry, note the file length, then write a second entry.
    let committed_len = {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&entry1).expect("append 1");
        std::fs::metadata(&wal_path)
            .expect("stat after first append")
            .len()
    };

    {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&entry2).expect("append 2");
    }

    // Truncate the file to midway through the second record.
    let full_len = std::fs::metadata(&wal_path).expect("stat").len();
    let mid = committed_len + (full_len - committed_len) / 2;
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .expect("open for truncation");
        f.set_len(mid).expect("set_len mid-record");
    }

    // Recovery: only the fully committed entry must survive.
    {
        let wal = open_test_wal(&wal_path, config);
        let entries = wal.read_all().expect("read after mid-record truncation");
        assert_eq!(
            entries.len(),
            1,
            "mid-record truncation: only committed entries must survive (seed={seed})"
        );
        assert_eq!(entries[0], entry1);
    }
}

/// Tail corruption: random garbage bytes appended after committed records.
///
/// Simulates bit-rot, a concurrent write from another process, or a kernel
/// buffer flush that produces garbage at the file tail. The WAL reader must
/// detect the structurally invalid tail bytes and recover the committed prefix.
#[test]
fn simulation_wal_tail_corruption() {
    let seed = 46u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");
    let config = WalConfig {
        max_size: u64::MAX,
        sync_mode: SyncMode::None,
    };

    let entry1 = make_entry(b"tail-safe-1", b"val-1");
    let entry2 = make_entry(b"tail-safe-2", b"val-2");

    // Write two valid entries and close.
    {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&entry1).expect("append 1");
        wal.append(&entry2).expect("append 2");
    }

    // Append garbage bytes that do not form a valid record.
    // 13 bytes — not a multiple of 4, so any length prefix interpretation fails.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open for tail corruption");
        file.write_all(b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x01\x02\x03\x04\x05")
            .expect("write garbage tail");
        file.sync_all().expect("sync");
    }

    // Recovery: valid committed records survive; garbage tail is discarded.
    {
        let wal = open_test_wal(&wal_path, config);
        let entries = wal.read_all().expect("read after tail corruption");
        assert_eq!(
            entries.len(),
            2,
            "tail corruption: both committed entries must survive (seed={seed})"
        );
        assert_eq!(entries[0], entry1);
        assert_eq!(entries[1], entry2);
    }
}

/// Tampering: byte-flip in ciphertext with a recomputed CRC must be
/// detected by AEAD authentication, not silently truncated.
#[test]
fn simulation_aead_detects_tampered_ciphertext_with_valid_crc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");
    let config = WalConfig {
        max_size: u64::MAX,
        sync_mode: SyncMode::EveryWrite,
    };

    // Write two records and close.
    {
        let wal = open_test_wal(&wal_path, config.clone());
        wal.append(&make_entry(b"k1", b"v1")).expect("append 1");
        wal.append(&make_entry(b"k2", b"v2")).expect("append 2");
    }

    // Tamper with record 0's ciphertext, then recompute the CRC so the
    // structural check passes. This isolates the AEAD tag check.
    {
        let mut data = std::fs::read(&wal_path).expect("read wal");
        let header_size = encryption::ENCRYPTION_HEADER_SIZE;
        // Record 0 starts at header_size: [u32 len][ciphertext][u32 crc]
        let len_off = header_size;
        let ct_off = len_off + 4;
        let len = u32::from_le_bytes(data[len_off..len_off + 4].try_into().unwrap()) as usize;
        let crc_off = ct_off + len;

        // Flip one byte in the middle of the ciphertext (avoid the GCM tag
        // region to prove the tag still catches body tampering).
        data[ct_off + len / 2] ^= 0x01;

        // Recompute and overwrite the CRC so the structural check passes.
        let new_crc = crc32fast::hash(&data[ct_off..ct_off + len]);
        data[crc_off..crc_off + 4].copy_from_slice(&new_crc.to_le_bytes());

        std::fs::write(&wal_path, &data).expect("write tampered");
    }

    // Reopen and read. AEAD failure must surface as Crypto error — not
    // silent truncation that returns [].
    let wal = open_test_wal(&wal_path, config);
    let result = wal.read_all();
    assert!(
        matches!(result, Err(StorageError::Crypto { .. })),
        "tampered ciphertext must be rejected with Crypto error; got {:?}",
        result
    );
}
