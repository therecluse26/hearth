//! WAL crash-recovery simulation tests.
//!
//! Oracle invariant: after crash recovery, all committed WAL entries survive.
//! No partial entries appear in the recovered log.
//!
//! Seeds are documented per-test for deterministic replay when madsim is
//! enabled via `RUSTFLAGS='--cfg madsim'` in a future phase.

use std::io::Write;

use hearth::core::{TenantId, Timestamp};
use hearth::storage::wal::{SyncMode, Wal, WalConfig, WalEntry, WalOperation};

/// Helper to create a test WAL entry.
fn make_entry(key: &[u8], value: &[u8]) -> WalEntry {
    WalEntry {
        timestamp: Timestamp::from_micros(1_700_000_000_000_000),
        tenant_id: TenantId::generate(),
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
        let wal = Wal::open(&wal_path, config.clone()).expect("open");
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
        let wal = Wal::open(&wal_path, config).expect("reopen");
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
        let wal = Wal::open(&wal_path, config.clone()).expect("open");
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
        let wal = Wal::open(&wal_path, config).expect("reopen");
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
        let wal = Wal::open(&wal_path, config.clone()).expect("open");
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
        let wal = Wal::open(&wal_path, config).expect("reopen");
        let entries = wal.read_all().expect("read after failure");
        assert_eq!(
            entries.len(),
            1,
            "partial record from I/O failure must be discarded (seed={seed})"
        );
        assert_eq!(entries[0], entry1);
    }
}
