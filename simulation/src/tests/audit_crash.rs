//! Audit engine crash-recovery and integrity simulation tests.
//!
//! Oracle invariants:
//! - After a crash anywhere inside `append()`, recovery yields either zero
//!   partial event (batch rolled back) or one complete event (primary +
//!   both secondary indexes together). No dangling index entries, no
//!   orphan primaries.
//! - Under sustained concurrent write load the hash chain must remain
//!   consistent and every appended event must be queryable.
//!
//! These invariants are only enforceable because `EmbeddedAuditEngine::append`
//! performs its three writes through `StorageEngine::put_batch`, which the
//! storage engine serializes into a single WAL record. The WAL framing —
//! `[u32 len][payload][u32 crc]` — provides all-or-nothing durability: a
//! partially-written record fails CRC check on replay and is discarded.

use std::io::Write;
use std::sync::Arc;
use std::thread;

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{RealmId, SystemClock};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Build a `CreateAuditEvent` with a synthetic sequence marker so tests can
/// assert ordering.
fn make_event(realm_id: RealmId, seq: u32) -> CreateAuditEvent {
    CreateAuditEvent {
        realm_id,
        actor: format!("actor-{seq:04}"),
        action: AuditAction::UserCreated,
        resource_type: "user".to_string(),
        resource_id: format!("user-{seq:04}"),
        metadata: None,
    }
}

/// Open (or reopen) an audit engine against a fixed storage directory.
fn open_audit(dir: &std::path::Path) -> (Arc<EmbeddedStorageEngine>, EmbeddedAuditEngine) {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = EmbeddedAuditEngine::new(Arc::clone(&storage) as Arc<dyn StorageEngine>, clock);
    (storage, audit)
}

/// Crash mid-batch: a partially-written WAL record must be discarded on
/// replay so no orphan audit primary/index keys survive.
///
/// Strategy:
/// 1. Append two complete audit events (each is one atomic `put_batch`).
/// 2. Simulate a crash inside a third `append()` by appending garbage
///    bytes to the WAL tail — this mirrors a half-written record.
/// 3. Reopen the engine (WAL replay discards the corrupt tail).
/// 4. Assert exactly two events are queryable and the hash chain
///    verifies.
#[test]
fn simulation_audit_crash_mid_batch_discards_partial_event() {
    let seed = 51u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: two successful appends.
    {
        let (_storage, audit) = open_audit(dir.path());
        audit
            .append(&make_event(realm.clone(), 1))
            .expect("append 1");
        audit
            .append(&make_event(realm.clone(), 2))
            .expect("append 2");
    }

    // Phase 2: simulate a crash during a third append by injecting an
    // orphan length header at the WAL tail. WAL replay interprets this
    // as a truncated record and discards it (same policy as other
    // single-record crashes).
    {
        let wal_path = dir.path().join("hearth.wal");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal for corruption");
        // Orphan record header claiming a 4 KiB payload that never arrives.
        file.write_all(&4096u32.to_le_bytes())
            .expect("write orphan length");
        file.sync_all().expect("sync");
    }

    // Phase 3: reopen and verify invariant.
    {
        let (_storage, audit) = open_audit(dir.path());
        let events = audit
            .query(&AuditQuery::for_realm(realm.clone()))
            .expect("query after crash");
        assert_eq!(
            events.len(),
            2,
            "crash mid-batch must roll back the entire event — no partial survivor (seed={seed})"
        );

        // Hash chain must still be consistent: if any of the three index
        // entries had leaked, the linked chain would be broken.
        let valid = audit
            .verify_integrity(&realm, None, None)
            .expect("verify after crash");
        assert!(
            valid,
            "audit chain integrity must survive aborted batch (seed={seed})"
        );
    }
}

/// CRC-level corruption of the final audit record must leave exactly the
/// previously-committed events in place. This is a stronger form of the
/// above test: the record's length and payload bytes are written, but
/// the CRC trailer is flipped.
#[test]
fn simulation_audit_crash_corrupt_crc_rolls_back_last_event() {
    let seed = 52u64;
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: three successful appends.
    {
        let (_storage, audit) = open_audit(dir.path());
        for i in 1..=3 {
            audit.append(&make_event(realm.clone(), i)).expect("append");
        }
    }

    // Phase 2: flip the last 4 bytes of the WAL (the CRC of the last
    // record). Replay must drop the record and stop.
    {
        let wal_path = dir.path().join("hearth.wal");
        let mut bytes = std::fs::read(&wal_path).expect("read wal");
        let len = bytes.len();
        assert!(len >= 4, "wal must have at least one CRC trailer");
        for b in &mut bytes[len - 4..] {
            *b ^= 0xFF;
        }
        std::fs::write(&wal_path, &bytes).expect("write back corrupt wal");
    }

    // Phase 3: recovery must see exactly 2 events, chain still valid.
    {
        let (_storage, audit) = open_audit(dir.path());
        let events = audit
            .query(&AuditQuery::for_realm(realm.clone()))
            .expect("query after CRC corruption");
        assert_eq!(
            events.len(),
            2,
            "bad CRC on final record must drop it whole (seed={seed})"
        );

        let valid = audit
            .verify_integrity(&realm, None, None)
            .expect("verify after CRC corruption");
        assert!(valid, "hash chain must be intact after CRC rollback");
    }
}

/// Sustained concurrent write load: multiple writers must not corrupt the
/// hash chain. This covers `TEST_SCENARIOS.md` §Audit Logging Simulation
/// bullet 2.
///
/// Eight threads each append 250 events; the engine must durably store
/// all 2_000, serialize chain ordering correctly, and pass integrity
/// verification. The test is parameter-sensitive only up to total
/// count; contention increases but correctness is absolute.
#[test]
fn simulation_audit_integrity_under_sustained_load() {
    let seed = 53u64;
    let _ = seed;

    const THREADS: u32 = 8;
    const EVENTS_PER_THREAD: u32 = 250;
    const TOTAL: usize = (THREADS * EVENTS_PER_THREAD) as usize;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    let (_storage, audit) = open_audit(dir.path());
    let audit = Arc::new(audit);

    let mut handles = Vec::with_capacity(THREADS as usize);
    for thread_id in 0..THREADS {
        let audit = Arc::clone(&audit);
        let realm = realm.clone();
        let handle = thread::spawn(move || {
            for i in 0..EVENTS_PER_THREAD {
                let marker = thread_id * EVENTS_PER_THREAD + i;
                audit
                    .append(&make_event(realm.clone(), marker))
                    .expect("append under load");
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("thread joined");
    }

    // Every append must have landed.
    let events = audit
        .query(&AuditQuery::for_realm(realm.clone()))
        .expect("query after load");
    assert_eq!(
        events.len(),
        TOTAL,
        "all {TOTAL} events must be persisted under sustained load (seed={seed})"
    );

    // Timestamps monotonic (SystemClock resolution is microsecond; the
    // engine tie-breaks duplicates by sequence within a realm).
    for window in events.windows(2) {
        assert!(
            window[1].timestamp >= window[0].timestamp,
            "event ordering violated under load (seed={seed})"
        );
    }

    // Chain must verify end-to-end.
    let valid = audit
        .verify_integrity(&realm, None, None)
        .expect("verify after load");
    assert!(
        valid,
        "hash chain must remain consistent under concurrent writes (seed={seed})"
    );
}
