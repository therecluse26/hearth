//! Raft state machine: applies committed log entries to `EmbeddedStorageEngine`.
//!
//! [`HearthStateMachine`] implements [`RaftStateMachine`] from openraft 0.9.
//!
//! ## spawn_blocking contract
//! `StorageEngine` is synchronous (`fn`, not `async fn`).  Every call to the
//! engine from an async context MUST use `tokio::task::spawn_blocking` to
//! avoid blocking the Tokio executor thread pool under load.
//!
//! ## Snapshot format
//! Snapshots are serialised with `ciborium` (CBOR) and then compressed with
//! `flate2` (gzip).  CBOR is chosen because it encodes `Vec<u8>` as compact
//! byte strings, not arrays of integers, keeping snapshot sizes small.

use std::collections::BTreeSet;
use std::io::{Cursor, Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use openraft::storage::RaftSnapshotBuilder;
use openraft::{
    EntryPayload, LogId, Snapshot, SnapshotMeta, StorageError, StorageIOError,
    StoredMembership,
};
use openraft::storage::RaftStateMachine;
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;
use tracing::{debug, info, instrument};

use crate::cluster::types::{
    HearthLogResponse, HearthNode, HearthRaftConfig, RaftCommand,
};
use crate::core::RealmId;
use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Error helpers ─────────────────────────────────────────────────────────────

fn io_write_err(e: impl std::error::Error + Send + Sync + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write(&e),
    }
}

fn io_read_err(e: impl std::error::Error + Send + Sync + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::read(&e),
    }
}

fn to_write_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    io_write_err(e)
}

fn to_read_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    io_read_err(e)
}

// ── Snapshot wire format ──────────────────────────────────────────────────────

/// A single realm's full key-space at snapshot time.
#[derive(Serialize, Deserialize)]
struct RealmData {
    realm_id: RealmId,
    /// All (key, value) pairs for this realm, sorted by key.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The full snapshot payload serialised via CBOR then gzip-compressed.
#[derive(Serialize, Deserialize)]
struct SnapshotPayload {
    realms: Vec<RealmData>,
}

// ── Stored snapshot ───────────────────────────────────────────────────────────

struct StoredSnapshot {
    meta: SnapshotMeta<u64, HearthNode>,
    /// Compressed (gzip) CBOR-encoded `SnapshotPayload`.
    data: Vec<u8>,
}

// ── HearthSnapshotBuilder ─────────────────────────────────────────────────────

/// Builds a snapshot by scanning the full key-space of each known realm.
///
/// Returned by [`HearthStateMachine::get_snapshot_builder`].  The builder
/// holds its own `Arc` to the engine so snapshot creation doesn't block
/// the state machine from continuing to apply entries concurrently.
pub struct HearthSnapshotBuilder {
    engine: Arc<dyn StorageEngine>,
    known_realms: BTreeSet<RealmId>,
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, HearthNode>,
}

impl RaftSnapshotBuilder<HearthRaftConfig> for HearthSnapshotBuilder {
    #[instrument(skip(self), name = "snapshot_build")]
    async fn build_snapshot(&mut self) -> Result<Snapshot<HearthRaftConfig>, StorageError<u64>> {
        let engine = Arc::clone(&self.engine);
        let realms = self.known_realms.iter().cloned().collect::<Vec<_>>();
        let last_applied = self.last_applied.clone();
        let last_membership = self.last_membership.clone();

        let snapshot_id = format!(
            "snap-{}-{}",
            last_applied
                .as_ref()
                .map(|id| id.index)
                .unwrap_or(0),
            uuid::Uuid::new_v4()
        );

        // Scan the full key-space of every known realm inside spawn_blocking —
        // StorageEngine::scan is a synchronous call.
        let payload: SnapshotPayload = spawn_blocking(move || {
            let mut realm_data_vec = Vec::with_capacity(realms.len());
            for realm_id in &realms {
                let entries = engine
                    .scan(realm_id, &[], &[0xFF; 256])
                    .map_err(|e| io_read_err(e))?
                    .into_iter()
                    .map(|e| (e.key, e.value))
                    .collect();
                realm_data_vec.push(RealmData {
                    realm_id: realm_id.clone(),
                    entries,
                });
            }
            Ok::<SnapshotPayload, StorageError<u64>>(SnapshotPayload {
                realms: realm_data_vec,
            })
        })
        .await
        .map_err(|e| io_read_err(std::io::Error::other(e.to_string())))??;

        // Serialise to CBOR then gzip-compress.
        let compressed = compress_payload(&payload)?;

        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id: snapshot_id.clone(),
        };

        info!(
            snapshot_id = %snapshot_id,
            realms = payload.realms.len(),
            compressed_bytes = compressed.len(),
            "snapshot built"
        );

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(compressed)),
        })
    }
}

// ── HearthStateMachine ────────────────────────────────────────────────────────

/// Applies committed Raft entries to [`EmbeddedStorageEngine`].
///
/// Tracks which realms have received writes so snapshot creation can scan
/// every live realm without a separate realm-registry call.
pub struct HearthStateMachine {
    /// The underlying storage engine.  Replaced atomically on snapshot install.
    engine: Arc<dyn StorageEngine>,
    /// Config used to open a fresh engine after snapshot install.
    storage_config: StorageConfig,
    /// Set of realms that have had at least one write applied.
    known_realms: BTreeSet<RealmId>,
    /// Last applied log id (updated after every `apply` call).
    last_applied: Option<LogId<u64>>,
    /// Last applied membership config.
    last_membership: StoredMembership<u64, HearthNode>,
    /// Most recently built or installed snapshot (kept for `get_current_snapshot`).
    current_snapshot: Option<StoredSnapshot>,
}

impl HearthStateMachine {
    /// Create a state machine wrapping an existing storage engine.
    pub fn new(engine: Arc<dyn StorageEngine>, storage_config: StorageConfig) -> Self {
        Self {
            engine,
            storage_config,
            known_realms: BTreeSet::new(),
            last_applied: None,
            last_membership: StoredMembership::default(),
            current_snapshot: None,
        }
    }
}

impl RaftStateMachine<HearthRaftConfig> for HearthStateMachine {
    type SnapshotBuilder = HearthSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, HearthNode>), StorageError<u64>> {
        Ok((self.last_applied.clone(), self.last_membership.clone()))
    }

    #[instrument(skip(self, entries), name = "sm_apply")]
    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<HearthLogResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = openraft::Entry<HearthRaftConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let mut responses = Vec::with_capacity(entries.len());
        let start = Instant::now();
        let count = entries.len();

        for entry in entries {
            self.last_applied = Some(entry.log_id.clone());

            match &entry.payload {
                EntryPayload::Blank => {}

                EntryPayload::Normal(cmd) => {
                    self.apply_command(cmd.clone()).await?;
                }

                EntryPayload::Membership(membership) => {
                    self.last_membership = StoredMembership::new(
                        Some(entry.log_id.clone()),
                        membership.clone(),
                    );
                    debug!(log_id = ?entry.log_id, "membership change applied");
                }
            }

            responses.push(HearthLogResponse::default());
        }

        let elapsed = start.elapsed();
        if count > 0 {
            let throughput = count as f64 / elapsed.as_secs_f64();
            info!(
                entries = count,
                elapsed_ms = elapsed.as_millis(),
                entries_per_sec = throughput as u64,
                "state machine apply complete"
            );
        }

        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        HearthSnapshotBuilder {
            engine: Arc::clone(&self.engine),
            known_realms: self.known_realms.clone(),
            last_applied: self.last_applied.clone(),
            last_membership: self.last_membership.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    #[instrument(skip(self, snapshot), name = "sm_install_snapshot")]
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, HearthNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let compressed = snapshot.into_inner();

        // Decompress and deserialise the payload.
        let payload = decompress_payload(&compressed)?;

        // Extract realm IDs before moving payload into spawn_blocking.
        let realm_ids: BTreeSet<RealmId> = payload
            .realms
            .iter()
            .map(|r| r.realm_id.clone())
            .collect();

        let data_dir = self.storage_config.data_dir.clone();
        let storage_config = self.storage_config.clone();

        // Replay into a fresh engine in a temp directory, then atomically
        // rename to the production data directory.
        let new_engine: Arc<dyn StorageEngine> = spawn_blocking(move || {
            install_snapshot_blocking(&data_dir, storage_config, &payload)
        })
        .await
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;

        // Swap in the new engine.
        self.engine = new_engine;

        // Rebuild known_realms from the snapshot.
        self.known_realms = realm_ids;

        self.last_applied = meta.last_log_id.clone();
        self.last_membership = meta.last_membership.clone();

        self.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: compressed,
        });

        info!(
            snapshot_id = %meta.snapshot_id,
            realms = self.known_realms.len(),
            "snapshot installed"
        );

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<HearthRaftConfig>>, StorageError<u64>> {
        match &self.current_snapshot {
            None => Ok(None),
            Some(snap) => Ok(Some(Snapshot {
                meta: snap.meta.clone(),
                snapshot: Box::new(Cursor::new(snap.data.clone())),
            })),
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

impl HearthStateMachine {
    /// Apply a single [`RaftCommand`] to the storage engine via `spawn_blocking`.
    async fn apply_command(&mut self, cmd: RaftCommand) -> Result<(), StorageError<u64>> {
        let engine = Arc::clone(&self.engine);

        match cmd {
            RaftCommand::Put {
                leader_timestamp: _,
                realm,
                key,
                value,
            } => {
                self.known_realms.insert(realm.clone());
                spawn_blocking(move || {
                    engine.put(&realm, &key, &value).map_err(to_write_err)
                })
                .await
                .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
            }

            RaftCommand::Delete {
                leader_timestamp: _,
                realm,
                key,
            } => {
                self.known_realms.insert(realm.clone());
                spawn_blocking(move || {
                    engine.delete(&realm, &key).map_err(to_write_err)
                })
                .await
                .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
            }

            RaftCommand::Batch {
                leader_timestamp: _,
                realm,
                entries,
            } => {
                self.known_realms.insert(realm.clone());
                spawn_blocking(move || {
                    engine.put_batch(&realm, &entries).map_err(to_write_err)
                })
                .await
                .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
            }
        }

        Ok(())
    }
}

/// Compress a [`SnapshotPayload`] to CBOR + gzip bytes.
fn compress_payload(payload: &SnapshotPayload) -> Result<Vec<u8>, StorageError<u64>> {
    let mut cbor_buf = Vec::new();
    ciborium::into_writer(payload, &mut cbor_buf)
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))?;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&cbor_buf)
        .map_err(to_write_err)?;
    encoder.finish().map_err(to_write_err)
}

/// Decompress gzip + CBOR bytes back to a [`SnapshotPayload`].
fn decompress_payload(data: &[u8]) -> Result<SnapshotPayload, StorageError<u64>> {
    let mut decoder = GzDecoder::new(data);
    let mut cbor_buf = Vec::new();
    decoder.read_to_end(&mut cbor_buf).map_err(to_read_err)?;
    ciborium::from_reader(&cbor_buf[..])
        .map_err(|e| io_read_err(std::io::Error::other(e.to_string())))
}

/// Blocking: replay snapshot into a temp dir, atomic-rename to prod data dir.
///
/// Returns a new [`Arc<dyn StorageEngine>`] opened from the production path.
fn install_snapshot_blocking(
    data_dir: &PathBuf,
    storage_config: StorageConfig,
    payload: &SnapshotPayload,
) -> Result<Arc<dyn StorageEngine>, StorageError<u64>> {
    let parent = data_dir
        .parent()
        .ok_or_else(|| io_write_err(std::io::Error::other("data_dir has no parent")))?;

    let temp_dir = parent.join(format!(
        "hearth-snap-{}.tmp",
        uuid::Uuid::new_v4()
    ));

    // Create a fresh engine in the temp directory.
    let temp_config = StorageConfig::dev(temp_dir.clone());
    let temp_engine =
        EmbeddedStorageEngine::open(temp_config).map_err(to_write_err)?;

    // Replay all entries from the snapshot.
    for realm_data in &payload.realms {
        temp_engine
            .put_batch(&realm_data.realm_id, &realm_data.entries)
            .map_err(to_write_err)?;
    }

    // Drop the temp engine to flush WAL before rename.
    drop(temp_engine);

    // Atomic rename: move old prod dir aside, then temp dir → prod dir.
    let backup_dir = parent.join("hearth-data.pre-snapshot");

    if data_dir.exists() {
        if backup_dir.exists() {
            std::fs::remove_dir_all(&backup_dir).map_err(to_write_err)?;
        }
        std::fs::rename(data_dir, &backup_dir).map_err(to_write_err)?;
    }
    std::fs::rename(&temp_dir, data_dir).map_err(to_write_err)?;

    // Non-blocking cleanup of the backup.
    if backup_dir.exists() {
        let _ = std::fs::remove_dir_all(&backup_dir);
    }

    // Open the production engine from its new data.
    let new_engine = EmbeddedStorageEngine::open(storage_config).map_err(to_write_err)?;
    Ok(Arc::new(new_engine))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::cluster::types::RaftCommand;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn make_realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    fn make_log_id(index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(1, 0), index)
    }

    fn make_put_entry(
        index: u64,
        realm: RealmId,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Put {
                leader_timestamp: 0,
                realm,
                key,
                value,
            }),
        }
    }

    fn make_delete_entry(
        index: u64,
        realm: RealmId,
        key: Vec<u8>,
    ) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Delete {
                leader_timestamp: 0,
                realm,
                key,
            }),
        }
    }

    fn make_batch_entry(
        index: u64,
        realm: RealmId,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Batch {
                leader_timestamp: 0,
                realm,
                entries,
            }),
        }
    }

    fn open_sm(dir: &std::path::Path) -> HearthStateMachine {
        let config = StorageConfig::dev(dir.to_path_buf());
        let engine = EmbeddedStorageEngine::open(config.clone()).expect("open engine");
        HearthStateMachine::new(Arc::new(engine), config)
    }

    // ── Put / Delete / Batch ──────────────────────────────────────────────────

    #[tokio::test]
    async fn put_command_stores_value() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        sm.apply([make_put_entry(1, realm.clone(), b"k".to_vec(), b"v".to_vec())])
            .await
            .unwrap();

        let got = sm.engine.get(&realm, b"k").unwrap();
        assert_eq!(got, Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn delete_command_removes_value() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        sm.apply([
            make_put_entry(1, realm.clone(), b"k".to_vec(), b"v".to_vec()),
            make_delete_entry(2, realm.clone(), b"k".to_vec()),
        ])
        .await
        .unwrap();

        let got = sm.engine.get(&realm, b"k").unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn batch_command_writes_all_pairs() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();
        let pairs = vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), b"2".to_vec()),
            (b"c".to_vec(), b"3".to_vec()),
        ];

        sm.apply([make_batch_entry(1, realm.clone(), pairs.clone())])
            .await
            .unwrap();

        for (k, v) in &pairs {
            let got = sm.engine.get(&realm, k).unwrap();
            assert_eq!(got.as_deref(), Some(v.as_slice()));
        }
    }

    #[tokio::test]
    async fn last_applied_tracks_log_index() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        assert!(sm.applied_state().await.unwrap().0.is_none());

        sm.apply([
            make_put_entry(1, realm.clone(), b"x".to_vec(), b"y".to_vec()),
            make_put_entry(5, realm.clone(), b"a".to_vec(), b"b".to_vec()),
        ])
        .await
        .unwrap();

        let (last, _) = sm.applied_state().await.unwrap();
        assert_eq!(last.unwrap().index, 5);
    }

    // ── Snapshot round-trip ───────────────────────────────────────────────────

    #[tokio::test]
    async fn snapshot_roundtrip_identical_keyspace() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();

        let data_dir_a = dir_a.path().join("data");
        let data_dir_b = dir_b.path().join("data");

        // Node A: build data and take a snapshot.
        let snapshot = {
            let mut sm_a = open_sm(&data_dir_a);
            let realm = make_realm();

            sm_a.apply([
                make_put_entry(1, realm.clone(), b"foo".to_vec(), b"bar".to_vec()),
                make_put_entry(2, realm.clone(), b"hello".to_vec(), b"world".to_vec()),
                make_batch_entry(
                    3,
                    realm.clone(),
                    vec![
                        (b"a".to_vec(), b"1".to_vec()),
                        (b"b".to_vec(), b"2".to_vec()),
                    ],
                ),
            ])
            .await
            .unwrap();

            let mut builder = sm_a.get_snapshot_builder().await;
            builder.build_snapshot().await.unwrap()
        };

        // Node B: install the snapshot then verify key-space matches.
        let mut sm_b = open_sm(&data_dir_b);
        sm_b.install_snapshot(&snapshot.meta, snapshot.snapshot)
            .await
            .unwrap();

        // Snapshot correctness: same known realms and same entries for each realm.
        assert_eq!(sm_b.known_realms.len(), 1);
        let realm_id = sm_b.known_realms.iter().next().unwrap().clone();

        let check_pairs: &[(&[u8], &[u8])] = &[
            (b"foo", b"bar"),
            (b"hello", b"world"),
            (b"a", b"1"),
            (b"b", b"2"),
        ];
        for (k, v) in check_pairs {
            let got = sm_b.engine.get(&realm_id, k).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(*v),
                "key {:?} mismatch after snapshot install",
                k
            );
        }
    }

    #[tokio::test]
    async fn snapshot_compress_decompress_roundtrip() {
        let payload = SnapshotPayload {
            realms: vec![RealmData {
                realm_id: make_realm(),
                entries: vec![
                    (b"key1".to_vec(), b"value1".to_vec()),
                    (b"key2".to_vec(), b"value2".to_vec()),
                ],
            }],
        };

        let compressed = compress_payload(&payload).unwrap();
        assert!(!compressed.is_empty());

        let decoded = decompress_payload(&compressed).unwrap();
        assert_eq!(decoded.realms.len(), 1);
        assert_eq!(decoded.realms[0].entries.len(), 2);
        assert_eq!(decoded.realms[0].entries[0].0, b"key1");
        assert_eq!(decoded.realms[0].entries[1].1, b"value2");
    }

    #[tokio::test]
    async fn get_current_snapshot_none_initially() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        assert!(sm.get_current_snapshot().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_current_snapshot_returns_after_build_and_install() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let mut sm = open_sm(&data_dir);
        let realm = make_realm();

        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"k".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();

        let mut builder = sm.get_snapshot_builder().await;
        let snap = builder.build_snapshot().await.unwrap();
        let meta = snap.meta.clone();
        let data = snap.snapshot.clone();

        sm.install_snapshot(&meta, data).await.unwrap();
        assert!(sm.get_current_snapshot().await.unwrap().is_some());
    }

    // ── Concurrent reads during snapshot ─────────────────────────────────────

    #[tokio::test]
    async fn concurrent_reads_during_snapshot_build() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let mut sm = open_sm(&data_dir);
        let realm = make_realm();
        let pairs: Vec<_> = (0u8..20)
            .map(|i| (vec![i], vec![i * 2]))
            .collect();

        sm.apply([make_batch_entry(1, realm.clone(), pairs.clone())])
            .await
            .unwrap();

        // Clone the engine so a "concurrent reader" can access it.
        let engine_for_reader = Arc::clone(&sm.engine);
        let realm_for_reader = realm.clone();

        let read_handle = tokio::spawn(async move {
            for (k, _) in &pairs {
                let _ = engine_for_reader.get(&realm_for_reader, k).unwrap();
            }
        });

        let mut builder = sm.get_snapshot_builder().await;
        let snap = builder.build_snapshot().await.unwrap();

        read_handle.await.unwrap();

        // Snapshot must include all pairs.
        let payload = decompress_payload(&snap.snapshot.into_inner()).unwrap();
        assert_eq!(payload.realms[0].entries.len(), 20);
    }
}
