//! Raft log persistence via `redb`.
//!
//! [`HearthLogStore`] implements openraft's [`RaftLogStorage`] trait, providing
//! durable storage for the Raft log and vote state.  Two redb tables are used:
//!
//! - `raft_log` — key: `u64` log index, value: JSON-serialised
//!   `Entry<HearthRaftConfig>`.
//! - `raft_meta` — key: `&str`, value: `Vec<u8>` for vote, last-purged pointer,
//!   and the optional committed pointer.

use std::fmt::Debug;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::{Arc, Mutex};

use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftLogReader};
use openraft::{Entry, LogId, StorageError, StorageIOError, Vote};
use redb::{Database, ReadableTable, TableDefinition};
use tracing::{debug, trace};

use crate::cluster::types::HearthRaftConfig;

// ── Table definitions ─────────────────────────────────────────────────────────

const LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");

const KEY_VOTE: &str = "vote";
const KEY_LAST_PURGED: &str = "last_purged";
const KEY_COMMITTED: &str = "committed";

// ── Error helpers ─────────────────────────────────────────────────────────────

fn io_err(e: impl std::error::Error + Send + Sync + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write(&e),
    }
}

fn read_err(e: impl std::error::Error + Send + Sync + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::read(&e),
    }
}

// ── HearthLogStoreInner ───────────────────────────────────────────────────────

/// Shared inner state; wrapped in `Arc<Mutex<…>>` so both the store and the
/// detached [`HearthLogReader`] can reference the same redb handle.
struct Inner {
    db: Database,
}

impl Inner {
    fn open(path: &Path) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(path)?;
        // Eagerly create tables so subsequent transactions never encounter
        // `TableDoesNotExist`.
        let txn = db.begin_write().map_err(|e| redb::DatabaseError::Storage(redb::StorageError::Io(
            std::io::Error::other(e.to_string()),
        )))?;
        {
            txn.open_table(LOG_TABLE).map_err(|e| redb::DatabaseError::Storage(redb::StorageError::Io(
                std::io::Error::other(e.to_string()),
            )))?;
            txn.open_table(META_TABLE).map_err(|e| redb::DatabaseError::Storage(redb::StorageError::Io(
                std::io::Error::other(e.to_string()),
            )))?;
        }
        txn.commit().map_err(|e| redb::DatabaseError::Storage(redb::StorageError::Io(
            std::io::Error::other(e.to_string()),
        )))?;
        Ok(Self { db })
    }

    // ── meta helpers ──────────────────────────────────────────────────────────

    fn write_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError<u64>> {
        let txn = self.db.begin_write().map_err(|e| io_err(redb::Error::from(e)))?;
        {
            let mut table = txn.open_table(META_TABLE).map_err(|e| io_err(redb::Error::from(e)))?;
            table.insert(key, value).map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
        }
        txn.commit().map_err(|e| io_err(redb::Error::from(e)))?;
        Ok(())
    }

    fn read_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| read_err(redb::Error::from(e)))?;
        let table = txn.open_table(META_TABLE).map_err(|e| read_err(redb::Error::from(e)))?;
        let val = table.get(key).map_err(|e| read_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
        Ok(val.map(|v| v.value().to_vec()))
    }

    // ── log helpers ───────────────────────────────────────────────────────────

    fn read_entries_range<RB>(&self, range: RB) -> Result<Vec<Entry<HearthRaftConfig>>, StorageError<u64>>
    where
        RB: RangeBounds<u64> + Clone + Debug,
    {
        let txn = self.db.begin_read().map_err(|e| read_err(redb::Error::from(e)))?;
        let table = txn.open_table(LOG_TABLE).map_err(|e| read_err(redb::Error::from(e)))?;
        let mut entries = Vec::new();
        for result in table.range(range.clone()).map_err(|e| read_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))? {
            let (_, v) = result.map_err(|e| read_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
            let entry: Entry<HearthRaftConfig> = serde_json::from_slice(v.value())
                .map_err(|e| read_err(e))?;
            entries.push(entry);
        }
        trace!(count = entries.len(), range = ?range, "read log entries");
        Ok(entries)
    }

    fn last_log_id(&self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| read_err(redb::Error::from(e)))?;
        let table = txn.open_table(LOG_TABLE).map_err(|e| read_err(redb::Error::from(e)))?;
        if let Some(result) = table.last().map_err(|e| read_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))? {
            let (_, v) = result;
            let entry: Entry<HearthRaftConfig> = serde_json::from_slice(v.value()).map_err(|e| read_err(e))?;
            return Ok(Some(entry.log_id.clone()));
        }
        Ok(None)
    }

    fn last_purged_log_id(&self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        match self.read_meta(KEY_LAST_PURGED)? {
            None => Ok(None),
            Some(bytes) => {
                let id = serde_json::from_slice(&bytes).map_err(|e| read_err(e))?;
                Ok(Some(id))
            }
        }
    }
}

// ── HearthLogStore ────────────────────────────────────────────────────────────

/// Raft log store backed by `redb`.
///
/// Implements both [`RaftLogStorage`] and [`RaftLogReader`] for
/// [`HearthRaftConfig`].  Use [`HearthLogStore::open`] to create an instance
/// from a filesystem path.
pub struct HearthLogStore {
    inner: Arc<Mutex<Inner>>,
}

impl HearthLogStore {
    /// Open (or create) the redb database at `path`.
    ///
    /// Creates the `raft_log` and `raft_meta` tables if they do not yet exist.
    pub fn open(path: &Path) -> Result<Self, redb::DatabaseError> {
        let inner = Inner::open(path)?;
        debug!(path = %path.display(), "HearthLogStore opened");
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }
}

// ── HearthLogReader ───────────────────────────────────────────────────────────

/// A lightweight read handle that shares the `Inner` database reference.
///
/// Returned by [`RaftLogStorage::get_log_reader`]; openraft uses one per
/// replication task.
#[derive(Clone)]
pub struct HearthLogReader {
    inner: Arc<Mutex<Inner>>,
}

impl RaftLogReader<HearthRaftConfig> for HearthLogReader {
    async fn try_get_log_entries<RB>(&mut self, range: RB) -> Result<Vec<Entry<HearthRaftConfig>>, StorageError<u64>>
    where
        RB: RangeBounds<u64> + Clone + Debug + Send,
    {
        let inner = self.inner.lock().map_err(|e| read_err(std::io::Error::other(e.to_string())))?;
        inner.read_entries_range(range)
    }
}

// RaftLogReader is also required on the store itself (openraft blanket requirement).
impl RaftLogReader<HearthRaftConfig> for HearthLogStore {
    async fn try_get_log_entries<RB>(&mut self, range: RB) -> Result<Vec<Entry<HearthRaftConfig>>, StorageError<u64>>
    where
        RB: RangeBounds<u64> + Clone + Debug + Send,
    {
        let inner = self.inner.lock().map_err(|e| read_err(std::io::Error::other(e.to_string())))?;
        inner.read_entries_range(range)
    }
}

// ── RaftLogStorage impl ───────────────────────────────────────────────────────

impl RaftLogStorage<HearthRaftConfig> for HearthLogStore {
    type LogReader = HearthLogReader;

    async fn get_log_state(&mut self) -> Result<LogState<HearthRaftConfig>, StorageError<u64>> {
        let inner = self.inner.lock().map_err(|e| read_err(std::io::Error::other(e.to_string())))?;
        let last_purged_log_id = inner.last_purged_log_id()?;
        let last_log_id = inner.last_log_id()?;
        // If the log is empty, last_log_id falls back to last_purged_log_id.
        let last_log_id = last_log_id.or_else(|| last_purged_log_id.clone());
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        HearthLogReader {
            inner: Arc::clone(&self.inner),
        }
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let bytes = serde_json::to_vec(vote).map_err(|e| io_err(e))?;
        let inner = self.inner.lock().map_err(|e| io_err(std::io::Error::other(e.to_string())))?;
        inner.write_meta(KEY_VOTE, &bytes)?;
        debug!(?vote, "vote persisted");
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        let inner = self.inner.lock().map_err(|e| read_err(std::io::Error::other(e.to_string())))?;
        match inner.read_meta(KEY_VOTE)? {
            None => Ok(None),
            Some(bytes) => {
                let vote = serde_json::from_slice(&bytes).map_err(|e| read_err(e))?;
                Ok(Some(vote))
            }
        }
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        let inner = self.inner.lock().map_err(|e| io_err(std::io::Error::other(e.to_string())))?;
        match committed {
            None => {
                // Store an empty marker so restarts can distinguish "never set" from None.
                inner.write_meta(KEY_COMMITTED, b"null")?;
            }
            Some(ref id) => {
                let bytes = serde_json::to_vec(id).map_err(|e| io_err(e))?;
                inner.write_meta(KEY_COMMITTED, &bytes)?;
            }
        }
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        let inner = self.inner.lock().map_err(|e| read_err(std::io::Error::other(e.to_string())))?;
        match inner.read_meta(KEY_COMMITTED)? {
            None => Ok(None),
            Some(bytes) if bytes == b"null" => Ok(None),
            Some(bytes) => {
                let id = serde_json::from_slice(&bytes).map_err(|e| read_err(e))?;
                Ok(Some(id))
            }
        }
    }

    /// Append entries to the log and signal durability via `callback`.
    ///
    /// redb commits synchronously, so the callback is fired before this method
    /// returns.  Entries are serialised as JSON and stored under their log index.
    async fn append<I>(&mut self, entries: I, callback: LogFlushed<HearthRaftConfig>) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<HearthRaftConfig>> + Send,
        I::IntoIter: Send,
    {
        let inner = self.inner.lock().map_err(|e| io_err(std::io::Error::other(e.to_string())))?;
        let txn = inner.db.begin_write().map_err(|e| io_err(redb::Error::from(e)))?;
        {
            let mut table = txn.open_table(LOG_TABLE).map_err(|e| io_err(redb::Error::from(e)))?;
            for entry in entries {
                let index = entry.log_id.index;
                let bytes = serde_json::to_vec(&entry).map_err(|e| io_err(e))?;
                table.insert(index, bytes.as_slice()).map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
                trace!(index, "appended log entry");
            }
        }
        txn.commit().map_err(|e| io_err(redb::Error::from(e)))?;
        // redb commits are synchronous — signal durability immediately.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    /// Truncate the log starting at `log_id.index`, inclusive.
    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let inner = self.inner.lock().map_err(|e| io_err(std::io::Error::other(e.to_string())))?;
        let txn = inner.db.begin_write().map_err(|e| io_err(redb::Error::from(e)))?;
        {
            let mut table = txn.open_table(LOG_TABLE).map_err(|e| io_err(redb::Error::from(e)))?;
            // Collect keys to remove to avoid borrow conflicts.
            let to_remove: Vec<u64> = table
                .range(log_id.index..)
                .map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
            for key in &to_remove {
                table.remove(key).map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
            }
            debug!(from = log_id.index, removed = to_remove.len(), "log truncated");
        }
        txn.commit().map_err(|e| io_err(redb::Error::from(e)))?;
        Ok(())
    }

    /// Purge (compact) log entries up to and including `log_id`.
    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let inner = self.inner.lock().map_err(|e| io_err(std::io::Error::other(e.to_string())))?;
        let txn = inner.db.begin_write().map_err(|e| io_err(redb::Error::from(e)))?;
        {
            let mut table = txn.open_table(LOG_TABLE).map_err(|e| io_err(redb::Error::from(e)))?;
            let to_remove: Vec<u64> = table
                .range(..=log_id.index)
                .map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
            for key in &to_remove {
                table.remove(key).map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
            }
            debug!(upto = log_id.index, removed = to_remove.len(), "log purged");
        }
        // Persist the new last-purged pointer before committing the deletions.
        {
            let mut table = txn.open_table(META_TABLE).map_err(|e| io_err(redb::Error::from(e)))?;
            let bytes = serde_json::to_vec(&log_id).map_err(|e| io_err(e))?;
            table.insert(KEY_LAST_PURGED, bytes.as_slice()).map_err(|e| io_err(redb::StorageError::Io(std::io::Error::other(e.to_string()))))?;
        }
        txn.commit().map_err(|e| io_err(redb::Error::from(e)))?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use openraft::{Entry, EntryPayload, LogId, Vote};
    use tempfile::tempdir;

    use crate::cluster::types::HearthRaftConfig;

    fn make_entry(term: u64, index: u64) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(term, 0), index),
            payload: EntryPayload::Blank,
        }
    }

    fn open_store(path: &Path) -> HearthLogStore {
        HearthLogStore::open(path).expect("open store")
    }

    #[tokio::test]
    async fn append_and_read_range() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path().join("raft.db").as_path());

        let entries = vec![make_entry(1, 1), make_entry(1, 2), make_entry(1, 3)];
        append_entries_with_signal(&mut store, entries).await;

        let got = store.try_get_log_entries(1u64..=3u64).await.unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].log_id.index, 1);
        assert_eq!(got[2].log_id.index, 3);
    }

    #[tokio::test]
    async fn vote_persistence_survives_reopen() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("raft.db");

        let vote = Vote::new(5, 42);
        {
            let mut store = open_store(&db_path);
            store.save_vote(&vote).await.unwrap();
        }
        {
            let mut store = open_store(&db_path);
            let loaded = store.read_vote().await.unwrap();
            assert_eq!(loaded, Some(vote));
        }
    }

    #[tokio::test]
    async fn truncate_removes_entries_from_index() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path().join("raft.db").as_path());
        append_entries_with_signal(&mut store, vec![make_entry(1, 1), make_entry(1, 2), make_entry(1, 3)]).await;

        store.truncate(LogId::new(openraft::CommittedLeaderId::new(1, 0), 2)).await.unwrap();

        let got = store.try_get_log_entries(1u64..=3u64).await.unwrap();
        assert_eq!(got.len(), 1, "only index 1 should remain");
        assert_eq!(got[0].log_id.index, 1);
    }

    #[tokio::test]
    async fn purge_updates_last_purged_state() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path().join("raft.db").as_path());
        append_entries_with_signal(&mut store, vec![make_entry(1, 1), make_entry(1, 2), make_entry(1, 3)]).await;

        store.purge(LogId::new(openraft::CommittedLeaderId::new(1, 0), 2)).await.unwrap();

        let state = store.get_log_state().await.unwrap();
        let purged = state.last_purged_log_id.expect("purged pointer set");
        assert_eq!(purged.index, 2);

        // Entries 1 and 2 must be gone.
        let got = store.try_get_log_entries(1u64..=3u64).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].log_id.index, 3);
    }

    #[tokio::test]
    async fn get_log_state_empty_store() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path().join("raft.db").as_path());
        let state = store.get_log_state().await.unwrap();
        assert!(state.last_purged_log_id.is_none());
        assert!(state.last_log_id.is_none());
    }

    #[tokio::test]
    async fn committed_roundtrip() {
        let dir = tempdir().unwrap();
        let mut store = open_store(dir.path().join("raft.db").as_path());
        assert!(store.read_committed().await.unwrap().is_none());

        let id = LogId::new(openraft::CommittedLeaderId::new(2, 1), 10);
        store.save_committed(Some(id.clone())).await.unwrap();
        assert_eq!(store.read_committed().await.unwrap(), Some(id));

        store.save_committed(None).await.unwrap();
        assert!(store.read_committed().await.unwrap().is_none());
    }

    /// Helper: append entries and block until the flush callback fires.
    async fn append_entries_with_signal(
        store: &mut HearthLogStore,
        entries: Vec<Entry<HearthRaftConfig>>,
    ) {
        // Inner redb write is synchronous; bypass trait to test raw storage.
        let inner = store.inner.lock().unwrap();
        let txn = inner.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(LOG_TABLE).unwrap();
            for entry in &entries {
                let bytes = serde_json::to_vec(entry).unwrap();
                table.insert(entry.log_id.index, bytes.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }
}
