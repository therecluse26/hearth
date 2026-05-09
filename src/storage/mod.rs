//! Storage engine: WAL, memtable, SSTs, and tiered hot/cold storage.
//!
//! The leaf layer. Pure data persistence with no knowledge of identity,
//! auth, or authorization concepts.
//!
//! # Public API
//!
//! The [`StorageEngine`] trait defines the interface for upper layers.
//! [`EmbeddedStorageEngine`] is the default implementation composing
//! WAL, memtable, SST, and hot tier components.

pub mod auto_size;
#[allow(dead_code)]
pub mod encryption;
mod engine;
pub mod error;
pub mod fs;
#[allow(dead_code)]
pub(crate) mod key_registry;
#[allow(dead_code)]
pub(crate) mod memtable;
#[allow(dead_code)]
pub(crate) mod sst;
#[allow(dead_code)]
mod tiered;
pub mod wal;

pub use engine::{EmbeddedStorageEngine, StorageConfig};
pub use error::StorageError;
pub use fs::{Fs, FsFile, RealFs};

use crate::core::RealmId;

/// A single key-value entry returned from a scan operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEntry {
    /// The raw key bytes (without realm prefix).
    pub key: Vec<u8>,
    /// The value bytes.
    pub value: Vec<u8>,
}

/// Trait defining the public storage engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `RealmId` for multi-realm isolation.
pub trait StorageEngine: Send + Sync {
    /// Retrieves a value by realm and key. Returns `None` if not found.
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Inserts or updates a key-value pair for the given realm.
    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Deletes a key for the given realm.
    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError>;

    /// Scans a range of keys for the given realm (half-open interval `[start, end)`).
    ///
    /// Returns entries sorted by key. Merges data across memtable and SST layers.
    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError>;

    /// Atomically writes a batch of `(key, value)` pairs for a single realm.
    ///
    /// All entries land durably or none do: a crash or I/O fault mid-way
    /// leaves either the empty pre-batch state or the fully-applied
    /// post-batch state. This is the primitive upper layers should use
    /// whenever two or more writes must be visible together after recovery
    /// (e.g., a primary record plus its secondary indexes).
    ///
    /// The default implementation falls back to sequential `put()` calls,
    /// which does NOT provide atomicity — implementers that care must
    /// override.
    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        for (key, value) in entries {
            self.put(realm_id, key, value)?;
        }
        Ok(())
    }
}
