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

mod engine;
pub mod error;
pub mod fs;
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

use crate::core::TenantId;

/// A single key-value entry returned from a scan operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEntry {
    /// The raw key bytes (without tenant prefix).
    pub key: Vec<u8>,
    /// The value bytes.
    pub value: Vec<u8>,
}

/// Trait defining the public storage engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `TenantId` for multi-tenant isolation.
pub trait StorageEngine: Send + Sync {
    /// Retrieves a value by tenant and key. Returns `None` if not found.
    fn get(&self, tenant_id: &TenantId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Inserts or updates a key-value pair for the given tenant.
    fn put(&self, tenant_id: &TenantId, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Deletes a key for the given tenant.
    fn delete(&self, tenant_id: &TenantId, key: &[u8]) -> Result<(), StorageError>;

    /// Scans a range of keys for the given tenant (half-open interval `[start, end)`).
    ///
    /// Returns entries sorted by key. Merges data across memtable and SST layers.
    fn scan(
        &self,
        tenant_id: &TenantId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError>;
}
