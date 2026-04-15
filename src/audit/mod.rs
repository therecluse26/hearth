//! Audit logging: append-only, tamper-evident event log.
//!
//! Cross-cutting infrastructure for recording security-critical mutations.
//! All events are tenant-scoped and linked via a SHA-256 hash chain for
//! tamper detection.
//!
//! # Public API
//!
//! The [`AuditEngine`] trait defines the interface. [`EmbeddedAuditEngine`]
//! is the storage-backed implementation.
//!
//! Events are **append-only**: the trait exposes no update or delete
//! operations. This is enforced at the type level.

mod engine;
pub mod error;
pub(crate) mod keys;
mod types;

pub use engine::EmbeddedAuditEngine;
pub use error::AuditError;
pub use types::{AuditAction, AuditEvent, AuditQuery, CreateAuditEvent};

use crate::core::{TenantId, Timestamp};

/// Trait defining the audit engine interface.
///
/// **Append-only by design**: no methods exist to update or delete events.
/// This guarantees immutability at the API level.
pub trait AuditEngine: Send + Sync {
    /// Appends a new audit event to the log.
    ///
    /// The engine assigns the event ID, timestamp, and integrity hash.
    /// Returns the complete event including computed fields.
    fn append(&self, event: &CreateAuditEvent) -> Result<AuditEvent, AuditError>;

    /// Queries audit events matching the given criteria.
    ///
    /// Results are returned in chronological order. All filters are
    /// combined with AND semantics.
    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError>;

    /// Verifies the integrity of the audit log hash chain.
    ///
    /// Walks the event chain for the given tenant and time range,
    /// recomputing hashes and comparing against stored values.
    /// Returns `true` if the chain is valid, `false` if tampered.
    fn verify_integrity(
        &self,
        tenant_id: &TenantId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, AuditError>;
}
