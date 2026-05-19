//! Audit logging: append-only, tamper-evident event log.
//!
//! Cross-cutting infrastructure for recording security-critical mutations.
//! All events are realm-scoped and linked via a SHA-256 hash chain for
//! tamper detection.
//!
//! # Public API
//!
//! The [`AuditEngine`] trait defines the interface. [`EmbeddedAuditEngine`]
//! is the storage-backed implementation.
//!
//! Events are **append-only**: the trait exposes no update or delete
//! operations. This is enforced at the type level. The sole exception is
//! [`AuditEngine::prune_before`], an explicit administrative deletion used
//! for compliance-driven retention (e.g., COPPA data deletion).

pub mod context;
mod engine;
pub mod error;
pub(crate) mod keys;
mod types;

pub use context::{Actor, AuditContext};
pub use engine::EmbeddedAuditEngine;
pub use error::AuditError;
pub use types::{
    AuditAction, AuditEvent, AuditFailurePolicy, AuditQuery, AuditRetentionConfig, CreateAuditEvent,
};

use crate::core::{RealmId, Timestamp};

/// Trait defining the audit engine interface.
///
/// Events are append-only by design to maintain the tamper-evident hash chain.
/// The only administrative deletion path is [`prune_before`], which is
/// intentional and explicitly breaks the chain for the pruned window.
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
    /// Walks the event chain for the given realm and time range,
    /// recomputing hashes and comparing against stored values.
    /// Returns `true` if the chain is valid, `false` if tampered.
    fn verify_integrity(
        &self,
        realm_id: &RealmId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, AuditError>;

    /// Returns the retention configuration for a realm.
    ///
    /// Returns the default config (90 days) if none has been set.
    fn get_retention_config(&self, realm_id: &RealmId) -> Result<AuditRetentionConfig, AuditError>;

    /// Updates the retention configuration for a realm.
    fn set_retention_config(
        &self,
        realm_id: &RealmId,
        config: &AuditRetentionConfig,
    ) -> Result<(), AuditError>;

    /// Deletes all audit events strictly older than `cutoff`.
    ///
    /// This is an intentional administrative operation for compliance-driven
    /// retention (e.g., COPPA). It breaks the hash chain for the pruned
    /// window — integrity verification should only be run against the
    /// retained window after pruning.
    ///
    /// Returns the number of primary events deleted.
    fn prune_before(&self, realm_id: &RealmId, cutoff: Timestamp) -> Result<u64, AuditError>;
}
