//! Authorization engine: Zanzibar-style relationship tuples.
//!
//! Provides `check()`, `expand()`, `write_tuples()`, and `watch()` operations
//! for permission evaluation via graph traversal.
//!
//! # Architecture
//!
//! The authorization engine stores relationship tuples of the form
//! `(object#relation@subject)` and evaluates permissions by traversing
//! the resulting graph. Two storage indexes (forward and reverse)
//! enable efficient lookups in both directions.

mod engine;
pub mod error;
#[allow(dead_code)]
pub(crate) mod keys;
mod types;

pub use engine::{AuthzConfig, EmbeddedAuthzEngine};
pub use error::AuthzError;
pub use types::{ObjectRef, RelationshipTuple, SubjectRef, TupleWrite, WatchFilter};

use crate::core::TenantId;

/// Trait defining the authorization engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `TenantId` for multi-tenant isolation.
///
/// The engine evaluates Zanzibar-style relationship tuples via graph traversal:
/// - `check()`: Does subject have relation on object? (BFS with cycle detection)
/// - `expand()`: Which subjects have relation on object? (BFS collection)
/// - `write_tuples()`: Add or remove relationship tuples.
/// - `watch()`: Subscribe to tuple changes (stub for Phase 1+).
pub trait AuthorizationEngine: Send + Sync {
    /// Checks whether `subject` has `relation` on `object` for the given tenant.
    ///
    /// Performs a BFS traversal through userset indirections with cycle detection
    /// and depth limiting. Returns `false` (fail-closed) if max depth is reached.
    fn check(
        &self,
        tenant_id: &TenantId,
        object: &ObjectRef,
        relation: &str,
        subject: &SubjectRef,
    ) -> Result<bool, AuthzError>;

    /// Expands all subjects that have `relation` on `object` for the given tenant.
    ///
    /// Performs a BFS traversal collecting all reachable `SubjectRef::Direct` nodes.
    /// Respects the same depth limit and cycle detection as `check()`.
    fn expand(
        &self,
        tenant_id: &TenantId,
        object: &ObjectRef,
        relation: &str,
    ) -> Result<Vec<SubjectRef>, AuthzError>;

    /// Writes (adds or deletes) relationship tuples for the given tenant.
    ///
    /// Each write is applied atomically to both forward and reverse indexes.
    fn write_tuples(&self, tenant_id: &TenantId, writes: &[TupleWrite]) -> Result<(), AuthzError>;

    /// Subscribes to relationship tuple changes matching the filter.
    ///
    /// **Stub for Phase 1+**: Returns `AuthzError::MaxDepthExceeded` (placeholder).
    fn watch(&self, tenant_id: &TenantId, filter: &WatchFilter) -> Result<(), AuthzError>;
}
