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
pub use types::{
    ConsistencyToken, NamespaceConfig, ObjectRef, ObjectTypeConfig, RelationConfig,
    RelationshipTuple, SubjectRef, TupleChangeAction, TupleChangeEvent, TupleWrite, WatchFilter,
    WatchReceiver,
};

use crate::core::RealmId;

/// Trait defining the authorization engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `RealmId` for multi-realm isolation.
///
/// The engine evaluates Zanzibar-style relationship tuples via graph traversal:
/// - `check()`: Does subject have relation on object? (BFS with cycle detection)
/// - `expand()`: Which subjects have relation on object? (BFS collection)
/// - `write_tuples()`: Add or remove relationship tuples.
/// - `watch()`: Subscribe to tuple changes (stub for Phase 1+).
pub trait AuthorizationEngine: Send + Sync {
    /// Checks whether `subject` has `relation` on `object` for the given realm.
    ///
    /// Performs a BFS traversal through userset indirections with cycle detection
    /// and depth limiting. Returns `false` (fail-closed) if max depth is reached.
    ///
    /// The optional `at_least` token guarantees the check sees all writes up to
    /// that version. In single-node mode this is always satisfied.
    fn check(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
        subject: &SubjectRef,
        at_least: Option<&ConsistencyToken>,
    ) -> Result<bool, AuthzError>;

    /// Expands all subjects that have `relation` on `object` for the given realm.
    ///
    /// Performs a BFS traversal collecting all reachable `SubjectRef::Direct` nodes.
    /// Respects the same depth limit and cycle detection as `check()`.
    ///
    /// The optional `at_least` token guarantees the expansion sees all writes up to
    /// that version. In single-node mode this is always satisfied.
    fn expand(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
        at_least: Option<&ConsistencyToken>,
    ) -> Result<Vec<SubjectRef>, AuthzError>;

    /// Writes (adds or deletes) relationship tuples for the given realm.
    ///
    /// Returns a `ConsistencyToken` representing the version after this write.
    /// Callers can pass this token to subsequent reads via `at_least` to
    /// guarantee they see the effects of this write.
    fn write_tuples(
        &self,
        realm_id: &RealmId,
        writes: &[TupleWrite],
    ) -> Result<ConsistencyToken, AuthzError>;

    /// Sets the namespace configuration for a realm.
    ///
    /// The namespace defines valid object types, relations, and allowed subject
    /// types. Once set, `write_tuples()` validates tuples against this schema.
    fn set_namespace(&self, realm_id: &RealmId, config: &NamespaceConfig)
        -> Result<(), AuthzError>;

    /// Gets the namespace configuration for a realm, if one exists.
    fn get_namespace(&self, realm_id: &RealmId) -> Result<Option<NamespaceConfig>, AuthzError>;

    /// Subscribes to relationship tuple changes matching the filter.
    ///
    /// Returns a `WatchReceiver` that delivers:
    /// 1. Replayed events from storage (catch-up since `resume_from`)
    /// 2. Live events via a broadcast channel
    ///
    /// The optional `resume_from` token replays all events since that version.
    fn watch(
        &self,
        realm_id: &RealmId,
        filter: &WatchFilter,
        resume_from: Option<&ConsistencyToken>,
    ) -> Result<WatchReceiver, AuthzError>;
}
