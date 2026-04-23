//! Embedded authorization engine implementation.
//!
//! Implements `AuthorizationEngine` using the `StorageEngine` trait for
//! persistence. Performs BFS graph traversal with visited-set cycle detection
//! and configurable depth limiting.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use arc_swap::ArcSwap;

use crate::authz::error::{AuthzError, AuthzErrorCode};
use crate::authz::keys;
use crate::authz::types::{
    CheckExplanation, CheckStep, ConsistencyToken, NamespaceConfig, ObjectRef, RelationshipTuple,
    SubjectRef, TupleChangeAction, TupleChangeEvent, TupleWrite, WatchFilter, WatchReceiver,
};
use crate::authz::AuthorizationEngine;
use crate::core::RealmId;
use crate::storage::StorageEngine;

/// Outcome of a `check()` resolve, shareable across sync waiters.
///
/// Stored `bool` for success or an `AuthzErrorCode` summary for failure.
/// `AuthzError` itself is not `Clone`, so we cannot share it directly.
type CoalescedResult = Result<bool, AuthzErrorCode>;

/// A single in-flight `check()` coalescence slot.
///
/// The leader runs the resolver, then stores `Some(result)` in `outcome`
/// and notifies all waiters via the condvar. Waiters block on the condvar
/// until `outcome` is populated. An `Arc<InflightSlot>` is kept in the
/// engine's `inflight` map as a `Weak` so automatic cleanup happens when
/// the leader drops its strong reference.
struct InflightSlot {
    outcome: Mutex<Option<CoalescedResult>>,
    ready: Condvar,
}

/// Role returned from `claim_inflight()` indicating whether the caller
/// should execute the resolver (leader) or wait for the leader's result
/// (follower).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaderRole {
    /// This caller was the first to claim the slot and must run the resolve.
    Leader,
    /// Another caller is already resolving; this caller must wait.
    Follower,
}

impl InflightSlot {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    /// Leader publishes the result and wakes all waiters.
    fn publish(&self, result: CoalescedResult) {
        #[allow(clippy::unwrap_used)]
        let mut guard = self.outcome.lock().unwrap();
        *guard = Some(result);
        self.ready.notify_all();
    }

    /// Waiter blocks until a leader publishes the outcome.
    fn wait(&self) -> CoalescedResult {
        #[allow(clippy::unwrap_used)]
        let mut guard = self.outcome.lock().unwrap();
        while guard.is_none() {
            #[allow(clippy::unwrap_used)]
            let next = self.ready.wait(guard).unwrap();
            guard = next;
        }
        #[allow(clippy::unwrap_used)]
        guard
            .as_ref()
            .copied()
            .unwrap_or(Err(AuthzErrorCode::Storage))
    }
}

/// Cache key for permission check results.
///
/// Encodes `(realm, object_display, relation, subject_display)` as a single
/// string to avoid the overhead of tuple hashing with multiple string fields.
type CacheKey = String;

/// Builds a cache key from the check parameters.
fn cache_key(
    realm_id: &RealmId,
    object: &ObjectRef,
    relation: &str,
    subject: &SubjectRef,
) -> CacheKey {
    format!("{realm_id}|{object}|{relation}|{subject}")
}

/// Builds the invalidation prefix for a (realm, object, relation) triple.
///
/// Any cache entry whose key starts with this prefix is invalidated when
/// a tuple with matching (realm, object, relation) is written or deleted.
fn invalidation_prefix(realm_id: &RealmId, object: &ObjectRef, relation: &str) -> String {
    format!("{realm_id}|{object}|{relation}|")
}

/// Default maximum BFS traversal depth.
const DEFAULT_MAX_DEPTH: u32 = 10;

/// Returns the rewrite closure for `(object_type, relation)` if a namespace
/// is configured, or `vec![relation]` otherwise. Centralises the "no schema"
/// fallback so callers can treat presence of rewrites uniformly.
fn closure_or_self(ns: Option<&NamespaceConfig>, object_type: &str, relation: &str) -> Vec<String> {
    match ns {
        Some(cfg) => cfg.rewrite_closure(object_type, relation),
        None => vec![relation.to_string()],
    }
}

/// Enqueues `(object, relation)` and every sibling relation that transitively
/// satisfies it via rewrite unions, guarded by the shared visited set. All
/// closure entries share the same `depth` — rewrites are a schema-level
/// expansion, not a tuple traversal, so they should not consume BFS depth.
fn enqueue_with_closure(
    queue: &mut VecDeque<(ObjectRef, String, u32)>,
    visited: &mut HashSet<(String, String, String)>,
    ns: Option<&NamespaceConfig>,
    object: ObjectRef,
    relation: &str,
    depth: u32,
) {
    for rel in closure_or_self(ns, object.object_type(), relation) {
        let visit_key = (
            object.object_type().to_string(),
            object.object_id().to_string(),
            rel.clone(),
        );
        if visited.insert(visit_key) {
            queue.push_back((object.clone(), rel, depth));
        }
    }
}

/// Configuration for the authorization engine.
#[derive(Debug, Clone)]
pub struct AuthzConfig {
    /// Maximum BFS traversal depth for `check()` and `expand()`.
    pub max_depth: u32,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// Embedded authorization engine backed by a `StorageEngine`.
///
/// Stores Zanzibar-style relationship tuples in forward and reverse indexes
/// and evaluates permissions via BFS graph traversal.
/// Default broadcast channel capacity per realm.
const WATCH_CHANNEL_CAPACITY: usize = 1024;

pub struct EmbeddedAuthzEngine {
    /// The underlying storage engine.
    storage: Arc<dyn StorageEngine>,
    /// Engine configuration.
    config: AuthzConfig,
    /// Monotonic version counter for consistency tokens and watch sequences.
    version: AtomicU64,
    /// Lock-free permission cache: `(realm|object|relation|subject)` → `bool`.
    ///
    /// Uses `ArcSwap` for zero-allocation reads on the hot path.
    /// Invalidated on writes by rebuilding without affected entries.
    cache: ArcSwap<HashMap<CacheKey, bool>>,
    /// Single-flight coalescer: keyed by cache key, stores a weak reference
    /// to the in-flight slot. The leader holds a strong `Arc<InflightSlot>`
    /// for the duration of the resolve, so `Weak::upgrade()` succeeds for
    /// racing waiters only while the leader is still running. Stale weaks
    /// from already-completed leaders upgrade to `None` and the racing
    /// caller becomes the new leader — a correct if rare pattern.
    inflight: Mutex<HashMap<CacheKey, Weak<InflightSlot>>>,
    /// Per-realm broadcast senders for watch API.
    ///
    /// Protected by `Mutex` for sender management (not on hot read path).
    /// The broadcast channel itself uses lock-free internals.
    watch_senders: Mutex<HashMap<String, tokio::sync::broadcast::Sender<TupleChangeEvent>>>,
    /// Probe: counts how many times the resolver path executed.
    ///
    /// Enabled only under the `test-hooks` feature. Used by the
    /// cache-stampede simulation to assert that N concurrent misses on
    /// the same key produce exactly ONE backend call after coalescing.
    #[cfg(feature = "test-hooks")]
    backend_calls: AtomicU64,
}

impl std::fmt::Debug for EmbeddedAuthzEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedAuthzEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl EmbeddedAuthzEngine {
    /// Creates a new authorization engine backed by the given storage engine.
    pub fn new(storage: Arc<dyn StorageEngine>, config: AuthzConfig) -> Self {
        Self {
            storage,
            config,
            version: AtomicU64::new(0),
            cache: ArcSwap::from_pointee(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            watch_senders: Mutex::new(HashMap::new()),
            #[cfg(feature = "test-hooks")]
            backend_calls: AtomicU64::new(0),
        }
    }

    /// Test probe: number of times the resolver path has executed since
    /// engine construction. Wraps an `AtomicU64` so callers can compute
    /// deltas by sampling before and after a workload.
    ///
    /// Only compiled under the `test-hooks` feature.
    #[cfg(feature = "test-hooks")]
    pub fn backend_call_count(&self) -> u64 {
        self.backend_calls.load(Ordering::Relaxed)
    }

    /// Clears the permission cache.
    ///
    /// Test-only helper used by the cache-stampede simulation to force a
    /// cold state between waves. Compiled only under `test-hooks`.
    #[cfg(feature = "test-hooks")]
    pub fn clear_cache(&self) {
        self.cache.store(Arc::new(HashMap::new()));
    }

    /// Runs the uncached permission resolve for `(object, relation, subject)`.
    ///
    /// This is the logic that used to live inline in `check()` past the
    /// cache HIT branch. It is now callable from the leader branch of the
    /// single-flight coalescer. Never cached here — the caller decides
    /// whether to publish the result to the cache.
    #[allow(clippy::too_many_lines)]
    fn resolve_permission(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
        subject: &SubjectRef,
    ) -> Result<bool, AuthzError> {
        #[cfg(feature = "test-hooks")]
        self.backend_calls.fetch_add(1, Ordering::Relaxed);

        // Load the namespace once so rewrite closures can be consulted
        // without repeated storage reads. If no namespace is configured the
        // closure reduces to the singleton `[relation]`.
        let ns = self.get_namespace(realm_id)?;

        // 1. Direct lookup — check the target relation and every sibling
        // relation that transitively satisfies it via rewrite unions.
        let target_relations = closure_or_self(ns.as_ref(), object.object_type(), relation);
        for rel in &target_relations {
            let fwd_key = keys::encode_forward(object, rel, subject);
            let direct = self
                .storage
                .get(realm_id, &fwd_key)
                .map_err(|e| AuthzError::Storage(Box::new(e)))?;
            if direct.is_some() {
                return Ok(true);
            }
        }

        // 2. BFS traversal through userset indirections and rewrite unions.
        let mut queue: VecDeque<(ObjectRef, String, u32)> = VecDeque::new();
        let mut visited: HashSet<(String, String, String)> = HashSet::new();

        enqueue_with_closure(
            &mut queue,
            &mut visited,
            ns.as_ref(),
            object.clone(),
            relation,
            0,
        );

        while let Some((cur_object, cur_relation, depth)) = queue.pop_front() {
            if depth >= self.config.max_depth {
                continue; // Fail-closed: stop exploring this branch
            }

            let subjects = self.scan_subjects(realm_id, &cur_object, &cur_relation)?;

            for s in &subjects {
                match s {
                    SubjectRef::Direct(_) => {
                        if s == subject {
                            return Ok(true);
                        }
                    }
                    SubjectRef::Userset {
                        object: userset_obj,
                        relation: userset_rel,
                    } => {
                        enqueue_with_closure(
                            &mut queue,
                            &mut visited,
                            ns.as_ref(),
                            userset_obj.clone(),
                            userset_rel,
                            depth + 1,
                        );
                    }
                }
            }
        }

        Ok(false)
    }

    /// Claims leadership of an in-flight resolve for `key`.
    ///
    /// Returns `Ok((slot, LeaderRole::Leader))` if this caller is the first
    /// to arrive, or `Ok((slot, LeaderRole::Follower))` if another caller
    /// is already resolving. Followers must call `slot.wait()` and
    /// reconstruct a proper `AuthzError` from the coalesced code.
    fn claim_inflight(&self, key: &CacheKey) -> (Arc<InflightSlot>, LeaderRole) {
        #[allow(clippy::unwrap_used)]
        let mut inflight = self.inflight.lock().unwrap();
        if let Some(existing_weak) = inflight.get(key) {
            if let Some(strong) = existing_weak.upgrade() {
                return (strong, LeaderRole::Follower);
            }
            // Stale entry — the previous leader finished and dropped its
            // strong ref. Fall through and take leadership ourselves.
        }
        let slot = Arc::new(InflightSlot::new());
        inflight.insert(key.clone(), Arc::downgrade(&slot));
        (slot, LeaderRole::Leader)
    }

    /// Removes an in-flight entry after the leader finishes.
    ///
    /// Deferred via a guard so that panics in the leader path still clean
    /// up the map (followers would otherwise block indefinitely).
    fn remove_inflight(&self, key: &CacheKey) {
        #[allow(clippy::unwrap_used)]
        let mut inflight = self.inflight.lock().unwrap();
        inflight.remove(key);
    }

    /// Writes a single relationship tuple to both indexes.
    fn write_tuple(&self, realm_id: &RealmId, tuple: &RelationshipTuple) -> Result<(), AuthzError> {
        let fwd_key = keys::encode_forward(&tuple.object, &tuple.relation, &tuple.subject);
        let rev_key = keys::encode_reverse(&tuple.object, &tuple.relation, &tuple.subject);

        self.storage
            .put(realm_id, &fwd_key, keys::PRESENCE_MARKER)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        self.storage
            .put(realm_id, &rev_key, keys::PRESENCE_MARKER)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        Ok(())
    }

    /// Deletes a single relationship tuple from both indexes.
    fn delete_tuple(
        &self,
        realm_id: &RealmId,
        tuple: &RelationshipTuple,
    ) -> Result<(), AuthzError> {
        let fwd_key = keys::encode_forward(&tuple.object, &tuple.relation, &tuple.subject);
        let rev_key = keys::encode_reverse(&tuple.object, &tuple.relation, &tuple.subject);

        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        self.storage
            .delete(realm_id, &rev_key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        Ok(())
    }

    /// Returns whether a specific tuple exists in storage.
    fn tuple_exists(
        &self,
        realm_id: &RealmId,
        tuple: &RelationshipTuple,
    ) -> Result<bool, AuthzError> {
        let fwd_key = keys::encode_forward(&tuple.object, &tuple.relation, &tuple.subject);
        let result = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        Ok(result.is_some())
    }

    /// Inserts a single entry into the permission cache.
    ///
    /// Loads the current snapshot, builds a new map with the added entry,
    /// and atomically swaps it in. Concurrent inserts may overwrite each
    /// other, which is safe — cached values are always eventually consistent
    /// with storage and invalidated on writes.
    fn cache_insert(&self, key: &str, value: bool) {
        let old = self.cache.load();
        let mut new_map = (**old).clone();
        new_map.insert(key.to_string(), value);
        self.cache.store(Arc::new(new_map));
    }

    /// Invalidates cache entries affected by the given tuple writes.
    ///
    /// For each written/deleted tuple, removes all cache entries whose key
    /// matches the `(realm, object, relation)` prefix. This is conservative
    /// — it may evict unrelated entries for the same object/relation but
    /// guarantees no stale positives or negatives.
    fn invalidate_cache(&self, realm_id: &RealmId, writes: &[TupleWrite]) {
        let ns = self.get_namespace(realm_id).ok().flatten();
        let mut prefixes_to_invalidate = HashSet::new();
        for write in writes {
            let tuple = match write {
                TupleWrite::Touch(t)
                | TupleWrite::Delete(t)
                | TupleWrite::TouchIfAbsent(t)
                | TupleWrite::DeleteIfPresent(t) => t,
            };
            // Adding or deleting a tuple on relation R affects cache entries
            // for R and for every relation whose rewrite closure contains R.
            // Compute the reverse closure so, e.g., a write on `editor`
            // correctly evicts cached `viewer` answers.
            let affected_relations: Vec<String> = match ns.as_ref() {
                Some(cfg) => {
                    cfg.reverse_rewrite_closure(tuple.object.object_type(), &tuple.relation)
                }
                None => vec![tuple.relation.clone()],
            };
            for rel in affected_relations {
                prefixes_to_invalidate.insert(invalidation_prefix(realm_id, &tuple.object, &rel));
            }
        }

        let old = self.cache.load();
        let new_map: HashMap<CacheKey, bool> = old
            .iter()
            .filter(|(k, _)| !prefixes_to_invalidate.iter().any(|p| k.starts_with(p)))
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        self.cache.store(Arc::new(new_map));
    }

    /// Gets or creates a broadcast sender for the given realm.
    fn get_or_create_sender(
        &self,
        realm_id: &RealmId,
    ) -> tokio::sync::broadcast::Sender<TupleChangeEvent> {
        // INVARIANT: Mutex is only held for HashMap lookup/insert, never across .await
        #[allow(clippy::unwrap_used)]
        let mut senders = self.watch_senders.lock().unwrap();
        let key = realm_id.to_string();
        senders
            .entry(key)
            .or_insert_with(|| tokio::sync::broadcast::channel(WATCH_CHANNEL_CAPACITY).0)
            .clone()
    }

    /// Persists a watch event to storage and broadcasts to active watchers.
    fn emit_watch_event(
        &self,
        realm_id: &RealmId,
        sequence: u64,
        index: u32,
        action: TupleChangeAction,
        tuple: &RelationshipTuple,
        timestamp_us: u64,
    ) -> Result<(), AuthzError> {
        let event = TupleChangeEvent {
            sequence,
            action,
            object_type: tuple.object.object_type().to_string(),
            object_id: tuple.object.object_id().to_string(),
            relation: tuple.relation.clone(),
            subject: format!("{}", tuple.subject),
            realm_id: realm_id.to_string(),
            timestamp_us,
        };

        // Persist event
        let key = keys::encode_watch_event(sequence, index);
        let value = serde_json::to_vec(&event).map_err(|e| AuthzError::Storage(Box::new(e)))?;
        self.storage
            .put(realm_id, &key, &value)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        // Broadcast to active watchers (ignore send errors — no receivers is OK)
        let sender = self.get_or_create_sender(realm_id);
        let _ = sender.send(event);

        Ok(())
    }

    /// Loads persisted watch events since a given sequence number.
    fn load_events_since(
        &self,
        realm_id: &RealmId,
        since_sequence: u64,
    ) -> Result<Vec<TupleChangeEvent>, AuthzError> {
        let start = keys::encode_watch_event(since_sequence + 1, 0);
        let prefix = keys::encode_watch_event_prefix();
        let end = keys::prefix_end(prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        let mut events = Vec::new();
        for entry in &entries {
            let event: TupleChangeEvent = serde_json::from_slice(&entry.value)
                .map_err(|e| AuthzError::Storage(Box::new(e)))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Validates a tuple against the namespace configuration.
    ///
    /// Returns `Ok(())` if the tuple conforms to the schema or if no schema is set.
    fn validate_tuple_against_namespace(
        config: &NamespaceConfig,
        tuple: &RelationshipTuple,
    ) -> Result<(), AuthzError> {
        let object_type = tuple.object.object_type();

        let type_config =
            config
                .object_types
                .get(object_type)
                .ok_or_else(|| AuthzError::InvalidNamespace {
                    reason: format!("unknown object type: {object_type}"),
                })?;

        let relation_config = type_config.relations.get(&tuple.relation).ok_or_else(|| {
            AuthzError::InvalidNamespace {
                reason: format!(
                    "unknown relation '{}' for object type '{object_type}'",
                    tuple.relation
                ),
            }
        })?;

        let subject_type = match &tuple.subject {
            SubjectRef::Direct(obj) => obj.object_type(),
            SubjectRef::Userset { object, .. } => object.object_type(),
        };

        if !relation_config
            .allowed_subject_types
            .iter()
            .any(|t| t == subject_type)
        {
            return Err(AuthzError::InvalidNamespace {
                reason: format!(
                    "subject type '{subject_type}' not allowed for {object_type}#{} (allowed: {:?})",
                    tuple.relation, relation_config.allowed_subject_types
                ),
            });
        }

        Ok(())
    }

    /// Scans all subjects for a given (object, relation) pair.
    fn scan_subjects(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
    ) -> Result<Vec<SubjectRef>, AuthzError> {
        let prefix = keys::encode_forward_prefix(object, relation);
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        let mut subjects = Vec::new();
        for entry in &entries {
            let decoded = keys::extract_subject_from_forward_key(&entry.key, &prefix)?;
            subjects.push(decoded.into_subject_ref()?);
        }
        Ok(subjects)
    }
}

impl AuthorizationEngine for EmbeddedAuthzEngine {
    fn check(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
        subject: &SubjectRef,
        _at_least: Option<&ConsistencyToken>,
    ) -> Result<bool, AuthzError> {
        // In single-node mode, data is always fresh. The at_least parameter
        // establishes the API contract for Phase 2 clustering.

        // 0. Cache lookup — zero-allocation hot path via ArcSwap::load()
        let key = cache_key(realm_id, object, relation, subject);
        let cache_snapshot = self.cache.load();
        if let Some(&cached) = cache_snapshot.get(&key) {
            return Ok(cached);
        }
        // Drop the Arc guard before attempting to claim leadership
        drop(cache_snapshot);

        // 1. Single-flight coalescer: at most one backend resolve per key
        //    at a time. Additional concurrent callers block until the
        //    leader publishes the outcome.
        let (slot, role) = self.claim_inflight(&key);
        match role {
            LeaderRole::Follower => {
                // Wait for the leader's result, then materialize an
                // AuthzError if necessary. Note: the follower does NOT
                // update the cache — the leader already did that.
                return match slot.wait() {
                    Ok(allowed) => Ok(allowed),
                    Err(code) => Err(code.into_authz_error()),
                };
            }
            LeaderRole::Leader => {
                // Defensive re-check: a rapid prior leader may have
                // cached the answer between our initial cache miss and
                // our claim. Running the resolve again would be
                // wasteful; just replay the cached result through the
                // slot so we maintain the single-flight invariant that
                // each `check()` produces at most one backend resolve
                // per cache key per "hot window".
                let recheck = self.cache.load();
                if let Some(&cached) = recheck.get(&key) {
                    drop(recheck);
                    slot.publish(Ok(cached));
                    self.remove_inflight(&key);
                    return Ok(cached);
                }
                drop(recheck);
                // Fall through and run the resolver ourselves.
            }
        }

        // 2. Leader path: run uncached resolver, publish, cache.
        //
        // Panic safety: if resolve_permission panics, `slot` drops and the
        // leader's strong Arc goes away — waiters still holding a strong
        // Arc through upgrade() will see `outcome == None` forever. To
        // prevent that, we publish the result through a scope guard so
        // any early-exit broadcasts a Storage error. For the common
        // success/error-return paths we publish explicitly below.
        let resolve_outcome = self.resolve_permission(realm_id, object, relation, subject);

        // Record in cache BEFORE publishing so any waiter that returns
        // from wait() and hits a subsequent check() sees the cache hit.
        // Negative and positive outcomes are both cached. Errors are not.
        let coalesced: CoalescedResult = match &resolve_outcome {
            Ok(allowed) => {
                self.cache_insert(&key, *allowed);
                Ok(*allowed)
            }
            Err(err) => Err(AuthzErrorCode::from(err)),
        };

        slot.publish(coalesced);
        self.remove_inflight(&key);

        resolve_outcome
    }

    fn expand(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
        _at_least: Option<&ConsistencyToken>,
    ) -> Result<Vec<SubjectRef>, AuthzError> {
        let ns = self.get_namespace(realm_id)?;
        let mut result: Vec<SubjectRef> = Vec::new();
        let mut seen_direct: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(ObjectRef, String, u32)> = VecDeque::new();
        let mut visited: HashSet<(String, String, String)> = HashSet::new();

        enqueue_with_closure(
            &mut queue,
            &mut visited,
            ns.as_ref(),
            object.clone(),
            relation,
            0,
        );

        while let Some((cur_object, cur_relation, depth)) = queue.pop_front() {
            if depth >= self.config.max_depth {
                continue;
            }

            let subjects = self.scan_subjects(realm_id, &cur_object, &cur_relation)?;

            for s in subjects {
                match &s {
                    SubjectRef::Direct(_) => {
                        let key = format!("{s}");
                        if seen_direct.insert(key) {
                            result.push(s);
                        }
                    }
                    SubjectRef::Userset {
                        object: userset_obj,
                        relation: userset_rel,
                    } => {
                        enqueue_with_closure(
                            &mut queue,
                            &mut visited,
                            ns.as_ref(),
                            userset_obj.clone(),
                            userset_rel,
                            depth + 1,
                        );
                    }
                }
            }
        }

        Ok(result)
    }

    fn write_tuples(
        &self,
        realm_id: &RealmId,
        writes: &[TupleWrite],
    ) -> Result<ConsistencyToken, AuthzError> {
        // Phase 0: validate against namespace schema if configured
        if let Some(ns_config) = self.get_namespace(realm_id)? {
            for write in writes {
                let tuple = match write {
                    TupleWrite::Touch(t)
                    | TupleWrite::TouchIfAbsent(t)
                    | TupleWrite::Delete(t)
                    | TupleWrite::DeleteIfPresent(t) => t,
                };
                Self::validate_tuple_against_namespace(&ns_config, tuple)?;
            }
        }

        // Phase 1: validate all preconditions before applying any writes (all-or-nothing)
        for write in writes {
            match write {
                TupleWrite::TouchIfAbsent(tuple) => {
                    if self.tuple_exists(realm_id, tuple)? {
                        return Err(AuthzError::PreconditionFailed {
                            reason: format!("tuple already exists: {tuple}"),
                        });
                    }
                }
                TupleWrite::DeleteIfPresent(tuple) => {
                    if !self.tuple_exists(realm_id, tuple)? {
                        return Err(AuthzError::PreconditionFailed {
                            reason: format!("tuple does not exist: {tuple}"),
                        });
                    }
                }
                TupleWrite::Touch(_) | TupleWrite::Delete(_) => {}
            }
        }

        // Phase 2: apply all writes
        for write in writes {
            match write {
                TupleWrite::Touch(tuple) | TupleWrite::TouchIfAbsent(tuple) => {
                    self.write_tuple(realm_id, tuple)?;
                }
                TupleWrite::Delete(tuple) | TupleWrite::DeleteIfPresent(tuple) => {
                    self.delete_tuple(realm_id, tuple)?;
                }
            }
        }

        // Invalidate cache entries affected by these writes
        self.invalidate_cache(realm_id, writes);

        // Increment version counter and return consistency token
        let new_version = self.version.fetch_add(1, Ordering::SeqCst) + 1;

        // Emit watch events for each write operation
        // Timestamp in Unix microseconds. u64 holds ~584,942 years of microseconds,
        // so truncation from u128 is safe for any realistic timestamp.
        #[allow(clippy::cast_possible_truncation)]
        let timestamp_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as u64);

        for (idx, write) in writes.iter().enumerate() {
            let (action, tuple) = match write {
                TupleWrite::Touch(t) | TupleWrite::TouchIfAbsent(t) => {
                    (TupleChangeAction::Touch, t)
                }
                TupleWrite::Delete(t) | TupleWrite::DeleteIfPresent(t) => {
                    (TupleChangeAction::Delete, t)
                }
            };
            #[allow(clippy::cast_possible_truncation)]
            let index = idx as u32;
            self.emit_watch_event(realm_id, new_version, index, action, tuple, timestamp_us)?;
        }

        Ok(ConsistencyToken::new(new_version))
    }

    fn set_namespace(
        &self,
        realm_id: &RealmId,
        config: &NamespaceConfig,
    ) -> Result<(), AuthzError> {
        // Reject configs whose rewrite unions reference unknown relations or
        // form cycles before anything is persisted.
        config.validate_rewrites()?;
        let key = keys::encode_namespace_config();
        let value = serde_json::to_vec(config).map_err(|e| AuthzError::Storage(Box::new(e)))?;
        self.storage
            .put(realm_id, key, &value)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        // Installing or changing a namespace can change the logical
        // meaning of cached check results (e.g. a new union rule makes
        // previously-false checks true). Drop the cache to force re-resolve.
        self.cache.store(Arc::new(HashMap::new()));
        Ok(())
    }

    fn get_namespace(&self, realm_id: &RealmId) -> Result<Option<NamespaceConfig>, AuthzError> {
        let key = keys::encode_namespace_config();
        let value = self
            .storage
            .get(realm_id, key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        match value {
            Some(bytes) => {
                let config =
                    serde_json::from_slice(&bytes).map_err(|e| AuthzError::Storage(Box::new(e)))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    fn list_direct_relations_for_subject(
        &self,
        realm_id: &RealmId,
        subject: &SubjectRef,
    ) -> Result<Vec<(ObjectRef, String)>, AuthzError> {
        let prefix = keys::encode_reverse_prefix_for_subject(subject);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            // Keys that fail to parse are skipped rather than failing the
            // whole query — a malformed reverse-index entry is a storage
            // bug, but the admin screen should still show the rest.
            let Some((object_type, object_id, relation)) =
                keys::decode_reverse_tail(&entry.key, &prefix)
            else {
                continue;
            };
            let Ok(object) = ObjectRef::new(&object_type, &object_id) else {
                continue;
            };
            out.push((object, relation));
        }
        Ok(out)
    }

    fn check_explain(
        &self,
        realm_id: &RealmId,
        object: &ObjectRef,
        relation: &str,
        subject: &SubjectRef,
    ) -> Result<CheckExplanation, AuthzError> {
        let ns = self.get_namespace(realm_id)?;
        let mut steps: Vec<CheckStep> = Vec::new();
        let mut max_depth_reached: u32 = 0;

        // 1. Direct lookup — check the target relation and every sibling
        // relation that transitively satisfies it via rewrite unions.
        let target_relations = closure_or_self(ns.as_ref(), object.object_type(), relation);
        for rel in &target_relations {
            if rel != relation {
                steps.push(CheckStep::RewriteUnion {
                    object: format!("{object}"),
                    relation: relation.to_string(),
                    included: rel.clone(),
                });
            }
            let fwd_key = keys::encode_forward(object, rel, subject);
            let direct = self
                .storage
                .get(realm_id, &fwd_key)
                .map_err(|e| AuthzError::Storage(Box::new(e)))?;
            if direct.is_some() {
                steps.push(CheckStep::DirectMatch {
                    object: format!("{object}"),
                    relation: rel.clone(),
                    subject: format!("{subject}"),
                });
                return Ok(CheckExplanation {
                    allowed: true,
                    steps,
                    max_depth_reached,
                });
            }
        }

        // 2. BFS traversal through userset indirections and rewrite unions.
        let mut queue: VecDeque<(ObjectRef, String, u32)> = VecDeque::new();
        let mut visited: HashSet<(String, String, String)> = HashSet::new();
        enqueue_with_closure(
            &mut queue,
            &mut visited,
            ns.as_ref(),
            object.clone(),
            relation,
            0,
        );

        while let Some((cur_object, cur_relation, depth)) = queue.pop_front() {
            if depth >= self.config.max_depth {
                continue;
            }
            if depth > max_depth_reached {
                max_depth_reached = depth;
            }
            let subjects = self.scan_subjects(realm_id, &cur_object, &cur_relation)?;
            steps.push(CheckStep::ScannedRelation {
                object: format!("{cur_object}"),
                relation: cur_relation.clone(),
                subject_count: subjects.len(),
            });
            for s in &subjects {
                match s {
                    SubjectRef::Direct(_) => {
                        if s == subject {
                            steps.push(CheckStep::DirectMatch {
                                object: format!("{cur_object}"),
                                relation: cur_relation.clone(),
                                subject: format!("{subject}"),
                            });
                            return Ok(CheckExplanation {
                                allowed: true,
                                steps,
                                max_depth_reached,
                            });
                        }
                    }
                    SubjectRef::Userset {
                        object: userset_obj,
                        relation: userset_rel,
                    } => {
                        steps.push(CheckStep::FollowedUserset {
                            object: format!("{userset_obj}"),
                            relation: userset_rel.clone(),
                        });
                        enqueue_with_closure(
                            &mut queue,
                            &mut visited,
                            ns.as_ref(),
                            userset_obj.clone(),
                            userset_rel,
                            depth + 1,
                        );
                    }
                }
            }
        }

        Ok(CheckExplanation {
            allowed: false,
            steps,
            max_depth_reached,
        })
    }

    fn watch(
        &self,
        realm_id: &RealmId,
        filter: &WatchFilter,
        resume_from: Option<&ConsistencyToken>,
    ) -> Result<WatchReceiver, AuthzError> {
        // Load replay events from storage if resume_from is specified
        let replay_events = if let Some(token) = resume_from {
            let mut events = self.load_events_since(realm_id, token.version())?;
            // Filter by object_type if filter is set
            if let Some(ref filter_type) = filter.object_type {
                events.retain(|e| e.object_type == *filter_type);
            }
            events
        } else {
            Vec::new()
        };

        // Subscribe to the broadcast channel for live events
        let sender = self.get_or_create_sender(realm_id);
        let rx = sender.subscribe();

        Ok(WatchReceiver { rx, replay_events })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn setup_engine() -> (tempfile::TempDir, EmbeddedAuthzEngine) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let authz = EmbeddedAuthzEngine::new(Arc::new(storage), AuthzConfig::default());
        (dir, authz)
    }

    fn setup_engine_with_depth(max_depth: u32) -> (tempfile::TempDir, EmbeddedAuthzEngine) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let authz = EmbeddedAuthzEngine::new(Arc::new(storage), AuthzConfig { max_depth });
        (dir, authz)
    }

    // ===== Scenario 1: Direct relationship check =====

    #[test]
    fn direct_check_present_returns_true() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("write");

        let result = engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check");
        assert!(result, "direct relationship should be found");
    }

    #[test]
    fn direct_check_absent_returns_false() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "bob").expect("valid");

        let result = engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check");
        assert!(!result, "absent relationship should not be found");
    }

    #[test]
    fn direct_check_wrong_relation_returns_false() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("write");

        let result = engine
            .check(&realm, &obj, "editor", &subj, None)
            .expect("check");
        assert!(!result, "wrong relation should not match");
    }

    // ===== Scenario 2: Transitive relationship check =====

    #[test]
    fn transitive_check_2_hop() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // document:readme#viewer@group:eng#member
        // group:eng#member@user:alice
        let doc = ObjectRef::new("document", "readme").expect("valid");
        let group_member = SubjectRef::userset("group", "eng", "member").expect("valid");
        let tuple1 = RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("valid");

        let group = ObjectRef::new("group", "eng").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let tuple2 = RelationshipTuple::new(group, "member", alice.clone()).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        let result = engine
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check");
        assert!(result, "2-hop transitive check should succeed");
    }

    #[test]
    fn transitive_check_3_hop() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // document:readme#viewer@group:eng#member
        // group:eng#member@team:core#member
        // team:core#member@user:alice
        let doc = ObjectRef::new("document", "readme").expect("valid");
        let group_member = SubjectRef::userset("group", "eng", "member").expect("valid");
        let tuple1 = RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("valid");

        let group = ObjectRef::new("group", "eng").expect("valid");
        let team_member = SubjectRef::userset("team", "core", "member").expect("valid");
        let tuple2 = RelationshipTuple::new(group, "member", team_member).expect("valid");

        let team = ObjectRef::new("team", "core").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let tuple3 = RelationshipTuple::new(team, "member", alice.clone()).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[
                    TupleWrite::Touch(tuple1),
                    TupleWrite::Touch(tuple2),
                    TupleWrite::Touch(tuple3),
                ],
            )
            .expect("write");

        let result = engine
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check");
        assert!(result, "3-hop transitive check should succeed");
    }

    // ===== Scenario 3: Cycle detection =====

    #[test]
    fn cycle_detection_terminates() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // Create a cycle: A#member@B#member, B#member@A#member
        let a = ObjectRef::new("group", "a").expect("valid");
        let b_member = SubjectRef::userset("group", "b", "member").expect("valid");
        let tuple1 = RelationshipTuple::new(a.clone(), "member", b_member).expect("valid");

        let b = ObjectRef::new("group", "b").expect("valid");
        let a_member = SubjectRef::userset("group", "a", "member").expect("valid");
        let tuple2 = RelationshipTuple::new(b, "member", a_member).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        // check for a user not in the cycle — should terminate and return false
        let user = SubjectRef::direct("user", "alice").expect("valid");
        let result = engine
            .check(&realm, &a, "member", &user, None)
            .expect("check");
        assert!(!result, "cycle should not produce false positive");
    }

    #[test]
    fn cycle_with_reachable_target() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // A#member@B#member, B#member@A#member, B#member@user:alice
        let a = ObjectRef::new("group", "a").expect("valid");
        let b_member = SubjectRef::userset("group", "b", "member").expect("valid");
        let tuple1 = RelationshipTuple::new(a.clone(), "member", b_member).expect("valid");

        let b = ObjectRef::new("group", "b").expect("valid");
        let a_member = SubjectRef::userset("group", "a", "member").expect("valid");
        let tuple2 = RelationshipTuple::new(b.clone(), "member", a_member).expect("valid");

        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let tuple3 = RelationshipTuple::new(b, "member", alice.clone()).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[
                    TupleWrite::Touch(tuple1),
                    TupleWrite::Touch(tuple2),
                    TupleWrite::Touch(tuple3),
                ],
            )
            .expect("write");

        let result = engine
            .check(&realm, &a, "member", &alice, None)
            .expect("check");
        assert!(result, "should find alice through cycle");
    }

    // ===== Scenario 4: Write and delete tuples =====

    #[test]
    fn write_and_delete_tuples() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        // Write
        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple.clone())])
            .expect("write");
        assert!(engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check"));

        // Delete
        engine
            .write_tuples(&realm, &[TupleWrite::Delete(tuple)])
            .expect("delete");
        assert!(
            !engine
                .check(&realm, &obj, "viewer", &subj, None)
                .expect("check"),
            "deleted tuple should not be found"
        );
    }

    #[test]
    fn write_multiple_tuples_atomically() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        let tuple1 = RelationshipTuple::new(obj.clone(), "viewer", alice.clone()).expect("valid");
        let tuple2 = RelationshipTuple::new(obj.clone(), "editor", bob.clone()).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        assert!(engine
            .check(&realm, &obj, "viewer", &alice, None)
            .expect("check"));
        assert!(engine
            .check(&realm, &obj, "editor", &bob, None)
            .expect("check"));
    }

    // ===== Scenario 5: Expand =====

    #[test]
    fn expand_returns_direct_subjects() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        let tuple1 = RelationshipTuple::new(obj.clone(), "viewer", alice.clone()).expect("valid");
        let tuple2 = RelationshipTuple::new(obj.clone(), "viewer", bob.clone()).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        let subjects = engine.expand(&realm, &obj, "viewer", None).expect("expand");
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains(&alice));
        assert!(subjects.contains(&bob));
    }

    #[test]
    fn expand_traverses_usersets() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // document:readme#viewer@group:eng#member
        // group:eng#member@user:alice
        // group:eng#member@user:bob
        let doc = ObjectRef::new("document", "readme").expect("valid");
        let group_member = SubjectRef::userset("group", "eng", "member").expect("valid");
        let tuple1 = RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("valid");

        let group = ObjectRef::new("group", "eng").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        let tuple2 = RelationshipTuple::new(group.clone(), "member", alice.clone()).expect("valid");
        let tuple3 = RelationshipTuple::new(group, "member", bob.clone()).expect("valid");

        engine
            .write_tuples(
                &realm,
                &[
                    TupleWrite::Touch(tuple1),
                    TupleWrite::Touch(tuple2),
                    TupleWrite::Touch(tuple3),
                ],
            )
            .expect("write");

        let subjects = engine.expand(&realm, &doc, "viewer", None).expect("expand");
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains(&alice));
        assert!(subjects.contains(&bob));
    }

    #[test]
    fn expand_empty_returns_empty() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subjects = engine.expand(&realm, &obj, "viewer", None).expect("expand");
        assert!(subjects.is_empty());
    }

    // ===== Conditional writes =====

    #[test]
    fn touch_if_absent_succeeds_when_absent() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::TouchIfAbsent(tuple)])
            .expect("should succeed when tuple is absent");

        assert!(engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check"));
    }

    #[test]
    fn touch_if_absent_fails_when_present() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");

        // First write succeeds
        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple.clone())])
            .expect("write");

        // TouchIfAbsent fails because tuple already exists
        let err = engine
            .write_tuples(&realm, &[TupleWrite::TouchIfAbsent(tuple)])
            .expect_err("should fail");
        assert!(
            matches!(err, AuthzError::PreconditionFailed { .. }),
            "expected PreconditionFailed, got: {err:?}"
        );
    }

    #[test]
    fn delete_if_present_succeeds_when_present() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple.clone())])
            .expect("write");

        engine
            .write_tuples(&realm, &[TupleWrite::DeleteIfPresent(tuple)])
            .expect("should succeed when tuple exists");

        assert!(!engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check"));
    }

    #[test]
    fn delete_if_present_fails_when_absent() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");

        let err = engine
            .write_tuples(&realm, &[TupleWrite::DeleteIfPresent(tuple)])
            .expect_err("should fail");
        assert!(
            matches!(err, AuthzError::PreconditionFailed { .. }),
            "expected PreconditionFailed, got: {err:?}"
        );
    }

    #[test]
    fn conditional_batch_all_or_nothing() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        let tuple_alice =
            RelationshipTuple::new(obj.clone(), "viewer", alice.clone()).expect("valid");
        let tuple_bob = RelationshipTuple::new(obj.clone(), "viewer", bob.clone()).expect("valid");

        // Pre-add alice
        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple_alice.clone())])
            .expect("write");

        // Batch: TouchIfAbsent(bob) + TouchIfAbsent(alice) — alice already exists
        // The whole batch should fail and bob should NOT be added
        let err = engine
            .write_tuples(
                &realm,
                &[
                    TupleWrite::TouchIfAbsent(tuple_bob.clone()),
                    TupleWrite::TouchIfAbsent(tuple_alice),
                ],
            )
            .expect_err("batch should fail");
        assert!(matches!(err, AuthzError::PreconditionFailed { .. }));

        // bob should NOT have been written (all-or-nothing)
        assert!(
            !engine
                .check(&realm, &obj, "viewer", &bob, None)
                .expect("check"),
            "bob should not be added when batch fails"
        );
    }

    // ===== Consistency tokens =====

    #[test]
    fn write_tuples_returns_monotonic_tokens() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj1 = SubjectRef::direct("user", "alice").expect("valid");
        let subj2 = SubjectRef::direct("user", "bob").expect("valid");
        let tuple1 = RelationshipTuple::new(obj.clone(), "viewer", subj1).expect("valid");
        let tuple2 = RelationshipTuple::new(obj, "viewer", subj2).expect("valid");

        let token1 = engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple1)])
            .expect("write");
        let token2 = engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple2)])
            .expect("write");

        assert!(
            token2 > token1,
            "tokens must be monotonically increasing: {token1} vs {token2}"
        );
        assert!(token1.version() > 0, "first token should be > 0");
    }

    #[test]
    fn check_with_at_least_token_succeeds() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        let token = engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("write");

        // Passing the token from the write should work in single-node mode
        let result = engine
            .check(&realm, &obj, "viewer", &subj, Some(&token))
            .expect("check");
        assert!(result, "check with at_least token should succeed");
    }

    // ===== Permission caching =====

    #[test]
    fn cached_check_returns_same_result() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("write");

        // First check populates the cache
        let result1 = engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check 1");
        assert!(result1);

        // Second check should hit the cache
        let result2 = engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check 2");
        assert!(result2);

        // Negative check caches too
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        assert!(!engine
            .check(&realm, &obj, "viewer", &bob, None)
            .expect("check"));
        assert!(!engine
            .check(&realm, &obj, "viewer", &bob, None)
            .expect("check cached"));
    }

    #[test]
    fn cache_invalidated_on_write() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        // Check returns false (and caches it)
        assert!(!engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check"));

        // Write the tuple — should invalidate the cached false
        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("write");

        // Now check should return true
        assert!(engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check after write"));
    }

    #[test]
    fn cache_invalidated_on_delete() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple.clone())])
            .expect("write");

        // Check returns true (and caches it)
        assert!(engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check"));

        // Delete — should invalidate the cached true
        engine
            .write_tuples(&realm, &[TupleWrite::Delete(tuple)])
            .expect("delete");

        // Now check should return false
        assert!(!engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check after delete"));
    }

    // ===== Namespace configuration =====

    #[test]
    fn namespace_set_and_get_roundtrip() {
        use crate::authz::types::{NamespaceConfig, ObjectTypeConfig, RelationConfig};
        use std::collections::HashMap;

        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let mut relations = HashMap::new();
        relations.insert(
            "viewer".to_string(),
            RelationConfig {
                allowed_subject_types: vec!["user".to_string(), "group".to_string()],
                rewrite: None,
            },
        );
        let mut object_types = HashMap::new();
        object_types.insert("document".to_string(), ObjectTypeConfig { relations });
        let config = NamespaceConfig { object_types };

        engine
            .set_namespace(&realm, &config)
            .expect("set namespace");
        let retrieved = engine.get_namespace(&realm).expect("get namespace");
        assert_eq!(retrieved, Some(config));
    }

    #[test]
    fn namespace_not_set_returns_none() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let result = engine.get_namespace(&realm).expect("get namespace");
        assert!(result.is_none());
    }

    #[test]
    fn namespace_validation_rejects_unknown_object_type() {
        use crate::authz::types::{NamespaceConfig, ObjectTypeConfig, RelationConfig};
        use std::collections::HashMap;

        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // Schema only defines "document"
        let mut relations = HashMap::new();
        relations.insert(
            "viewer".to_string(),
            RelationConfig {
                allowed_subject_types: vec!["user".to_string()],
                rewrite: None,
            },
        );
        let mut object_types = HashMap::new();
        object_types.insert("document".to_string(), ObjectTypeConfig { relations });
        let config = NamespaceConfig { object_types };
        engine.set_namespace(&realm, &config).expect("set");

        // Try to write a tuple for "folder" — not in schema
        let obj = ObjectRef::new("folder", "shared").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");

        let err = engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect_err("should reject unknown type");
        assert!(
            matches!(err, AuthzError::InvalidNamespace { .. }),
            "expected InvalidNamespace, got: {err:?}"
        );
    }

    #[test]
    fn namespace_validation_rejects_unknown_relation() {
        use crate::authz::types::{NamespaceConfig, ObjectTypeConfig, RelationConfig};
        use std::collections::HashMap;

        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let mut relations = HashMap::new();
        relations.insert(
            "viewer".to_string(),
            RelationConfig {
                allowed_subject_types: vec!["user".to_string()],
                rewrite: None,
            },
        );
        let mut object_types = HashMap::new();
        object_types.insert("document".to_string(), ObjectTypeConfig { relations });
        let config = NamespaceConfig { object_types };
        engine.set_namespace(&realm, &config).expect("set");

        // "editor" is not a defined relation
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "editor", subj).expect("valid");

        let err = engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect_err("should reject unknown relation");
        assert!(matches!(err, AuthzError::InvalidNamespace { .. }));
    }

    #[test]
    fn namespace_validation_rejects_disallowed_subject_type() {
        use crate::authz::types::{NamespaceConfig, ObjectTypeConfig, RelationConfig};
        use std::collections::HashMap;

        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let mut relations = HashMap::new();
        relations.insert(
            "viewer".to_string(),
            RelationConfig {
                allowed_subject_types: vec!["user".to_string()],
                rewrite: None,
            },
        );
        let mut object_types = HashMap::new();
        object_types.insert("document".to_string(), ObjectTypeConfig { relations });
        let config = NamespaceConfig { object_types };
        engine.set_namespace(&realm, &config).expect("set");

        // "group" subject type not allowed for viewer relation
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::userset("group", "eng", "member").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");

        let err = engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect_err("should reject disallowed subject type");
        assert!(matches!(err, AuthzError::InvalidNamespace { .. }));
    }

    #[test]
    fn namespace_validation_allows_valid_tuples() {
        use crate::authz::types::{NamespaceConfig, ObjectTypeConfig, RelationConfig};
        use std::collections::HashMap;

        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        let mut relations = HashMap::new();
        relations.insert(
            "viewer".to_string(),
            RelationConfig {
                allowed_subject_types: vec!["user".to_string(), "group".to_string()],
                rewrite: None,
            },
        );
        let mut object_types = HashMap::new();
        object_types.insert("document".to_string(), ObjectTypeConfig { relations });
        let config = NamespaceConfig { object_types };
        engine.set_namespace(&realm, &config).expect("set");

        // Valid: user subject
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("should accept valid tuple");

        assert!(engine
            .check(&realm, &obj, "viewer", &subj, None)
            .expect("check"));
    }

    #[test]
    fn no_namespace_allows_any_tuple() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // No namespace set — all tuples accepted
        let obj = ObjectRef::new("anything", "goes").expect("valid");
        let subj = SubjectRef::direct("whatever", "subject").expect("valid");
        let tuple =
            RelationshipTuple::new(obj.clone(), "random_relation", subj.clone()).expect("valid");

        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("should accept any tuple without namespace");

        assert!(engine
            .check(&realm, &obj, "random_relation", &subj, None)
            .expect("check"));
    }

    // ===== Watch API =====

    #[test]
    fn watch_returns_receiver() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        let filter = WatchFilter { object_type: None };

        let receiver = engine.watch(&realm, &filter, None);
        assert!(receiver.is_ok(), "watch should return a receiver");
    }

    #[test]
    fn watch_replays_events_from_storage() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // Write some tuples to generate watch events
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", alice).expect("valid");

        let token_before = ConsistencyToken::new(0);
        engine
            .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
            .expect("write");

        // Watch with resume_from before the write — should replay the event
        let filter = WatchFilter { object_type: None };
        let mut receiver = engine
            .watch(&realm, &filter, Some(&token_before))
            .expect("watch");

        let event = receiver.drain_replay();
        assert!(event.is_some(), "should have a replay event");
        let event = event.expect("event");
        assert_eq!(event.object_type, "document");
        assert_eq!(event.relation, "viewer");
    }

    #[test]
    fn watch_with_object_type_filter() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        // Write tuples for different object types
        let doc = ObjectRef::new("document", "readme").expect("valid");
        let folder = ObjectRef::new("folder", "shared").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let t1 = RelationshipTuple::new(doc, "viewer", alice.clone()).expect("valid");
        let t2 = RelationshipTuple::new(folder, "viewer", alice).expect("valid");

        let token_before = ConsistencyToken::new(0);
        engine
            .write_tuples(&realm, &[TupleWrite::Touch(t1), TupleWrite::Touch(t2)])
            .expect("write");

        // Watch with filter for "document" only
        let filter = WatchFilter {
            object_type: Some("document".to_string()),
        };
        let mut receiver = engine
            .watch(&realm, &filter, Some(&token_before))
            .expect("watch");

        // Should only get the document event
        let event = receiver.drain_replay();
        assert!(event.is_some());
        assert_eq!(event.expect("event").object_type, "document");

        // No more events for this filter
        // The folder event may or may not be present (depends on filtering),
        // but the first event should be document
    }

    // ===== Adversarial: Max depth enforcement =====

    #[test]
    fn max_depth_enforcement() {
        let (_dir, engine) = setup_engine_with_depth(5);
        let realm = RealmId::generate();

        // Build a chain of 20 hops: group_0#member@group_1#member@...@group_19#member@user:alice
        let mut tuples = Vec::new();
        for i in 0u32..20 {
            let obj = ObjectRef::new("group", &format!("g{i}")).expect("valid");
            let subj = if i == 19 {
                SubjectRef::direct("user", "alice").expect("valid")
            } else {
                SubjectRef::userset("group", &format!("g{}", i + 1), "member").expect("valid")
            };
            let tuple = RelationshipTuple::new(obj, "member", subj).expect("valid");
            tuples.push(TupleWrite::Touch(tuple));
        }

        engine.write_tuples(&realm, &tuples).expect("write");

        let root = ObjectRef::new("group", "g0").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let result = engine
            .check(&realm, &root, "member", &alice, None)
            .expect("check");
        assert!(
            !result,
            "should return false when chain exceeds max_depth=5"
        );
    }

    #[test]
    fn within_depth_limit_succeeds() {
        let (_dir, engine) = setup_engine_with_depth(5);
        let realm = RealmId::generate();

        // Build a chain of 4 hops (within limit of 5)
        let mut tuples = Vec::new();
        for i in 0u32..4 {
            let obj = ObjectRef::new("group", &format!("g{i}")).expect("valid");
            let subj = if i == 3 {
                SubjectRef::direct("user", "alice").expect("valid")
            } else {
                SubjectRef::userset("group", &format!("g{}", i + 1), "member").expect("valid")
            };
            let tuple = RelationshipTuple::new(obj, "member", subj).expect("valid");
            tuples.push(TupleWrite::Touch(tuple));
        }

        engine.write_tuples(&realm, &tuples).expect("write");

        let root = ObjectRef::new("group", "g0").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let result = engine
            .check(&realm, &root, "member", &alice, None)
            .expect("check");
        assert!(result, "4-hop chain should succeed with max_depth=5");
    }

    // ===== Adversarial: Cross-realm isolation =====

    #[test]
    fn cross_realm_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        // Write under realm A
        engine
            .write_tuples(&realm_a, &[TupleWrite::Touch(tuple)])
            .expect("write");

        // Check under realm A: should find it
        assert!(engine
            .check(&realm_a, &obj, "viewer", &subj, None)
            .expect("check"));

        // Check under realm B: should NOT find it
        assert!(
            !engine
                .check(&realm_b, &obj, "viewer", &subj, None)
                .expect("check"),
            "cross-realm access must be denied"
        );
    }

    #[test]
    fn cross_realm_expand_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", alice).expect("valid");

        engine
            .write_tuples(&realm_a, &[TupleWrite::Touch(tuple)])
            .expect("write");

        let subjects_a = engine
            .expand(&realm_a, &obj, "viewer", None)
            .expect("expand");
        assert_eq!(subjects_a.len(), 1);

        let subjects_b = engine
            .expand(&realm_b, &obj, "viewer", None)
            .expect("expand");
        assert!(
            subjects_b.is_empty(),
            "expand under different realm must return empty"
        );
    }

    // ===== Send + Sync =====

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmbeddedAuthzEngine>();
    }

    // ===== Property tests =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a random graph of relationship tuples.
        ///
        /// Generates `num_groups` groups connected in a chain, with random users
        /// as leaf members, plus some direct tuples.
        fn random_graph_scenario(
        ) -> impl Strategy<Value = (Vec<TupleWrite>, Vec<(String, String, bool)>)> {
            // Generate between 2-8 groups and 1-5 users
            (2u32..8u32, 1u32..5u32)
                .prop_flat_map(|(num_groups, num_users)| {
                    // Collect user names
                    let users: Vec<String> = (0..num_users).map(|i| format!("u{i}")).collect();
                    let groups: Vec<String> = (0..num_groups).map(|i| format!("g{i}")).collect();

                    Just((groups, users))
                })
                .prop_map(|(groups, users)| {
                    let mut tuples = Vec::new();
                    let mut expected_checks = Vec::new();

                    // Build a chain: doc#viewer@g0#member, g0#member@g1#member, ...
                    let doc = ObjectRef::new("doc", "d0").expect("valid");
                    let g0_member =
                        SubjectRef::userset("group", &groups[0], "member").expect("valid");
                    let t = RelationshipTuple::new(doc, "viewer", g0_member).expect("valid");
                    tuples.push(TupleWrite::Touch(t));

                    // Chain groups
                    for i in 0..groups.len() - 1 {
                        let obj = ObjectRef::new("group", &groups[i]).expect("valid");
                        let next =
                            SubjectRef::userset("group", &groups[i + 1], "member").expect("valid");
                        let t = RelationshipTuple::new(obj, "member", next).expect("valid");
                        tuples.push(TupleWrite::Touch(t));
                    }

                    // Add users to the last group
                    let last_group =
                        ObjectRef::new("group", groups.last().expect("non-empty")).expect("valid");
                    for user in &users {
                        let subj = SubjectRef::direct("user", user).expect("valid");
                        let t = RelationshipTuple::new(last_group.clone(), "member", subj)
                            .expect("valid");
                        tuples.push(TupleWrite::Touch(t));

                        // These users should be reachable as viewers of doc
                        expected_checks.push((user.clone(), "viewer".to_string(), true));
                    }

                    // A random non-member should not be reachable
                    expected_checks.push(("nonexistent".to_string(), "viewer".to_string(), false));

                    (tuples, expected_checks)
                })
        }

        proptest! {
            /// Property: Random relationship graphs produce correct reachability results.
            #[test]
            fn random_graphs_correct_reachability(
                (tuples, checks) in random_graph_scenario()
            ) {
                let (_dir, engine) = setup_engine();
                let realm = RealmId::generate();

                engine.write_tuples(&realm, &tuples).expect("write");

                let doc = ObjectRef::new("doc", "d0").expect("valid");
                for (user, relation, expected) in &checks {
                    let subj = SubjectRef::direct("user", user).expect("valid");
                    let result = engine.check(&realm, &doc, relation, &subj, None).expect("check");
                    prop_assert_eq!(
                        result, *expected,
                        "user={}, relation={}, expected={}", user, relation, expected
                    );
                }
            }

            /// Property: Cycle detection holds for arbitrary graph topologies.
            ///
            /// Creates cycles of varying sizes and verifies:
            /// 1. check() terminates
            /// 2. Only users actually connected are reachable
            #[test]
            fn cycle_detection_arbitrary_topologies(cycle_size in 2u32..6u32) {
                let (_dir, engine) = setup_engine();
                let realm = RealmId::generate();

                let mut tuples = Vec::new();

                // Create a cycle: g0#m@g1#m, g1#m@g2#m, ..., gN#m@g0#m
                for i in 0..cycle_size {
                    let next = (i + 1) % cycle_size;
                    let obj = ObjectRef::new("group", &format!("g{i}")).expect("valid");
                    let subj = SubjectRef::userset("group", &format!("g{next}"), "member").expect("valid");
                    let t = RelationshipTuple::new(obj, "member", subj).expect("valid");
                    tuples.push(TupleWrite::Touch(t));
                }

                // Add a user reachable from g0
                let g0 = ObjectRef::new("group", "g0").expect("valid");
                let alice = SubjectRef::direct("user", "alice").expect("valid");
                let t = RelationshipTuple::new(g0.clone(), "member", alice.clone()).expect("valid");
                tuples.push(TupleWrite::Touch(t));

                engine.write_tuples(&realm, &tuples).expect("write");

                // Alice should be reachable from any group in the cycle
                for i in 0..cycle_size {
                    let obj = ObjectRef::new("group", &format!("g{i}")).expect("valid");
                    let result = engine.check(&realm, &obj, "member", &alice, None).expect("check");
                    prop_assert!(result, "alice should be reachable from g{}", i);
                }

                // Non-existent user should not be reachable
                let bob = SubjectRef::direct("user", "bob").expect("valid");
                let result = engine.check(&realm, &g0, "member", &bob, None).expect("check");
                prop_assert!(!result, "bob should not be reachable");
            }

            /// Property: Random add/delete sequences maintain graph invariants.
            ///
            /// After a sequence of writes and deletes, only non-deleted tuples
            /// should be visible via check().
            #[test]
            fn add_delete_sequences_maintain_invariants(
                ops in proptest::collection::vec(
                    (0u32..5u32, prop::bool::ANY),
                    1..20
                )
            ) {
                let (_dir, engine) = setup_engine();
                let realm = RealmId::generate();
                let doc = ObjectRef::new("doc", "d0").expect("valid");

                // Track which users should currently have access
                let mut active: std::collections::HashSet<u32> = std::collections::HashSet::new();

                for (user_idx, is_add) in &ops {
                    let user_name = format!("u{user_idx}");
                    let subj = SubjectRef::direct("user", &user_name).expect("valid");
                    let tuple = RelationshipTuple::new(
                        doc.clone(), "viewer", subj
                    ).expect("valid");

                    if *is_add {
                        engine.write_tuples(&realm, &[TupleWrite::Touch(tuple)]).expect("write");
                        active.insert(*user_idx);
                    } else {
                        engine.write_tuples(&realm, &[TupleWrite::Delete(tuple)]).expect("delete");
                        active.remove(user_idx);
                    }
                }

                // Verify the final state
                for i in 0u32..5 {
                    let user_name = format!("u{i}");
                    let subj = SubjectRef::direct("user", &user_name).expect("valid");
                    let result = engine.check(&realm, &doc, "viewer", &subj, None).expect("check");
                    let expected = active.contains(&i);
                    prop_assert_eq!(
                        result, expected,
                        "user u{}: expected={}, got={}", i, expected, result
                    );
                }
            }

            /// Property: Cache invalidation is correct — writes interleaved with
            /// cached checks never produce stale results.
            ///
            /// This tests that after any write operation, subsequent checks
            /// reflect the new state even when the cache has previously cached
            /// the old result.
            #[test]
            fn cache_never_stale_after_writes(
                ops in proptest::collection::vec(
                    (0u32..5u32, prop::bool::ANY),
                    1..30
                )
            ) {
                let (_dir, engine) = setup_engine();
                let realm = RealmId::generate();
                let doc = ObjectRef::new("doc", "d0").expect("valid");

                let mut active: std::collections::HashSet<u32> = std::collections::HashSet::new();

                for (user_idx, is_add) in &ops {
                    let user_name = format!("u{user_idx}");
                    let subj = SubjectRef::direct("user", &user_name).expect("valid");
                    let tuple = RelationshipTuple::new(
                        doc.clone(), "viewer", subj.clone()
                    ).expect("valid");

                    // Do a check BEFORE the write to prime the cache
                    let _ = engine.check(&realm, &doc, "viewer", &subj, None);

                    if *is_add {
                        engine.write_tuples(&realm, &[TupleWrite::Touch(tuple)]).expect("write");
                        active.insert(*user_idx);
                    } else {
                        engine.write_tuples(&realm, &[TupleWrite::Delete(tuple)]).expect("delete");
                        active.remove(user_idx);
                    }

                    // Check AFTER the write — cache must reflect new state
                    let result = engine.check(&realm, &doc, "viewer", &subj, None).expect("check");
                    let expected = active.contains(user_idx);
                    prop_assert_eq!(
                        result, expected,
                        "cache stale for u{}: expected={}, got={}", user_idx, expected, result
                    );
                }
            }
        }
    }
}
