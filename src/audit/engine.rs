//! Embedded audit engine implementation.
//!
//! Stores audit events in the storage engine with hash chain integrity.
//! Events are append-only: no update or delete operations exist.

use std::sync::Arc;

use ring::digest;

use crate::core::{AuditEventId, Clock, TenantId, Timestamp};
use crate::storage::StorageEngine;

use super::error::AuditError;
use super::keys;
use super::types::{AuditAction, AuditEvent, AuditQuery, CreateAuditEvent};
use super::AuditEngine;

/// The genesis hash used as the "previous hash" for the first event in a tenant.
const GENESIS_HASH: &str = "genesis";

/// Embedded audit engine backed by the storage layer.
///
/// Thread-safe via the underlying `StorageEngine`.
pub struct EmbeddedAuditEngine {
    /// Storage backend.
    storage: Arc<dyn StorageEngine>,
    /// Clock for timestamps.
    clock: Arc<dyn Clock>,
}

impl EmbeddedAuditEngine {
    /// Creates a new audit engine.
    pub fn new(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> Self {
        Self { storage, clock }
    }

    /// Computes the SHA-256 integrity hash for an event.
    ///
    /// `Hash = SHA-256(prev_hash || event_data_json)`
    /// where `event_data_json` is the event serialized without the `integrity_hash` field.
    fn compute_hash(prev_hash: &str, event: &AuditEvent) -> String {
        // Serialize the event without the integrity_hash for hashing
        let hashable = serde_json::json!({
            "id": event.id,
            "tenant_id": event.tenant_id,
            "actor": event.actor,
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "timestamp": event.timestamp,
            "metadata": event.metadata,
        });

        let event_bytes = hashable.to_string();
        let mut data = Vec::with_capacity(prev_hash.len() + event_bytes.len());
        data.extend_from_slice(prev_hash.as_bytes());
        data.extend_from_slice(event_bytes.as_bytes());

        let hash = digest::digest(&digest::SHA256, &data);
        hex_encode(hash.as_ref())
    }

    /// Gets the last event's integrity hash for a tenant, or `GENESIS_HASH` if none.
    fn get_last_hash(&self, tenant_id: &TenantId) -> Result<String, AuditError> {
        let prefix = keys::event_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self.storage.scan(tenant_id, &prefix, &end)?;

        if let Some(last_entry) = entries.last() {
            let event: AuditEvent = serde_json::from_slice(&last_entry.value).map_err(|e| {
                AuditError::Serialization {
                    reason: e.to_string(),
                }
            })?;
            Ok(event.integrity_hash)
        } else {
            Ok(GENESIS_HASH.to_string())
        }
    }
}

impl AuditEngine for EmbeddedAuditEngine {
    fn append(&self, request: &CreateAuditEvent) -> Result<AuditEvent, AuditError> {
        let event_id = AuditEventId::generate();
        let timestamp = self.clock.now();
        let prev_hash = self.get_last_hash(&request.tenant_id)?;

        // Build the event (integrity_hash will be filled after computation)
        let mut event = AuditEvent {
            id: event_id,
            tenant_id: request.tenant_id.clone(),
            actor: request.actor.clone(),
            action: request.action.clone(),
            resource_type: request.resource_type.clone(),
            resource_id: request.resource_id.clone(),
            timestamp,
            metadata: request.metadata.clone(),
            integrity_hash: String::new(),
        };

        // Compute and set integrity hash
        event.integrity_hash = Self::compute_hash(&prev_hash, &event);

        // Serialize the complete event
        let value = serde_json::to_vec(&event).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;

        // Store event primary key
        let primary_key = keys::encode_event_key(timestamp, &event.id);
        self.storage.put(&request.tenant_id, &primary_key, &value)?;

        // Store actor index (value = primary key for lookups)
        let actor_key = keys::encode_actor_index(&request.actor, timestamp, &event.id);
        self.storage
            .put(&request.tenant_id, &actor_key, &primary_key)?;

        // Store action index (value = primary key for lookups)
        let action_key = keys::encode_action_index(request.action.as_str(), timestamp, &event.id);
        self.storage
            .put(&request.tenant_id, &action_key, &primary_key)?;

        Ok(event)
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError> {
        // Determine if we're scanning by actor, action, or just time range
        if let Some(ref actor) = query.actor {
            return self.query_by_actor(query, actor);
        }
        if let Some(ref action) = query.action {
            return self.query_by_action(query, action);
        }

        // Default: scan primary event keys by time range
        let start = match query.start_time {
            Some(ts) => keys::event_scan_start(ts),
            None => keys::event_scan_prefix(),
        };
        let end = match query.end_time {
            Some(ts) => keys::event_scan_end(ts),
            None => keys::prefix_end(&keys::event_scan_prefix()),
        };

        let entries = self.storage.scan(&query.tenant_id, &start, &end)?;
        let mut events = Vec::new();

        for entry in entries {
            let event: AuditEvent =
                serde_json::from_slice(&entry.value).map_err(|e| AuditError::Serialization {
                    reason: e.to_string(),
                })?;
            events.push(event);

            if let Some(limit) = query.limit {
                if events.len() >= limit {
                    break;
                }
            }
        }

        Ok(events)
    }

    fn verify_integrity(
        &self,
        tenant_id: &TenantId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, AuditError> {
        let scan_start = match start {
            Some(ts) => keys::event_scan_start(ts),
            None => keys::event_scan_prefix(),
        };
        let scan_end = match end {
            Some(ts) => keys::event_scan_end(ts),
            None => keys::prefix_end(&keys::event_scan_prefix()),
        };

        let entries = self.storage.scan(tenant_id, &scan_start, &scan_end)?;

        // If verifying from the beginning, use genesis hash; otherwise get
        // the hash of the event immediately before the start
        let mut prev_hash = if start.is_none() {
            GENESIS_HASH.to_string()
        } else {
            // Need to find the event before start to get its hash
            let all_start = keys::event_scan_prefix();
            let all_entries = self.storage.scan(tenant_id, &all_start, &scan_start)?;
            if let Some(last) = all_entries.last() {
                let event: AuditEvent =
                    serde_json::from_slice(&last.value).map_err(|e| AuditError::Serialization {
                        reason: e.to_string(),
                    })?;
                event.integrity_hash
            } else {
                GENESIS_HASH.to_string()
            }
        };

        for entry in entries {
            let event: AuditEvent =
                serde_json::from_slice(&entry.value).map_err(|e| AuditError::Serialization {
                    reason: e.to_string(),
                })?;

            let expected_hash = Self::compute_hash(&prev_hash, &event);
            if event.integrity_hash != expected_hash {
                return Ok(false);
            }
            prev_hash = event.integrity_hash;
        }

        Ok(true)
    }
}

impl EmbeddedAuditEngine {
    /// Queries events by actor using the actor index.
    fn query_by_actor(
        &self,
        query: &AuditQuery,
        actor: &str,
    ) -> Result<Vec<AuditEvent>, AuditError> {
        let prefix = keys::actor_scan_prefix(actor);
        let end = keys::prefix_end(&prefix);
        let index_entries = self.storage.scan(&query.tenant_id, &prefix, &end)?;

        let mut events = Vec::new();
        for index_entry in index_entries {
            // The index value is the primary event key
            let event_value = self.storage.get(&query.tenant_id, &index_entry.value)?;

            if let Some(value) = event_value {
                let event: AuditEvent =
                    serde_json::from_slice(&value).map_err(|e| AuditError::Serialization {
                        reason: e.to_string(),
                    })?;

                // Apply time range filter
                if let Some(start) = query.start_time {
                    if event.timestamp < start {
                        continue;
                    }
                }
                if let Some(end_time) = query.end_time {
                    if event.timestamp >= end_time {
                        continue;
                    }
                }

                events.push(event);

                if let Some(limit) = query.limit {
                    if events.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(events)
    }

    /// Queries events by action type using the action index.
    fn query_by_action(
        &self,
        query: &AuditQuery,
        action: &AuditAction,
    ) -> Result<Vec<AuditEvent>, AuditError> {
        let prefix = keys::action_scan_prefix(action.as_str());
        let end = keys::prefix_end(&prefix);
        let index_entries = self.storage.scan(&query.tenant_id, &prefix, &end)?;

        let mut events = Vec::new();
        for index_entry in index_entries {
            let event_value = self.storage.get(&query.tenant_id, &index_entry.value)?;

            if let Some(value) = event_value {
                let event: AuditEvent =
                    serde_json::from_slice(&value).map_err(|e| AuditError::Serialization {
                        reason: e.to_string(),
                    })?;

                // Apply time range filter
                if let Some(start) = query.start_time {
                    if event.timestamp < start {
                        continue;
                    }
                }
                if let Some(end_time) = query.end_time {
                    if event.timestamp >= end_time {
                        continue;
                    }
                }

                events.push(event);

                if let Some(limit) = query.limit {
                    if events.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(events)
    }
}

/// Encodes bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, TenantId, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};
    use std::sync::Arc;

    fn setup() -> (EmbeddedAuditEngine, TenantId) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

        let engine =
            EmbeddedAuditEngine::new(storage as Arc<dyn StorageEngine>, clock as Arc<dyn Clock>);
        let tenant_id = TenantId::generate();
        (engine, tenant_id)
    }

    fn setup_with_clock() -> (EmbeddedAuditEngine, TenantId, Arc<FakeClock>) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

        let engine = EmbeddedAuditEngine::new(
            storage as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let tenant_id = TenantId::generate();
        (engine, tenant_id, clock)
    }

    // === Scenario: Security-critical mutations emit structured audit events ===

    #[test]
    fn append_event_returns_correct_fields() {
        let (engine, tenant_id) = setup();

        let request = CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "user_abc".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_xyz".to_string(),
            metadata: Some(serde_json::json!({"ip": "10.0.0.1"})),
        };

        let event = engine.append(&request).expect("append");

        // Verify all required fields are present and correct
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.actor, "user_abc");
        assert_eq!(event.action, AuditAction::UserCreated);
        assert_eq!(event.resource_type, "user");
        assert_eq!(event.resource_id, "user_xyz");
        assert_eq!(event.timestamp, Timestamp::from_micros(1_000_000));
        assert!(event.metadata.is_some(), "metadata should be preserved");
        assert!(
            !event.integrity_hash.is_empty(),
            "integrity hash must be set"
        );
        // ID should be non-nil
        assert_ne!(*event.id.as_uuid(), uuid::Uuid::nil());
    }

    #[test]
    fn append_multiple_events_returns_ordered_by_time() {
        let (engine, tenant_id, clock) = setup_with_clock();

        let r1 = CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "user_a".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "u1".to_string(),
            metadata: None,
        };
        let e1 = engine.append(&r1).expect("append 1");

        clock.advance(1_000_000); // +1 second

        let r2 = CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "user_b".to_string(),
            action: AuditAction::SessionCreated,
            resource_type: "session".to_string(),
            resource_id: "s1".to_string(),
            metadata: None,
        };
        let e2 = engine.append(&r2).expect("append 2");

        assert!(e2.timestamp > e1.timestamp, "second event should be later");
    }

    // === Scenario: Append-only — no update or delete API ===
    // This is enforced at the type level: AuditEngine trait has no
    // update/delete methods. The test verifies that appended events
    // persist and cannot be removed through the engine's API.

    #[test]
    fn events_are_persistent_and_immutable() {
        let (engine, tenant_id) = setup();

        let request = CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "admin".to_string(),
            action: AuditAction::TenantCreated,
            resource_type: "tenant".to_string(),
            resource_id: "t1".to_string(),
            metadata: None,
        };
        let event = engine.append(&request).expect("append");

        // Query back — the event should still be there
        let query = AuditQuery {
            tenant_id: tenant_id.clone(),
            ..AuditQuery::for_tenant(tenant_id.clone())
        };
        let events = engine.query(&query).expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    // === Scenario: Query by time range, actor, action type ===

    #[test]
    fn query_by_time_range() {
        let (engine, tenant_id, clock) = setup_with_clock();

        // Event at t=1s
        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "a".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(2_000_000); // t=3s

        // Event at t=3s
        let e2 = engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "b".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(2_000_000); // t=5s

        // Event at t=5s
        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "c".to_string(),
                action: AuditAction::TokenIssued,
                resource_type: "token".to_string(),
                resource_id: "t1".to_string(),
                metadata: None,
            })
            .expect("append");

        // Query: events between t=2s and t=4s (should only get e2)
        let query = AuditQuery {
            tenant_id: tenant_id.clone(),
            start_time: Some(Timestamp::from_micros(2_000_000)),
            end_time: Some(Timestamp::from_micros(4_000_000)),
            ..AuditQuery::for_tenant(tenant_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, e2.id);
    }

    #[test]
    fn query_by_actor() {
        let (engine, tenant_id, clock) = setup_with_clock();

        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "alice".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "bob".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u2".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "alice".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append");

        // Query for alice only
        let query = AuditQuery {
            tenant_id: tenant_id.clone(),
            actor: Some("alice".to_string()),
            ..AuditQuery::for_tenant(tenant_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.actor == "alice"));
    }

    #[test]
    fn query_by_action_type() {
        let (engine, tenant_id, clock) = setup_with_clock();

        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "a".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "b".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append");

        clock.advance(1_000_000);

        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "c".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u2".to_string(),
                metadata: None,
            })
            .expect("append");

        // Query for UserCreated only
        let query = AuditQuery {
            tenant_id: tenant_id.clone(),
            action: Some(AuditAction::UserCreated),
            ..AuditQuery::for_tenant(tenant_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.action == AuditAction::UserCreated));
    }

    #[test]
    fn query_with_limit() {
        let (engine, tenant_id, clock) = setup_with_clock();

        for i in 0..5 {
            engine
                .append(&CreateAuditEvent {
                    tenant_id: tenant_id.clone(),
                    actor: "a".to_string(),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        let query = AuditQuery {
            tenant_id: tenant_id.clone(),
            limit: Some(3),
            ..AuditQuery::for_tenant(tenant_id.clone())
        };
        let results = engine.query(&query).expect("query");
        assert_eq!(results.len(), 3);
    }

    // === Scenario: Tenant-scoped events ===

    #[test]
    fn events_scoped_to_tenant() {
        let (engine, tenant_a) = setup();
        let tenant_b = TenantId::generate();

        // Append to tenant A
        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_a.clone(),
                actor: "a".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append to A");

        // Append to tenant B
        engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_b.clone(),
                actor: "b".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append to B");

        // Query tenant A — should only see tenant A's event
        let results_a = engine
            .query(&AuditQuery::for_tenant(tenant_a.clone()))
            .expect("query A");
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0].tenant_id, tenant_a);
        assert_eq!(results_a[0].actor, "a");

        // Query tenant B — should only see tenant B's event
        let results_b = engine
            .query(&AuditQuery::for_tenant(tenant_b.clone()))
            .expect("query B");
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0].tenant_id, tenant_b);
        assert_eq!(results_b[0].actor, "b");
    }

    // === Integrity hash chain ===

    #[test]
    fn integrity_hash_chain_is_valid() {
        let (engine, tenant_id, clock) = setup_with_clock();

        for i in 0..5 {
            engine
                .append(&CreateAuditEvent {
                    tenant_id: tenant_id.clone(),
                    actor: format!("actor_{i}"),
                    action: AuditAction::UserCreated,
                    resource_type: "user".to_string(),
                    resource_id: format!("u{i}"),
                    metadata: None,
                })
                .expect("append");
            clock.advance(1_000_000);
        }

        let valid = engine
            .verify_integrity(&tenant_id, None, None)
            .expect("verify");
        assert!(valid, "hash chain should be valid");
    }

    #[test]
    fn different_events_produce_different_hashes() {
        let (engine, tenant_id, clock) = setup_with_clock();

        let e1 = engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "alice".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append 1");

        clock.advance(1_000_000);

        let e2 = engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "bob".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: "s1".to_string(),
                metadata: None,
            })
            .expect("append 2");

        assert_ne!(
            e1.integrity_hash, e2.integrity_hash,
            "different events should have different hashes"
        );
    }

    #[test]
    fn genesis_hash_for_empty_tenant() {
        let (engine, tenant_id) = setup();

        // First event should chain from genesis
        let event = engine
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "a".to_string(),
                action: AuditAction::TenantCreated,
                resource_type: "tenant".to_string(),
                resource_id: "t1".to_string(),
                metadata: None,
            })
            .expect("append");

        // Verify the hash was computed using genesis
        assert!(!event.integrity_hash.is_empty());
        // Integrity check should pass
        let valid = engine
            .verify_integrity(&tenant_id, None, None)
            .expect("verify");
        assert!(valid);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::core::{Clock, FakeClock, TenantId, Timestamp};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use proptest::prelude::*;
    use std::sync::Arc;

    /// Strategy for generating a random `AuditAction`.
    fn arb_action() -> impl Strategy<Value = AuditAction> {
        prop_oneof![
            Just(AuditAction::UserCreated),
            Just(AuditAction::UserUpdated),
            Just(AuditAction::UserDeleted),
            Just(AuditAction::CredentialSet),
            Just(AuditAction::CredentialChanged),
            Just(AuditAction::CredentialVerified),
            Just(AuditAction::SessionCreated),
            Just(AuditAction::SessionRevoked),
            Just(AuditAction::TokenIssued),
            Just(AuditAction::TokenRefreshed),
            Just(AuditAction::TenantCreated),
            Just(AuditAction::TenantUpdated),
            Just(AuditAction::TenantDeleted),
            Just(AuditAction::ClientRegistered),
            Just(AuditAction::AuthorizationCodeIssued),
            Just(AuditAction::AuthorizationCodeExchanged),
            Just(AuditAction::TupleWritten),
            Just(AuditAction::TupleDeleted),
        ]
    }

    /// Strategy for a random audit event request.
    #[allow(dead_code)]
    fn arb_create_event(tenant_id: TenantId) -> impl Strategy<Value = CreateAuditEvent> {
        (
            "[a-z]{3,8}", // actor
            arb_action(),
            "[a-z]{3,8}",      // resource_type
            "[a-z0-9_]{3,12}", // resource_id
        )
            .prop_map(move |(actor, action, resource_type, resource_id)| {
                CreateAuditEvent {
                    tenant_id: tenant_id.clone(),
                    actor,
                    action,
                    resource_type,
                    resource_id,
                    metadata: None,
                }
            })
    }

    // Property: event count equals mutation count
    proptest! {
        #[test]
        fn event_count_matches_mutation_count(
            count in 1_usize..50,
        ) {
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let config = StorageConfig::dev(temp_dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let engine = EmbeddedAuditEngine::new(
                storage as Arc<dyn StorageEngine>,
                Arc::clone(&clock) as Arc<dyn Clock>,
            );
            let tenant_id = TenantId::generate();

            for i in 0..count {
                engine
                    .append(&CreateAuditEvent {
                        tenant_id: tenant_id.clone(),
                        actor: format!("actor_{i}"),
                        action: AuditAction::UserCreated,
                        resource_type: "user".to_string(),
                        resource_id: format!("u{i}"),
                        metadata: None,
                    })
                    .expect("append");
                clock.advance(1_000_000);
            }

            let events = engine
                .query(&AuditQuery::for_tenant(tenant_id))
                .expect("query");
            prop_assert_eq!(events.len(), count);
        }
    }

    // Property: events are strictly ordered by timestamp
    proptest! {
        #[test]
        fn events_strictly_ordered_by_timestamp(
            actions in prop::collection::vec(arb_action(), 2..30),
        ) {
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let config = StorageConfig::dev(temp_dir.path().to_path_buf());
            let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
            let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
            let engine = EmbeddedAuditEngine::new(
                storage as Arc<dyn StorageEngine>,
                Arc::clone(&clock) as Arc<dyn Clock>,
            );
            let tenant_id = TenantId::generate();

            for (i, action) in actions.iter().enumerate() {
                engine
                    .append(&CreateAuditEvent {
                        tenant_id: tenant_id.clone(),
                        actor: format!("actor_{i}"),
                        action: action.clone(),
                        resource_type: "resource".to_string(),
                        resource_id: format!("r{i}"),
                        metadata: None,
                    })
                    .expect("append");
                // Advance clock between events to ensure distinct timestamps
                clock.advance(1_000);
            }

            let events = engine
                .query(&AuditQuery::for_tenant(tenant_id))
                .expect("query");

            // Verify strict ordering
            for i in 1..events.len() {
                prop_assert!(
                    events[i].timestamp > events[i - 1].timestamp,
                    "event {} ({:?}) should have timestamp > event {} ({:?})",
                    i, events[i].timestamp,
                    i - 1, events[i - 1].timestamp,
                );
            }
        }
    }
}
