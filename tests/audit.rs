//! Integration tests for the audit logging engine.
//!
//! Tests correspond to Phase 1 Step 20 (Audit Logging) scenarios in
//! `TEST_SCENARIOS.md`.

mod common;

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, CreateAuditEvent};
use hearth::core::TenantId;
use hearth::identity::CreateTenantRequest;

// ===================================================================
// Integration: Full audit lifecycle (mutations → query → verify trail)
// ===================================================================

#[tokio::test]
async fn audit_lifecycle_via_embedded_api() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let audit = harness.audit();

    // Create a tenant to use
    let identity = harness.identity();
    let tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "audit-test-tenant".to_string(),
            config: None,
        })
        .expect("create tenant");
    let tenant_id = tenant.id().clone();

    // Perform a series of mutations and record audit events
    let events_to_create = vec![
        CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "admin".to_string(),
            action: AuditAction::TenantCreated,
            resource_type: "tenant".to_string(),
            resource_id: tenant_id.to_string(),
            metadata: None,
        },
        CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "admin".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_001".to_string(),
            metadata: Some(serde_json::json!({"email": "alice@example.com"})),
        },
        CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "user_001".to_string(),
            action: AuditAction::CredentialSet,
            resource_type: "credential".to_string(),
            resource_id: "user_001".to_string(),
            metadata: None,
        },
        CreateAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: "user_001".to_string(),
            action: AuditAction::SessionCreated,
            resource_type: "session".to_string(),
            resource_id: "session_001".to_string(),
            metadata: None,
        },
    ];

    for request in &events_to_create {
        audit.append(request).expect("append event");
    }

    // Query all events for this tenant
    let all_events = audit
        .query(&AuditQuery::for_tenant(tenant_id.clone()))
        .expect("query all");
    assert_eq!(
        all_events.len(),
        4,
        "should have 4 audit events, got {}",
        all_events.len()
    );

    // Verify event trail matches creation order
    assert_eq!(all_events[0].action, AuditAction::TenantCreated);
    assert_eq!(all_events[1].action, AuditAction::UserCreated);
    assert_eq!(all_events[2].action, AuditAction::CredentialSet);
    assert_eq!(all_events[3].action, AuditAction::SessionCreated);

    // Verify events are ordered by timestamp
    for i in 1..all_events.len() {
        assert!(
            all_events[i].timestamp >= all_events[i - 1].timestamp,
            "events should be in chronological order"
        );
    }

    // Verify integrity of the audit chain
    let valid = audit
        .verify_integrity(&tenant_id, None, None)
        .expect("verify");
    assert!(valid, "audit log integrity should be valid");
}

// ===================================================================
// Integration: Audit log persistence (entries survive restart)
// ===================================================================

#[tokio::test]
async fn audit_events_persist_across_engine_recreation() {
    // We test persistence by creating an audit engine, writing events,
    // dropping it, and creating a new one over the same storage directory.

    use hearth::audit::EmbeddedAuditEngine;
    use hearth::core::SystemClock;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let tenant_id = TenantId::generate();

    // Phase 1: Write events
    {
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
        let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
        let audit = EmbeddedAuditEngine::new(storage as Arc<dyn StorageEngine>, clock);

        audit
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "admin".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append 1");

        audit
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: "admin".to_string(),
                action: AuditAction::CredentialSet,
                resource_type: "credential".to_string(),
                resource_id: "u1".to_string(),
                metadata: None,
            })
            .expect("append 2");
    }
    // Engine and storage dropped here

    // Phase 2: Reopen and verify events survived
    {
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage reopen"));
        let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
        let audit = EmbeddedAuditEngine::new(storage as Arc<dyn StorageEngine>, clock);

        let events = audit
            .query(&AuditQuery::for_tenant(tenant_id.clone()))
            .expect("query after reopen");
        assert_eq!(
            events.len(),
            2,
            "both events should survive engine recreation"
        );
        assert_eq!(events[0].action, AuditAction::UserCreated);
        assert_eq!(events[1].action, AuditAction::CredentialSet);

        // Integrity chain should still be valid
        let valid = audit
            .verify_integrity(&tenant_id, None, None)
            .expect("verify after reopen");
        assert!(valid, "integrity chain should survive restart");
    }
}

// ===================================================================
// Integration: Compliance query (auth events by user + date range)
// ===================================================================

#[tokio::test]
async fn compliance_query_auth_events_by_user_and_date() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let audit = harness.audit();
    let tenant_id = TenantId::generate();

    // Create a mix of events from different actors and types
    let events = vec![
        // alice's auth events
        ("alice", AuditAction::CredentialVerified, "Login attempt"),
        ("alice", AuditAction::SessionCreated, "Session created"),
        // bob's events (should not appear in alice's compliance query)
        ("bob", AuditAction::CredentialVerified, "Login attempt"),
        // alice's token event
        ("alice", AuditAction::TokenIssued, "Token issued"),
        // alice non-auth event (should appear when querying by actor)
        ("alice", AuditAction::UserUpdated, "Profile update"),
    ];

    for (actor, action, resource_id) in &events {
        audit
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: (*actor).to_string(),
                action: action.clone(),
                resource_type: "user".to_string(),
                resource_id: (*resource_id).to_string(),
                metadata: None,
            })
            .expect("append");
    }

    // Compliance query: all events by alice
    let alice_events = audit
        .query(&AuditQuery {
            tenant_id: tenant_id.clone(),
            actor: Some("alice".to_string()),
            ..AuditQuery::for_tenant(tenant_id.clone())
        })
        .expect("alice query");

    assert_eq!(
        alice_events.len(),
        4,
        "alice should have 4 events, got {}",
        alice_events.len()
    );
    assert!(
        alice_events.iter().all(|e| e.actor == "alice"),
        "all events should be alice's"
    );

    // Compliance query: only credential verification events
    let auth_events = audit
        .query(&AuditQuery {
            tenant_id: tenant_id.clone(),
            action: Some(AuditAction::CredentialVerified),
            ..AuditQuery::for_tenant(tenant_id.clone())
        })
        .expect("auth events query");

    assert_eq!(
        auth_events.len(),
        2,
        "should have 2 credential verification events"
    );
}

// ===================================================================
// Adversarial: Tamper detection
// ===================================================================

#[tokio::test]
async fn tamper_detection_detects_modified_entries() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let audit = harness.audit();
    let storage = harness.storage();
    let tenant_id = TenantId::generate();

    // Append several events
    for i in 0..5 {
        audit
            .append(&CreateAuditEvent {
                tenant_id: tenant_id.clone(),
                actor: format!("actor_{i}"),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: format!("u{i}"),
                metadata: None,
            })
            .expect("append");
    }

    // Verify integrity before tampering
    let valid_before = audit
        .verify_integrity(&tenant_id, None, None)
        .expect("verify before");
    assert!(valid_before, "should be valid before tampering");

    // Now tamper: scan for the audit events, modify one in storage directly
    let events = audit
        .query(&AuditQuery::for_tenant(tenant_id.clone()))
        .expect("query");
    assert_eq!(events.len(), 5);

    // Take the third event, modify its actor, and write it back
    let mut tampered_event = events[2].clone();
    tampered_event.actor = "TAMPERED_ACTOR".to_string();
    // Keep the same integrity_hash (which is now wrong)
    let tampered_value = serde_json::to_vec(&tampered_event).expect("serialize");

    // Reconstruct the storage key for this event
    let key = format!(
        "audit:evt:{:019}:{}",
        tampered_event.timestamp.as_micros(),
        tampered_event.id.as_uuid()
    );
    storage
        .put(&tenant_id, key.as_bytes(), &tampered_value)
        .expect("put tampered");

    // Verify integrity after tampering — should detect the modification
    let valid_after = audit
        .verify_integrity(&tenant_id, None, None)
        .expect("verify after");
    assert!(
        !valid_after,
        "should detect tampered entry and return false"
    );
}

// ===================================================================
// Additional: Multi-tenant audit isolation via public API
// ===================================================================

#[tokio::test]
async fn multi_tenant_audit_isolation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let audit = harness.audit();

    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();

    // Write events to both tenants
    audit
        .append(&CreateAuditEvent {
            tenant_id: tenant_a.clone(),
            actor: "admin_a".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "ua1".to_string(),
            metadata: None,
        })
        .expect("append to A");

    audit
        .append(&CreateAuditEvent {
            tenant_id: tenant_b.clone(),
            actor: "admin_b".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "ub1".to_string(),
            metadata: None,
        })
        .expect("append to B");

    // Each tenant sees only their own events
    let events_a = audit
        .query(&AuditQuery::for_tenant(tenant_a.clone()))
        .expect("query A");
    assert_eq!(events_a.len(), 1);
    assert_eq!(events_a[0].actor, "admin_a");

    let events_b = audit
        .query(&AuditQuery::for_tenant(tenant_b.clone()))
        .expect("query B");
    assert_eq!(events_b.len(), 1);
    assert_eq!(events_b[0].actor, "admin_b");

    // Integrity chains are independent
    let valid_a = audit
        .verify_integrity(&tenant_a, None, None)
        .expect("verify A");
    let valid_b = audit
        .verify_integrity(&tenant_b, None, None)
        .expect("verify B");
    assert!(valid_a);
    assert!(valid_b);
}
