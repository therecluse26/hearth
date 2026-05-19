#![allow(clippy::unwrap_used)]
mod common;

use common::TestHarness;
use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, IdentityEngine,
    OrganizationRole,
};

fn find_event(
    events: &[hearth::audit::AuditEvent],
    action: hearth::audit::AuditAction,
) -> Option<&hearth::audit::AuditEvent> {
    events.iter().find(|e| e.action == action)
}

#[tokio::test]
async fn test_delete_user_audited() {
    let harness = TestHarness::embedded().await.expect("harness");
    let realm_id = create_test_realm(&harness).await;

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "to-delete@test.com".to_string(),
                display_name: "Delete Me".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let user_id = user.id().clone();
    harness
        .identity()
        .delete_user(&realm_id, &user_id)
        .expect("delete user");

    let events = harness
        .audit()
        .query(&AuditQuery::for_realm(realm_id.clone()))
        .expect("query audit");

    let event = find_event(&events, AuditAction::UserDeleted).expect("no UserDeleted event found");
    assert_eq!(event.actor, "system");
    assert_eq!(event.resource_type, "user");
    assert_eq!(event.resource_id, user_id.as_uuid().to_string());
}

#[tokio::test]
async fn test_add_member_audited() {
    let harness = TestHarness::embedded().await.expect("harness");
    let realm_id = create_test_realm(&harness).await;

    let org = harness
        .identity()
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "audit-org".to_string(),
                slug: "audit-org".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "member@test.com".to_string(),
                display_name: "Member".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    harness
        .identity()
        .add_member(&realm_id, org.id(), user.id(), OrganizationRole::Member)
        .expect("add member");

    let events = harness
        .audit()
        .query(&AuditQuery::for_realm(realm_id))
        .expect("query audit");

    let event = find_event(&events, AuditAction::GroupMemberAdded)
        .expect("no GroupMemberAdded event found");
    assert_eq!(event.actor, "system");
    assert_eq!(event.resource_type, "org_membership");
    assert_eq!(event.resource_id, user.id().as_uuid().to_string());
}

#[tokio::test]
async fn test_delete_realm_cascading_one_event() {
    let harness = TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("cascade-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "a@cascade.com".to_string(),
                display_name: "A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user A");

    harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "b@cascade.com".to_string(),
                display_name: "B".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user B");

    harness
        .identity()
        .delete_realm(&realm_id)
        .expect("delete realm");

    let events = harness
        .audit()
        .query(&AuditQuery::for_realm(realm_id))
        .expect("query audit");

    let realm_deleted_events: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::RealmDeleted)
        .collect();
    assert_eq!(
        realm_deleted_events.len(),
        1,
        "delete_realm should emit exactly 1 RealmDeleted event"
    );

    let event = realm_deleted_events[0];
    assert_eq!(event.actor, "system");
}

#[tokio::test]
async fn test_destructive_delete_fails_when_audit_down() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = hearth::storage::StorageConfig::dev(temp_dir.path().to_path_buf());
    let storage =
        std::sync::Arc::new(hearth::storage::EmbeddedStorageEngine::open(config).expect("storage"));
    let clock: std::sync::Arc<dyn hearth::core::Clock> =
        std::sync::Arc::new(hearth::core::SystemClock);

    struct FailingAuditEngine;
    impl hearth::audit::AuditEngine for FailingAuditEngine {
        fn append(
            &self,
            _event: &hearth::audit::CreateAuditEvent,
        ) -> Result<hearth::audit::AuditEvent, hearth::audit::AuditError> {
            Err(hearth::audit::AuditError::IntegrityViolation {
                reason: "simulated".to_string(),
            })
        }
        fn query(
            &self,
            _query: &AuditQuery,
        ) -> Result<Vec<hearth::audit::AuditEvent>, hearth::audit::AuditError> {
            Ok(Vec::new())
        }
        fn verify_integrity(
            &self,
            _realm_id: &hearth::core::RealmId,
            _start: Option<hearth::core::Timestamp>,
            _end: Option<hearth::core::Timestamp>,
        ) -> Result<bool, hearth::audit::AuditError> {
            Ok(true)
        }
        fn get_retention_config(
            &self,
            _realm_id: &hearth::core::RealmId,
        ) -> Result<hearth::audit::AuditRetentionConfig, hearth::audit::AuditError> {
            Ok(hearth::audit::AuditRetentionConfig::default())
        }
        fn set_retention_config(
            &self,
            _realm_id: &hearth::core::RealmId,
            _config: &hearth::audit::AuditRetentionConfig,
        ) -> Result<(), hearth::audit::AuditError> {
            Ok(())
        }
        fn prune_before(
            &self,
            _realm_id: &hearth::core::RealmId,
            _cutoff: hearth::core::Timestamp,
        ) -> Result<u64, hearth::audit::AuditError> {
            Ok(0)
        }
    }

    let audit = std::sync::Arc::new(FailingAuditEngine);
    let engine = hearth::identity::EmbeddedIdentityEngine::new(
        std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
        std::sync::Arc::clone(&clock),
        hearth::identity::IdentityConfig {
            credential: hearth::identity::CredentialConfig::fast_for_testing(),
            ..Default::default()
        },
        audit,
    )
    .expect("engine");

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "fail-audit-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let user = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "d@fail.com".to_string(),
                display_name: "D".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let result = engine.delete_user(&realm_id, user.id());
    assert!(
        result.is_err(),
        "destructive delete must fail when audit is down"
    );
    let err_text = format!("{}", result.unwrap_err());
    assert!(err_text.contains("audit"), "error must mention audit");
}

async fn create_test_realm(harness: &TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("audit-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}
