//! Authorization engine integration tests (black box).
//!
//! Covers `TEST_SCENARIOS.md` § Authorization Engine — Integration:
//! 1. Permission check via embedded public API (zero internal imports)
//! 2. Write relationship + check permission round-trip via public API

mod common;

use common::TestHarness;
use std::collections::HashMap;

use hearth::authz::{
    ConsistencyToken, NamespaceConfig, ObjectRef, ObjectTypeConfig, RelationConfig,
    RelationshipTuple, SubjectRef, TupleWrite, WatchFilter,
};
use hearth::core::RealmId;

/// Scenario 1: Permission check via embedded public API.
///
/// Verifies that direct and transitive permission checks work through
/// the public `AuthorizationEngine` trait with zero internal imports.
#[tokio::test]
async fn permission_check_via_embedded_api() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm = RealmId::generate();

    // Set up: document:design#viewer@group:eng#member, group:eng#member@user:alice
    let doc = ObjectRef::new("document", "design").expect("valid");
    let group_member = SubjectRef::userset("group", "eng", "member").expect("valid");
    let tuple1 = RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("valid");

    let group = ObjectRef::new("group", "eng").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let tuple2 = RelationshipTuple::new(group, "member", alice.clone()).expect("valid");

    authz
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
        )
        .expect("write tuples");

    // Direct check: alice is not a direct viewer (only transitive)
    let bob = SubjectRef::direct("user", "bob").expect("valid");
    assert!(
        !authz
            .check(&realm, &doc, "viewer", &bob, None)
            .expect("check bob"),
        "bob should not have viewer access"
    );

    // Transitive check: alice has viewer through group membership
    assert!(
        authz
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check alice"),
        "alice should have transitive viewer access"
    );

    // Expand: should find alice as a reachable viewer
    let viewers = authz.expand(&realm, &doc, "viewer", None).expect("expand");
    assert!(
        viewers.contains(&alice),
        "expand should include alice, got: {viewers:?}"
    );
}

/// Scenario 2: Write relationship + check permission round-trip via public API.
///
/// Verifies the full lifecycle: write → check → delete → check.
#[tokio::test]
async fn write_check_delete_roundtrip_via_public_api() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm = RealmId::generate();

    let doc = ObjectRef::new("folder", "shared").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let bob = SubjectRef::direct("user", "bob").expect("valid");
    let tuple_alice = RelationshipTuple::new(doc.clone(), "editor", alice.clone()).expect("valid");
    let tuple_bob = RelationshipTuple::new(doc.clone(), "editor", bob.clone()).expect("valid");

    // Initially: no permissions
    assert!(!authz
        .check(&realm, &doc, "editor", &alice, None)
        .expect("check"));
    assert!(!authz
        .check(&realm, &doc, "editor", &bob, None)
        .expect("check"));

    // Write: add both alice and bob as editors
    authz
        .write_tuples(
            &realm,
            &[
                TupleWrite::Touch(tuple_alice.clone()),
                TupleWrite::Touch(tuple_bob.clone()),
            ],
        )
        .expect("write");

    // Verify: both have permission
    assert!(authz
        .check(&realm, &doc, "editor", &alice, None)
        .expect("check"));
    assert!(authz
        .check(&realm, &doc, "editor", &bob, None)
        .expect("check"));

    // Expand: should return both
    let editors = authz.expand(&realm, &doc, "editor", None).expect("expand");
    assert_eq!(editors.len(), 2, "should have 2 editors, got: {editors:?}");

    // Delete: remove alice's permission
    authz
        .write_tuples(&realm, &[TupleWrite::Delete(tuple_alice)])
        .expect("delete");

    // Verify: alice no longer has permission, bob still does
    assert!(
        !authz
            .check(&realm, &doc, "editor", &alice, None)
            .expect("check"),
        "alice should no longer be editor after delete"
    );
    assert!(
        authz
            .check(&realm, &doc, "editor", &bob, None)
            .expect("check"),
        "bob should still be editor"
    );

    // Expand: should return only bob
    let editors = authz.expand(&realm, &doc, "editor", None).expect("expand");
    assert_eq!(
        editors.len(),
        1,
        "should have 1 editor after delete, got: {editors:?}"
    );
    assert!(editors.contains(&bob));
}

// === Integration: Schema migration ===
// Set schema → write valid tuples → update schema → verify new rules enforced

/// Scenario: Namespace schema migration — update schema, new rules enforced.
#[tokio::test]
async fn namespace_schema_migration() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm = RealmId::generate();

    // 1. Set initial schema: document has viewer with user subject only
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
    let config_v1 = NamespaceConfig {
        object_types: object_types.clone(),
    };
    authz
        .set_namespace(&realm, &config_v1)
        .expect("set namespace v1");

    // 2. Write valid tuple
    let doc = ObjectRef::new("document", "readme").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let tuple = RelationshipTuple::new(doc.clone(), "viewer", alice.clone()).expect("valid");
    authz
        .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
        .expect("write valid tuple");

    // 3. Migrate: add "group" as allowed subject type for viewer
    let mut relations_v2 = HashMap::new();
    relations_v2.insert(
        "viewer".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string(), "group".to_string()],
            rewrite: None,
        },
    );
    let mut object_types_v2 = HashMap::new();
    object_types_v2.insert(
        "document".to_string(),
        ObjectTypeConfig {
            relations: relations_v2,
        },
    );
    let config_v2 = NamespaceConfig {
        object_types: object_types_v2,
    };
    authz
        .set_namespace(&realm, &config_v2)
        .expect("set namespace v2");

    // 4. Now group subjects should be accepted
    let group_subj = SubjectRef::userset("group", "eng", "member").expect("valid");
    let group_tuple = RelationshipTuple::new(doc, "viewer", group_subj).expect("valid");
    authz
        .write_tuples(&realm, &[TupleWrite::Touch(group_tuple)])
        .expect("group subject should now be accepted after migration");
}

// === Integration: User deletion cascade with authz ===
// Create user → add permission → delete user → permission tuple still exists
// (authz doesn't auto-cascade user deletion — that's the caller's responsibility)

/// Scenario: User deletion does not auto-cascade authz tuples.
#[tokio::test]
async fn user_deletion_does_not_cascade_authz_tuples() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let identity = harness.identity();
    let realm = RealmId::generate();

    // Create user
    let user = identity
        .create_user(
            &realm,
            &hearth::identity::CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Add authz tuple
    let doc = ObjectRef::new("document", "readme").expect("valid");
    let subj = SubjectRef::direct("user", &user.id().as_uuid().to_string()).expect("valid");
    let tuple = RelationshipTuple::new(doc.clone(), "viewer", subj.clone()).expect("valid");
    authz
        .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
        .expect("write tuple");

    // Verify permission
    assert!(authz
        .check(&realm, &doc, "viewer", &subj, None)
        .expect("check"));

    // Delete user
    identity
        .delete_user(&realm, user.id())
        .expect("delete user");

    // Authz tuple still exists (no cascade — caller is responsible for cleanup)
    assert!(
        authz
            .check(&realm, &doc, "viewer", &subj, None)
            .expect("check"),
        "authz tuple should still exist after user deletion"
    );
}

// === Adversarial: Malformed schema rejected ===

/// Scenario: Malformed namespace schemas are rejected or handled gracefully.
#[tokio::test]
async fn malformed_schema_rejected() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm = RealmId::generate();

    // Empty schema — no object types defined
    let empty_config = NamespaceConfig {
        object_types: HashMap::new(),
    };
    authz
        .set_namespace(&realm, &empty_config)
        .expect("set empty namespace");

    // Any write should fail since no types are defined
    let obj = ObjectRef::new("document", "readme").expect("valid");
    let subj = SubjectRef::direct("user", "alice").expect("valid");
    let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");

    let err = authz
        .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
        .expect_err("should reject with empty schema");
    assert!(
        matches!(err, hearth::authz::AuthzError::InvalidNamespace { .. }),
        "expected InvalidNamespace, got: {err:?}"
    );
}

// === Integration: Watch end-to-end ===

/// Scenario: Watch API delivers live events for tuple changes.
#[tokio::test]
async fn watch_end_to_end_live_events() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm = RealmId::generate();

    // Subscribe before any writes
    let filter = WatchFilter { object_type: None };
    let mut receiver = authz.watch(&realm, &filter, None).expect("watch");

    // Write a tuple
    let doc = ObjectRef::new("document", "readme").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let tuple = RelationshipTuple::new(doc, "viewer", alice).expect("valid");
    let token = authz
        .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
        .expect("write");

    // Should receive the event via broadcast
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .expect("should receive within timeout")
        .expect("channel should not be closed");

    assert_eq!(event.object_type, "document");
    assert_eq!(event.object_id, "readme");
    assert_eq!(event.relation, "viewer");
    assert_eq!(event.subject, "user:alice");
    assert_eq!(event.sequence, token.version());
}

/// Scenario: Watch replay delivers historical events since a token.
#[tokio::test]
async fn watch_replay_delivers_historical_events() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm = RealmId::generate();

    // Write two batches of tuples
    let doc = ObjectRef::new("document", "readme").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let t1 = RelationshipTuple::new(doc.clone(), "viewer", alice).expect("valid");
    let token1 = authz
        .write_tuples(&realm, &[TupleWrite::Touch(t1)])
        .expect("write");

    let bob = SubjectRef::direct("user", "bob").expect("valid");
    let t2 = RelationshipTuple::new(doc, "editor", bob).expect("valid");
    let _token2 = authz
        .write_tuples(&realm, &[TupleWrite::Touch(t2)])
        .expect("write");

    // Watch from token1 — should replay only events after token1
    let filter = WatchFilter { object_type: None };
    let mut receiver = authz.watch(&realm, &filter, Some(&token1)).expect("watch");

    let event = receiver.drain_replay();
    assert!(event.is_some(), "should have replay event for second write");
    let event = event.expect("event");
    assert_eq!(event.relation, "editor");
    assert_eq!(event.subject, "user:bob");
}

// === Adversarial: Watch without auth rejected ===

/// Scenario: Watch subscription validates realm context.
/// (In the current single-node implementation, any caller can watch
/// any realm — but the API requires a valid `RealmId`. This test
/// verifies the watch channel is realm-isolated.)
#[tokio::test]
async fn watch_realm_isolation() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");
    let authz = harness.authz();
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    // Subscribe to realm A
    let filter = WatchFilter { object_type: None };
    let _receiver_a = authz.watch(&realm_a, &filter, None).expect("watch");

    // Write to realm B — should not appear in realm A's watch
    let doc = ObjectRef::new("document", "readme").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let tuple = RelationshipTuple::new(doc, "viewer", alice).expect("valid");
    authz
        .write_tuples(&realm_b, &[TupleWrite::Touch(tuple)])
        .expect("write");

    // Replay from realm A should be empty (no events written to realm A)
    let token_zero = ConsistencyToken::new(0);
    let mut receiver_a = authz
        .watch(&realm_a, &filter, Some(&token_zero))
        .expect("watch");
    assert!(
        receiver_a.drain_replay().is_none(),
        "realm A should have no events from realm B"
    );
}
