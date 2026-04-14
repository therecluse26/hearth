//! Authorization engine integration tests (black box).
//!
//! Covers `TEST_SCENARIOS.md` § Authorization Engine — Integration:
//! 1. Permission check via embedded public API (zero internal imports)
//! 2. Write relationship + check permission round-trip via public API

mod common;

use common::TestHarness;
use hearth::authz::{ObjectRef, RelationshipTuple, SubjectRef, TupleWrite};
use hearth::core::TenantId;

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
    let tenant = TenantId::generate();

    // Set up: document:design#viewer@group:eng#member, group:eng#member@user:alice
    let doc = ObjectRef::new("document", "design").expect("valid");
    let group_member = SubjectRef::userset("group", "eng", "member").expect("valid");
    let tuple1 = RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("valid");

    let group = ObjectRef::new("group", "eng").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let tuple2 = RelationshipTuple::new(group, "member", alice.clone()).expect("valid");

    authz
        .write_tuples(
            &tenant,
            &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
        )
        .expect("write tuples");

    // Direct check: alice is not a direct viewer (only transitive)
    let bob = SubjectRef::direct("user", "bob").expect("valid");
    assert!(
        !authz
            .check(&tenant, &doc, "viewer", &bob)
            .expect("check bob"),
        "bob should not have viewer access"
    );

    // Transitive check: alice has viewer through group membership
    assert!(
        authz
            .check(&tenant, &doc, "viewer", &alice)
            .expect("check alice"),
        "alice should have transitive viewer access"
    );

    // Expand: should find alice as a reachable viewer
    let viewers = authz.expand(&tenant, &doc, "viewer").expect("expand");
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
    let tenant = TenantId::generate();

    let doc = ObjectRef::new("folder", "shared").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let bob = SubjectRef::direct("user", "bob").expect("valid");
    let tuple_alice = RelationshipTuple::new(doc.clone(), "editor", alice.clone()).expect("valid");
    let tuple_bob = RelationshipTuple::new(doc.clone(), "editor", bob.clone()).expect("valid");

    // Initially: no permissions
    assert!(!authz.check(&tenant, &doc, "editor", &alice).expect("check"));
    assert!(!authz.check(&tenant, &doc, "editor", &bob).expect("check"));

    // Write: add both alice and bob as editors
    authz
        .write_tuples(
            &tenant,
            &[
                TupleWrite::Touch(tuple_alice.clone()),
                TupleWrite::Touch(tuple_bob.clone()),
            ],
        )
        .expect("write");

    // Verify: both have permission
    assert!(authz.check(&tenant, &doc, "editor", &alice).expect("check"));
    assert!(authz.check(&tenant, &doc, "editor", &bob).expect("check"));

    // Expand: should return both
    let editors = authz.expand(&tenant, &doc, "editor").expect("expand");
    assert_eq!(editors.len(), 2, "should have 2 editors, got: {editors:?}");

    // Delete: remove alice's permission
    authz
        .write_tuples(&tenant, &[TupleWrite::Delete(tuple_alice)])
        .expect("delete");

    // Verify: alice no longer has permission, bob still does
    assert!(
        !authz.check(&tenant, &doc, "editor", &alice).expect("check"),
        "alice should no longer be editor after delete"
    );
    assert!(
        authz.check(&tenant, &doc, "editor", &bob).expect("check"),
        "bob should still be editor"
    );

    // Expand: should return only bob
    let editors = authz.expand(&tenant, &doc, "editor").expect("expand");
    assert_eq!(
        editors.len(),
        1,
        "should have 1 editor after delete, got: {editors:?}"
    );
    assert!(editors.contains(&bob));
}
