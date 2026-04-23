//! Integration tests for the `check_explain()` diagnostic API.
//!
//! Covers:
//! - A union-hierarchy hit produces `RewriteUnion` + `DirectMatch` steps.
//! - A miss produces `ScannedRelation` steps for every relation explored
//!   and `max_depth_reached` reports how deep the BFS went.
//! - A userset hop emits `FollowedUserset` + a subsequent scan.

use std::collections::HashMap;
use std::sync::Arc;

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, CheckStep, EmbeddedAuthzEngine, NamespaceConfig, ObjectRef,
    ObjectTypeConfig, RelationConfig, RelationRewrite, RelationshipTuple, SubjectRef, TupleWrite,
};
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

fn setup_engine() -> (tempfile::TempDir, Arc<EmbeddedAuthzEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open storage");
    let engine = EmbeddedAuthzEngine::new(Arc::new(storage), AuthzConfig::default());
    (dir, Arc::new(engine))
}

/// `viewer ⊇ editor ⊇ owner` on `document`, accepting `user` subjects only.
fn namespace_with_hierarchy() -> NamespaceConfig {
    let mut relations = HashMap::new();
    relations.insert(
        "owner".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    relations.insert(
        "editor".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["owner".to_string()],
            }),
        },
    );
    relations.insert(
        "viewer".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["editor".to_string()],
            }),
        },
    );
    let mut object_types = HashMap::new();
    object_types.insert("document".to_string(), ObjectTypeConfig { relations });
    NamespaceConfig { object_types }
}

#[test]
fn explain_reports_rewrite_union_and_direct_match() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    engine
        .set_namespace(&realm, &namespace_with_hierarchy())
        .expect("set_namespace");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(doc.clone(), "owner", alice.clone()).expect("tuple"),
            )],
        )
        .expect("write");

    let explanation = engine
        .check_explain(&realm, &doc, "viewer", &alice)
        .expect("check_explain");

    assert!(explanation.allowed, "owner should satisfy viewer");

    // At least one rewrite step mentioning the union expansion path,
    // plus a DirectMatch on the satisfying relation.
    let has_rewrite = explanation.steps.iter().any(|s| {
        matches!(
            s,
            CheckStep::RewriteUnion {
                included, ..
            } if included == "owner" || included == "editor"
        )
    });
    assert!(
        has_rewrite,
        "expected a RewriteUnion step, got: {:?}",
        explanation.steps
    );
    let has_direct = explanation
        .steps
        .iter()
        .any(|s| matches!(s, CheckStep::DirectMatch { relation, .. } if relation == "owner"));
    assert!(
        has_direct,
        "expected a DirectMatch on owner, got: {:?}",
        explanation.steps
    );
}

#[test]
fn explain_reports_miss_with_scanned_relations() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    engine
        .set_namespace(&realm, &namespace_with_hierarchy())
        .expect("set_namespace");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let bob = SubjectRef::direct("user", "bob").expect("subj");

    // No tuples — bob should be denied and the explanation must record
    // every (object, relation) the BFS scanned.
    let explanation = engine
        .check_explain(&realm, &doc, "viewer", &bob)
        .expect("check_explain");

    assert!(!explanation.allowed, "no tuples — check must fail");
    assert!(
        !explanation.steps.is_empty(),
        "miss should still emit scan steps"
    );
    let scanned_relations: Vec<_> = explanation
        .steps
        .iter()
        .filter_map(|s| match s {
            CheckStep::ScannedRelation { relation, .. } => Some(relation.clone()),
            _ => None,
        })
        .collect();
    assert!(
        scanned_relations.contains(&"viewer".to_string()),
        "expected viewer to be scanned, got {scanned_relations:?}"
    );
    assert!(
        scanned_relations.contains(&"editor".to_string()),
        "union closure should scan editor too, got {scanned_relations:?}"
    );
}

#[test]
fn list_direct_relations_for_subject_returns_all_grants() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();

    // No namespace — free-form tuples. Grant alice direct access on two
    // different objects, plus an unrelated grant to bob to prove scoping.
    let alice = SubjectRef::direct("user", "alice").expect("alice");
    let bob = SubjectRef::direct("user", "bob").expect("bob");
    let doc = ObjectRef::new("document", "readme").expect("doc");
    let proj = ObjectRef::new("project", "atlas").expect("proj");
    engine
        .write_tuples(
            &realm,
            &[
                TupleWrite::Touch(
                    RelationshipTuple::new(doc.clone(), "viewer", alice.clone()).expect("t"),
                ),
                TupleWrite::Touch(
                    RelationshipTuple::new(doc.clone(), "editor", alice.clone()).expect("t"),
                ),
                TupleWrite::Touch(
                    RelationshipTuple::new(proj.clone(), "owner", alice.clone()).expect("t"),
                ),
                TupleWrite::Touch(RelationshipTuple::new(doc.clone(), "viewer", bob).expect("t")),
            ],
        )
        .expect("write");

    let grants = engine
        .list_direct_relations_for_subject(&realm, &alice)
        .expect("list");

    // Three alice grants, bob's tuple must not appear.
    assert_eq!(
        grants.len(),
        3,
        "expected 3 grants for alice, got: {grants:?}"
    );
    let as_pairs: Vec<(String, String)> = grants
        .iter()
        .map(|(o, r)| (format!("{o}"), r.clone()))
        .collect();
    assert!(as_pairs.contains(&("document:readme".to_string(), "viewer".to_string())));
    assert!(as_pairs.contains(&("document:readme".to_string(), "editor".to_string())));
    assert!(as_pairs.contains(&("project:atlas".to_string(), "owner".to_string())));
}

#[test]
fn explain_follows_userset_and_records_hop() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    // No namespace — freely write `document:readme#viewer@group:eng#member`
    // and `group:eng#member@user:alice`. Explain must emit the follow-up hop.
    let doc = ObjectRef::new("document", "readme").expect("obj");
    let group_member = SubjectRef::userset("group", "eng", "member").expect("userset subj");
    let alice_direct = SubjectRef::direct("user", "alice").expect("alice subj");
    let alice_as_member = SubjectRef::direct("user", "alice").expect("alice again");
    let group = ObjectRef::new("group", "eng").expect("group obj");

    engine
        .write_tuples(
            &realm,
            &[
                TupleWrite::Touch(
                    RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("t1"),
                ),
                TupleWrite::Touch(
                    RelationshipTuple::new(group, "member", alice_as_member).expect("t2"),
                ),
            ],
        )
        .expect("write");

    let explanation = engine
        .check_explain(&realm, &doc, "viewer", &alice_direct)
        .expect("check_explain");

    assert!(explanation.allowed, "alice should resolve through group");
    let followed = explanation
        .steps
        .iter()
        .any(|s| matches!(s, CheckStep::FollowedUserset { relation, .. } if relation == "member"));
    assert!(
        followed,
        "expected a FollowedUserset for group#member, got: {:?}",
        explanation.steps
    );
    assert!(
        explanation.max_depth_reached >= 1,
        "crossing a userset should record depth ≥ 1, got {}",
        explanation.max_depth_reached
    );
}
