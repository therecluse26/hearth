//! Integration tests for relation-union rewrites on the authz engine.
//!
//! Covers:
//! - A direct tuple on a sibling relation satisfies a union-bearing relation.
//! - Transitive unions (`viewer ⊇ editor ⊇ owner`) resolve end-to-end.
//! - `set_namespace` rejects configs whose unions reference unknown
//!   relations or form cycles.
//! - `expand()` surfaces subjects granted via sibling relations.
//! - Cache invalidation: writing to `editor` correctly invalidates a cached
//!   `viewer` check.
//! - Regression: namespaces without rewrites behave exactly as before.

use std::collections::HashMap;
use std::sync::Arc;

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, NamespaceConfig, ObjectRef,
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

/// Builds a test namespace with a two-level hierarchy on `document`:
/// `viewer ⊇ editor ⊇ owner`. All relations accept `user` subjects.
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
fn direct_sibling_satisfies_union_relation() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    engine
        .set_namespace(&realm, &namespace_with_hierarchy())
        .expect("set_namespace");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    // Alice is only an editor — but viewer union should include editor.
    engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(doc.clone(), "editor", alice.clone()).expect("tuple"),
            )],
        )
        .expect("write");

    assert!(
        engine
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check"),
        "editor should satisfy viewer through union rewrite"
    );
    assert!(
        engine
            .check(&realm, &doc, "editor", &alice, None)
            .expect("check"),
        "direct editor tuple should satisfy editor"
    );
    assert!(
        !engine
            .check(&realm, &doc, "owner", &alice, None)
            .expect("check"),
        "editor does not imply owner (unions only climb one direction)"
    );
}

#[test]
fn transitive_union_resolves_across_levels() {
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

    // owner ⊆ editor ⊆ viewer — every level should evaluate to true.
    for rel in ["owner", "editor", "viewer"] {
        assert!(
            engine
                .check(&realm, &doc, rel, &alice, None)
                .expect("check"),
            "owner should satisfy {rel} transitively"
        );
    }
}

#[test]
fn set_namespace_rejects_cycle() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();

    // a ⊇ b, b ⊇ a — a cycle.
    let mut relations = HashMap::new();
    relations.insert(
        "a".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["b".to_string()],
            }),
        },
    );
    relations.insert(
        "b".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["a".to_string()],
            }),
        },
    );
    let mut object_types = HashMap::new();
    object_types.insert("widget".to_string(), ObjectTypeConfig { relations });
    let ns = NamespaceConfig { object_types };

    let err = engine
        .set_namespace(&realm, &ns)
        .expect_err("cycle must be rejected");
    assert!(
        format!("{err}").contains("cycle"),
        "error should mention cycle: {err}"
    );
}

#[test]
fn set_namespace_rejects_unknown_union_target() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();

    let mut relations = HashMap::new();
    relations.insert(
        "viewer".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: Some(RelationRewrite::Union {
                includes: vec!["nonexistent".to_string()],
            }),
        },
    );
    let mut object_types = HashMap::new();
    object_types.insert("widget".to_string(), ObjectTypeConfig { relations });
    let ns = NamespaceConfig { object_types };

    let err = engine
        .set_namespace(&realm, &ns)
        .expect_err("unknown union target must be rejected");
    assert!(
        format!("{err}").contains("unknown relation"),
        "error should mention unknown relation: {err}"
    );
}

#[test]
fn expand_includes_subjects_from_union_siblings() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    engine
        .set_namespace(&realm, &namespace_with_hierarchy())
        .expect("set_namespace");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    let bob = SubjectRef::direct("user", "bob").expect("subj");

    engine
        .write_tuples(
            &realm,
            &[
                TupleWrite::Touch(
                    RelationshipTuple::new(doc.clone(), "owner", alice.clone()).expect("tuple"),
                ),
                TupleWrite::Touch(
                    RelationshipTuple::new(doc.clone(), "editor", bob.clone()).expect("tuple"),
                ),
            ],
        )
        .expect("write");

    // expand(viewer) must collect both — owner rolls up through editor.
    let viewers = engine.expand(&realm, &doc, "viewer", None).expect("expand");
    assert!(
        viewers.contains(&alice),
        "alice (owner) missing: {viewers:?}"
    );
    assert!(viewers.contains(&bob), "bob (editor) missing: {viewers:?}");
}

#[test]
fn write_on_sibling_invalidates_cached_union_check() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    engine
        .set_namespace(&realm, &namespace_with_hierarchy())
        .expect("set_namespace");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");

    // Prime the cache: viewer check is currently false.
    assert!(
        !engine
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check"),
        "baseline: viewer should be false"
    );

    // Now grant editor — reverse-closure invalidation must evict the cached
    // viewer=false answer, otherwise the next viewer check returns stale.
    engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(doc.clone(), "editor", alice.clone()).expect("tuple"),
            )],
        )
        .expect("write");

    assert!(
        engine
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check"),
        "viewer cache should have been invalidated by the editor write"
    );
}

#[test]
fn namespace_without_rewrites_behaves_as_before() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();

    // Schema with no rewrites: editor does NOT imply viewer.
    let mut relations = HashMap::new();
    relations.insert(
        "editor".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    relations.insert(
        "viewer".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    let mut object_types = HashMap::new();
    object_types.insert("document".to_string(), ObjectTypeConfig { relations });
    engine
        .set_namespace(&realm, &NamespaceConfig { object_types })
        .expect("set_namespace");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(doc.clone(), "editor", alice.clone()).expect("tuple"),
            )],
        )
        .expect("write");

    assert!(
        engine
            .check(&realm, &doc, "editor", &alice, None)
            .expect("check"),
        "direct editor must match"
    );
    assert!(
        !engine
            .check(&realm, &doc, "viewer", &alice, None)
            .expect("check"),
        "no rewrite: editor must NOT satisfy viewer"
    );
}
