//! Integration tests for the Roles & Permissions preset namespace.
//!
//! Covers:
//! - Preset passes `validate_rewrites` (no cycles, no dangling references).
//! - `ensure_preset_namespace` is idempotent (second call is a no-op).
//! - `ensure_preset_namespace` does NOT overwrite an existing custom namespace.
//! - Hierarchy resolves end-to-end: an `organization#owner` tuple satisfies
//!   checks at every level up through `organization#viewer`.
//! - The preset accepts a `realm#admin` tuple (the existing Hearth gate).
//! - Writes to undeclared object types on a presetted realm are rejected.

use std::sync::Arc;

use hearth::authz::{
    ensure_preset_namespace, preset_namespace, AuthorizationEngine, AuthzConfig,
    EmbeddedAuthzEngine, ObjectRef, RelationshipTuple, SubjectRef, TupleWrite,
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

#[test]
fn preset_namespace_validates() {
    let ns = preset_namespace();
    ns.validate_rewrites()
        .expect("preset namespace must pass rewrite validation");
}

#[test]
fn preset_declares_all_three_object_types() {
    let ns = preset_namespace();
    for ty in ["realm", "organization", "application", "hearth"] {
        assert!(
            ns.object_types.contains_key(ty),
            "preset missing object type {ty}"
        );
    }

    let org = &ns.object_types["organization"];
    for rel in ["owner", "admin", "member", "viewer"] {
        assert!(
            org.relations.contains_key(rel),
            "organization missing relation {rel}"
        );
    }
}

#[test]
fn ensure_preset_namespace_is_idempotent() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();

    let installed_first = ensure_preset_namespace(engine.as_ref(), &realm).expect("first install");
    assert!(installed_first, "first call should install the preset");

    let installed_second =
        ensure_preset_namespace(engine.as_ref(), &realm).expect("second install");
    assert!(!installed_second, "second call should be a no-op");

    let got = engine
        .get_namespace(&realm)
        .expect("get_namespace")
        .expect("namespace present");
    assert_eq!(got, preset_namespace(), "stored namespace matches preset");
}

#[test]
fn ensure_preset_namespace_does_not_overwrite_custom() {
    use std::collections::HashMap;

    use hearth::authz::{NamespaceConfig, ObjectTypeConfig, RelationConfig};

    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();

    // Install a custom namespace first.
    let mut relations = HashMap::new();
    relations.insert(
        "custom".to_string(),
        RelationConfig {
            allowed_subject_types: vec!["user".to_string()],
            rewrite: None,
        },
    );
    let mut object_types = HashMap::new();
    object_types.insert("thing".to_string(), ObjectTypeConfig { relations });
    let custom = NamespaceConfig { object_types };
    engine
        .set_namespace(&realm, &custom)
        .expect("custom set_namespace");

    let installed = ensure_preset_namespace(engine.as_ref(), &realm).expect("ensure");
    assert!(
        !installed,
        "ensure must not overwrite an existing namespace"
    );

    let got = engine
        .get_namespace(&realm)
        .expect("get_namespace")
        .expect("present");
    assert_eq!(got, custom, "custom namespace preserved");
}

#[test]
fn organization_owner_tuple_satisfies_every_level() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    ensure_preset_namespace(engine.as_ref(), &realm).expect("ensure");

    let org = ObjectRef::new("organization", "acme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(org.clone(), "owner", alice.clone()).expect("tuple"),
            )],
        )
        .expect("write");

    for rel in ["owner", "admin", "member", "viewer"] {
        assert!(
            engine
                .check(&realm, &org, rel, &alice, None)
                .expect("check"),
            "owner must satisfy {rel} via preset union hierarchy"
        );
    }
}

#[test]
fn realm_admin_tuple_accepted_by_preset() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    ensure_preset_namespace(engine.as_ref(), &realm).expect("ensure");

    // `realm:<id>#admin@user:<id>` mirrors the existing `hearth#admin` gate.
    let realm_obj = ObjectRef::new("realm", &realm.to_string()).expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(realm_obj.clone(), "admin", alice.clone()).expect("tuple"),
            )],
        )
        .expect("preset must accept realm#admin tuples");

    assert!(engine
        .check(&realm, &realm_obj, "admin", &alice, None)
        .expect("check"));
}

#[test]
fn preset_rejects_undeclared_object_type() {
    let (_dir, engine) = setup_engine();
    let realm = RealmId::generate();
    ensure_preset_namespace(engine.as_ref(), &realm).expect("ensure");

    let doc = ObjectRef::new("document", "readme").expect("obj");
    let alice = SubjectRef::direct("user", "alice").expect("subj");
    let err = engine
        .write_tuples(
            &realm,
            &[TupleWrite::Touch(
                RelationshipTuple::new(doc, "viewer", alice).expect("tuple"),
            )],
        )
        .expect_err("undeclared object type must be rejected");
    assert!(
        format!("{err}").contains("document"),
        "error should mention the undeclared type: {err}"
    );
}
