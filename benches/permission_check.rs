//! Criterion benchmarks for the authorization engine.
//!
//! Covers `TEST_SCENARIOS.md` § Authorization Engine — Benchmark:
//! 1. Direct permission check: p50 < 20 μs, p99 < 200 μs
//! 2. 3-hop graph traversal: p50 < 100 μs, p99 < 1 ms
//! 3. Cached permission check: p50 < 5 μs (`ArcSwap` cache hit)

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite,
};
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an authz engine with a direct relationship for benchmarking.
fn setup_direct() -> (
    tempfile::TempDir,
    EmbeddedAuthzEngine,
    RealmId,
    ObjectRef,
    SubjectRef,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let engine = EmbeddedAuthzEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    );
    let realm = RealmId::generate();

    let obj = ObjectRef::new("document", "readme").expect("valid");
    let subj = SubjectRef::direct("user", "alice").expect("valid");
    let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

    engine
        .write_tuples(&realm, &[TupleWrite::Touch(tuple)])
        .expect("write");

    (dir, engine, realm, obj, subj)
}

/// Sets up an authz engine with a 3-hop transitive relationship.
fn setup_3_hop() -> (
    tempfile::TempDir,
    EmbeddedAuthzEngine,
    RealmId,
    ObjectRef,
    SubjectRef,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let engine = EmbeddedAuthzEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    );
    let realm = RealmId::generate();

    // doc#viewer@group:eng#member → group:eng#member@team:core#member → team:core#member@user:alice
    let doc = ObjectRef::new("document", "readme").expect("valid");
    let group_member = SubjectRef::userset("group", "eng", "member").expect("valid");
    let t1 = RelationshipTuple::new(doc.clone(), "viewer", group_member).expect("valid");

    let group = ObjectRef::new("group", "eng").expect("valid");
    let team_member = SubjectRef::userset("team", "core", "member").expect("valid");
    let t2 = RelationshipTuple::new(group, "member", team_member).expect("valid");

    let team = ObjectRef::new("team", "core").expect("valid");
    let alice = SubjectRef::direct("user", "alice").expect("valid");
    let t3 = RelationshipTuple::new(team, "member", alice.clone()).expect("valid");

    engine
        .write_tuples(
            &realm,
            &[
                TupleWrite::Touch(t1),
                TupleWrite::Touch(t2),
                TupleWrite::Touch(t3),
            ],
        )
        .expect("write");

    (dir, engine, realm, doc, alice)
}

fn bench_direct_check(c: &mut Criterion) {
    let (_dir, engine, realm, obj, subj) = setup_direct();

    c.bench_function("authz_direct_check", |b| {
        b.iter(|| {
            let result = engine
                .check(&realm, &obj, "viewer", &subj, None)
                .expect("check");
            assert!(result);
        });
    });
}

fn bench_3_hop_traversal(c: &mut Criterion) {
    let (_dir, engine, realm, doc, alice) = setup_3_hop();

    c.bench_function("authz_3_hop_traversal", |b| {
        b.iter(|| {
            let result = engine
                .check(&realm, &doc, "viewer", &alice, None)
                .expect("check");
            assert!(result);
        });
    });
}

fn bench_cached_check(c: &mut Criterion) {
    let (_dir, engine, realm, obj, subj) = setup_direct();

    // Prime the cache with an initial check
    let result = engine
        .check(&realm, &obj, "viewer", &subj, None)
        .expect("check");
    assert!(result);

    c.bench_function("authz_cached_check", |b| {
        b.iter(|| {
            let result = engine
                .check(&realm, &obj, "viewer", &subj, None)
                .expect("check");
            assert!(result);
        });
    });
}

criterion_group!(
    benches,
    bench_direct_check,
    bench_3_hop_traversal,
    bench_cached_check
);
criterion_main!(benches);
