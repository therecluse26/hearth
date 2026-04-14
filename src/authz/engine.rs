//! Embedded authorization engine implementation.
//!
//! Implements `AuthorizationEngine` using the `StorageEngine` trait for
//! persistence. Performs BFS graph traversal with visited-set cycle detection
//! and configurable depth limiting.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use crate::authz::error::AuthzError;
use crate::authz::keys;
use crate::authz::types::{ObjectRef, RelationshipTuple, SubjectRef, TupleWrite, WatchFilter};
use crate::authz::AuthorizationEngine;
use crate::core::TenantId;
use crate::storage::StorageEngine;

/// Default maximum BFS traversal depth.
const DEFAULT_MAX_DEPTH: u32 = 10;

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
pub struct EmbeddedAuthzEngine {
    /// The underlying storage engine.
    storage: Arc<dyn StorageEngine>,
    /// Engine configuration.
    config: AuthzConfig,
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
        Self { storage, config }
    }

    /// Writes a single relationship tuple to both indexes.
    fn write_tuple(
        &self,
        tenant_id: &TenantId,
        tuple: &RelationshipTuple,
    ) -> Result<(), AuthzError> {
        let fwd_key = keys::encode_forward(&tuple.object, &tuple.relation, &tuple.subject);
        let rev_key = keys::encode_reverse(&tuple.object, &tuple.relation, &tuple.subject);

        self.storage
            .put(tenant_id, &fwd_key, keys::PRESENCE_MARKER)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        self.storage
            .put(tenant_id, &rev_key, keys::PRESENCE_MARKER)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        Ok(())
    }

    /// Deletes a single relationship tuple from both indexes.
    fn delete_tuple(
        &self,
        tenant_id: &TenantId,
        tuple: &RelationshipTuple,
    ) -> Result<(), AuthzError> {
        let fwd_key = keys::encode_forward(&tuple.object, &tuple.relation, &tuple.subject);
        let rev_key = keys::encode_reverse(&tuple.object, &tuple.relation, &tuple.subject);

        self.storage
            .delete(tenant_id, &fwd_key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        self.storage
            .delete(tenant_id, &rev_key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;

        Ok(())
    }

    /// Scans all subjects for a given (object, relation) pair.
    fn scan_subjects(
        &self,
        tenant_id: &TenantId,
        object: &ObjectRef,
        relation: &str,
    ) -> Result<Vec<SubjectRef>, AuthzError> {
        let prefix = keys::encode_forward_prefix(object, relation);
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(tenant_id, &prefix, &end)
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
        tenant_id: &TenantId,
        object: &ObjectRef,
        relation: &str,
        subject: &SubjectRef,
    ) -> Result<bool, AuthzError> {
        // 1. Direct lookup — hot path: single storage.get()
        let fwd_key = keys::encode_forward(object, relation, subject);
        let direct = self
            .storage
            .get(tenant_id, &fwd_key)
            .map_err(|e| AuthzError::Storage(Box::new(e)))?;
        if direct.is_some() {
            return Ok(true);
        }

        // 2. BFS traversal through userset indirections
        let mut queue: VecDeque<(ObjectRef, String, u32)> = VecDeque::new();
        let mut visited: HashSet<(String, String, String)> = HashSet::new();

        // Mark initial (object, relation) as visited
        visited.insert((
            object.object_type().to_string(),
            object.object_id().to_string(),
            relation.to_string(),
        ));

        queue.push_back((object.clone(), relation.to_string(), 0));

        while let Some((cur_object, cur_relation, depth)) = queue.pop_front() {
            if depth >= self.config.max_depth {
                continue; // Fail-closed: stop exploring this branch
            }

            // Scan all subjects of (cur_object, cur_relation)
            let subjects = self.scan_subjects(tenant_id, &cur_object, &cur_relation)?;

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
                        let visit_key = (
                            userset_obj.object_type().to_string(),
                            userset_obj.object_id().to_string(),
                            userset_rel.clone(),
                        );
                        if visited.insert(visit_key) {
                            queue.push_back((userset_obj.clone(), userset_rel.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    fn expand(
        &self,
        tenant_id: &TenantId,
        object: &ObjectRef,
        relation: &str,
    ) -> Result<Vec<SubjectRef>, AuthzError> {
        let mut result: Vec<SubjectRef> = Vec::new();
        let mut seen_direct: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(ObjectRef, String, u32)> = VecDeque::new();
        let mut visited: HashSet<(String, String, String)> = HashSet::new();

        visited.insert((
            object.object_type().to_string(),
            object.object_id().to_string(),
            relation.to_string(),
        ));

        queue.push_back((object.clone(), relation.to_string(), 0));

        while let Some((cur_object, cur_relation, depth)) = queue.pop_front() {
            if depth >= self.config.max_depth {
                continue;
            }

            let subjects = self.scan_subjects(tenant_id, &cur_object, &cur_relation)?;

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
                        let visit_key = (
                            userset_obj.object_type().to_string(),
                            userset_obj.object_id().to_string(),
                            userset_rel.clone(),
                        );
                        if visited.insert(visit_key) {
                            queue.push_back((userset_obj.clone(), userset_rel.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    fn write_tuples(&self, tenant_id: &TenantId, writes: &[TupleWrite]) -> Result<(), AuthzError> {
        for write in writes {
            match write {
                TupleWrite::Touch(tuple) => self.write_tuple(tenant_id, tuple)?,
                TupleWrite::Delete(tuple) => self.delete_tuple(tenant_id, tuple)?,
            }
        }
        Ok(())
    }

    fn watch(&self, _tenant_id: &TenantId, _filter: &WatchFilter) -> Result<(), AuthzError> {
        // Stub for Phase 1+
        Err(AuthzError::InvalidTuple {
            reason: "watch() is not yet implemented (Phase 1+)".to_string(),
        })
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
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&tenant, &[TupleWrite::Touch(tuple)])
            .expect("write");

        let result = engine.check(&tenant, &obj, "viewer", &subj).expect("check");
        assert!(result, "direct relationship should be found");
    }

    #[test]
    fn direct_check_absent_returns_false() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "bob").expect("valid");

        let result = engine.check(&tenant, &obj, "viewer", &subj).expect("check");
        assert!(!result, "absent relationship should not be found");
    }

    #[test]
    fn direct_check_wrong_relation_returns_false() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        engine
            .write_tuples(&tenant, &[TupleWrite::Touch(tuple)])
            .expect("write");

        let result = engine.check(&tenant, &obj, "editor", &subj).expect("check");
        assert!(!result, "wrong relation should not match");
    }

    // ===== Scenario 2: Transitive relationship check =====

    #[test]
    fn transitive_check_2_hop() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

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
                &tenant,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        let result = engine
            .check(&tenant, &doc, "viewer", &alice)
            .expect("check");
        assert!(result, "2-hop transitive check should succeed");
    }

    #[test]
    fn transitive_check_3_hop() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

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
                &tenant,
                &[
                    TupleWrite::Touch(tuple1),
                    TupleWrite::Touch(tuple2),
                    TupleWrite::Touch(tuple3),
                ],
            )
            .expect("write");

        let result = engine
            .check(&tenant, &doc, "viewer", &alice)
            .expect("check");
        assert!(result, "3-hop transitive check should succeed");
    }

    // ===== Scenario 3: Cycle detection =====

    #[test]
    fn cycle_detection_terminates() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        // Create a cycle: A#member@B#member, B#member@A#member
        let a = ObjectRef::new("group", "a").expect("valid");
        let b_member = SubjectRef::userset("group", "b", "member").expect("valid");
        let tuple1 = RelationshipTuple::new(a.clone(), "member", b_member).expect("valid");

        let b = ObjectRef::new("group", "b").expect("valid");
        let a_member = SubjectRef::userset("group", "a", "member").expect("valid");
        let tuple2 = RelationshipTuple::new(b, "member", a_member).expect("valid");

        engine
            .write_tuples(
                &tenant,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        // check for a user not in the cycle — should terminate and return false
        let user = SubjectRef::direct("user", "alice").expect("valid");
        let result = engine.check(&tenant, &a, "member", &user).expect("check");
        assert!(!result, "cycle should not produce false positive");
    }

    #[test]
    fn cycle_with_reachable_target() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

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
                &tenant,
                &[
                    TupleWrite::Touch(tuple1),
                    TupleWrite::Touch(tuple2),
                    TupleWrite::Touch(tuple3),
                ],
            )
            .expect("write");

        let result = engine.check(&tenant, &a, "member", &alice).expect("check");
        assert!(result, "should find alice through cycle");
    }

    // ===== Scenario 4: Write and delete tuples =====

    #[test]
    fn write_and_delete_tuples() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        // Write
        engine
            .write_tuples(&tenant, &[TupleWrite::Touch(tuple.clone())])
            .expect("write");
        assert!(engine.check(&tenant, &obj, "viewer", &subj).expect("check"));

        // Delete
        engine
            .write_tuples(&tenant, &[TupleWrite::Delete(tuple)])
            .expect("delete");
        assert!(
            !engine.check(&tenant, &obj, "viewer", &subj).expect("check"),
            "deleted tuple should not be found"
        );
    }

    #[test]
    fn write_multiple_tuples_atomically() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        let tuple1 = RelationshipTuple::new(obj.clone(), "viewer", alice.clone()).expect("valid");
        let tuple2 = RelationshipTuple::new(obj.clone(), "editor", bob.clone()).expect("valid");

        engine
            .write_tuples(
                &tenant,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        assert!(engine
            .check(&tenant, &obj, "viewer", &alice)
            .expect("check"));
        assert!(engine.check(&tenant, &obj, "editor", &bob).expect("check"));
    }

    // ===== Scenario 5: Expand =====

    #[test]
    fn expand_returns_direct_subjects() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let bob = SubjectRef::direct("user", "bob").expect("valid");
        let tuple1 = RelationshipTuple::new(obj.clone(), "viewer", alice.clone()).expect("valid");
        let tuple2 = RelationshipTuple::new(obj.clone(), "viewer", bob.clone()).expect("valid");

        engine
            .write_tuples(
                &tenant,
                &[TupleWrite::Touch(tuple1), TupleWrite::Touch(tuple2)],
            )
            .expect("write");

        let subjects = engine.expand(&tenant, &obj, "viewer").expect("expand");
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains(&alice));
        assert!(subjects.contains(&bob));
    }

    #[test]
    fn expand_traverses_usersets() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

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
                &tenant,
                &[
                    TupleWrite::Touch(tuple1),
                    TupleWrite::Touch(tuple2),
                    TupleWrite::Touch(tuple3),
                ],
            )
            .expect("write");

        let subjects = engine.expand(&tenant, &doc, "viewer").expect("expand");
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains(&alice));
        assert!(subjects.contains(&bob));
    }

    #[test]
    fn expand_empty_returns_empty() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subjects = engine.expand(&tenant, &obj, "viewer").expect("expand");
        assert!(subjects.is_empty());
    }

    // ===== watch() stub =====

    #[test]
    fn watch_returns_error() {
        let (_dir, engine) = setup_engine();
        let tenant = TenantId::generate();
        let filter = WatchFilter { object_type: None };

        let result = engine.watch(&tenant, &filter);
        assert!(result.is_err(), "watch should return error in Phase 0");
    }

    // ===== Adversarial: Max depth enforcement =====

    #[test]
    fn max_depth_enforcement() {
        let (_dir, engine) = setup_engine_with_depth(5);
        let tenant = TenantId::generate();

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

        engine.write_tuples(&tenant, &tuples).expect("write");

        let root = ObjectRef::new("group", "g0").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let result = engine
            .check(&tenant, &root, "member", &alice)
            .expect("check");
        assert!(
            !result,
            "should return false when chain exceeds max_depth=5"
        );
    }

    #[test]
    fn within_depth_limit_succeeds() {
        let (_dir, engine) = setup_engine_with_depth(5);
        let tenant = TenantId::generate();

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

        engine.write_tuples(&tenant, &tuples).expect("write");

        let root = ObjectRef::new("group", "g0").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let result = engine
            .check(&tenant, &root, "member", &alice)
            .expect("check");
        assert!(result, "4-hop chain should succeed with max_depth=5");
    }

    // ===== Adversarial: Cross-tenant isolation =====

    #[test]
    fn cross_tenant_isolation() {
        let (_dir, engine) = setup_engine();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", subj.clone()).expect("valid");

        // Write under tenant A
        engine
            .write_tuples(&tenant_a, &[TupleWrite::Touch(tuple)])
            .expect("write");

        // Check under tenant A: should find it
        assert!(engine
            .check(&tenant_a, &obj, "viewer", &subj)
            .expect("check"));

        // Check under tenant B: should NOT find it
        assert!(
            !engine
                .check(&tenant_b, &obj, "viewer", &subj)
                .expect("check"),
            "cross-tenant access must be denied"
        );
    }

    #[test]
    fn cross_tenant_expand_isolation() {
        let (_dir, engine) = setup_engine();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let obj = ObjectRef::new("document", "readme").expect("valid");
        let alice = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj.clone(), "viewer", alice).expect("valid");

        engine
            .write_tuples(&tenant_a, &[TupleWrite::Touch(tuple)])
            .expect("write");

        let subjects_a = engine.expand(&tenant_a, &obj, "viewer").expect("expand");
        assert_eq!(subjects_a.len(), 1);

        let subjects_b = engine.expand(&tenant_b, &obj, "viewer").expect("expand");
        assert!(
            subjects_b.is_empty(),
            "expand under different tenant must return empty"
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
                let tenant = TenantId::generate();

                engine.write_tuples(&tenant, &tuples).expect("write");

                let doc = ObjectRef::new("doc", "d0").expect("valid");
                for (user, relation, expected) in &checks {
                    let subj = SubjectRef::direct("user", user).expect("valid");
                    let result = engine.check(&tenant, &doc, relation, &subj).expect("check");
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
                let tenant = TenantId::generate();

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

                engine.write_tuples(&tenant, &tuples).expect("write");

                // Alice should be reachable from any group in the cycle
                for i in 0..cycle_size {
                    let obj = ObjectRef::new("group", &format!("g{i}")).expect("valid");
                    let result = engine.check(&tenant, &obj, "member", &alice).expect("check");
                    prop_assert!(result, "alice should be reachable from g{}", i);
                }

                // Non-existent user should not be reachable
                let bob = SubjectRef::direct("user", "bob").expect("valid");
                let result = engine.check(&tenant, &g0, "member", &bob).expect("check");
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
                let tenant = TenantId::generate();
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
                        engine.write_tuples(&tenant, &[TupleWrite::Touch(tuple)]).expect("write");
                        active.insert(*user_idx);
                    } else {
                        engine.write_tuples(&tenant, &[TupleWrite::Delete(tuple)]).expect("delete");
                        active.remove(user_idx);
                    }
                }

                // Verify the final state
                for i in 0u32..5 {
                    let user_name = format!("u{i}");
                    let subj = SubjectRef::direct("user", &user_name).expect("valid");
                    let result = engine.check(&tenant, &doc, "viewer", &subj).expect("check");
                    let expected = active.contains(&i);
                    prop_assert_eq!(
                        result, expected,
                        "user u{}: expected={}, got={}", i, expected, result
                    );
                }
            }
        }
    }
}
