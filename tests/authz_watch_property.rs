//! Property test: concurrent watch subscriptions see all tuple writes.
//!
//! Covers `TEST_SCENARIOS.md` § Zanzibar Full — Property:
//! "Random tuple writes + concurrent watch subscriptions (N subscribers,
//!  M writes across 1–3 tenants) — every subscriber observes exactly M
//!  events per tenant in monotonic sequence order."
//!
//! Uses a shared embedded authz engine; opens N broadcast receivers per
//! tenant before any writes, performs M writes, then drains each receiver
//! with a bounded deadline to assert completeness and ordering.

use std::sync::Arc;
use std::time::Duration;

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite, WatchFilter,
};
use hearth::core::TenantId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use proptest::prelude::*;
use tokio::runtime::Runtime;

/// Builds an authz engine on a fresh tempdir.
fn setup_engine() -> (tempfile::TempDir, Arc<EmbeddedAuthzEngine>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open storage");
    let engine = EmbeddedAuthzEngine::new(Arc::new(storage), AuthzConfig::default());
    (dir, Arc::new(engine))
}

/// Synthesises a deterministic tuple from an integer seed.
fn make_tuple(seed: u32) -> RelationshipTuple {
    let obj = ObjectRef::new("document", &format!("doc{seed}")).expect("valid object");
    let subj = SubjectRef::direct("user", &format!("user{seed}")).expect("valid subject");
    RelationshipTuple::new(obj, "viewer", subj).expect("valid tuple")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    /// For every tenant used in a run: N concurrent subscribers all observe
    /// the exact set of writes performed against that tenant, in the order
    /// write_tuples() dispatched them (monotonic by sequence).
    #[test]
    fn concurrent_watchers_receive_all_writes(
        num_subscribers in 2u32..6,
        num_writes in 4u32..20,
        num_tenants in 1u32..=3,
    ) {
        let rt = Runtime::new().expect("tokio runtime");
        let (_dir, engine) = setup_engine();

        // Pre-allocate tenants so watchers and writers refer to the same ids.
        let tenants: Vec<TenantId> = (0..num_tenants).map(|_| TenantId::generate()).collect();

        // Subscribe N receivers per tenant BEFORE any writes so no event is missed.
        // watch() must be called on the tokio runtime (it only uses sync APIs
        // internally but we keep the runtime-bound convention).
        let subscribers: Vec<(TenantId, Vec<hearth::authz::WatchReceiver>)> = rt.block_on(async {
            let mut result = Vec::with_capacity(tenants.len());
            for tenant in &tenants {
                let mut rxs = Vec::with_capacity(num_subscribers as usize);
                for _ in 0..num_subscribers {
                    let rx = engine
                        .watch(tenant, &WatchFilter { object_type: None }, None)
                        .expect("watch");
                    rxs.push(rx);
                }
                result.push((tenant.clone(), rxs));
            }
            result
        });

        // Perform M writes, round-robin across tenants so each tenant gets a
        // predictable slice of the total M writes.
        let mut expected_per_tenant: std::collections::HashMap<TenantId, Vec<u64>> =
            std::collections::HashMap::new();
        for tenant in &tenants {
            expected_per_tenant.insert(tenant.clone(), Vec::new());
        }

        for i in 0..num_writes {
            let tenant = &tenants[(i as usize) % tenants.len()];
            let tuple = make_tuple(i);
            let token = engine
                .write_tuples(tenant, &[TupleWrite::Touch(tuple)])
                .expect("write");
            expected_per_tenant
                .get_mut(tenant)
                .expect("tenant present")
                .push(token.version());
        }

        // Drain each receiver with a bounded deadline and assert invariants.
        rt.block_on(async {
            for (tenant, rxs) in subscribers {
                let expected = expected_per_tenant
                    .get(&tenant)
                    .expect("tenant present")
                    .clone();

                for mut rx in rxs {
                    let mut observed: Vec<u64> = Vec::with_capacity(expected.len());
                    for _ in 0..expected.len() {
                        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                            .await
                            .expect("timeout waiting for watch event")
                            .expect("channel closed before receiving all events");
                        observed.push(event.sequence);
                    }

                    prop_assert_eq!(
                        observed.len(),
                        expected.len(),
                        "subscriber must observe every event for its tenant"
                    );

                    // Monotonic sequence ordering — strictly increasing, matches dispatch order.
                    for win in observed.windows(2) {
                        prop_assert!(
                            win[0] < win[1],
                            "watch events must be delivered in strictly increasing sequence order"
                        );
                    }

                    prop_assert_eq!(
                        observed,
                        expected.clone(),
                        "subscriber's observed sequence set must equal writes-for-tenant set"
                    );
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}
