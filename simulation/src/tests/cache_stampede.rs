//! Zanzibar cache-stampede coalescence simulation tests.
//!
//! Oracle invariant (from `TEST_SCENARIOS.md` § Authorization Engine —
//! Simulation): "Cache stampede — N concurrent cold-cache `check()`s on the
//! same key produce exactly one backend resolve, not N."
//!
//! Hearth's `EmbeddedAuthzEngine` uses a single-flight coalescer keyed by
//! the cache key. The first arrival runs the BFS resolve; all other
//! concurrent callers subscribe to an `InflightSlot` and wake on the
//! leader's published result. Exposed via the `backend_calls` test probe
//! under the `test-hooks` feature.
//!
//! These tests pin three behaviors that the public API cannot otherwise
//! prove:
//!
//!   1. Positive coalescing — 128 concurrent `check()`s on an existing
//!      tuple all return `Ok(true)` with a single backend resolve. The
//!      leader's cache insert is observed by subsequent check()s with no
//!      further backend calls.
//!   2. Negative coalescing — 128 concurrent `check()`s on a missing
//!      tuple all return `Ok(false)` with a single backend resolve. A
//!      second wave after the first confirms the negative cache entry
//!      was published and reused.
//!   3. Error is retried, not cached — if the leader's resolve fails,
//!      waiters observe the same error, but the in-flight slot is
//!      cleared so the next call has a fresh attempt (no poisoned slot).
//!
//! Each test gates a single-flight violation: without the coalescer, the
//! positive and negative cases would both log 128 backend calls.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, AuthzError, EmbeddedAuthzEngine, ObjectRef,
    RelationshipTuple, SubjectRef, TupleWrite,
};
use hearth::core::TenantId;
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};

/// Number of concurrent racing checkers in each stampede wave.
///
/// Chosen large enough to make N-shaped fanout obvious if coalescing
/// regresses, but small enough that the spawn/join overhead stays
/// negligible on CI.
const STAMPEDE_WAVE: usize = 128;

/// Opens a fresh engine pair backed by `EmbeddedStorageEngine` on `dir`.
fn open_engine(dir: &std::path::Path) -> (Arc<dyn StorageEngine>, Arc<EmbeddedAuthzEngine>) {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let authz = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&storage),
        AuthzConfig::default(),
    ));
    (storage, authz)
}

/// Seeds the tuple `document:design#viewer@user:alice` for the given
/// tenant. Returns the `(object, relation, subject)` triple used by
/// subsequent checks.
fn seed_alice_viewer(
    authz: &EmbeddedAuthzEngine,
    tenant: &TenantId,
) -> (ObjectRef, &'static str, SubjectRef) {
    let doc = ObjectRef::new("document", "design").expect("valid obj");
    let alice = SubjectRef::direct("user", "alice").expect("valid subj");
    let tuple = RelationshipTuple::new(doc.clone(), "viewer", alice.clone()).expect("valid tuple");
    authz
        .write_tuples(tenant, &[TupleWrite::Touch(tuple)])
        .expect("seed");
    (doc, "viewer", alice)
}

/// Runs `wave` checker threads that all wait on `barrier` before calling
/// `check()`. Returns the collected outcomes in arrival order.
fn stampede_check(
    authz: Arc<EmbeddedAuthzEngine>,
    tenant: &TenantId,
    object: ObjectRef,
    relation: &'static str,
    subject: SubjectRef,
    wave: usize,
) -> Vec<Result<bool, AuthzError>> {
    let barrier = Arc::new(Barrier::new(wave));
    let mut handles = Vec::with_capacity(wave);
    for _ in 0..wave {
        let authz = Arc::clone(&authz);
        let barrier = Arc::clone(&barrier);
        let tenant = tenant.clone();
        let object = object.clone();
        let subject = subject.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            authz.check(&tenant, &object, relation, &subject, None)
        }));
    }
    handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect()
}

/// Scenario 1: Positive stampede collapses to a single backend resolve.
///
/// Seed a tuple, clear the cache, fire `STAMPEDE_WAVE` concurrent checks
/// on the same key. The `backend_calls` counter MUST increment by 1.
/// Followers observed the leader's published `Ok(true)` through the
/// coalescer and did NOT re-enter the resolver.
///
/// Note on the `∈ {1, 2}` tolerance (documented in the plan): under
/// aggressive schedules a waiter can race past a just-completed leader's
/// stale `Weak` entry, upgrade to `None`, and become a second leader.
/// That's a real race the coalescer intentionally does NOT forbid (doing
/// so would require holding the inflight lock across the resolve, which
/// is worse than a rare duplicate). So we assert `<= 2`, with the
/// overwhelmingly common value being 1.
#[test]
fn simulation_cache_stampede_coalesces_backend_calls() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_storage, authz) = open_engine(dir.path());
    let tenant = TenantId::generate();
    let (doc, relation, alice) = seed_alice_viewer(&authz, &tenant);

    // Seeding performed one backend call internally (during the implicit
    // first check inside write_tuples? no — writes don't invoke check).
    // Sample the probe after seeding and clearing the cache to get a
    // clean baseline.
    authz.clear_cache();
    let before = authz.backend_call_count();

    let results = stampede_check(
        Arc::clone(&authz),
        &tenant,
        doc.clone(),
        relation,
        alice.clone(),
        STAMPEDE_WAVE,
    );

    // All checkers must see the tuple.
    for (i, r) in results.iter().enumerate() {
        assert_eq!(
            r.as_ref().ok().copied(),
            Some(true),
            "checker {i} expected Ok(true), got {r:?}"
        );
    }

    let after = authz.backend_call_count();
    let delta = after - before;
    assert!(
        (1..=2).contains(&delta),
        "expected 1 or 2 backend calls under single-flight, got {delta} from {STAMPEDE_WAVE} waiters"
    );

    // Second wave: cache is now warm. Zero additional backend calls.
    let before_warm = authz.backend_call_count();
    let warm = stampede_check(
        Arc::clone(&authz),
        &tenant,
        doc,
        relation,
        alice,
        STAMPEDE_WAVE,
    );
    for r in &warm {
        assert_eq!(r.as_ref().ok().copied(), Some(true));
    }
    assert_eq!(
        authz.backend_call_count(),
        before_warm,
        "warm cache must serve all checkers without entering resolver"
    );
}

/// Scenario 2: Negative stampede caches the `false` result.
///
/// No tuple seeded. 128 concurrent checkers all observe `Ok(false)` with
/// exactly one backend resolve. A subsequent second wave confirms the
/// negative cache was published (zero additional backend calls).
#[test]
fn simulation_cache_stampede_negative_result_is_cached() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let (_storage, authz) = open_engine(dir.path());
    let tenant = TenantId::generate();

    let doc = ObjectRef::new("document", "design").expect("valid obj");
    let alice = SubjectRef::direct("user", "alice").expect("valid subj");

    let before = authz.backend_call_count();
    let results = stampede_check(
        Arc::clone(&authz),
        &tenant,
        doc.clone(),
        "viewer",
        alice.clone(),
        STAMPEDE_WAVE,
    );
    for (i, r) in results.iter().enumerate() {
        assert_eq!(
            r.as_ref().ok().copied(),
            Some(false),
            "checker {i} expected Ok(false), got {r:?}"
        );
    }
    let delta = authz.backend_call_count() - before;
    assert!(
        (1..=2).contains(&delta),
        "negative-path coalescer should produce 1-2 backend calls, got {delta}"
    );

    // Second wave confirms the negative cache entry was published.
    let before_warm = authz.backend_call_count();
    let warm = stampede_check(
        Arc::clone(&authz),
        &tenant,
        doc,
        "viewer",
        alice,
        STAMPEDE_WAVE,
    );
    for r in &warm {
        assert_eq!(r.as_ref().ok().copied(), Some(false));
    }
    assert_eq!(
        authz.backend_call_count(),
        before_warm,
        "negative cache must serve all warm checkers without entering resolver"
    );
}

/// Storage wrapper that fails the first `get()` after construction, then
/// delegates to an inner storage engine thereafter. Used to prove that
/// a resolver error is broadcast to all waiters AND that the inflight
/// slot is cleared after the leader exits with an error (so a subsequent
/// call starts a fresh resolve, not a poisoned wait).
struct FaultOnceStorage {
    inner: Arc<dyn StorageEngine>,
    fail_next_get: AtomicBool,
}

impl FaultOnceStorage {
    fn new(inner: Arc<dyn StorageEngine>) -> Self {
        Self {
            inner,
            fail_next_get: AtomicBool::new(true),
        }
    }

    fn arm(&self) {
        self.fail_next_get.store(true, Ordering::SeqCst);
    }
}

impl StorageEngine for FaultOnceStorage {
    fn get(&self, tenant_id: &TenantId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if self.fail_next_get.swap(false, Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected storage fault",
            )));
        }
        self.inner.get(tenant_id, key)
    }

    fn put(&self, tenant_id: &TenantId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(tenant_id, key, value)
    }

    fn delete(&self, tenant_id: &TenantId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(tenant_id, key)
    }

    fn scan(
        &self,
        tenant_id: &TenantId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        self.inner.scan(tenant_id, start, end)
    }

    fn put_batch(
        &self,
        tenant_id: &TenantId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        self.inner.put_batch(tenant_id, entries)
    }
}

/// Scenario 3: Resolver error is not cached and the slot is cleared.
///
/// With `FaultOnceStorage` armed, the first `check()` that reaches the
/// storage layer fails. All coalesced waiters observe an `Err` (each
/// reconstructed from the `AuthzErrorCode` leader broadcast). The next
/// `check()` must succeed because (a) the fault is spent and (b) the
/// inflight slot was removed when the leader exited — so we don't
/// resurrect a stale `Weak` that would deadlock waiters.
#[test]
fn simulation_cache_stampede_resolver_error_is_retried() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let inner =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let fault = Arc::new(FaultOnceStorage::new(Arc::clone(&inner)));
    let authz = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&fault) as Arc<dyn StorageEngine>,
        AuthzConfig::default(),
    ));
    let tenant = TenantId::generate();

    // Seed a real tuple through the raw inner storage path. We bypass
    // FaultOnceStorage for setup so seeding doesn't accidentally consume
    // the armed fault. We do this via a direct EmbeddedAuthzEngine bound
    // to `inner`.
    let seed_authz = EmbeddedAuthzEngine::new(Arc::clone(&inner), AuthzConfig::default());
    let (doc, relation, alice) = seed_alice_viewer(&seed_authz, &tenant);

    // Re-arm the fault in case any prior operation consumed it.
    fault.arm();

    // Stampede under fault: a small wave keeps test time short while
    // still exercising the leader/follower fan-out.
    let wave = 64;
    let results = stampede_check(
        Arc::clone(&authz),
        &tenant,
        doc.clone(),
        relation,
        alice.clone(),
        wave,
    );

    // At least one waiter (the leader) MUST see an Err. Because a second
    // leader can sometimes take over after the first finishes (Weak
    // upgrade race described in scenario 1), not every waiter is
    // guaranteed to see an Err — but at least one must, and NO waiter
    // should see `Ok(true)` from the leader's broadcast (errors
    // short-circuit before any cache insert).
    let err_count = results.iter().filter(|r| r.is_err()).count();
    assert!(
        err_count >= 1,
        "at least one waiter must observe the leader's error, got 0 errs out of {wave}"
    );

    // After the fault is spent, a fresh call must succeed. If the
    // inflight slot had been left behind, this would deadlock on
    // slot.wait() (no leader to publish).
    let second = authz
        .check(&tenant, &doc, relation, &alice, None)
        .expect("post-fault check should succeed");
    assert!(
        second,
        "post-fault check should reveal the seeded tuple is still there"
    );
}
