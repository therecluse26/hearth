//! Multi-tenancy crash-recovery simulation tests.
//!
//! Oracle invariant (from `TEST_SCENARIOS.md` § Multi-Tenancy — Simulation):
//! "Crash during cascading tenant deletion — recovery completes deletion or
//!  fully rolls back."
//!
//! Hearth's `delete_tenant` does not transactionally group the 11-step
//! cascade, so the invariant we can reasonably enforce is the stronger of the
//! two: a subsequent call MUST converge to "no residue anywhere" even when a
//! prior invocation crashed mid-way. This is the contract the idempotency
//! changes in `identity::engine::delete_tenant` were introduced to maintain.
//!
//! Rather than wiring fault injection into a custom `StorageEngine`, we
//! simulate the post-crash state directly: after seeding data we drop the
//! identity engine, reopen storage at the leaf level, and surgically delete a
//! subset of keys. This produces the exact durable states a real crash could
//! leave behind without introducing a new test framework.

use std::sync::Arc;

use hearth::authz::{
    AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, RelationshipTuple,
    SubjectRef, TupleWrite,
};
use hearth::core::{Clock, SystemClock, TenantId};
use hearth::identity::{
    CreateTenantRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    IdentityError,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Keys for the system tenant. Derived from `src/identity/keys.rs` so the
/// simulation doesn't need to depend on internal `pub(crate)` helpers.
fn system_tenant_id() -> TenantId {
    TenantId::new(uuid::Uuid::nil())
}

fn tenant_record_key(tenant_id: &TenantId) -> Vec<u8> {
    format!("tenant:id:{}", tenant_id.as_uuid()).into_bytes()
}

/// Cascade key prefixes — every byte sequence that should be empty for a
/// fully-deleted tenant. Mirrors the exact strings declared in
/// `src/identity/keys.rs`; a future addition there that forgets to wire a new
/// prefix into `delete_tenant` will leak residue and fail this test.
const CASCADE_PREFIXES: &[&[u8]] = &[
    b"usr:id:",
    b"usr:email:",
    b"ses:id:",
    b"ses:user:",
    b"cred:user:",
    b"oauth:client:",
    b"oauth:code:",
    b"oauth:family:",
    b"oauth:device:",
    b"oauth:ucode:",
    b"oauth:revjti:",
    b"rel:",
    b"mfa:totp:",
    b"webauthn:cred:",
    b"webauthn:disc:",
    b"magic:link:",
];

/// Builds a fresh identity + authz engine pair backed by shared storage on
/// the given directory. Reopen semantics: a second call on the same dir
/// recovers from WAL, mimicking a process restart after a crash.
fn open_engines(
    dir: &std::path::Path,
) -> (
    Arc<dyn StorageEngine>,
    EmbeddedIdentityEngine,
    EmbeddedAuthzEngine,
) {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let identity = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
    )
    .expect("identity engine");
    let authz = EmbeddedAuthzEngine::new(Arc::clone(&storage), AuthzConfig::default());
    (storage, identity, authz)
}

/// Seeds N users, a few tuples, and an OAuth client into the tenant so the
/// cascade has real work to do. Returns the tenant id.
fn seed_tenant(identity: &EmbeddedIdentityEngine, authz: &EmbeddedAuthzEngine) -> TenantId {
    let tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "crash-sim-tenant".to_string(),
            config: None,
        })
        .expect("create tenant");
    let tenant_id = tenant.id().clone();

    for i in 0..5 {
        identity
            .create_user(
                &tenant_id,
                &CreateUserRequest {
                    email: format!("user-{i}@crash.example.com"),
                    display_name: format!("Crash User {i}"),
                },
            )
            .expect("create user");
    }

    for i in 0..3 {
        let obj = ObjectRef::new("document", &format!("doc{i}")).expect("object");
        let subj = SubjectRef::direct("user", &format!("user{i}")).expect("subject");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("tuple");
        authz
            .write_tuples(&tenant_id, &[TupleWrite::Touch(tuple)])
            .expect("write tuple");
    }

    tenant_id
}

/// Counts every residual key for `tenant_id` across all cascade prefixes.
/// A completed deletion leaves this at zero.
fn count_residual_keys(storage: &dyn StorageEngine, tenant_id: &TenantId) -> usize {
    let mut total = 0usize;
    for prefix in CASCADE_PREFIXES {
        let end = prefix_end(prefix);
        let entries = storage
            .scan(tenant_id, prefix, &end)
            .expect("scan cascade prefix");
        total += entries.len();
    }
    total
}

/// End-of-range sentinel for a prefix scan. Matches `identity::keys::prefix_end`
/// by incrementing the final byte, which gives the exclusive upper bound used
/// by the production cascade.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Crash AFTER tenant-record deletion but BEFORE cascade cleanup completes.
///
/// This is the scenario the idempotency fix was designed for: the tenant
/// record is gone (so the old `get_tenant()?.ok_or(TenantNotFound)` check
/// would bail out) yet downstream keyspaces still hold orphaned data. A
/// second `delete_tenant` call must fully clean the residue rather than
/// returning `TenantNotFound`.
#[test]
fn simulation_crash_after_record_deletion_cleans_residue() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Phase 1: seed a full tenant, then crash-simulate by deleting only the
    // tenant record. This mirrors the durable state after a crash between
    // "delete tenant record" and "delete cascade keys" in an alternate
    // cascade ordering, or after a future transactional rewrite where the
    // record commit lands before cascade commits replay from the WAL.
    let tenant_id = {
        let (storage, identity, authz) = open_engines(dir.path());
        let tid = seed_tenant(&identity, &authz);

        // Surgical "crash": delete just the tenant record, leave everything
        // else (users, tuples, oauth clients, signing key) in place.
        storage
            .delete(&system_tenant_id(), &tenant_record_key(&tid))
            .expect("delete tenant record");

        // Sanity check: cascade data is still present.
        assert!(
            count_residual_keys(storage.as_ref(), &tid) > 0,
            "expected residual cascade data after simulated crash"
        );

        tid
    };

    // Phase 2: reopen (WAL replay) and re-run delete_tenant. The fix guarantees
    // this converges even though get_tenant() now returns None.
    {
        let (storage, identity, _authz) = open_engines(dir.path());
        identity
            .delete_tenant(&tenant_id)
            .expect("idempotent delete after crash");

        let residual = count_residual_keys(storage.as_ref(), &tenant_id);
        assert_eq!(
            residual, 0,
            "expected zero residual cascade keys after recovery, found {residual}"
        );
    }
}

/// Crash DURING cascade with tenant record still present.
///
/// Seed, partially delete users via the storage API (mimicking a crash after
/// some but not all cascade steps), then re-run delete_tenant. The second
/// call must converge to zero residue.
#[test]
fn simulation_crash_mid_cascade_record_intact() {
    let dir = tempfile::tempdir().expect("tempdir");

    let tenant_id = {
        let (storage, identity, authz) = open_engines(dir.path());
        let tid = seed_tenant(&identity, &authz);

        // Simulate a crash after deleting SOME but not all users — the oauth
        // clients, tuples, and remaining users still exist. Here we walk the
        // user prefix and delete the first two entries only.
        let start = b"usr:id:".to_vec();
        let end = prefix_end(&start);
        let users = storage.scan(&tid, &start, &end).expect("scan users");
        for entry in users.iter().take(2) {
            storage
                .delete(&tid, &entry.key)
                .expect("delete partial user");
        }

        assert!(
            count_residual_keys(storage.as_ref(), &tid) > 0,
            "residual data must remain after partial cascade"
        );
        tid
    };

    {
        let (storage, identity, _authz) = open_engines(dir.path());
        identity
            .delete_tenant(&tenant_id)
            .expect("complete cascade on retry");
        assert_eq!(
            count_residual_keys(storage.as_ref(), &tenant_id),
            0,
            "cascade must be fully cleaned on retry"
        );
    }
}

/// Calling delete_tenant for a tenant that never existed still errors out.
///
/// Guards the `TenantNotFound` contract: the idempotency fix only changes
/// behavior when cascade residue exists — a truly unknown tenant id must
/// remain an error so callers don't silently mask bugs.
#[test]
fn simulation_delete_unknown_tenant_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_storage, identity, _authz) = open_engines(dir.path());

    let unknown = TenantId::generate();
    let err = identity
        .delete_tenant(&unknown)
        .expect_err("unknown tenant must error");
    assert!(
        matches!(err, IdentityError::TenantNotFound),
        "expected TenantNotFound, got {err:?}"
    );
}
