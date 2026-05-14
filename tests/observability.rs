//! Black-box fault-injection tests for the observability endpoints.
//!
//! Covers `/healthz` (liveness), `/readyz` (readiness), and `/metrics`
//! (Prometheus scrape) under normal and failure conditions.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, CreateAuditEvent};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine};
use hearth::protocol::http::{router, AppState};
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};
use tower::ServiceExt as _;

// ── Fault-injectable storage wrapper ─────────────────────────────────────────

/// Delegates all operations to a real storage engine until `block_reads` is
/// set to `true`, after which every `get()` returns an I/O error.
///
/// Used to let the identity engine initialise normally (seeding the system
/// realm requires successful reads) and then drive `is_storage_healthy()` to
/// return `false` on demand.
struct PartialFaultEngine {
    inner: Arc<EmbeddedStorageEngine>,
    block_reads: Arc<AtomicBool>,
}

impl StorageEngine for PartialFaultEngine {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if self.block_reads.load(Ordering::Relaxed) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected storage fault",
            )));
        }
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        self.inner.scan(realm_id, start, end)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn body_to_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body bytes");
    String::from_utf8(bytes.to_vec()).expect("UTF-8 body")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `/healthz` (liveness probe) MUST return `200 OK` unconditionally.
#[tokio::test]
async fn healthz_returns_200_always() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp).await;
    assert!(
        body.contains("\"ok\""),
        "healthz body should contain ok; got: {body}"
    );
}

/// `/readyz` returns `200 OK` when storage is accessible.
#[tokio::test]
async fn readyz_returns_200_when_storage_healthy() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp).await;
    assert!(
        body.contains("ready"),
        "body should indicate ready state; got: {body}"
    );
}

/// `/readyz` returns `503 Service Unavailable` when the storage probe errors.
///
/// A `PartialFaultEngine` wrapper lets the identity engine initialise
/// normally (seeding the system realm requires working writes + reads) before
/// fault injection is enabled.
#[tokio::test]
async fn readyz_returns_503_when_storage_unhealthy() {
    let h = common::TestHarness::embedded().await.expect("harness");

    // Back the fault engine with a real on-disk store so seeding succeeds.
    let fault_dir = tempfile::tempdir().expect("tempdir for fault storage");
    let real_storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(fault_dir.path().to_path_buf()))
            .expect("open fault storage"),
    );
    let block_reads = Arc::new(AtomicBool::new(false));
    let fault_storage: Arc<dyn StorageEngine> = Arc::new(PartialFaultEngine {
        inner: Arc::clone(&real_storage),
        block_reads: Arc::clone(&block_reads),
    });

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };

    // Construct with reads enabled — seeding the system realm succeeds.
    let identity = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&fault_storage),
        clock,
        config,
        h.rbac_arc(),
        h.audit_arc(),
    )
    .expect("identity engine creation");
    let identity: Arc<dyn IdentityEngine> = Arc::new(identity);

    // Enable fault: all subsequent `get()` calls now return an I/O error.
    block_reads.store(true, Ordering::Relaxed);

    let state = Arc::new(AppState::new(identity, h.rbac_arc(), h.audit_arc()));
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_to_string(resp).await;
    assert!(
        body.contains("unavailable"),
        "body should indicate storage unavailable; got: {body}"
    );
}

/// `/metrics` reflects counter increments: after a token issuance the
/// `hearth_tokens_issued_total` time series appears in the scrape output.
#[tokio::test]
async fn metrics_tokens_issued_counter_increments() {
    let h = common::TestHarness::embedded().await.expect("harness");

    // Use a unique realm label so this counter label does not appear before
    // this test increments it, regardless of other tests in the same process.
    let realm_label = format!("obs-tok-{}", RealmId::generate().as_uuid());

    let app = build_app(&h);

    // Snapshot before: the unique realm label must not appear yet.
    let before = body_to_string(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("response"),
    )
    .await;
    assert!(
        !before.contains(&realm_label),
        "realm label must not appear before increment"
    );

    // Increment — mirrors what the HTTP token endpoint does internally.
    hearth::metrics::metrics()
        .tokens_issued_total
        .with_label_values(&[realm_label.as_str(), "authorization_code"])
        .inc();

    // Snapshot after: the label and metric family must now be present.
    let after = body_to_string(
        app.oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response"),
    )
    .await;
    assert!(
        after.contains("hearth_tokens_issued_total"),
        "/metrics should expose the tokens_issued_total family"
    );
    assert!(
        after.contains(&realm_label),
        "realm label should appear after increment"
    );
}

/// Tampering with the audit chain causes `verify_integrity` to detect the
/// mismatch and increment `hearth_audit_integrity_failures_total`, which
/// surfaces in the `/metrics` scrape output.
#[tokio::test]
async fn metrics_audit_integrity_failure_increments() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();

    // Baseline — read before the test so the assertion stays valid even if
    // other parallel tests also increment this global counter.
    let failures_before = hearth::metrics::metrics()
        .audit_integrity_failures_total
        .get();

    // Append one real event to create a non-empty chain.
    h.audit()
        .append(&CreateAuditEvent {
            realm_id: realm.clone(),
            actor: "test_actor".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "obs-test-user".to_string(),
            metadata: None,
        })
        .expect("append audit event");

    // Tamper: scan raw storage to find the event entry, then overwrite its
    // `integrity_hash` with a bogus value.
    //
    // Key format: `audit:evt:{timestamp_19d}:{uuid}`
    // ';' (0x3B) is one byte past ':' (0x3A), bounding the scan to this prefix.
    let entries = h
        .storage()
        .scan(&realm, b"audit:evt:", b"audit:evt;")
        .expect("scan audit event keys");
    assert!(
        !entries.is_empty(),
        "should have at least one stored audit event"
    );

    let mut event_json: serde_json::Value =
        serde_json::from_slice(&entries[0].value).expect("deserialize stored event");
    event_json["integrity_hash"] =
        serde_json::json!("tampered_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    let tampered = serde_json::to_vec(&event_json).expect("reserialize tampered event");

    h.storage()
        .put(&realm, &entries[0].key, &tampered)
        .expect("write tampered event back to storage");

    // `verify_integrity` must detect the mismatch and return `false`.
    let ok = h
        .audit()
        .verify_integrity(&realm, None, None)
        .expect("verify_integrity should not I/O-error on tampered data");
    assert!(
        !ok,
        "verify_integrity should return false for tampered chain"
    );

    // The counter must have gone up by at least one.
    let failures_after = hearth::metrics::metrics()
        .audit_integrity_failures_total
        .get();
    assert!(
        failures_after > failures_before,
        "audit integrity failure counter should increment: before={failures_before}, after={failures_after}"
    );

    // The metric must also appear in the HTTP scrape output.
    let app = build_app(&h);
    let metrics_body = body_to_string(
        app.oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response"),
    )
    .await;
    assert!(
        metrics_body.contains("hearth_audit_integrity_failures_total"),
        "/metrics should expose the audit integrity failures counter"
    );
}
