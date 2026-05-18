//! Test harness integration tests.
//!
//! Covers `TEST_SCENARIOS.md` § Test Infrastructure:
//! 1. Embedded mode starts and stops cleanly
//! 2. Dual-mode pattern: same logic runs against embedded mode
//! 3. Server mode returns `ServerNotAvailable` until the HTTP harness is wired

mod common;

use common::{HarnessMode, TestHarness, TestHarnessError};
use hearth::core::RealmId;

/// Scenario 1: Embedded mode starts with isolated temp dir and stops cleanly.
#[tokio::test]
async fn embedded_mode_starts_and_stops_cleanly() {
    let harness = TestHarness::embedded()
        .await
        .expect("embedded harness should start");

    assert_eq!(harness.mode(), HarnessMode::Embedded);
    assert!(
        harness.base_url().is_none(),
        "embedded mode has no base URL"
    );

    // Verify storage is functional with a basic round-trip
    let realm = RealmId::generate();
    harness
        .storage()
        .put(&realm, b"harness-key", b"harness-value")
        .expect("put should succeed");
    let val = harness
        .storage()
        .get(&realm, b"harness-key")
        .expect("get should succeed");
    assert_eq!(val, Some(b"harness-value".to_vec()));

    // Drop triggers cleanup — temp dir removed automatically
    drop(harness);
}

/// Scenario 2: Dual-mode pattern — same async test logic runs against embedded mode.
#[tokio::test]
async fn dual_mode_embedded() {
    run_dual_mode_assertions(
        TestHarness::embedded()
            .await
            .expect("embedded harness should start"),
    )
    .await;
}

/// Shared test logic for the dual-mode pattern.
#[allow(clippy::unused_async)]
async fn run_dual_mode_assertions(harness: TestHarness) {
    let realm = RealmId::generate();

    // Write
    harness
        .storage()
        .put(&realm, b"dual-key", b"dual-value")
        .expect("put should succeed in any mode");

    // Read back
    let val = harness
        .storage()
        .get(&realm, b"dual-key")
        .expect("get should succeed in any mode");
    assert_eq!(val, Some(b"dual-value".to_vec()));

    // Delete
    harness
        .storage()
        .delete(&realm, b"dual-key")
        .expect("delete should succeed in any mode");

    // Confirm deleted
    let val = harness
        .storage()
        .get(&realm, b"dual-key")
        .expect("get after delete should succeed");
    assert_eq!(val, None, "deleted key should return None");
}

/// Validates that server mode correctly returns `ServerNotAvailable` error
/// when the HTTP layer is not yet implemented.
#[tokio::test]
async fn server_mode_returns_not_available() {
    let err = TestHarness::server()
        .await
        .expect_err("server mode should fail until HTTP layer exists");
    assert!(
        matches!(err, TestHarnessError::ServerNotAvailable),
        "error should be ServerNotAvailable, got: {err}"
    );
}
