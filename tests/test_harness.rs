//! Test harness integration tests.
//!
//! Covers `TEST_SCENARIOS.md` § Test Infrastructure:
//! 1. Embedded mode starts and stops cleanly
//! 2. Server mode starts and stops cleanly (ignored until HTTP layer)
//! 3. Dual-mode pattern: same logic runs against both modes
//! 4. Server-mode tests are `#[ignore]`-tagged (validated by #2 and #3)

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

/// Scenario 2: Server mode starts on random port, accepts connections, stops cleanly.
///
/// Ignored until the HTTP/protocol layer is implemented.
#[tokio::test]
#[ignore = "HTTP layer not yet implemented"]
async fn server_mode_starts_and_stops_cleanly() {
    let harness = TestHarness::server()
        .await
        .expect("server harness should start");

    assert_eq!(harness.mode(), HarnessMode::Server);
    assert!(
        harness.base_url().is_some(),
        "server mode should have a base URL"
    );

    // Verify storage accessible through server
    let realm = RealmId::generate();
    harness
        .storage()
        .put(&realm, b"server-key", b"server-value")
        .expect("put should succeed");
    let val = harness
        .storage()
        .get(&realm, b"server-key")
        .expect("get should succeed");
    assert_eq!(val, Some(b"server-value".to_vec()));

    drop(harness);
}

/// Scenario 3: Dual-mode pattern — same async test logic runs against embedded mode.
///
/// Demonstrates the dual-mode testing pattern where identical assertions
/// run against both embedded and server harnesses.
#[tokio::test]
async fn dual_mode_embedded() {
    run_dual_mode_assertions(
        TestHarness::embedded()
            .await
            .expect("embedded harness should start"),
    )
    .await;
}

/// Scenario 3: Dual-mode pattern — same async test logic runs against server mode.
///
/// Ignored until the HTTP/protocol layer is implemented.
#[tokio::test]
#[ignore = "HTTP layer not yet implemented"]
async fn dual_mode_server() {
    run_dual_mode_assertions(
        TestHarness::server()
            .await
            .expect("server harness should start"),
    )
    .await;
}

/// Shared test logic for the dual-mode pattern.
///
/// This function contains assertions that must hold regardless of whether
/// the harness is running in embedded or server mode.
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
    let result = TestHarness::server().await;
    assert!(
        result.is_err(),
        "server mode should fail until HTTP layer exists"
    );
    let err = result.expect_err("server mode should return error");
    assert!(
        matches!(err, TestHarnessError::ServerNotAvailable),
        "error should be ServerNotAvailable, got: {err}"
    );
}
