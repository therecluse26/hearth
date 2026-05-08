//! Black-box integration tests for periodic cleanup via the
//! `IdentityEngine` trait. Verifies that `sweep_expired()` is wired
//! correctly through the trait → engine → cleanup module → storage path.

mod common;

#[tokio::test]
async fn sweep_expired_on_empty_realm_returns_zero() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_id = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "cleanup-test".into(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let stats = harness
        .identity()
        .sweep_expired(&realm_id)
        .expect("sweep_expired");

    assert_eq!(stats.total_deleted(), 0);
    assert_eq!(stats.errors, 0);
}

#[tokio::test]
async fn sweep_expired_does_not_error_on_deleted_realm_id() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    // Use a non-existent realm ID — sweep should still succeed with zero deletions.
    let fake_realm = hearth::core::RealmId::generate();

    let stats = harness
        .identity()
        .sweep_expired(&fake_realm)
        .expect("sweep_expired on unknown realm");

    assert_eq!(stats.total_deleted(), 0);
}
