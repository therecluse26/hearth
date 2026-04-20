//! Integration tests for realm reconciliation.
//!
//! Tests the `reconcile_realms()` function which syncs YAML-declared
//! realms with storage on startup.

mod common;

use std::collections::HashMap;

use hearth::config::{AuthConfig, Config, RealmYamlConfig};
use hearth::identity::reconcile::reconcile_realms;
use hearth::identity::{CreateRealmRequest, RealmConfig, RealmStatus};

/// Helper: builds a minimal `Config` with the given realms map.
fn config_with_realms(realms: Option<HashMap<String, RealmYamlConfig>>) -> Config {
    let mut config = Config::dev();
    config.realms = realms;
    config
}

// ===== Scenario 1: Default realm creation when no realms key =====

#[tokio::test]
async fn creates_default_realm_when_no_yaml_and_no_storage() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let config = config_with_realms(None);
    let report = reconcile_realms(identity, &config).expect("reconcile");

    assert_eq!(report.created, vec!["default"]);
    assert!(report.updated.is_empty());
    assert!(report.archived.is_empty());

    // Verify realm exists
    let realm = identity
        .get_realm_by_name("default")
        .expect("get_realm_by_name")
        .expect("default realm should exist");
    assert_eq!(realm.name(), "default");
    assert_eq!(realm.status(), RealmStatus::Active);
}

// ===== Scenario 2: Backward compat — existing realms preserved =====

#[tokio::test]
async fn skips_reconciliation_when_realms_exist_and_no_yaml_key() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Pre-create a realm
    identity
        .create_realm(&CreateRealmRequest {
            name: "existing".to_string(),
            config: None,
        })
        .expect("create existing realm");

    let config = config_with_realms(None);
    let report = reconcile_realms(identity, &config).expect("reconcile");

    // Should not create "default" or touch existing
    assert!(report.created.is_empty());
    assert!(report.updated.is_empty());
    assert!(report.archived.is_empty());

    // Existing realm still there
    assert!(identity
        .get_realm_by_name("existing")
        .expect("get")
        .is_some());
}

// ===== Scenario 3: Create new realm from YAML =====

#[tokio::test]
async fn creates_realm_from_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let mut realms = HashMap::new();
    realms.insert("portal".to_string(), RealmYamlConfig::default());

    let config = config_with_realms(Some(realms));
    let report = reconcile_realms(identity, &config).expect("reconcile");

    assert_eq!(report.created, vec!["portal"]);

    let realm = identity
        .get_realm_by_name("portal")
        .expect("get")
        .expect("portal should exist");
    assert_eq!(realm.status(), RealmStatus::Active);
}

// ===== Scenario 4: Update existing realm config from YAML =====

#[tokio::test]
async fn updates_realm_config_from_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Pre-create a realm with old config
    identity
        .create_realm(&CreateRealmRequest {
            name: "portal".to_string(),
            config: Some(RealmConfig {
                session_ttl_micros: Some(3_600_000_000), // 1h
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    // YAML declares different config
    let mut realms = HashMap::new();
    realms.insert(
        "portal".to_string(),
        RealmYamlConfig {
            session_ttl: Some("12h".to_string()),
            ..RealmYamlConfig::default()
        },
    );

    let mut config = config_with_realms(Some(realms));
    config.auth = AuthConfig::default();

    let report = reconcile_realms(identity, &config).expect("reconcile");

    assert_eq!(report.updated, vec!["portal"]);
    assert!(report.created.is_empty());

    let realm = identity
        .get_realm_by_name("portal")
        .expect("get")
        .expect("portal should exist");
    assert_eq!(realm.config().session_ttl_micros, Some(43_200_000_000));
}

// ===== Scenario 5: Archive realm removed from YAML =====

#[tokio::test]
async fn archives_realm_removed_from_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Create two realms
    identity
        .create_realm(&CreateRealmRequest {
            name: "keep".to_string(),
            config: None,
        })
        .expect("create keep");
    identity
        .create_realm(&CreateRealmRequest {
            name: "remove-me".to_string(),
            config: None,
        })
        .expect("create remove-me");

    // YAML only declares "keep"
    let mut realms = HashMap::new();
    realms.insert("keep".to_string(), RealmYamlConfig::default());

    let config = config_with_realms(Some(realms));
    let report = reconcile_realms(identity, &config).expect("reconcile");

    assert_eq!(report.archived, vec!["remove-me"]);

    let archived = identity
        .get_realm_by_name("remove-me")
        .expect("get")
        .expect("should still exist");
    assert_eq!(archived.status(), RealmStatus::Archived);

    // "keep" should remain active
    let kept = identity
        .get_realm_by_name("keep")
        .expect("get")
        .expect("should exist");
    assert_eq!(kept.status(), RealmStatus::Active);
}

// ===== Scenario 6: Un-archive realm that reappears in YAML =====

#[tokio::test]
async fn unarchives_realm_that_reappears_in_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Create and archive a realm
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "comeback".to_string(),
            config: None,
        })
        .expect("create");
    identity
        .update_realm(
            realm.id(),
            &hearth::identity::UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive");

    // Now YAML brings it back
    let mut realms = HashMap::new();
    realms.insert("comeback".to_string(), RealmYamlConfig::default());

    let config = config_with_realms(Some(realms));
    let report = reconcile_realms(identity, &config).expect("reconcile");

    assert_eq!(report.unarchived, vec!["comeback"]);

    let realm = identity
        .get_realm_by_name("comeback")
        .expect("get")
        .expect("should exist");
    assert_eq!(realm.status(), RealmStatus::Active);
}

// ===== Scenario 7: Idempotent — reconcile twice with no changes =====

#[tokio::test]
async fn idempotent_reconciliation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let mut realms = HashMap::new();
    realms.insert("stable".to_string(), RealmYamlConfig::default());

    let config = config_with_realms(Some(realms));

    // First reconcile creates
    let report1 = reconcile_realms(identity, &config).expect("reconcile 1");
    assert_eq!(report1.created, vec!["stable"]);

    // Second reconcile should be a no-op
    let report2 = reconcile_realms(identity, &config).expect("reconcile 2");
    assert!(report2.created.is_empty(), "no creates on second run");
    assert!(report2.updated.is_empty(), "no updates on second run");
    assert!(report2.archived.is_empty(), "no archives on second run");
    assert!(report2.unarchived.is_empty(), "no unarchives on second run");
}
