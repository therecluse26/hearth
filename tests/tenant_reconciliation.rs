//! Integration tests for tenant reconciliation.
//!
//! Tests the `reconcile_tenants()` function which syncs YAML-declared
//! tenants with storage on startup.

mod common;

use std::collections::HashMap;

use hearth::config::{AuthConfig, Config, TenantYamlConfig};
use hearth::identity::reconcile::reconcile_tenants;
use hearth::identity::{CreateTenantRequest, TenantConfig, TenantStatus};

/// Helper: builds a minimal `Config` with the given tenants map.
fn config_with_tenants(tenants: Option<HashMap<String, TenantYamlConfig>>) -> Config {
    let mut config = Config::dev();
    config.tenants = tenants;
    config
}

// ===== Scenario 1: Default tenant creation when no tenants key =====

#[tokio::test]
async fn creates_default_tenant_when_no_yaml_and_no_storage() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let config = config_with_tenants(None);
    let report = reconcile_tenants(identity, &config).expect("reconcile");

    assert_eq!(report.created, vec!["default"]);
    assert!(report.updated.is_empty());
    assert!(report.archived.is_empty());

    // Verify tenant exists
    let tenant = identity
        .get_tenant_by_name("default")
        .expect("get_tenant_by_name")
        .expect("default tenant should exist");
    assert_eq!(tenant.name(), "default");
    assert_eq!(tenant.status(), TenantStatus::Active);
}

// ===== Scenario 2: Backward compat — existing tenants preserved =====

#[tokio::test]
async fn skips_reconciliation_when_tenants_exist_and_no_yaml_key() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Pre-create a tenant
    identity
        .create_tenant(&CreateTenantRequest {
            name: "existing".to_string(),
            config: None,
        })
        .expect("create existing tenant");

    let config = config_with_tenants(None);
    let report = reconcile_tenants(identity, &config).expect("reconcile");

    // Should not create "default" or touch existing
    assert!(report.created.is_empty());
    assert!(report.updated.is_empty());
    assert!(report.archived.is_empty());

    // Existing tenant still there
    assert!(identity
        .get_tenant_by_name("existing")
        .expect("get")
        .is_some());
}

// ===== Scenario 3: Create new tenant from YAML =====

#[tokio::test]
async fn creates_tenant_from_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let mut tenants = HashMap::new();
    tenants.insert("portal".to_string(), TenantYamlConfig::default());

    let config = config_with_tenants(Some(tenants));
    let report = reconcile_tenants(identity, &config).expect("reconcile");

    assert_eq!(report.created, vec!["portal"]);

    let tenant = identity
        .get_tenant_by_name("portal")
        .expect("get")
        .expect("portal should exist");
    assert_eq!(tenant.status(), TenantStatus::Active);
}

// ===== Scenario 4: Update existing tenant config from YAML =====

#[tokio::test]
async fn updates_tenant_config_from_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Pre-create a tenant with old config
    identity
        .create_tenant(&CreateTenantRequest {
            name: "portal".to_string(),
            config: Some(TenantConfig {
                session_ttl_micros: Some(3_600_000_000), // 1h
                ..TenantConfig::default()
            }),
        })
        .expect("create tenant");

    // YAML declares different config
    let mut tenants = HashMap::new();
    tenants.insert(
        "portal".to_string(),
        TenantYamlConfig {
            session_ttl: Some("12h".to_string()),
            ..TenantYamlConfig::default()
        },
    );

    let mut config = config_with_tenants(Some(tenants));
    config.auth = AuthConfig::default();

    let report = reconcile_tenants(identity, &config).expect("reconcile");

    assert_eq!(report.updated, vec!["portal"]);
    assert!(report.created.is_empty());

    let tenant = identity
        .get_tenant_by_name("portal")
        .expect("get")
        .expect("portal should exist");
    assert_eq!(tenant.config().session_ttl_micros, Some(43_200_000_000));
}

// ===== Scenario 5: Archive tenant removed from YAML =====

#[tokio::test]
async fn archives_tenant_removed_from_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Create two tenants
    identity
        .create_tenant(&CreateTenantRequest {
            name: "keep".to_string(),
            config: None,
        })
        .expect("create keep");
    identity
        .create_tenant(&CreateTenantRequest {
            name: "remove-me".to_string(),
            config: None,
        })
        .expect("create remove-me");

    // YAML only declares "keep"
    let mut tenants = HashMap::new();
    tenants.insert("keep".to_string(), TenantYamlConfig::default());

    let config = config_with_tenants(Some(tenants));
    let report = reconcile_tenants(identity, &config).expect("reconcile");

    assert_eq!(report.archived, vec!["remove-me"]);

    let archived = identity
        .get_tenant_by_name("remove-me")
        .expect("get")
        .expect("should still exist");
    assert_eq!(archived.status(), TenantStatus::Archived);

    // "keep" should remain active
    let kept = identity
        .get_tenant_by_name("keep")
        .expect("get")
        .expect("should exist");
    assert_eq!(kept.status(), TenantStatus::Active);
}

// ===== Scenario 6: Un-archive tenant that reappears in YAML =====

#[tokio::test]
async fn unarchives_tenant_that_reappears_in_yaml() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Create and archive a tenant
    let tenant = identity
        .create_tenant(&CreateTenantRequest {
            name: "comeback".to_string(),
            config: None,
        })
        .expect("create");
    identity
        .update_tenant(
            tenant.id(),
            &hearth::identity::UpdateTenantRequest {
                status: Some(TenantStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive");

    // Now YAML brings it back
    let mut tenants = HashMap::new();
    tenants.insert("comeback".to_string(), TenantYamlConfig::default());

    let config = config_with_tenants(Some(tenants));
    let report = reconcile_tenants(identity, &config).expect("reconcile");

    assert_eq!(report.unarchived, vec!["comeback"]);

    let tenant = identity
        .get_tenant_by_name("comeback")
        .expect("get")
        .expect("should exist");
    assert_eq!(tenant.status(), TenantStatus::Active);
}

// ===== Scenario 7: Idempotent — reconcile twice with no changes =====

#[tokio::test]
async fn idempotent_reconciliation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let mut tenants = HashMap::new();
    tenants.insert("stable".to_string(), TenantYamlConfig::default());

    let config = config_with_tenants(Some(tenants));

    // First reconcile creates
    let report1 = reconcile_tenants(identity, &config).expect("reconcile 1");
    assert_eq!(report1.created, vec!["stable"]);

    // Second reconcile should be a no-op
    let report2 = reconcile_tenants(identity, &config).expect("reconcile 2");
    assert!(report2.created.is_empty(), "no creates on second run");
    assert!(report2.updated.is_empty(), "no updates on second run");
    assert!(report2.archived.is_empty(), "no archives on second run");
    assert!(report2.unarchived.is_empty(), "no unarchives on second run");
}
