//! Integration tests for config snapshot round-trip and diff engine.
//!
//! Verifies:
//! - Snapshot is `None` before first write (idempotent first startup).
//! - Snapshot survives a `save_snapshot` → `load_snapshot` round-trip.
//! - Diff is empty when config hasn't changed.
//! - Diff is non-empty when config changes between restarts.
//! - Phase C diff handlers are idempotent and produce correct storage mutations.

#![allow(clippy::unwrap_used)]

mod common;

use hearth::config::{
    compute_diff, ConfigDiff, ConfigSnapshot, EmailTransport, GroupYamlConfig,
    OrganizationYamlConfig, RealmAuthYaml, RealmTokenYaml, RealmWebYaml, RealmYamlConfig,
    RoleYamlConfig,
};
use hearth::identity::reconcile::{apply_diff, load_snapshot, save_snapshot};

fn base_config() -> hearth::config::Config {
    let mut c = hearth::config::Config::default();
    c.oidc.issuer = Some("https://auth.example.com".to_string());
    c.token.issuer = Some("https://auth.example.com".to_string());
    c.token.audience = Some("myapp".to_string());
    c.storage.data_dir = "/data/hearth".to_string();
    c
}

/// Builds a config with a single realm named `"tenant"` using the given YAML config.
fn config_with_realm(realm_yaml: RealmYamlConfig) -> hearth::config::Config {
    let mut c = base_config();
    let mut realms = std::collections::HashMap::new();
    realms.insert("tenant".to_string(), realm_yaml);
    c.realms = Some(realms);
    c
}

// ── Snapshot persistence ──────────────────────────────────────────────────────

#[tokio::test]
async fn snapshot_absent_before_first_write() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let snap = load_snapshot(harness.storage()).expect("load_snapshot");
    assert!(
        snap.is_none(),
        "expected None before any snapshot is written"
    );
}

#[tokio::test]
async fn snapshot_round_trip() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config = base_config();
    let snap = ConfigSnapshot::from_config(&config);
    save_snapshot(harness.storage(), &snap).expect("save_snapshot");

    let loaded = load_snapshot(harness.storage())
        .expect("load_snapshot")
        .expect("snapshot should exist after write");

    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.oidc_issuer, snap.oidc_issuer);
    assert_eq!(loaded.token.issuer, snap.token.issuer);
    assert_eq!(loaded.token.audience, snap.token.audience);
    assert_eq!(loaded.storage_data_dir, snap.storage_data_dir);
    assert_eq!(loaded.realms, snap.realms);
}

#[tokio::test]
async fn save_is_idempotent() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config = base_config();
    let snap = ConfigSnapshot::from_config(&config);

    save_snapshot(harness.storage(), &snap).expect("first save");
    save_snapshot(harness.storage(), &snap).expect("second save");

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    assert_eq!(loaded.token.issuer, snap.token.issuer);
}

// ── Diff detection ────────────────────────────────────────────────────────────

#[tokio::test]
async fn diff_empty_when_config_unchanged() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config = base_config();
    let snap = ConfigSnapshot::from_config(&config);
    save_snapshot(harness.storage(), &snap).expect("save");

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config);
    assert!(diffs.is_empty(), "no diffs expected, got: {diffs:?}");
}

#[tokio::test]
async fn diff_detects_realm_added_between_restarts() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = base_config();
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save v1");

    let mut config_v2 = base_config();
    let mut realms = std::collections::HashMap::new();
    realms.insert("production".to_string(), RealmYamlConfig::default());
    config_v2.realms = Some(realms);

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    let added: Vec<_> = diffs
        .iter()
        .filter(|d| matches!(d, ConfigDiff::RealmAdded(_)))
        .collect();
    assert_eq!(added.len(), 1);
    assert!(matches!(&added[0], ConfigDiff::RealmAdded(n) if n == "production"));
}

#[tokio::test]
async fn diff_detects_oidc_issuer_change() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = base_config();
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let mut config_v2 = base_config();
    config_v2.oidc.issuer = Some("https://new-issuer.example.com".to_string());

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs
            .iter()
            .any(|d| matches!(d, ConfigDiff::OidcIssuerChanged { .. })),
        "expected OidcIssuerChanged, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_email_transport_change() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = base_config();
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let mut config_v2 = base_config();
    config_v2.email.transport = EmailTransport::Smtp;

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs
            .iter()
            .any(|d| matches!(d, ConfigDiff::EmailTransportChanged { .. })),
        "expected EmailTransportChanged, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_realm_settings_changed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    // Change session TTL for the realm.
    let config_v2 = config_with_realm(RealmYamlConfig {
        session_ttl: Some("4h".to_string()),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::RealmSettingsChanged { realm } if realm == "tenant"
        )),
        "expected RealmSettingsChanged, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_mfa_policy_changed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig {
        auth: Some(RealmAuthYaml {
            mfa_required: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::RealmSettingsChanged { realm } if realm == "tenant"
        )),
        "expected RealmSettingsChanged for MFA change, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_theme_changed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig {
        web: Some(RealmWebYaml {
            theme: Some("ocean".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::RealmSettingsChanged { realm } if realm == "tenant"
        )),
        "expected RealmSettingsChanged for theme change, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_token_ttl_changed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig {
        auth: Some(RealmAuthYaml {
            token: Some(RealmTokenYaml {
                access_token_ttl: Some("30m".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::RealmSettingsChanged { realm } if realm == "tenant"
        )),
        "expected RealmSettingsChanged for token TTL change, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_org_added() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let mut realm_v2 = RealmYamlConfig::default();
    let mut orgs = std::collections::HashMap::new();
    orgs.insert(
        "acme".to_string(),
        OrganizationYamlConfig {
            name: "Acme Corp".to_string(),
            description: None,
            config: None,
        },
    );
    realm_v2.organizations = Some(orgs);
    let config_v2 = config_with_realm(realm_v2);

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::OrgAdded { realm, slug }
            if realm == "tenant" && slug == "acme"
        )),
        "expected OrgAdded, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_org_removed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let mut realm_v1 = RealmYamlConfig::default();
    let mut orgs = std::collections::HashMap::new();
    orgs.insert(
        "legacy".to_string(),
        OrganizationYamlConfig {
            name: "Legacy Inc".to_string(),
            description: None,
            config: None,
        },
    );
    realm_v1.organizations = Some(orgs);
    let config_v1 = config_with_realm(realm_v1);
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig::default()); // org removed
    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::OrgRemoved { realm, slug }
            if realm == "tenant" && slug == "legacy"
        )),
        "expected OrgRemoved, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_application_added() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let mut realm_v2 = RealmYamlConfig::default();
    let mut apps = std::collections::HashMap::new();
    apps.insert(
        "dashboard".to_string(),
        hearth::config::ApplicationYamlConfig {
            name: "Dashboard".to_string(),
            redirect_uris: None,
            grant_types: None,
            confidential: None,
            client_secret: None,
            require_consent: None,
            client_logo_url: None,
            slug: None,
            trust_level: None,
            declared_scopes: None,
            consent_spans_orgs: None,
        },
    );
    realm_v2.applications = Some(apps);
    let config_v2 = config_with_realm(realm_v2);

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::ApplicationAdded { realm, key }
            if realm == "tenant" && key == "dashboard"
        )),
        "expected ApplicationAdded, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_application_removed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let mut realm_v1 = RealmYamlConfig::default();
    let mut apps = std::collections::HashMap::new();
    apps.insert(
        "old-portal".to_string(),
        hearth::config::ApplicationYamlConfig {
            name: "Old Portal".to_string(),
            redirect_uris: None,
            grant_types: None,
            confidential: None,
            client_secret: None,
            require_consent: None,
            client_logo_url: None,
            slug: None,
            trust_level: None,
            declared_scopes: None,
            consent_spans_orgs: None,
        },
    );
    realm_v1.applications = Some(apps);
    let config_v1 = config_with_realm(realm_v1);
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig::default()); // app removed
    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::ApplicationRemoved { realm, key }
            if realm == "tenant" && key == "old-portal"
        )),
        "expected ApplicationRemoved, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_role_added() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig {
        roles: Some(vec![RoleYamlConfig {
            name: "editor".to_string(),
            description: None,
            permissions: vec![],
            parents: vec![],
            scope_kind: None,
        }]),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::RoleAdded { realm, name }
            if realm == "tenant" && name == "editor"
        )),
        "expected RoleAdded, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_role_removed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig {
        roles: Some(vec![RoleYamlConfig {
            name: "viewer".to_string(),
            description: None,
            permissions: vec![],
            parents: vec![],
            scope_kind: None,
        }]),
        ..Default::default()
    });
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig::default()); // role removed
    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::RoleRemoved { realm, name }
            if realm == "tenant" && name == "viewer"
        )),
        "expected RoleRemoved, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_group_added() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig::default());
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig {
        groups: Some(vec![GroupYamlConfig {
            name: "administrators".to_string(),
            slug: None,
            description: None,
        }]),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::GroupAdded { realm, name }
            if realm == "tenant" && name == "administrators"
        )),
        "expected GroupAdded, got: {diffs:?}"
    );
}

#[tokio::test]
async fn diff_detects_group_removed() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = config_with_realm(RealmYamlConfig {
        groups: Some(vec![GroupYamlConfig {
            name: "beta-testers".to_string(),
            slug: None,
            description: None,
        }]),
        ..Default::default()
    });
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let config_v2 = config_with_realm(RealmYamlConfig::default()); // group removed
    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs.iter().any(|d| matches!(
            d,
            ConfigDiff::GroupRemoved { realm, name }
            if realm == "tenant" && name == "beta-testers"
        )),
        "expected GroupRemoved, got: {diffs:?}"
    );
}

#[tokio::test]
async fn no_within_realm_diffs_for_new_realm() {
    // When a realm is new (RealmAdded), org/app/role/group diffs must NOT be
    // emitted for it — only RealmAdded should appear.
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = base_config(); // no realms
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let mut orgs = std::collections::HashMap::new();
    orgs.insert(
        "corp".to_string(),
        OrganizationYamlConfig {
            name: "Corp".to_string(),
            description: None,
            config: None,
        },
    );
    let config_v2 = config_with_realm(RealmYamlConfig {
        groups: Some(vec![GroupYamlConfig {
            name: "admins".to_string(),
            slug: None,
            description: None,
        }]),
        organizations: Some(orgs),
        ..Default::default()
    });

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);

    assert!(
        diffs
            .iter()
            .any(|d| matches!(d, ConfigDiff::RealmAdded(n) if n == "tenant")),
        "expected RealmAdded"
    );
    assert!(
        !diffs
            .iter()
            .any(|d| matches!(d, ConfigDiff::OrgAdded { .. })),
        "must not emit OrgAdded for a brand-new realm (already covered by RealmAdded)"
    );
    assert!(
        !diffs
            .iter()
            .any(|d| matches!(d, ConfigDiff::GroupAdded { .. })),
        "must not emit GroupAdded for a brand-new realm"
    );
}

// ── apply_diff handlers ───────────────────────────────────────────────────────

#[tokio::test]
async fn apply_diff_config_only_returns_ok() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let config_v1 = base_config();
    let snap_v1 = ConfigSnapshot::from_config(&config_v1);
    save_snapshot(harness.storage(), &snap_v1).expect("save");

    let mut config_v2 = base_config();
    config_v2.oidc.issuer = Some("https://changed.example.com".to_string());
    config_v2.token.issuer = Some("https://changed.example.com".to_string());
    config_v2.email.transport = EmailTransport::Sendgrid;

    let loaded = load_snapshot(harness.storage())
        .expect("load")
        .expect("present");
    let diffs = compute_diff(&loaded, &config_v2);
    assert!(!diffs.is_empty(), "expected some diffs");

    apply_diff(&diffs, &config_v2, harness.identity(), harness.rbac())
        .expect("apply_diff must not fail for config-only variants");
}

#[tokio::test]
async fn apply_diff_org_added_creates_org_in_storage() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    // Create the realm in storage so apply_diff can look it up.
    let realm = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(hearth::identity::RealmConfig::default()),
        })
        .expect("create realm");

    // Build a diff: org "newco" was added to the realm's YAML.
    let mut realm_yaml = RealmYamlConfig::default();
    let mut orgs = std::collections::HashMap::new();
    orgs.insert(
        "newco".to_string(),
        OrganizationYamlConfig {
            name: "NewCo".to_string(),
            description: Some("A new company".to_string()),
            config: None,
        },
    );
    realm_yaml.organizations = Some(orgs);
    let config_with_org = config_with_realm(realm_yaml);

    let diffs = vec![ConfigDiff::OrgAdded {
        realm: "tenant".to_string(),
        slug: "newco".to_string(),
    }];

    apply_diff(&diffs, &config_with_org, harness.identity(), harness.rbac()).expect("apply_diff");

    // Org should now exist in storage.
    let org = harness
        .identity()
        .get_organization_by_slug(realm.id(), "newco")
        .expect("get org")
        .expect("org should exist after apply_diff");
    assert_eq!(org.name(), "NewCo");
}

#[tokio::test]
async fn apply_diff_idempotent_on_org_added() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(hearth::identity::RealmConfig::default()),
        })
        .expect("create realm");

    let mut realm_yaml = RealmYamlConfig::default();
    let mut orgs = std::collections::HashMap::new();
    orgs.insert(
        "stable-org".to_string(),
        OrganizationYamlConfig {
            name: "Stable Org".to_string(),
            description: None,
            config: None,
        },
    );
    realm_yaml.organizations = Some(orgs);
    let config_with_org = config_with_realm(realm_yaml);

    let diffs = vec![ConfigDiff::OrgAdded {
        realm: "tenant".to_string(),
        slug: "stable-org".to_string(),
    }];

    // Apply twice — second run must not fail or duplicate the org.
    apply_diff(&diffs, &config_with_org, harness.identity(), harness.rbac()).expect("first apply");
    apply_diff(&diffs, &config_with_org, harness.identity(), harness.rbac()).expect("second apply");

    let page = harness
        .identity()
        .list_organizations(realm.id(), None, 100)
        .expect("list orgs");
    let matching: Vec<_> = page
        .items
        .iter()
        .filter(|o| o.slug() == "stable-org")
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "org must exist exactly once after idempotent apply"
    );
}

#[tokio::test]
async fn apply_diff_role_added_creates_role_in_storage() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(hearth::identity::RealmConfig::default()),
        })
        .expect("create realm");

    let config_with_role = config_with_realm(RealmYamlConfig {
        roles: Some(vec![RoleYamlConfig {
            name: "content-editor".to_string(),
            description: Some("Can edit content".to_string()),
            permissions: vec![],
            parents: vec![],
            scope_kind: None,
        }]),
        ..Default::default()
    });

    let diffs = vec![ConfigDiff::RoleAdded {
        realm: "tenant".to_string(),
        name: "content-editor".to_string(),
    }];

    apply_diff(
        &diffs,
        &config_with_role,
        harness.identity(),
        harness.rbac(),
    )
    .expect("apply_diff");

    let role = harness
        .rbac()
        .get_role_by_name(realm.id(), "content-editor")
        .expect("get role")
        .expect("role should exist after apply_diff");
    assert_eq!(role.name, "content-editor");
}

#[tokio::test]
async fn apply_diff_group_added_creates_group_in_storage() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(hearth::identity::RealmConfig::default()),
        })
        .expect("create realm");

    let config_with_group = config_with_realm(RealmYamlConfig {
        groups: Some(vec![GroupYamlConfig {
            name: "power-users".to_string(),
            slug: Some("power-users".to_string()),
            description: None,
        }]),
        ..Default::default()
    });

    let diffs = vec![ConfigDiff::GroupAdded {
        realm: "tenant".to_string(),
        name: "power-users".to_string(),
    }];

    apply_diff(
        &diffs,
        &config_with_group,
        harness.identity(),
        harness.rbac(),
    )
    .expect("apply_diff");

    let groups = harness
        .rbac()
        .list_groups(realm.id(), None, 100)
        .expect("list groups");
    assert!(
        groups.items.iter().any(|g| g.name == "power-users"),
        "group should exist after apply_diff"
    );
}
