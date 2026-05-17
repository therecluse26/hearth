//! Integration tests for Phase D: orphaned-realm detection.
//!
//! Verifies that `detect_orphaned_realms` correctly:
//! - detects archived realms with live users as orphans
//! - skips archived realms that have no users
//! - clears orphan records when the condition is resolved via `migrate_from`
//! - clears orphan records when the condition is resolved via `archive_drop`
//! - writes and reads `config:orphan:{slug}` keys via `load_orphaned_realms`

#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashMap;

use hearth::config::{Config, RealmYamlConfig};
use hearth::identity::reconcile::{detect_orphaned_realms, load_orphaned_realms, reconcile_realms};
use hearth::identity::{CreateUserRequest, RealmStatus};

fn config_with_realms(realms: Option<HashMap<String, RealmYamlConfig>>) -> Config {
    Config {
        realms,
        ..Config::default()
    }
}

/// Helper: create a realm with one user, then archive it via reconcile.
/// Returns the realm slug (name).
async fn create_and_archive_realm_with_user(harness: &common::TestHarness, slug: &str) -> String {
    // Create the realm.
    let realm = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: slug.to_string(),
            config: Some(hearth::identity::RealmConfig::default()),
        })
        .expect("create realm");

    // Add a user.
    harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("user@{slug}.test"),
                display_name: "Test User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    // Archive it by reconciling with a YAML map that omits this slug.
    let config = config_with_realms(Some(HashMap::new()));
    reconcile_realms(harness.identity(), harness.rbac(), &config).expect("reconcile");

    // Confirm archived.
    let r = harness
        .identity()
        .get_realm_by_name(slug)
        .expect("get realm")
        .expect("realm exists");
    assert_eq!(r.status(), RealmStatus::Archived, "realm must be archived");

    slug.to_string()
}

// ── Detection ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn detects_orphan_when_archived_realm_has_users() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let slug = create_and_archive_realm_with_user(&harness, "legacy").await;

    let config = config_with_realms(Some(HashMap::new()));
    let orphans = detect_orphaned_realms(harness.identity(), &config, harness.storage());

    assert_eq!(orphans.len(), 1, "expected one orphan");
    assert_eq!(orphans[0].realm_slug, slug);
    assert!(orphans[0].user_count > 0, "user count must be > 0");
}

#[tokio::test]
async fn no_orphan_when_archived_realm_is_empty() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    // Create and immediately archive a realm with NO users.
    harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: "empty-realm".to_string(),
            config: Some(hearth::identity::RealmConfig::default()),
        })
        .expect("create realm");

    let config = config_with_realms(Some(HashMap::new()));
    reconcile_realms(harness.identity(), harness.rbac(), &config).expect("reconcile");

    let orphans = detect_orphaned_realms(harness.identity(), &config, harness.storage());
    assert!(
        orphans.is_empty(),
        "empty archived realm must not be an orphan"
    );
}

// ── Resolution via migrate_from ────────────────────────────────────────────────

#[tokio::test]
async fn orphan_resolved_by_migrate_from() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    create_and_archive_realm_with_user(&harness, "old-realm").await;

    // First detection — should be orphaned.
    let config_no_resolution = config_with_realms(Some(HashMap::new()));
    let orphans =
        detect_orphaned_realms(harness.identity(), &config_no_resolution, harness.storage());
    assert_eq!(orphans.len(), 1, "expected orphan on first detection");

    // Resolve by adding a destination realm with `migrate_from: old-realm`.
    let destination = RealmYamlConfig {
        migrate_from: Some("old-realm".to_string()),
        ..RealmYamlConfig::default()
    };
    let mut realms = HashMap::new();
    realms.insert("new-realm".to_string(), destination);
    let config_resolved = config_with_realms(Some(realms));

    let orphans_after =
        detect_orphaned_realms(harness.identity(), &config_resolved, harness.storage());
    assert!(
        orphans_after.is_empty(),
        "orphan must be cleared when migrate_from is declared"
    );

    // Confirm the storage key is also gone.
    let loaded = load_orphaned_realms(harness.storage());
    assert!(
        loaded.is_empty(),
        "config:orphan key must be deleted on resolution"
    );
}

// ── Resolution via archive_drop ────────────────────────────────────────────────

#[tokio::test]
async fn orphan_resolved_by_archive_drop() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    create_and_archive_realm_with_user(&harness, "drop-me").await;

    // First detection — should be orphaned.
    let config_no_resolution = config_with_realms(Some(HashMap::new()));
    let orphans =
        detect_orphaned_realms(harness.identity(), &config_no_resolution, harness.storage());
    assert_eq!(orphans.len(), 1, "expected orphan on first detection");

    // Resolve by re-adding the slug with `archive_drop: true`.
    let tombstone = RealmYamlConfig {
        archive_drop: Some(true),
        ..RealmYamlConfig::default()
    };
    let mut realms = HashMap::new();
    realms.insert("drop-me".to_string(), tombstone);
    let config_resolved = config_with_realms(Some(realms));

    let orphans_after =
        detect_orphaned_realms(harness.identity(), &config_resolved, harness.storage());
    assert!(
        orphans_after.is_empty(),
        "orphan must be cleared when archive_drop is declared"
    );

    // The storage key must also be gone.
    let loaded = load_orphaned_realms(harness.storage());
    assert!(
        loaded.is_empty(),
        "config:orphan key must be deleted on resolution"
    );
}

// ── Persistence ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn orphan_record_persisted_and_loadable() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    create_and_archive_realm_with_user(&harness, "persisted-orphan").await;

    let config = config_with_realms(Some(HashMap::new()));
    detect_orphaned_realms(harness.identity(), &config, harness.storage());

    // load_orphaned_realms should return the same record without re-running detection.
    let loaded = load_orphaned_realms(harness.storage());
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].realm_slug, "persisted-orphan");
    assert!(loaded[0].user_count > 0);
    assert!(!loaded[0].detected_at.is_empty());
}

#[tokio::test]
async fn detected_at_preserved_across_detection_runs() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    create_and_archive_realm_with_user(&harness, "stable-orphan").await;

    let config = config_with_realms(Some(HashMap::new()));
    let first_run = detect_orphaned_realms(harness.identity(), &config, harness.storage());
    let first_at = first_run[0].detected_at.clone();

    let second_run = detect_orphaned_realms(harness.identity(), &config, harness.storage());
    assert_eq!(
        second_run[0].detected_at, first_at,
        "detected_at must be stable across repeated detection runs"
    );
}

// ── archive_drop suppresses reconcile unarchiving ─────────────────────────────

#[tokio::test]
async fn archive_drop_prevents_realm_unarchiving_on_reconcile() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    create_and_archive_realm_with_user(&harness, "keep-archived").await;

    // Re-add the slug to YAML with archive_drop: true.
    let tombstone = RealmYamlConfig {
        archive_drop: Some(true),
        ..RealmYamlConfig::default()
    };
    let mut realms = HashMap::new();
    realms.insert("keep-archived".to_string(), tombstone);
    let config = config_with_realms(Some(realms));

    reconcile_realms(harness.identity(), harness.rbac(), &config).expect("reconcile");

    // Realm must stay archived — archive_drop skips unarchiving.
    let realm = harness
        .identity()
        .get_realm_by_name("keep-archived")
        .expect("get realm")
        .expect("realm exists");
    assert_eq!(
        realm.status(),
        RealmStatus::Archived,
        "realm must remain archived when archive_drop is set"
    );
}
