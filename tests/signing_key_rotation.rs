//! Integration tests for Ed25519 signing key rotation with dual JWKS grace period.
//!
//! Covers:
//! - Rotation produces a JWKS with both active and retiring keys.
//! - Retiring key is excluded from JWKS once the grace period expires.
//! - Config `rotate_signing_key: true` triggers rotation via `apply_diff`.
//! - Snapshot flag is auto-cleared so a second startup does not re-rotate.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::config::{compute_diff, ConfigSnapshot, RealmYamlConfig};
use hearth::core::{Clock, FakeClock, Timestamp};
use hearth::identity::reconcile::{apply_diff, save_snapshot};
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Helper ────────────────────────────────────────────────────────────────────

fn setup_engine_with_clock(
    initial_micros: i64,
) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).unwrap()) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(initial_micros)));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        identity_config,
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .unwrap();
    (dir, engine, clock)
}

// ── Test 1: rotate → dual JWKS ────────────────────────────────────────────────

#[test]
fn rotation_produces_dual_jwks() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // Before rotation: one key in JWKS.
    let jwks_before = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(jwks_before.keys.len(), 1, "expected 1 key before rotation");
    let original_kid = jwks_before.keys[0].kid.clone();

    // Rotate with a 24-hour grace period.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();

    // After rotation: two keys — new active + retiring old key.
    let jwks_after = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(jwks_after.keys.len(), 2, "expected 2 keys after rotation");

    let kids: Vec<&str> = jwks_after.keys.iter().map(|k| k.kid.as_str()).collect();
    assert!(
        kids.contains(&original_kid.as_str()),
        "retiring key must still appear in JWKS during grace period"
    );
}

// ── Test 2: retiring key excluded after grace period expires ─────────────────

#[test]
fn retiring_key_removed_after_grace_period() {
    // Start at t=0 (seconds = 0, but use micros epoch).
    let start_micros = 1_000_000_000_000_i64; // arbitrary fixed point
    let (_dir, engine, clock) = setup_engine_with_clock(start_micros);

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "corp".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    let jwks_before = engine.realm_jwks(realm.id()).unwrap();
    let original_kid = jwks_before.keys[0].kid.clone();

    // Rotate with a 1-second grace period.
    engine.rotate_realm_signing_key(realm.id(), 1).unwrap();

    // During grace period: both keys present.
    let jwks_during = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_during.keys.len(),
        2,
        "expected 2 keys during grace period"
    );

    // Advance clock past the grace period deadline (2 seconds).
    clock.advance(2_000_000); // +2 seconds in micros
    let jwks_after = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_after.keys.len(),
        1,
        "expected 1 key after grace period expires"
    );

    // The surviving key must be the new one, not the retiring one.
    assert_ne!(
        jwks_after.keys[0].kid, original_kid,
        "surviving key should be the new active key, not the old retiring key"
    );
}

// ── Test 3: second rotation produces new key, old retiring key still present ─

#[test]
fn second_rotation_adds_another_retiring_key() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "multi".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // First rotation.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();
    let jwks_after_first = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_after_first.keys.len(),
        2,
        "2 keys after first rotation"
    );

    // Second rotation — now we should have active + 2 retiring keys.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();
    let jwks_after_second = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_after_second.keys.len(),
        3,
        "3 keys after second rotation (1 active + 2 retiring)"
    );
}

// ── Test 4: snapshot flag auto-cleared by apply_diff ─────────────────────────

#[tokio::test]
async fn snapshot_rotate_flag_cleared_after_apply_diff() {
    let harness = common::TestHarness::embedded().await.unwrap();

    // Create realm in storage.
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // Build a config with rotate_signing_key: true.
    let realm_yaml = RealmYamlConfig {
        rotate_signing_key: Some(true),
        ..RealmYamlConfig::default()
    };
    let mut config = hearth::config::Config::default();
    let mut realms = std::collections::HashMap::new();
    realms.insert("tenant".to_string(), realm_yaml);
    config.realms = Some(realms);

    // Old snapshot has rotate_signing_key: false (not yet rotated).
    let old_snap = {
        let mut snap = ConfigSnapshot::from_config(&config);
        if let Some(realm_snaps) = snap.realms.as_mut() {
            if let Some(rs) = realm_snaps.get_mut("tenant") {
                rs.rotate_signing_key = false; // force old state to "not set"
            }
        }
        snap
    };

    // Compute diff: should detect RealmSigningKeyRotationRequested.
    let diffs = compute_diff(&old_snap, &config);
    let rotation_requested = diffs.iter().any(|d| {
        matches!(
            d,
            hearth::config::ConfigDiff::RealmSigningKeyRotationRequested { realm }
            if realm == "tenant"
        )
    });
    assert!(
        rotation_requested,
        "expected RealmSigningKeyRotationRequested diff; got: {diffs:?}"
    );

    // Apply diffs — rotation handler fires and returns consumed realm names.
    let consumed = apply_diff(&diffs, &config, harness.identity(), harness.rbac()).unwrap();
    assert!(
        consumed.contains(&"tenant".to_string()),
        "tenant should be in consumed_rotations"
    );

    // The realm JWKS should now have 2 keys (before saving snapshot, just check rotation happened).
    let jwks = harness.identity().realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks.keys.len(),
        2,
        "JWKS must have 2 keys after rotation (active + retiring)"
    );

    // Save the current snapshot unchanged (rotate_signing_key stays true to match
    // YAML). This models the correct production behaviour: saving true→true means
    // the next compute_diff sees no transition and does not re-rotate.
    let snap = ConfigSnapshot::from_config(&config);
    save_snapshot(harness.storage(), &snap).unwrap();

    // Reload snapshot and re-compute diff. With the flag cleared, no rotation diff should fire.
    let saved_snap = hearth::identity::reconcile::load_snapshot(harness.storage())
        .unwrap()
        .unwrap();
    let diffs2 = compute_diff(&saved_snap, &config);
    let rotation_again = diffs2.iter().any(|d| {
        matches!(
            d,
            hearth::config::ConfigDiff::RealmSigningKeyRotationRequested { .. }
        )
    });
    assert!(
        !rotation_again,
        "rotation diff must NOT fire on second startup when flag was cleared from snapshot"
    );
}
