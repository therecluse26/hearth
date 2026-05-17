//! Integration tests verifying that the global signing key survives engine
//! restarts (WAL replay). Acceptance criteria for HEA-546.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, FakeClock, Timestamp};
use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

fn open_engine(storage: Arc<dyn StorageEngine>, clock: Arc<dyn Clock>) -> EmbeddedIdentityEngine {
    let config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        config,
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .unwrap()
}

/// The global signing key must be identical across engine restarts so that
/// tokens signed with it remain valid after a `kill -9` + WAL replay.
#[test]
fn global_signing_key_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    // ── First startup ────────────────────────────────────────────────────────
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());
    let engine1 = open_engine(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    let pubkey_before = engine1.signing_key().public_key_bytes().to_vec();
    drop(engine1);

    // Close and reopen storage — simulates a server restart with WAL replay.
    drop(storage);
    let storage_cfg2 = StorageConfig::dev(dir.path().to_path_buf());
    let storage2 = Arc::new(EmbeddedStorageEngine::open(storage_cfg2).unwrap());

    // ── Second startup (WAL replay) ──────────────────────────────────────────
    let engine2 = open_engine(
        Arc::clone(&storage2) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    let pubkey_after = engine2.signing_key().public_key_bytes().to_vec();

    assert_eq!(
        pubkey_before, pubkey_after,
        "global signing key must be identical across engine restarts"
    );
}

/// A third startup must still return the same key (idempotent load path).
#[test]
fn global_signing_key_stable_across_multiple_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    let mut last_pubkey: Option<Vec<u8>> = None;

    for _ in 0..3 {
        let cfg = StorageConfig::dev(dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(cfg).unwrap());
        let engine = open_engine(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let pubkey = engine.signing_key().public_key_bytes().to_vec();
        if let Some(ref prev) = last_pubkey {
            assert_eq!(prev, &pubkey, "key must not change across restarts");
        }
        last_pubkey = Some(pubkey);
        drop(engine);
        drop(storage);
    }
}
