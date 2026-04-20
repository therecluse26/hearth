//! Session crash-recovery simulation tests.
//!
//! Oracle invariant: no committed session is lost after crash recovery.
//! TTL enforcement remains correct under clock skew.

use std::sync::Arc;

use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    SessionContext,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Crash recovery preserves all committed sessions.
#[test]
fn simulation_crash_recovery_sessions() {
    let seed = 50u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();
    let mut session_ids = Vec::new();

    // Phase 1: Create users and sessions, then drop (crash)
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
        )
        .expect("engine");

        for i in 0..5 {
            let user = engine
                .create_user(
                    &realm,
                    &CreateUserRequest {
                        email: format!("crash-{i}@example.com"),
                        display_name: format!("Crash User {i}"),
                    },
                )
                .expect("create user");

            let session = engine
                .create_session(&realm, user.id(), &SessionContext::default())
                .expect("create session");
            session_ids.push((session.id().clone(), user.id().clone()));
        }
    }

    // Phase 2: Recover from WAL and verify all sessions survived
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("reopen");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
        )
        .expect("engine recovery");

        for (session_id, user_id) in &session_ids {
            let recovered = engine
                .get_session(&realm, session_id)
                .expect("get session after recovery");
            assert!(
                recovered.is_some(),
                "session {} must survive crash recovery (seed={seed})",
                session_id.as_uuid()
            );
            let session = recovered.expect("session");
            assert_eq!(
                session.user_id(),
                user_id,
                "session must be bound to correct user after recovery"
            );
        }
    }
}

/// TTL expiration correct under simulated clock skew / time drift.
#[test]
fn simulation_ttl_clock_skew() {
    let seed = 51u64;
    // Deterministic seed for future madsim integration.
    let _ = seed;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let engine = EmbeddedIdentityEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        identity_config.clone(),
    )
    .expect("engine");

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "skew@example.com".to_string(),
                display_name: "Clock Skew User".to_string(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let ttl = identity_config.session.ttl_micros;

    // 1. Session is valid at creation time
    assert!(
        engine
            .get_session(&realm, session.id())
            .expect("get")
            .is_some(),
        "session must be valid at creation (seed={seed})"
    );

    // 2. Forward jump past TTL: session expires
    clock.advance(ttl + 1);
    assert!(
        engine
            .get_session(&realm, session.id())
            .expect("get")
            .is_none(),
        "session must expire after TTL (seed={seed})"
    );

    // 3. Clock jumps BACKWARD (simulating NTP correction)
    clock.set(Timestamp::from_micros(1_000_000 + ttl / 2));
    let after_backward = engine
        .get_session(&realm, session.id())
        .expect("get after backward drift");
    assert!(
        after_backward.is_some(),
        "backward clock drift to mid-TTL makes session appear valid (expected, seed={seed})"
    );

    // 4. Create a new session, refresh it, verify new TTL baseline
    let session2 = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session 2");

    clock.advance(ttl / 2);

    let refreshed = engine
        .refresh_session(&realm, session2.id())
        .expect("refresh");
    let refreshed_expires = refreshed.expires_at();

    clock.advance(ttl / 2 + 1);

    assert!(
        engine
            .get_session(&realm, session2.id())
            .expect("get")
            .is_some(),
        "refreshed session must be valid past original expiry (seed={seed})"
    );

    let remaining = refreshed_expires.as_micros() - clock.now().as_micros();
    clock.advance(remaining + 1);
    assert!(
        engine
            .get_session(&realm, session2.id())
            .expect("get")
            .is_none(),
        "refreshed session must expire after new TTL (seed={seed})"
    );
}
