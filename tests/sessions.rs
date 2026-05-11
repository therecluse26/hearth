//! Integration tests for session management.
//!
//! Black box tests via `TestHarness` — exercises session operations
//! through the public `IdentityEngine` trait.

mod common;

use hearth::core::{RealmId, SessionId};
use hearth::identity::{CreateUserRequest, IdentityEngine, User};

/// Helper: creates a user with a unique email in the given realm.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ===== Scenario: Full lifecycle (create → validate → refresh → revoke → validate-fails) =====

#[tokio::test]
async fn session_full_lifecycle() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // 1. Create session
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    assert_eq!(session.user_id(), user.id());

    // 2. Validate (lookup should succeed)
    let fetched = harness
        .identity()
        .get_session(&realm, session.id())
        .expect("get session")
        .expect("session should exist");
    assert_eq!(fetched.id(), session.id());
    assert_eq!(fetched.user_id(), user.id());

    // 3. Refresh
    let refreshed = harness
        .identity()
        .refresh_session(&realm, session.id())
        .expect("refresh");
    assert_eq!(refreshed.id(), session.id());

    // 4. Revoke
    harness
        .identity()
        .revoke_session(&realm, session.id())
        .expect("revoke");

    // 5. Validate should now fail
    let gone = harness
        .identity()
        .get_session(&realm, session.id())
        .expect("get");
    assert!(gone.is_none(), "revoked session should not be found");
}

// ===== Scenario: Full lifecycle via server HTTP API =====

#[tokio::test]
#[ignore = "HTTP layer not implemented"]
async fn session_full_lifecycle_server() {
    // Placeholder — will be enabled when the HTTP protocol layer is built
    let _harness = common::TestHarness::server().await;
}

// ===== Scenario: Session data persists across server restart =====
// For embedded mode we test that session data survives engine re-creation
// by re-opening the same storage directory.

#[tokio::test]
async fn session_persists_across_restart() {
    use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
    use hearth::core::SystemClock;
    use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("tempdir");

    let realm = RealmId::generate();
    let session_id;

    // Phase 1: Create engine, create user + session
    {
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
        let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            clock,
            identity_config,
            Arc::clone(&audit),
        )
        .expect("engine creation");

        let user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "persist@example.com".to_string(),
                    display_name: "Persist User".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                                attributes: Default::default(),
                },
            )
            .expect("create user");

        let session = engine
            .create_session(
                &realm,
                user.id(),
                &hearth::identity::SessionContext::default(),
            )
            .expect("create session");
        session_id = session.id().clone();

        // Verify session exists
        let check = engine
            .get_session(&realm, &session_id)
            .expect("get session");
        assert!(check.is_some(), "session should exist before restart");

        // Drop engine — simulates server shutdown
    }

    // Phase 2: Re-open engine with same storage directory
    {
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("reopen"));
        let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            clock,
            identity_config,
            Arc::clone(&audit),
        )
        .expect("engine creation");

        // Session should survive restart (WAL durability)
        let recovered = engine
            .get_session(&realm, &session_id)
            .expect("get after restart");
        assert!(
            recovered.is_some(),
            "session should survive engine restart (WAL durability)"
        );
    }
}

// ===== Delete user cascades to sessions =====

#[tokio::test]
async fn delete_user_invalidates_sessions() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Create sessions
    let s1 = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session 1");
    let s2 = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session 2");

    // Delete user
    harness
        .identity()
        .delete_user(&realm, user.id())
        .expect("delete user");

    // Sessions should be gone
    assert!(harness
        .identity()
        .get_session(&realm, s1.id())
        .expect("get")
        .is_none());
    assert!(harness
        .identity()
        .get_session(&realm, s2.id())
        .expect("get")
        .is_none());
}

// ===== Cross-realm session isolation =====

#[tokio::test]
async fn sessions_are_realm_isolated() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let user = create_user(&harness, &realm_a);

    let session = harness
        .identity()
        .create_session(
            &realm_a,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Can't see realm A's session from realm B
    let cross_realm = harness
        .identity()
        .get_session(&realm_b, session.id())
        .expect("get");
    assert!(
        cross_realm.is_none(),
        "session should not be visible in different realm"
    );
}

// ===== Session for nonexistent user =====

#[tokio::test]
async fn create_session_for_nonexistent_user_fails() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let fake_user = hearth::core::UserId::generate();

    let err = harness
        .identity()
        .create_session(
            &realm,
            &fake_user,
            &hearth::identity::SessionContext::default(),
        )
        .expect_err("should fail");
    assert!(
        format!("{err}").contains("user not found"),
        "should indicate user not found: {err}"
    );
}

// ===== Revoke nonexistent session =====

#[tokio::test]
async fn revoke_nonexistent_session_returns_error() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();

    let err = harness
        .identity()
        .revoke_session(&realm, &SessionId::generate())
        .expect_err("should fail");
    assert!(
        format!("{err}").contains("session not found"),
        "should indicate session not found: {err}"
    );
}

// ============================================================================
// Adversarial tests
// ============================================================================

// ===== Replayed session tokens rejected after revocation =====

#[tokio::test]
async fn replayed_session_token_rejected_after_revocation() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Capture the session ID (simulating an attacker who observed it)
    let captured_id = session.id().clone();

    // Session works before revocation
    let pre_revoke = harness
        .identity()
        .get_session(&realm, &captured_id)
        .expect("get");
    assert!(
        pre_revoke.is_some(),
        "session should work before revocation"
    );

    // Revoke the session
    harness
        .identity()
        .revoke_session(&realm, &captured_id)
        .expect("revoke");

    // Replaying the same session ID should fail
    let replay = harness
        .identity()
        .get_session(&realm, &captured_id)
        .expect("get");
    assert!(
        replay.is_none(),
        "replayed session token must be rejected after revocation"
    );

    // Attempting to refresh the replayed session should also fail
    let refresh_err = harness
        .identity()
        .refresh_session(&realm, &captured_id)
        .expect_err("should fail");
    assert!(
        format!("{refresh_err}").contains("session not found"),
        "refresh of revoked session should fail: {refresh_err}"
    );
}

// ===== Session fixation: pre-auth session ID cannot be reused post-auth =====
// In our model, sessions are only created for authenticated users (post-authentication),
// so session fixation is prevented by design. This test verifies that creating a session
// always generates a fresh ID.

#[tokio::test]
async fn session_fixation_prevention() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Create multiple sessions — each must get a unique ID
    let s1 = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session 1");
    let s2 = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session 2");
    let s3 = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session 3");

    // All session IDs must be distinct (prevents fixation via ID reuse)
    assert_ne!(s1.id(), s2.id(), "sessions must have distinct IDs");
    assert_ne!(s2.id(), s3.id(), "sessions must have distinct IDs");
    assert_ne!(s1.id(), s3.id(), "sessions must have distinct IDs");

    // An attacker-supplied session ID should not be usable
    let attacker_id = SessionId::generate();
    let result = harness
        .identity()
        .get_session(&realm, &attacker_id)
        .expect("get");
    assert!(
        result.is_none(),
        "attacker-supplied session ID must not resolve"
    );
}

// ===== Enumeration resistance: all failure modes indistinguishable =====

#[tokio::test]
async fn enumeration_resistance() {
    use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
    use hearth::core::FakeClock;
    use hearth::identity::{
        CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, SessionConfig,
    };
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use std::sync::Arc;

    // Use FakeClock so we can control expiration
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(temp_dir.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(FakeClock::new(hearth::core::Timestamp::from_micros(
        1_000_000_000,
    )));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        session: SessionConfig {
            ttl_micros: 10_000_000, // 10 seconds for fast testing
        },
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
        identity_config,
        Arc::clone(&audit),
    )
    .expect("engine creation");

    let realm = RealmId::generate();
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "enum@example.com".to_string(),
                display_name: "Enum User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("create user");

    // Create a session, then revoke it
    let revoked_session = engine
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    engine
        .revoke_session(&realm, revoked_session.id())
        .expect("revoke");

    // Create a session, then let it expire
    let expired_session = engine
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    clock.advance(10_000_001); // Past TTL

    // Three scenarios:
    let nonexistent_id = SessionId::generate();

    let resp_nonexistent = engine
        .get_session(&realm, &nonexistent_id)
        .expect("get nonexistent");
    let resp_revoked = engine
        .get_session(&realm, revoked_session.id())
        .expect("get revoked");
    let resp_expired = engine
        .get_session(&realm, expired_session.id())
        .expect("get expired");

    // All three must be indistinguishable: None
    assert!(resp_nonexistent.is_none(), "nonexistent should be None");
    assert!(resp_revoked.is_none(), "revoked should be None");
    assert!(resp_expired.is_none(), "expired should be None");

    // Verify that the error type for refresh is also the same
    let err_nonexistent = engine
        .refresh_session(&realm, &nonexistent_id)
        .expect_err("refresh nonexistent");
    let err_revoked = engine
        .refresh_session(&realm, revoked_session.id())
        .expect_err("refresh revoked");
    let err_expired = engine
        .refresh_session(&realm, expired_session.id())
        .expect_err("refresh expired");

    // All should produce the same error message
    let msg_nonexistent = format!("{err_nonexistent}");
    let msg_revoked = format!("{err_revoked}");
    let msg_expired = format!("{err_expired}");

    assert_eq!(
        msg_nonexistent, msg_revoked,
        "nonexistent and revoked errors must be identical"
    );
    assert_eq!(
        msg_revoked, msg_expired,
        "revoked and expired errors must be identical"
    );
}
