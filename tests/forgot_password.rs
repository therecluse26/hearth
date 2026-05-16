//! Integration tests for the forgot-password / password-reset flow (HEA-489).
//!
//! ## Coverage matrix
//!
//! | Scenario | Test |
//! |---|---|
//! | Full reset flow (request → reset → verify) | `forgot_password_full_flow` |
//! | Session invalidation on reset | `forgot_password_invalidates_sessions` |
//! | Single-use token (replay rejected) | `forgot_password_token_single_use` |
//! | Enumeration resistance (unknown email silent) | `forgot_password_enumeration_resistance` |
//! | Token expiry (default 30-minute TTL) | `forgot_password_token_expires` |
//! | Rate limit (3 per 15 minutes) | `forgot_password_rate_limit` |
//! | Rate limit resets after window | `forgot_password_rate_limit_resets_after_window` |

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CleartextPassword, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
    IdentityEngine, IdentityError, SessionContext,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn build_engine() -> (EmbeddedIdentityEngine, Arc<FakeClock>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf())).expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        storage,
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine");
    (engine, clock, tmp)
}

fn create_user_with_password(
    engine: &impl IdentityEngine,
    realm: &RealmId,
    prefix: &str,
) -> hearth::identity::User {
    let user = engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("{prefix}-{}@example.com", uuid::Uuid::new_v4()),
                display_name: prefix.to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    engine
        .set_password(
            realm,
            user.id(),
            &CleartextPassword::from_string("OriginalPass1!".to_string()),
        )
        .expect("set password");
    user
}

// ── Scenario: full reset flow ─────────────────────────────────────────────────

/// Happy-path: request reset → use token → old password rejected, new accepted.
#[tokio::test]
async fn forgot_password_full_flow() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let identity = harness.identity();

    let user = identity
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    identity
        .set_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("OldSecret99!".to_string()),
        )
        .expect("set password");

    // Request a reset token.
    let token = identity
        .request_password_reset(&realm, user.email())
        .expect("request reset")
        .expect("known user must yield a token");

    // Consume the token with a new password.
    let returned_id = identity
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string("NewSecret99!".to_string()),
        )
        .expect("reset must succeed");

    assert_eq!(returned_id, *user.id(), "reset must return the user's ID");

    // Old password must now be rejected.
    let old_ok = identity
        .verify_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("OldSecret99!".to_string()),
        )
        .expect("verify old");
    assert!(!old_ok, "old password must be invalid after reset");

    // New password must be accepted.
    let new_ok = identity
        .verify_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("NewSecret99!".to_string()),
        )
        .expect("verify new");
    assert!(new_ok, "new password must be valid after reset");
}

// ── Scenario: session invalidation ───────────────────────────────────────────

/// Active sessions must be revoked when a password reset completes.
#[tokio::test]
async fn forgot_password_invalidates_sessions() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let identity = harness.identity();

    let user = identity
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bob@example.com".to_string(),
                display_name: "Bob".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    identity
        .set_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("BobPass1!".to_string()),
        )
        .expect("set password");

    // Create two active sessions.
    let session1 = identity
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session 1");
    let session2 = identity
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session 2");

    // Verify sessions are active pre-reset.
    assert!(
        identity
            .get_session(&realm, session1.id())
            .expect("get s1")
            .is_some(),
        "session1 must be active before reset"
    );

    // Request and consume a reset token.
    let token = identity
        .request_password_reset(&realm, user.email())
        .expect("request reset")
        .expect("token");
    identity
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string("NewBobPass1!".to_string()),
        )
        .expect("reset");

    // Both sessions must now be revoked.
    let s1_after = identity
        .get_session(&realm, session1.id())
        .expect("get s1 after");
    let s2_after = identity
        .get_session(&realm, session2.id())
        .expect("get s2 after");
    assert!(
        s1_after.is_none(),
        "session1 must be revoked after password reset"
    );
    assert!(
        s2_after.is_none(),
        "session2 must be revoked after password reset"
    );
}

// ── Scenario: single-use token ────────────────────────────────────────────────

/// A reset token may only be consumed once — replay must be rejected.
#[test]
fn forgot_password_token_single_use() {
    let (engine, _clock, _tmp) = build_engine();
    let realm = RealmId::generate();
    let user = create_user_with_password(&engine, &realm, "single-use");

    let token = engine
        .request_password_reset(&realm, user.email())
        .expect("request")
        .expect("token");

    // First use succeeds.
    engine
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string("NewValid1!".to_string()),
        )
        .expect("first use must succeed");

    // Second use with the same token must fail.
    let err = engine
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string("AnotherNew1!".to_string()),
        )
        .expect_err("replay must be rejected");

    assert!(
        matches!(err, IdentityError::PasswordResetTokenInvalid),
        "replay must return PasswordResetTokenInvalid, got: {err}"
    );
}

// ── Scenario: enumeration resistance ─────────────────────────────────────────

/// Requesting a reset for an unknown email must return `Ok(None)` — not an
/// error — so callers cannot distinguish registered from unregistered addresses.
#[test]
fn forgot_password_enumeration_resistance() {
    let (engine, _clock, _tmp) = build_engine();
    let realm = RealmId::generate();

    // Unknown address.
    let result = engine
        .request_password_reset(&realm, "nobody@example.com")
        .expect("must not error on unknown email");

    assert!(
        result.is_none(),
        "unknown email must return None (not an error): {result:?}"
    );
}

// ── Scenario: token expiry ────────────────────────────────────────────────────

/// The default 30-minute TTL must be enforced. A token used after expiry must
/// return `PasswordResetTokenInvalid`.
#[test]
fn forgot_password_token_expires() {
    let (engine, clock, _tmp) = build_engine();
    let realm = RealmId::generate();
    let user = create_user_with_password(&engine, &realm, "expiry");

    let token = engine
        .request_password_reset(&realm, user.email())
        .expect("request")
        .expect("token");

    // Advance past the default 30-minute TTL.
    const DEFAULT_TTL_MICROS: i64 = 30 * 60 * 1_000_000;
    clock.advance(DEFAULT_TTL_MICROS + 1);

    let err = engine
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string("TooLate1!".to_string()),
        )
        .expect_err("expired token must be rejected");

    assert!(
        matches!(err, IdentityError::PasswordResetTokenInvalid),
        "expired token must return PasswordResetTokenInvalid, got: {err}"
    );
}

// ── Scenario: rate limiting ───────────────────────────────────────────────────

/// After 3 reset requests the endpoint must block further attempts for the same
/// email within the 15-minute window.
#[test]
fn forgot_password_rate_limit() {
    let (engine, _clock, _tmp) = build_engine();
    let realm = RealmId::generate();
    let user = create_user_with_password(&engine, &realm, "rate-limit");

    // Three requests must succeed (returning Some token).
    for i in 1..=3u32 {
        let result = engine
            .request_password_reset(&realm, user.email())
            .expect("request must not error");
        assert!(
            result.is_some(),
            "request {i}/3 must return a token before rate limit"
        );
    }

    // Fourth request within the same 15-minute window must be rate-limited.
    let err = engine
        .request_password_reset(&realm, user.email())
        .expect_err("4th request must be rate-limited");

    assert!(
        matches!(err, IdentityError::RateLimited),
        "4th request must return RateLimited, got: {err}"
    );
}

/// After the 15-minute window elapses the rate limit must reset.
#[test]
fn forgot_password_rate_limit_resets_after_window() {
    let (engine, clock, _tmp) = build_engine();
    let realm = RealmId::generate();
    let user = create_user_with_password(&engine, &realm, "rl-reset");

    // Exhaust the limit.
    for _ in 0..3 {
        let _ = engine.request_password_reset(&realm, user.email());
    }
    engine
        .request_password_reset(&realm, user.email())
        .expect_err("must be limited before window reset");

    // Advance past the 15-minute window.
    const WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;
    clock.advance(WINDOW_MICROS + 1);

    // Should be permitted again after the window expires.
    let result = engine
        .request_password_reset(&realm, user.email())
        .expect("request after window must not error");
    assert!(
        result.is_some(),
        "request after window reset must return a token"
    );
}
