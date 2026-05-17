//! Named adversarial tests for HEA-330 — test pyramid gaps.
//!
//! ## Coverage matrix
//!
//! | Threat scenario | Named test in this file | Related tests elsewhere |
//! |---|---|---|
//! | Timing attack — user enumeration via credential error type | `timing_attack_*` | — |
//! | Account lockout — brute-force protection | `account_lockout_*` | — |
//! | User enumeration — magic link | — | `magic_link::magic_link_enumeration_resistance` |
//! | TLS downgrade prevention | — | `tls::tls_downgrade_prevention_rejects_tls10` |
//! | Privilege escalation (RBAC enforcement) | — | `admin_rbac_auth::permission_gated_denies_non_admin` |

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError, RateLimitConfig,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Builds a synchronous identity engine with the given `max_failed_attempts`.
fn build_engine(max_attempts: u32) -> (impl IdentityEngine, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            rate_limit: RateLimitConfig {
                max_failed_attempts: max_attempts,
                lockout_duration_micros: 15 * 60 * 1_000_000,
            },
            ..IdentityConfig::default()
        },
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine");
    (engine, temp)
}

fn make_realm(engine: &impl IdentityEngine) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("adv-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn new_user_req(prefix: &str) -> CreateUserRequest {
    CreateUserRequest {
        email: format!("{prefix}-{}@test.example", uuid::Uuid::new_v4()),
        display_name: prefix.to_string(),
        first_name: String::new(),
        last_name: String::new(),
        attributes: Default::default(),
    }
}

// ── Timing attack: user enumeration via credential verify ────────────────────

/// Vulnerability class: User Enumeration via `verify_password` (timing)
///
/// When called for a completely nonexistent user ID, `verify_password` must
/// return `InvalidCredential` — the same error variant as a wrong password.
/// Returning a distinct variant (e.g. `UserNotFound`) leaks user existence.
///
/// Defense: the engine performs a dummy hash comparison even when no record
/// is found, keeping timing indistinguishable and returning a uniform error.
#[test]
fn timing_attack_password_verify_nonexistent_user_identical_error() {
    let (engine, _tmp) = build_engine(5);
    let realm = make_realm(&engine);
    let nonexistent = UserId::generate();
    let pw = CleartextPassword::from_string("any-password".to_string());

    let err = engine
        .verify_password(&realm, &nonexistent, &pw)
        .expect_err("must fail for nonexistent user");

    assert!(
        matches!(err, IdentityError::InvalidCredential { .. }),
        "nonexistent user must return InvalidCredential (not UserNotFound): {err:?}"
    );
}

/// Vulnerability class: User Enumeration via `verify_password` (no credential)
///
/// A user who exists but has no password set must return `InvalidCredential`,
/// not a distinct error (e.g. `CredentialNotFound`). The error type must be
/// identical to a wrong-password failure so callers cannot distinguish the
/// two cases.
#[test]
fn timing_attack_password_verify_no_credential_identical_error() {
    let (engine, _tmp) = build_engine(5);
    let realm = make_realm(&engine);
    let user = engine
        .create_user(&realm, &new_user_req("timing-nocred"))
        .expect("create user");
    let pw = CleartextPassword::from_string("any-password".to_string());

    let err = engine
        .verify_password(&realm, user.id(), &pw)
        .expect_err("must fail — no credential set");

    assert!(
        matches!(err, IdentityError::InvalidCredential { .. }),
        "user with no credential must return InvalidCredential: {err:?}"
    );
}

/// Structural invariant: both code paths (nonexistent user, no credential)
/// return the same `InvalidCredential` variant, preventing discrimination.
#[test]
fn timing_attack_both_failure_paths_return_same_error_variant() {
    let (engine, _tmp) = build_engine(5);
    let realm = make_realm(&engine);
    let pw = CleartextPassword::from_string("pw".to_string());

    // Path A: user does not exist at all.
    let err_nonexistent = engine
        .verify_password(&realm, &UserId::generate(), &pw)
        .expect_err("nonexistent path");

    // Path B: user exists, no credential set.
    let user = engine
        .create_user(&realm, &new_user_req("timing-both"))
        .expect("create user");
    let err_no_cred = engine
        .verify_password(&realm, user.id(), &pw)
        .expect_err("no-credential path");

    // Both must be InvalidCredential — same discriminant.
    assert!(
        matches!(err_nonexistent, IdentityError::InvalidCredential { .. }),
        "nonexistent path must return InvalidCredential: {err_nonexistent:?}"
    );
    assert!(
        matches!(err_no_cred, IdentityError::InvalidCredential { .. }),
        "no-credential path must return InvalidCredential: {err_no_cred:?}"
    );
}

// ── Account lockout: brute-force protection ───────────────────────────────────

/// Vulnerability class: Brute-Force Password Attack
///
/// After `max_failed_attempts` consecutive wrong-password calls the account
/// must be locked — subsequent calls return `RateLimited` regardless of the
/// password supplied, preventing automated credential guessing.
#[test]
fn account_lockout_blocks_after_n_failures() {
    const MAX: u32 = 3;
    let (engine, _tmp) = build_engine(MAX);
    let realm = make_realm(&engine);

    let user = engine
        .create_user(&realm, &new_user_req("lockout"))
        .expect("create user");
    engine
        .set_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("correct".to_string()),
        )
        .expect("set password");

    let wrong = CleartextPassword::from_string("wrong".to_string());

    // First MAX wrong attempts return Ok(false) — the attempt counter increments
    // on each false verification, but the lockout is not yet applied.
    for attempt in 1..=MAX {
        let result = engine.verify_password(&realm, user.id(), &wrong);
        assert!(
            matches!(result, Ok(false)),
            "attempt {attempt}: expected Ok(false) pre-lockout, got {result:?}"
        );
    }

    // The (MAX+1)th attempt — same wrong password — must now be locked out.
    let result = engine.verify_password(&realm, user.id(), &wrong);
    assert!(
        matches!(result, Err(IdentityError::RateLimited)),
        "after {MAX} failures expected RateLimited; got: {result:?}"
    );
}

/// Lockout blocks even the correct password during the lockout window,
/// preventing "keep guessing until the right answer slips through" attacks.
#[test]
fn account_lockout_blocks_correct_password_during_window() {
    const MAX: u32 = 3;
    let (engine, _tmp) = build_engine(MAX);
    let realm = make_realm(&engine);

    let user = engine
        .create_user(&realm, &new_user_req("lockout-correct"))
        .expect("create user");
    let correct = CleartextPassword::from_string("correct".to_string());
    engine
        .set_password(&realm, user.id(), &correct)
        .expect("set password");

    // Exhaust the attempt budget.
    let wrong = CleartextPassword::from_string("wrong".to_string());
    for _ in 0..MAX {
        let _ = engine.verify_password(&realm, user.id(), &wrong);
    }

    // Even the correct password must be blocked during the lockout window.
    let result = engine.verify_password(&realm, user.id(), &correct);
    assert!(
        matches!(result, Err(IdentityError::RateLimited)),
        "correct password must be blocked during lockout window: {result:?}"
    );
}
