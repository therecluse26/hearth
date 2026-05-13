//! Adversarial JWT token suite — HEA-196
//!
//! Tests every JWT consumer (validate_token, refresh_tokens, introspect_token,
//! revoke_token) against each negative path from the threat model:
//! alg confusion (none, HS256), cross-realm replay, expired token, future-dated iat.
//!
//! ## Threat model
//!
//! | Attack                  | validate_token | refresh_tokens | introspect_token | revoke_token |
//! |-------------------------|:--------------:|:--------------:|:----------------:|:------------:|
//! | alg:none forgery        | tested         | tested         | tested           | tested       |
//! | HS256 key confusion     | tested         | tested         | (implicit)       | (implicit)   |
//! | Expired access token    | tokens.rs      | tested         | tested           | —            |
//! | Cross-realm replay      | tokens.rs      | tested         | tested           | tested       |
//! | Future-dated iat        | tested (risk)  | —              | —                | —            |
//! | Tampered payload        | tokens.rs      | tokens.rs      | tokens.rs        | tokens.rs    |
//! | Revoked JTI (cc)        | oauth.rs       | —              | tested           | —            |
//!
//! ## aud claim validation (HEA-239 — resolved)
//!
//! `validate_token`, `refresh_tokens`, and `introspect_token` now all enforce
//! RFC 7519 §4.1.3: `claims.aud.contains(&config.token.audience)` is checked
//! after `tid`. Tests in the `wrong_aud_*` section verify this enforcement.

mod common;

use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    CreateUserRequest, SessionContext, TokenIntrospectionRequest, TokenRevocationRequest, User,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("adv-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Adversarial User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

/// Builds an `alg:none` token from the payload of any valid token.
///
/// The header is replaced with `{"alg":"none","typ":"JWT"}` and the signature
/// field is set to the empty string, matching the canonical alg=none bypass.
fn forge_alg_none(valid_token: &str) -> String {
    let parts: Vec<&str> = valid_token.split('.').collect();
    assert_eq!(parts.len(), 3, "token must have three dot-separated parts");
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    format!("{}.{}.", header, parts[1])
}

/// Builds an `HS256`-claimed token from the payload of any valid token.
///
/// The signature is garbage bytes — the alg-check in `verify_token_signature`
/// fires before ring's Ed25519 verifier, so any non-EdDSA alg is rejected
/// regardless of signature content. This test proves that invariant.
fn forge_hs256(valid_token: &str) -> String {
    let parts: Vec<&str> = valid_token.split('.').collect();
    assert_eq!(parts.len(), 3, "token must have three dot-separated parts");
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    // Public key bytes used as HMAC secret — the classic key-confusion payload.
    let fake_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(b"hs256-key-confusion-garbage-not-a-real-hmac");
    format!("{}.{}.{}", header, parts[1], fake_sig)
}

/// Returns an engine backed by a controllable `FakeClock` for expiry tests.
async fn engine_with_fake_clock() -> (
    impl hearth::identity::IdentityEngine,
    std::sync::Arc<hearth::core::FakeClock>,
    tempfile::TempDir,
) {
    use hearth::audit::EmbeddedAuditEngine;
    use hearth::core::{Clock, FakeClock, Timestamp};
    use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
    use hearth::rbac::EmbeddedRbacEngine;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use std::sync::Arc;

    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("storage"),
    );
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        Arc::clone(&rbac) as Arc<dyn hearth::rbac::RbacEngine>,
        Arc::clone(&audit) as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine");
    (engine, clock, temp)
}

// ── alg:none — validate_token ─────────────────────────────────────────────────

/// Vulnerability class: Algorithm Confusion / alg:none bypass (OWASP A2)
///
/// An unsigned token with a valid payload must be rejected by validate_token.
/// Defense: `verify_token_signature` checks `header.alg == "EdDSA"` before
/// invoking ring's Ed25519 verifier.
#[tokio::test]
async fn alg_none_rejected_by_validate_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_alg_none(pair.access_token());
    let result = harness.identity().validate_token(&realm, &forged);
    assert!(
        result.is_err(),
        "alg:none access token must be rejected by validate_token, got: {result:?}"
    );
}

// ── alg:none — userinfo ───────────────────────────────────────────────────────

/// An alg:none access token presented to userinfo must return an error.
/// userinfo delegates to validate_token, which rejects alg:none at the
/// crypto layer; the error propagates as an identity error (not a panic).
#[tokio::test]
async fn alg_none_rejected_by_userinfo() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_alg_none(pair.access_token());
    let result = harness.identity().userinfo(&realm, &forged);
    assert!(
        result.is_err(),
        "alg:none token must be rejected by userinfo, got: {result:?}"
    );
}

// ── alg:none — refresh_tokens ─────────────────────────────────────────────────

/// An alg:none refresh token must be rejected by refresh_tokens.
#[tokio::test]
async fn alg_none_rejected_by_refresh_tokens() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_alg_none(pair.refresh_token());
    let result = harness.identity().refresh_tokens(&realm, &forged);
    assert!(
        result.is_err(),
        "alg:none refresh token must be rejected by refresh_tokens, got: {result:?}"
    );
}

// ── alg:none — introspect_token ───────────────────────────────────────────────

/// An alg:none token presented to introspect_token must return inactive, not
/// active. RFC 7662: cryptographically invalid tokens → `{"active": false}`.
#[tokio::test]
async fn alg_none_on_introspect_returns_inactive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_alg_none(pair.access_token());
    let response = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: forged,
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "alg:none token must introspect as inactive"
    );
}

// ── alg:none — revoke_token ───────────────────────────────────────────────────

/// An alg:none token presented to revoke_token must silently succeed (RFC 7009:
/// invalid tokens → 200 OK) without revoking any real session.
#[tokio::test]
async fn alg_none_on_revoke_is_silent_noop() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_alg_none(pair.access_token());
    // revoke_token must return Ok — not an error.
    harness
        .identity()
        .revoke_token(
            &realm,
            &TokenRevocationRequest {
                token: forged,
                token_type_hint: None,
            },
        )
        .expect("revoke of alg:none token must silently succeed (RFC 7009)");

    // The real session must be untouched.
    assert!(
        harness
            .identity()
            .validate_token(&realm, pair.access_token())
            .is_ok(),
        "real access token must still be valid after forged-token revoke attempt"
    );
}

// ── HS256 key confusion — validate_token ─────────────────────────────────────

/// Vulnerability class: JWT Algorithm Confusion — HS256 vs EdDSA
///
/// An attacker uses the Ed25519 public key bytes as an HMAC-SHA256 secret to
/// forge a token.  `verify_token_signature` must reject HS256-claimed tokens
/// before attempting signature verification.
#[tokio::test]
async fn hs256_forgery_rejected_by_validate_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_hs256(pair.access_token());
    let result = harness.identity().validate_token(&realm, &forged);
    assert!(
        result.is_err(),
        "HS256-claimed token must be rejected by validate_token, got: {result:?}"
    );
}

// ── HS256 key confusion — introspect_token ────────────────────────────────────

/// An HS256-claimed token presented to introspect_token must return inactive.
/// Defense: alg check fires before signature verification.
#[tokio::test]
async fn hs256_forgery_on_introspect_returns_inactive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_hs256(pair.access_token());
    let response = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: forged,
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "HS256-claimed token must introspect as inactive"
    );
}

// ── HS256 key confusion — refresh_tokens ─────────────────────────────────────

#[tokio::test]
async fn hs256_forgery_rejected_by_refresh_tokens() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let forged = forge_hs256(pair.refresh_token());
    let result = harness.identity().refresh_tokens(&realm, &forged);
    assert!(
        result.is_err(),
        "HS256-claimed refresh token must be rejected, got: {result:?}"
    );
}

// ── Expiry — refresh_tokens ───────────────────────────────────────────────────

/// An expired refresh token must be rejected by refresh_tokens.
/// Clock is advanced past the refresh-token TTL (≥30 days default).
#[tokio::test]
async fn expired_refresh_token_rejected() {
    use hearth::identity::IdentityEngine;

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = RealmId::generate();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("exp-refresh-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    // Advance clock past 31 days to expire the refresh token.
    clock.advance(31 * 24 * 3600 * 1_000_000);

    let result = engine.refresh_tokens(&realm, pair.refresh_token());
    assert!(
        result.is_err(),
        "expired refresh token must be rejected: {result:?}"
    );
}

// ── Expiry — introspect_token ─────────────────────────────────────────────────

/// An expired access token must introspect as inactive.
#[tokio::test]
async fn expired_token_introspects_inactive() {
    use hearth::identity::IdentityEngine;

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = RealmId::generate();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("exp-introspect-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    // Advance past the 900-second access-token TTL.
    clock.advance(901 * 1_000_000);

    let response = engine
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "expired token must introspect as inactive"
    );
}

// ── Cross-realm replay — validate_token ──────────────────────────────────────

/// A token issued in realm A must not be accepted by validate_token in realm B.
/// Defense: `verify_token_signature_for_realm` uses realm B's key; the signature
/// (made with realm A's key) fails verification.
#[tokio::test]
async fn cross_realm_replay_rejected_by_validate_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let user = create_user(&harness, &realm_a);
    let session = harness
        .identity()
        .create_session(&realm_a, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm_a, user.id(), session.id())
        .expect("tokens");

    let result = harness
        .identity()
        .validate_token(&realm_b, pair.access_token());
    assert!(
        result.is_err(),
        "access token from realm A must be rejected by realm B validate_token: {result:?}"
    );
}

// ── Cross-realm replay — refresh_tokens ──────────────────────────────────────

/// Vulnerability class: Cross-realm token replay
///
/// A token issued in realm A must not be accepted by refresh_tokens in realm B.
/// Defense: `verify_token_signature_for_realm` looks up realm B's signing key;
/// since the token was signed with realm A's key, the signature check fails.
#[tokio::test]
async fn cross_realm_replay_on_refresh_tokens() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let user = create_user(&harness, &realm_a);
    let session = harness
        .identity()
        .create_session(&realm_a, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm_a, user.id(), session.id())
        .expect("tokens");

    // Present realm_A's refresh token to realm_B's refresh endpoint.
    let result = harness
        .identity()
        .refresh_tokens(&realm_b, pair.refresh_token());
    assert!(
        result.is_err(),
        "refresh token from realm A must be rejected by realm B: {result:?}"
    );
}

// ── Cross-realm replay — introspect_token ────────────────────────────────────

/// A token issued in realm A introspected against realm B must return inactive.
#[tokio::test]
async fn cross_realm_replay_on_introspect_returns_inactive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let user = create_user(&harness, &realm_a);
    let session = harness
        .identity()
        .create_session(&realm_a, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm_a, user.id(), session.id())
        .expect("tokens");

    let response = harness
        .identity()
        .introspect_token(
            &realm_b,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "token from realm A must introspect as inactive against realm B"
    );
}

// ── Cross-realm replay — revoke_token ────────────────────────────────────────

/// A token from realm A presented to realm B's revoke endpoint must silently
/// succeed without revoking the real session in realm A (RFC 7009 §2.2: invalid
/// tokens → 200 OK, no error disclosure).
#[tokio::test]
async fn cross_realm_revoke_is_silent_noop() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let user = create_user(&harness, &realm_a);
    let session = harness
        .identity()
        .create_session(&realm_a, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm_a, user.id(), session.id())
        .expect("tokens");

    // Attempt revocation against realm B — must not error.
    harness
        .identity()
        .revoke_token(
            &realm_b,
            &TokenRevocationRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("cross-realm revoke must silently succeed (RFC 7009)");

    // The session in realm A must be unaffected.
    assert!(
        harness
            .identity()
            .validate_token(&realm_a, pair.access_token())
            .is_ok(),
        "session in realm A must not be revoked by a cross-realm revoke attempt"
    );
}

// ── Revoked JTI replay — introspect_token ────────────────────────────────────

/// A revoked access token must introspect as inactive even when the session
/// has been deleted.  This covers the code path where `validate_token` would
/// fail for a missing session but `introspect_token` must also return inactive
/// for a token whose session no longer exists.
#[tokio::test]
async fn revoked_session_token_introspects_inactive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    // Revoke via the official revocation endpoint.
    harness
        .identity()
        .revoke_token(
            &realm,
            &TokenRevocationRequest {
                token: pair.access_token().to_string(),
                token_type_hint: Some("access_token".to_string()),
            },
        )
        .expect("revoke");

    // Introspect after revocation — must return inactive.
    let response = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "revoked token must introspect as inactive"
    );
}

// ── V2: future-dated iat — validate_token (T11) ──────────────────────────────

/// Vulnerability class: Future-dated `iat` (V2, Medium severity — HEA-196)
///
/// A token issued at a future time (clock skewed forward at issuance) must be
/// rejected by validate_token when the validator's clock is behind the token's
/// iat by more than CLOCK_SKEW_SECS (60 s).
///
/// Test approach: use FakeClock to issue a token at time T+3600, then rewind
/// the clock to T. iat (T+3600) > now (T) + 60 s → InvalidToken.
#[tokio::test]
async fn future_iat_rejected_by_validate_token() {
    use hearth::identity::IdentityEngine;

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = RealmId::generate();

    // Advance clock 1 hour into the future, then issue a token.
    clock.advance(3600 * 1_000_000);
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("fut-iat-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    // Rewind clock back 1 hour so iat is 3600 s ahead of validator time.
    clock.advance(-3600 * 1_000_000);

    let result = engine.validate_token(&realm, pair.access_token());
    assert!(
        result.is_err(),
        "token with future iat must be rejected by validate_token: {result:?}"
    );
}

// ── V2: future-dated iat — refresh_tokens (T12) ──────────────────────────────

/// A refresh token with a future iat must be rejected by refresh_tokens.
#[tokio::test]
async fn future_iat_rejected_by_refresh_tokens() {
    use hearth::identity::IdentityEngine;

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = RealmId::generate();

    clock.advance(3600 * 1_000_000);
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("fut-iat-ref-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    clock.advance(-3600 * 1_000_000);

    let result = engine.refresh_tokens(&realm, pair.refresh_token());
    assert!(
        result.is_err(),
        "refresh token with future iat must be rejected: {result:?}"
    );
}

// ── V2: future-dated iat — introspect_token (T13) ────────────────────────────

/// A token with a future iat must introspect as inactive.
#[tokio::test]
async fn future_iat_introspects_inactive() {
    use hearth::identity::IdentityEngine;

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = RealmId::generate();

    clock.advance(3600 * 1_000_000);
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("fut-iat-intro-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    clock.advance(-3600 * 1_000_000);

    let response = engine
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "token with future iat must introspect as inactive"
    );
}

// ── V2: boundary — token within clock skew tolerance accepted ─────────────────

/// Tokens with iat within CLOCK_SKEW_SECS (60 s) of now must still be accepted.
/// This confirms the skew window is a tolerance, not a hard future-ban.
#[tokio::test]
async fn token_within_clock_skew_accepted() {
    use hearth::identity::IdentityEngine;

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = RealmId::generate();

    // Issue token 30 seconds in the future (within the 60 s skew window).
    clock.advance(30 * 1_000_000);
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("skew-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    // Roll back 30 s so iat is exactly 30 s ahead of validator — within tolerance.
    clock.advance(-30 * 1_000_000);

    assert!(
        engine.validate_token(&realm, pair.access_token()).is_ok(),
        "token with iat within clock-skew tolerance must be accepted"
    );
}

// ── aud claim enforcement (HEA-239) ──────────────────────────────────────────

/// Builds an identity engine with a custom token audience, sharing `storage`
/// and `clock` so the realm Ed25519 keys are identical across both engines.
///
/// This lets tests issue a token with audience "hearth" from one engine and
/// present it to a second engine expecting "other-service" — the signature
/// is cryptographically valid, so any rejection comes from the aud check.
fn build_engine_for_aud_test(
    storage: std::sync::Arc<dyn hearth::storage::StorageEngine>,
    clock: std::sync::Arc<dyn hearth::core::Clock>,
    audience: impl Into<String>,
) -> impl hearth::identity::IdentityEngine {
    use hearth::audit::EmbeddedAuditEngine;
    use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, TokenConfig};
    use hearth::rbac::EmbeddedRbacEngine;
    let audit = std::sync::Arc::new(EmbeddedAuditEngine::new(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
    ));
    let rbac = std::sync::Arc::new(EmbeddedRbacEngine::new(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
    ));
    EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            token: TokenConfig {
                audience: audience.into(),
                ..TokenConfig::default()
            },
            ..IdentityConfig::default()
        },
        rbac as std::sync::Arc<dyn hearth::rbac::RbacEngine>,
        audit as std::sync::Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine")
}

/// RFC 7519 §4.1.3 — wrong audience access token rejected by validate_token.
///
/// Engine A issues a token (aud="hearth"). Engine B expects aud="other-service".
/// Both share the same storage so the realm key is identical — the token is
/// cryptographically valid; rejection comes solely from the semantic aud check.
#[tokio::test]
async fn wrong_aud_rejected_by_validate_token() {
    use hearth::core::{FakeClock, Timestamp};
    use hearth::identity::IdentityEngine;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = std::sync::Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf())).expect("storage"),
    ) as std::sync::Arc<dyn StorageEngine>;
    let clock = std::sync::Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    ))) as std::sync::Arc<dyn hearth::core::Clock>;

    let engine_a = build_engine_for_aud_test(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
        "hearth",
    );
    let engine_b = build_engine_for_aud_test(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
        "other-service",
    );

    let realm = RealmId::generate();
    let user = engine_a
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("aud-mismatch-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine_a
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine_a
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    assert!(
        engine_a.validate_token(&realm, pair.access_token()).is_ok(),
        "token must be valid for its own engine (aud=hearth)"
    );
    let result = engine_b.validate_token(&realm, pair.access_token());
    assert!(
        result.is_err(),
        "aud=hearth must be rejected by engine expecting aud=other-service: {result:?}"
    );
}

/// RFC 7519 §4.1.3 — wrong audience refresh token rejected by refresh_tokens.
#[tokio::test]
async fn wrong_aud_rejected_by_refresh_tokens() {
    use hearth::core::{FakeClock, Timestamp};
    use hearth::identity::IdentityEngine;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = std::sync::Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf())).expect("storage"),
    ) as std::sync::Arc<dyn StorageEngine>;
    let clock = std::sync::Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    ))) as std::sync::Arc<dyn hearth::core::Clock>;

    let engine_a = build_engine_for_aud_test(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
        "hearth",
    );
    let engine_b = build_engine_for_aud_test(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
        "other-service",
    );

    let realm = RealmId::generate();
    let user = engine_a
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("aud-mismatch-ref-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine_a
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine_a
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let result = engine_b.refresh_tokens(&realm, pair.refresh_token());
    assert!(
        result.is_err(),
        "aud=hearth refresh token must be rejected by engine expecting aud=other-service: {result:?}"
    );
}

/// RFC 7519 §4.1.3 — wrong audience access token introspects as inactive.
#[tokio::test]
async fn wrong_aud_introspects_inactive() {
    use hearth::core::{FakeClock, Timestamp};
    use hearth::identity::IdentityEngine;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = std::sync::Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(tmp.path().to_path_buf())).expect("storage"),
    ) as std::sync::Arc<dyn StorageEngine>;
    let clock = std::sync::Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    ))) as std::sync::Arc<dyn hearth::core::Clock>;

    let engine_a = build_engine_for_aud_test(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
        "hearth",
    );
    let engine_b = build_engine_for_aud_test(
        std::sync::Arc::clone(&storage),
        std::sync::Arc::clone(&clock),
        "other-service",
    );

    let realm = RealmId::generate();
    let user = engine_a
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("aud-mismatch-intr-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine_a
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine_a
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens");

    let response = engine_b
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect must not error");
    assert!(
        !response.active,
        "aud=hearth token must introspect as inactive when engine expects aud=other-service"
    );
}
