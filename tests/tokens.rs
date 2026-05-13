//! Integration tests for JWT token issuance and validation.
//!
//! Black box tests via `TestHarness` — exercises token operations
//! through the public `IdentityEngine` trait.

mod common;

use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    verify_token_signature, CreateUserRequest, TokenIntrospectionRequest, TokenRevocationRequest,
    User,
};

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

/// Returns a JWT with a tampered payload and the original signature.
///
/// This simulates an attacker mutating claims without access to the signing key.
fn tamper_jwt_payload<F>(token: &str, mutate: F) -> String
where
    F: FnOnce(&mut serde_json::Value),
{
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "token must have 3 parts");

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode JWT payload");
    let mut payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("parse JWT payload JSON");
    mutate(&mut payload);

    let tampered_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).expect("serialize tampered payload"));

    format!("{}.{}.{}", parts[0], tampered_payload, parts[2])
}

// ===== Scenario: Token issuance and validation round-trip via public API =====

#[tokio::test]
async fn token_issuance_and_validation_roundtrip() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Create a session
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Issue tokens
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Access token should be non-empty
    assert!(!pair.access_token().is_empty(), "access token should exist");
    assert!(
        !pair.refresh_token().is_empty(),
        "refresh token should exist"
    );

    // Validate access token via session lookup (internal hot path)
    let claims = harness
        .identity()
        .validate_token(&realm, pair.access_token())
        .expect("validate access token");

    // Claims should reference the correct user and session
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.sid, session.id().to_string());
    assert_eq!(claims.tid, realm.to_string());
    assert_eq!(claims.token_type, "access");

    // JWKS should contain the Ed25519 signing key that issued the token
    // (plus RS256/ES256 ecosystem-compat entries from HEA-51 — those are
    // verification-only and not the signer for this access token).
    let jwks = harness.identity().jwks();
    let jwk = jwks
        .keys
        .iter()
        .find(|j| j.alg == "EdDSA")
        .expect("JWKS should include the EdDSA signer");
    let x_b64 = jwk.x.as_deref().expect("Ed25519 JWK must include x");
    let pub_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .expect("decode JWKS public key");
    let verified_claims = verify_token_signature(pair.access_token(), &pub_bytes)
        .expect("cryptographic verification should succeed");
    assert_eq!(verified_claims, claims);
}

// ===== Scenario: Token refresh flow end-to-end =====

#[tokio::test]
async fn token_refresh_flow_end_to_end() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);

    // Create session and initial tokens
    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let original_pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Validate original access token works
    let original_claims = harness
        .identity()
        .validate_token(&realm, original_pair.access_token())
        .expect("validate original");
    assert_eq!(original_claims.token_type, "access");

    // Refresh using the refresh token
    let refreshed_pair = harness
        .identity()
        .refresh_tokens(&realm, original_pair.refresh_token())
        .expect("refresh tokens");

    // New access token should be valid and bound to same user/session
    let refreshed_claims = harness
        .identity()
        .validate_token(&realm, refreshed_pair.access_token())
        .expect("validate refreshed access token");
    assert_eq!(refreshed_claims.sub, user.id().to_string());
    assert_eq!(refreshed_claims.sid, session.id().to_string());
    assert_eq!(refreshed_claims.token_type, "access");

    // New refresh token should also be valid
    let refreshed_refresh_claims =
        hearth::identity::decode_claims_unverified(refreshed_pair.refresh_token())
            .expect("decode refreshed refresh token");
    assert_eq!(refreshed_refresh_claims.token_type, "refresh");
    assert_eq!(refreshed_refresh_claims.sub, user.id().to_string());

    // Attempt to use access token as refresh token should fail
    let bad_refresh = harness
        .identity()
        .refresh_tokens(&realm, original_pair.access_token());
    assert!(
        bad_refresh.is_err(),
        "using access token as refresh should fail"
    );
}

// ===== Scenario: Token validation fails for revoked session =====

#[tokio::test]
async fn token_invalid_after_session_revoked() {
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
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Token works before revocation
    assert!(
        harness
            .identity()
            .validate_token(&realm, pair.access_token())
            .is_ok(),
        "token should be valid before revocation"
    );

    // Revoke the session
    harness
        .identity()
        .revoke_session(&realm, session.id())
        .expect("revoke session");

    // Token should now fail validation (session lookup fails)
    let result = harness
        .identity()
        .validate_token(&realm, pair.access_token());
    assert!(
        result.is_err(),
        "token should be invalid after session revocation"
    );
}

// ===== Scenario: Token validation fails for wrong realm =====

#[tokio::test]
async fn token_invalid_for_different_realm() {
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
    let pair = harness
        .identity()
        .issue_tokens(&realm_a, user.id(), session.id())
        .expect("issue tokens");

    // Validate with wrong realm should fail
    let result = harness
        .identity()
        .validate_token(&realm_b, pair.access_token());
    assert!(
        result.is_err(),
        "token should be invalid for different realm"
    );
}

// ===== Scenario: Issue tokens fails for nonexistent user =====

#[tokio::test]
async fn issue_tokens_fails_nonexistent_user() {
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

    // Delete the user
    harness
        .identity()
        .delete_user(&realm, user.id())
        .expect("delete user");

    // Issue tokens should fail
    let result = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id());
    assert!(result.is_err(), "issue tokens should fail for deleted user");
}

#[tokio::test]
async fn validate_token_rejects_tampered_payload() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let other_user = create_user(&harness, &realm);

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let tampered = tamper_jwt_payload(pair.access_token(), |payload| {
        payload["sub"] = serde_json::Value::String(other_user.id().to_string());
    });

    let result = harness.identity().validate_token(&realm, &tampered);
    assert!(result.is_err(), "tampered token must be rejected");
}

#[tokio::test]
async fn refresh_token_rejects_tampered_user_binding() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let other_user = create_user(&harness, &realm);

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let tampered = tamper_jwt_payload(pair.refresh_token(), |payload| {
        payload["sub"] = serde_json::Value::String(other_user.id().to_string());
    });

    let result = harness.identity().refresh_tokens(&realm, &tampered);
    assert!(result.is_err(), "tampered refresh token must be rejected");
}

#[tokio::test]
async fn revoke_token_ignores_tampered_payload() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let victim = create_user(&harness, &realm);
    let attacker = create_user(&harness, &realm);

    let victim_session = harness
        .identity()
        .create_session(
            &realm,
            victim.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create victim session");
    let victim_pair = harness
        .identity()
        .issue_tokens(&realm, victim.id(), victim_session.id())
        .expect("issue victim tokens");

    let attacker_session = harness
        .identity()
        .create_session(
            &realm,
            attacker.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create attacker session");
    let attacker_pair = harness
        .identity()
        .issue_tokens(&realm, attacker.id(), attacker_session.id())
        .expect("issue attacker tokens");

    let tampered = tamper_jwt_payload(attacker_pair.access_token(), |payload| {
        payload["sid"] = serde_json::Value::String(victim_session.id().to_string());
    });

    harness
        .identity()
        .revoke_token(
            &realm,
            &TokenRevocationRequest {
                token: tampered,
                token_type_hint: Some("access_token".to_string()),
            },
        )
        .expect("revoke token");

    let victim_result = harness
        .identity()
        .validate_token(&realm, victim_pair.access_token());
    assert!(
        victim_result.is_ok(),
        "tampered token revocation must not revoke victim session"
    );
}

#[tokio::test]
async fn introspection_returns_inactive_for_tampered_payload() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let user = create_user(&harness, &realm);
    let other_user = create_user(&harness, &realm);

    let session = harness
        .identity()
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let tampered = tamper_jwt_payload(pair.access_token(), |payload| {
        payload["sub"] = serde_json::Value::String(other_user.id().to_string());
    });

    let introspection = harness
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: tampered,
                token_type_hint: Some("access_token".to_string()),
            },
        )
        .expect("introspect token");

    assert!(
        !introspection.active,
        "tampered token must not introspect as active"
    );
}

// ===== Scenario: Expired access token is rejected =====

/// Builds an isolated identity engine backed by a `FakeClock` so we can
/// advance time without sleeping.
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
    // Start the clock at a realistic Unix timestamp so exp values are sensible.
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_700_000_000_000_000)));
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

#[tokio::test]
async fn validate_token_rejects_expired_access_token() {
    use hearth::identity::{IdentityEngine, SessionContext};

    let (engine, clock, _tmp) = engine_with_fake_clock().await;
    let realm = hearth::core::RealmId::generate();

    let user = engine
        .create_user(
            &realm,
            &hearth::identity::CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Token should be valid right after issuance.
    assert!(
        engine.validate_token(&realm, pair.access_token()).is_ok(),
        "freshly issued token must be valid"
    );

    // Advance clock past the 900-second access-token TTL.
    clock.advance(901 * 1_000_000);

    let result = engine.validate_token(&realm, pair.access_token());
    assert!(
        matches!(result, Err(hearth::identity::IdentityError::TokenExpired)),
        "expired token must be rejected: {result:?}"
    );
}

#[tokio::test]
async fn validate_token_rejects_refresh_token_as_access_token() {
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
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let result = harness.identity().validate_token(&realm, pair.refresh_token());
    assert!(
        result.is_err(),
        "refresh token must be rejected by validate_token"
    );
}

// ===== Scenario: Forged admin permission is rejected =====

#[tokio::test]
async fn validate_token_rejects_forged_admin_permission() {
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
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let tampered = tamper_jwt_payload(pair.access_token(), |payload| {
        payload["permissions"] = serde_json::json!(["hearth.admin"]);
    });

    let result = harness.identity().validate_token(&realm, &tampered);
    assert!(
        result.is_err(),
        "forged admin-permission token must be rejected"
    );
}

// ===== HEA-130: Forged exp extension is rejected =====
//
// An attacker with an expired refresh token mutates the `exp` claim to extend
// its lifetime. The tampered payload invalidates the Ed25519 signature, so
// `verify_token_signature_for_realm` must catch this before the expiry check.

#[tokio::test]
async fn refresh_token_rejects_forged_exp_extension() {
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
    let pair = harness
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    // Extend exp by one year. The signature over the original payload no longer
    // matches this modified payload, so the token must be rejected.
    let tampered = tamper_jwt_payload(pair.refresh_token(), |payload| {
        if let Some(exp) = payload["exp"].as_i64() {
            payload["exp"] = serde_json::Value::Number((exp + 31_536_000).into());
        }
    });

    let result = harness.identity().refresh_tokens(&realm, &tampered);
    assert!(
        result.is_err(),
        "refresh token with forged exp extension must be rejected"
    );
}

// ===== HEA-130: Forged session ID impersonation is rejected =====
//
// An attacker swaps `sid` in their own refresh token to point to a victim's
// session, hoping to mint tokens for the victim. The tampered payload
// invalidates the Ed25519 signature, so the attempt is blocked at the crypto
// layer before session ownership is ever evaluated.

#[tokio::test]
async fn refresh_token_rejects_forged_session_impersonation() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = RealmId::generate();
    let attacker = create_user(&harness, &realm);
    let victim = create_user(&harness, &realm);

    let victim_session = harness
        .identity()
        .create_session(
            &realm,
            victim.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create victim session");

    let attacker_session = harness
        .identity()
        .create_session(
            &realm,
            attacker.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create attacker session");
    let attacker_pair = harness
        .identity()
        .issue_tokens(&realm, attacker.id(), attacker_session.id())
        .expect("issue attacker tokens");

    // Attacker replaces their `sid` with the victim's session ID.
    let tampered = tamper_jwt_payload(attacker_pair.refresh_token(), |payload| {
        payload["sid"] = serde_json::Value::String(victim_session.id().to_string());
    });

    let result = harness.identity().refresh_tokens(&realm, &tampered);
    assert!(
        result.is_err(),
        "refresh token with forged session ID must be rejected"
    );

    // Victim's session must remain intact.
    let victim_pair = harness
        .identity()
        .issue_tokens(&realm, victim.id(), victim_session.id())
        .expect("issue victim tokens");
    assert!(
        harness
            .identity()
            .validate_token(&realm, victim_pair.access_token())
            .is_ok(),
        "victim session must remain intact after impersonation attempt"
    );
}
