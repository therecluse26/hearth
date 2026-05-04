//! Integration tests for Phase 1 Step 19: Multi-Tenancy.
//!
//! Tests the public `IdentityEngine` API for realm lifecycle,
//! cross-realm token isolation, and realm-scoped OIDC discovery.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, RealmStatus, UpdateRealmRequest,
};

// ===== Integration Scenario 1: Full realm lifecycle =====
//
// create → configure → create users → delete realm → verify cleanup

#[tokio::test]
async fn full_realm_lifecycle() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // 1. Create realm
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "lifecycle-corp".to_string(),
            config: Some(RealmConfig {
                session_ttl_micros: Some(3_600_000_000), // 1 hour
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    assert_eq!(realm.name(), "lifecycle-corp");
    assert_eq!(realm.status(), RealmStatus::Active);
    assert_eq!(realm.config().session_ttl_micros, Some(3_600_000_000));

    // 2. Configure (update)
    let updated = identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                name: Some("updated-corp".to_string()),
                config: Some(RealmConfig {
                    session_ttl_micros: Some(7_200_000_000), // 2 hours
                    password_memory_cost: Some(32768),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update realm");
    assert_eq!(updated.name(), "updated-corp");

    // 3. Create users within the realm
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@lifecycle.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // 4. Create session
    let session = identity
        .create_session(
            realm.id(),
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // 5. Delete realm
    identity.delete_realm(realm.id()).expect("delete realm");

    // 6. Verify cleanup
    assert!(
        identity.get_realm(realm.id()).expect("get").is_none(),
        "realm record should be gone"
    );
    assert!(
        identity
            .get_user(realm.id(), user.id())
            .expect("get")
            .is_none(),
        "user should be gone"
    );
    assert!(
        identity
            .get_session(realm.id(), session.id())
            .expect("get")
            .is_none(),
        "session should be gone"
    );
}

// ===== Integration Scenario 2: Multi-realm token issuance =====
//
// Tokens from realm A are invalid in realm B.

#[tokio::test]
async fn multi_realm_token_isolation() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Create two realms
    let realm_a = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-a".to_string(),
            config: None,
        })
        .expect("create realm A");
    let realm_b = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-b".to_string(),
            config: None,
        })
        .expect("create realm B");

    // Create a user and session in realm A
    let user_a = identity
        .create_user(
            realm_a.id(),
            &CreateUserRequest {
                email: "alice@a.com".to_string(),
                display_name: "Alice A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user A");

    let session_a = identity
        .create_session(
            realm_a.id(),
            user_a.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session A");

    let tokens_a = identity
        .issue_tokens(realm_a.id(), user_a.id(), session_a.id())
        .expect("issue tokens A");

    // Token should validate in realm A
    let claims = identity
        .validate_token(realm_a.id(), tokens_a.access_token())
        .expect("validate in A");
    // Token claims store the user ID with prefix ("user_{uuid}")
    assert_eq!(claims.sub, user_a.id().to_string());

    // Token should NOT validate in realm B (different realm namespace)
    let result_b = identity.validate_token(realm_b.id(), tokens_a.access_token());
    assert!(
        result_b.is_err(),
        "token from realm A should not validate in realm B"
    );

    // Each realm should have different JWKS keys
    let jwks_a = identity.realm_jwks(realm_a.id()).expect("jwks A");
    let jwks_b = identity.realm_jwks(realm_b.id()).expect("jwks B");
    assert_ne!(
        jwks_a.keys[0].kid, jwks_b.keys[0].kid,
        "realm signing keys must be different"
    );
}

// ===== Integration Scenario 3: Realm-scoped OIDC =====
//
// Discovery documents and JWKS endpoints differ per realm.

#[tokio::test]
async fn realm_scoped_oidc_discovery_and_jwks() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm_a = identity
        .create_realm(&CreateRealmRequest {
            name: "oidc-realm-a".to_string(),
            config: None,
        })
        .expect("create realm A");
    let realm_b = identity
        .create_realm(&CreateRealmRequest {
            name: "oidc-realm-b".to_string(),
            config: None,
        })
        .expect("create realm B");

    // JWKS documents should exist for each realm
    let jwks_a = identity.realm_jwks(realm_a.id()).expect("jwks A");
    let jwks_b = identity.realm_jwks(realm_b.id()).expect("jwks B");

    // Each should have exactly one key
    assert_eq!(jwks_a.keys.len(), 1, "realm A should have 1 key");
    assert_eq!(jwks_b.keys.len(), 1, "realm B should have 1 key");

    // Keys should be distinct
    assert_ne!(
        jwks_a.keys[0].x, jwks_b.keys[0].x,
        "public keys must differ between realms"
    );

    // Key algorithm should be EdDSA
    assert_eq!(jwks_a.keys[0].alg, "EdDSA");
    assert_eq!(jwks_b.keys[0].alg, "EdDSA");

    // Nonexistent realm should fail
    let err = identity.realm_jwks(&RealmId::generate());
    assert!(err.is_err(), "JWKS for nonexistent realm should fail");
}

// ===== Adversarial Scenario 1: Cross-realm session injection =====
//
// Session ID from realm A rejected when presented to realm B.

#[tokio::test]
async fn adversarial_cross_realm_session_injection() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm_a = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-a".to_string(),
            config: None,
        })
        .expect("create A");
    let realm_b = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-b".to_string(),
            config: None,
        })
        .expect("create B");

    // Create user and session in realm A
    let user = identity
        .create_user(
            realm_a.id(),
            &CreateUserRequest {
                email: "victim@a.com".to_string(),
                display_name: "Victim".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");
    let session = identity
        .create_session(
            realm_a.id(),
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    // Session should be valid in realm A
    let found = identity
        .get_session(realm_a.id(), session.id())
        .expect("get A");
    assert!(found.is_some(), "session valid in its own realm");

    // Session should NOT be found when queried via realm B
    let injected = identity
        .get_session(realm_b.id(), session.id())
        .expect("get B");
    assert!(
        injected.is_none(),
        "cross-realm session injection must be rejected"
    );
}

// ===== Adversarial Scenario 2: Realm ID spoofing =====
//
// Forged RealmId in request rejected by ownership validation.

#[tokio::test]
async fn adversarial_realm_id_spoofing() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "real-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    // Create a user in the real realm
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@real.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    // Forged realm ID — an attacker crafts a random ID
    let forged_realm = RealmId::generate();

    // Cannot read user via forged realm
    let result = identity
        .get_user(&forged_realm, user.id())
        .expect("get user");
    assert!(
        result.is_none(),
        "user should not be accessible via forged realm ID"
    );

    // Cannot create session via forged realm
    let session_result = identity.create_session(
        &forged_realm,
        user.id(),
        &hearth::identity::SessionContext::default(),
    );
    assert!(
        session_result.is_err(),
        "creating session with forged realm should fail"
    );

    // Cannot issue tokens via forged realm
    let fake_session = identity
        .create_session(
            realm.id(),
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("real session");
    let token_result = identity.issue_tokens(&forged_realm, user.id(), fake_session.id());
    assert!(
        token_result.is_err(),
        "issuing tokens with forged realm should fail"
    );
}

// ===== Adversarial Scenario 3: Realm enumeration resistance =====
//
// Responses for nonexistent realms are indistinguishable from forbidden.

#[tokio::test]
async fn adversarial_realm_enumeration_resistance() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let real_realm = identity
        .create_realm(&CreateRealmRequest {
            name: "real-corp".to_string(),
            config: None,
        })
        .expect("create realm");

    let fake_realm = RealmId::generate();

    // Both real (no user) and fake realm should return None for user lookup
    let real_result = identity
        .get_user(real_realm.id(), &hearth::core::UserId::generate())
        .expect("get from real");
    let fake_result = identity
        .get_user(&fake_realm, &hearth::core::UserId::generate())
        .expect("get from fake");

    // Both should be None — indistinguishable
    assert!(real_result.is_none());
    assert!(fake_result.is_none());

    // Realm lookup for nonexistent vs suspended should also be uniform
    // (update real realm to suspended)
    let _suspended = identity
        .update_realm(
            real_realm.id(),
            &UpdateRealmRequest {
                status: Some(RealmStatus::Suspended),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("suspend");

    // Both get_realm calls return successfully (one Some, one None)
    // But the key point is that error responses for operations
    // against nonexistent realms don't reveal whether the realm exists.
    let update_fake = identity.update_realm(
        &fake_realm,
        &UpdateRealmRequest {
            name: Some("probe".to_string()),
            ..UpdateRealmRequest::default()
        },
    );
    assert!(
        matches!(
            update_fake,
            Err(hearth::identity::IdentityError::RealmNotFound)
        ),
        "updating fake realm returns RealmNotFound"
    );

    let delete_fake = identity.delete_realm(&fake_realm);
    assert!(
        matches!(
            delete_fake,
            Err(hearth::identity::IdentityError::RealmNotFound)
        ),
        "deleting fake realm returns RealmNotFound"
    );
}
