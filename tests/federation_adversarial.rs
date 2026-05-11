//! Adversarial tests for external IdP federation (gap #5).
//!
//! Consolidates security-critical sad paths at the engine layer:
//! state-token replay, cross-realm state reuse, confirm-link cookie
//! cross-user replay, crafted ID-token claim tampering, and upstream
//! userinfo content that could leak into UI templates.

mod common;

use std::collections::BTreeMap;

use hearth::core::{IdpId, RealmId, Timestamp, UserId};
use hearth::identity::federation::{
    compute_confirm_ticket_mac, verify_confirm_ticket_mac, verify_id_token_claims,
    ConfirmLinkTicket, ExternalIdentity, FederationSecret, IdTokenClaims, IdpConfig, IdpKind,
    StateBag,
};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, IdentityEngine, IdentityError};

use common::TestHarness;

fn oidc_config(realm_id: &RealmId, idp_id: &IdpId, name: &str) -> IdpConfig {
    IdpConfig {
        id: idp_id.clone(),
        realm_id: realm_id.clone(),
        name: name.to_string(),
        kind: IdpKind::Oidc,
        display_name: name.to_string(),
        issuer: "https://idp.example".to_string(),
        authorization_endpoint: "https://idp.example/auth".to_string(),
        token_endpoint: "https://idp.example/token".to_string(),
        userinfo_endpoint: None,
        jwks_uri: Some("https://idp.example/jwks".to_string()),
        scopes: vec!["openid".to_string()],
        client_id: "c".to_string(),
        client_secret: FederationSecret::new("s".to_string()),
        claim_mappings: BTreeMap::new(),
        created_at: Timestamp::from_micros(0),
        updated_at: Timestamp::from_micros(0),
    }
}

fn realm_named(h: &TestHarness, name: &str) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: Default::default(),
        })
        .expect("create realm")
        .id()
        .clone()
}

// ===== State token replay / cross-realm =====

#[tokio::test]
async fn state_token_cannot_be_consumed_twice() {
    let h = TestHarness::embedded().await.unwrap();
    let realm = realm_named(&h, "demo");
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "g"))
        .unwrap();
    let bag = StateBag {
        state_token: "replay".to_string(),
        realm_id: realm.clone(),
        idp_id: idp,
        nonce: "n".to_string(),
        pkce_verifier: "v".to_string(),
        return_to: "/".to_string(),
        expires_at: Timestamp::from_micros(i64::MAX),
    };
    h.identity().put_federation_state(&bag).unwrap();
    h.identity()
        .take_federation_state(&realm, "replay")
        .expect("first take");
    // Second take is rejected. Intentionally vague error (no
    // "already-consumed" vs "not-found" distinction).
    let err = h
        .identity()
        .take_federation_state(&realm, "replay")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationInvalidState));
}

#[tokio::test]
async fn state_token_put_in_one_realm_is_invisible_to_another() {
    // Storage keys are realm-scoped — confirming the invariant at the
    // engine layer. An attacker who knows a state token from realm A
    // cannot take it from realm B to hijack that realm's session.
    let h = TestHarness::embedded().await.unwrap();
    let realm_a = realm_named(&h, "a");
    let realm_b = realm_named(&h, "b");
    let idp_a = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm_a, &idp_a, "g"))
        .unwrap();

    let bag = StateBag {
        state_token: "cross".to_string(),
        realm_id: realm_a.clone(),
        idp_id: idp_a,
        nonce: "n".to_string(),
        pkce_verifier: "v".to_string(),
        return_to: "/".to_string(),
        expires_at: Timestamp::from_micros(i64::MAX),
    };
    h.identity().put_federation_state(&bag).unwrap();

    // Same token, wrong realm — must fail.
    let err = h
        .identity()
        .take_federation_state(&realm_b, "cross")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationInvalidState));

    // Right realm still works (state not consumed by the miss).
    h.identity()
        .take_federation_state(&realm_a, "cross")
        .expect("right realm take");
}

// ===== Confirm-link ticket cross-user replay =====

#[tokio::test]
async fn confirm_link_ticket_cannot_be_stolen_by_another_user() {
    // Attacker model: user knows the opaque ticket string (e.g., via
    // a stray log or a copy/paste into a bug report). Without the
    // HMAC-bound cookie, can they attach an identity to their own
    // account? Hearth has two defenses:
    //
    //   1. Cookie MAC binds the ticket to the matched UserId
    //      (`compute_confirm_ticket_mac`).
    //   2. The engine-layer ticket persists the matched UserId; the
    //      POST handler re-checks it.
    //
    // This test exercises defense (1) directly.
    let secret = [7u8; 32];
    let alice = UserId::generate();
    let bob = UserId::generate();
    let ticket = "ticket-42";
    let tag = compute_confirm_ticket_mac(&secret, &alice, ticket);
    assert!(!verify_confirm_ticket_mac(&secret, &bob, ticket, &tag));
}

#[tokio::test]
async fn confirm_link_ticket_cannot_be_replayed() {
    let h = TestHarness::embedded().await.unwrap();
    let realm = realm_named(&h, "demo");
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "g"))
        .unwrap();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "a@x.c".to_string(),
                display_name: "A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .unwrap();
    let ticket = ConfirmLinkTicket {
        ticket: "t".to_string(),
        realm_id: realm.clone(),
        user_id: user.id().clone(),
        identity: ExternalIdentity {
            idp_id: idp.clone(),
            external_sub: "s".to_string(),
            email: "a@x.c".to_string(),
            email_verified: true,
            display_name: "A".to_string(),
            picture_url: None,
            first_name: String::new(),
            last_name: String::new(),
        },
        expires_at: Timestamp::from_micros(i64::MAX),
    };
    h.identity().put_confirm_link_ticket(&ticket).unwrap();
    h.identity().take_confirm_link_ticket(&realm, "t").unwrap();
    let err = h
        .identity()
        .take_confirm_link_ticket(&realm, "t")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationInvalidState));
}

// ===== ID-token claim tampering =====

fn claims_with(iss: &str, aud: serde_json::Value, exp: i64, nonce: &str) -> IdTokenClaims {
    IdTokenClaims {
        iss: iss.to_string(),
        sub: "ext-sub".to_string(),
        aud: Some(aud),
        nbf: None,
        exp,
        iat: Some(exp - 60),
        nonce: Some(nonce.to_string()),
        email: Some("alice@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Alice".to_string()),
        given_name: None,
        family_name: None,
        picture: None,
    }
}

fn state_bag_for(nonce: &str) -> StateBag {
    StateBag {
        state_token: "s".to_string(),
        realm_id: RealmId::generate(),
        idp_id: IdpId::generate(),
        nonce: nonce.to_string(),
        pkce_verifier: "v".to_string(),
        return_to: "/".to_string(),
        expires_at: Timestamp::from_micros(i64::MAX),
    }
}

#[tokio::test]
async fn tampered_issuer_is_rejected() {
    let cfg = oidc_config(&RealmId::generate(), &IdpId::generate(), "g");
    let state = state_bag_for("nnn");
    let claims = claims_with(
        "https://evil.example",
        serde_json::Value::String(cfg.client_id.clone()),
        1_700_000_000,
        "nnn",
    );
    let err = verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).unwrap_err();
    assert!(matches!(
        err,
        IdentityError::FederationTokenVerificationFailed
    ));
}

#[tokio::test]
async fn tampered_audience_is_rejected() {
    let cfg = oidc_config(&RealmId::generate(), &IdpId::generate(), "g");
    let state = state_bag_for("nnn");
    let claims = claims_with(
        &cfg.issuer,
        serde_json::Value::String("someone-elses-client".to_string()),
        1_700_000_000,
        "nnn",
    );
    let err = verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).unwrap_err();
    assert!(matches!(
        err,
        IdentityError::FederationTokenVerificationFailed
    ));
}

#[tokio::test]
async fn tampered_nonce_is_rejected() {
    let cfg = oidc_config(&RealmId::generate(), &IdpId::generate(), "g");
    let state = state_bag_for("expected-nonce");
    let claims = claims_with(
        &cfg.issuer,
        serde_json::Value::String(cfg.client_id.clone()),
        1_700_000_000,
        "attacker-chosen-nonce",
    );
    let err = verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).unwrap_err();
    assert!(matches!(
        err,
        IdentityError::FederationTokenVerificationFailed
    ));
}

#[tokio::test]
async fn expired_id_token_beyond_skew_is_rejected() {
    let cfg = oidc_config(&RealmId::generate(), &IdpId::generate(), "g");
    let state = state_bag_for("nnn");
    let claims = claims_with(
        &cfg.issuer,
        serde_json::Value::String(cfg.client_id.clone()),
        1_700_000_000,
        "nnn",
    );
    // Now = exp + 120 → outside the 60s tolerance.
    let err = verify_id_token_claims(&claims, &cfg, &state, 1_700_000_120).unwrap_err();
    assert!(matches!(
        err,
        IdentityError::FederationTokenVerificationFailed
    ));
}

// ===== GitHub userinfo content preserved verbatim =====

#[tokio::test]
async fn userinfo_display_name_with_html_is_preserved_verbatim() {
    // Template-layer escaping is the protection against script-in-name
    // attacks (Askama `{{ row.display_name }}` auto-escapes by default).
    // At the domain layer, we assert the string round-trips unchanged
    // so the attacker's input reaches the template as-is — which is
    // then escaped.
    let id = ExternalIdentity {
        idp_id: IdpId::generate(),
        external_sub: "42".to_string(),
        email: String::new(),
        email_verified: false,
        display_name: "<script>alert(1)</script>".to_string(),
        picture_url: None,
        first_name: String::new(),
        last_name: String::new(),
    };
    let json = serde_json::to_string(&id).unwrap();
    let back: ExternalIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(back.display_name, "<script>alert(1)</script>");
}

#[tokio::test]
async fn link_external_identity_refuses_to_rehome_across_users() {
    // Repeated from integration tests — but asserted here as an
    // adversarial invariant: a malicious IdP that re-emits the same
    // external sub for a different upstream user account cannot
    // hijack a local Hearth user's link.
    let h = TestHarness::embedded().await.unwrap();
    let realm = realm_named(&h, "demo");
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "g"))
        .unwrap();
    let alice = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "a@x.c".to_string(),
                display_name: "A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .unwrap();
    let bob = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "b@x.c".to_string(),
                display_name: "B".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .unwrap();
    h.identity()
        .link_external_identity(&realm, alice.id(), &idp, "shared")
        .unwrap();
    let err = h
        .identity()
        .link_external_identity(&realm, bob.id(), &idp, "shared")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationAlreadyLinked));
}
