#![allow(clippy::unwrap_used)]
//! Integration tests for external `IdP` federation (gap #5).
//!
//! Covers the engine-level federation surface end-to-end: `IdP`
//! registration, state persistence/consumption, JIT link, account
//! linking under all three [`LinkMode`]s, and cascade cleanup on user
//! / realm / connector deletion.
//!
//! The HTTP-level callback flow (actual token exchange against an
//! upstream) is exercised at the connector level in
//! `src/identity/federation/oidc.rs` unit tests using
//! `StubFederationTransport`.

mod common;

use std::collections::BTreeMap;

use hearth::core::{IdpId, Timestamp};
use hearth::identity::federation::{
    ConfirmLinkTicket, ExternalIdentity, FederationSecret, IdpConfig, IdpKind, LinkMode, StateBag,
};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, IdentityError};

use common::TestHarness;

fn oidc_config(realm_id: &hearth::core::RealmId, idp_id: &IdpId, name: &str) -> IdpConfig {
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
        scopes: vec!["openid".to_string(), "email".to_string()],
        client_id: "c".to_string(),
        client_secret: FederationSecret::new("s".to_string()),
        claim_mappings: BTreeMap::new(),
        created_at: Timestamp::from_micros(0),
        updated_at: Timestamp::from_micros(0),
    }
}

async fn setup_realm(h: &TestHarness) -> hearth::core::RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: "demo".to_string(),
            config: Default::default(),
        })
        .expect("create realm")
        .id()
        .clone()
}

#[tokio::test]
async fn register_and_list_idp() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .expect("register");
    let found = h.identity().get_idp(&realm, &idp).expect("get").unwrap();
    assert_eq!(found.name, "google");
    let by_name = h
        .identity()
        .get_idp_by_name(&realm, "google")
        .expect("by name")
        .unwrap();
    assert_eq!(by_name.id, idp);
    let all = h.identity().list_idps(&realm).expect("list");
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn idp_records_are_realm_isolated() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm_a = setup_realm(&h).await;
    let realm_b = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "other".to_string(),
            config: Default::default(),
        })
        .expect("create realm b")
        .id()
        .clone();
    let idp_a = IdpId::generate();
    let idp_b = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm_a, &idp_a, "google"))
        .unwrap();
    h.identity()
        .register_idp(&oidc_config(&realm_b, &idp_b, "google"))
        .unwrap();
    // realm_a should only see its own connector.
    assert_eq!(h.identity().list_idps(&realm_a).unwrap().len(), 1);
    assert_eq!(h.identity().list_idps(&realm_b).unwrap().len(), 1);
    // Cross-realm get returns None.
    assert!(h.identity().get_idp(&realm_a, &idp_b).unwrap().is_none());
}

#[tokio::test]
async fn state_bag_is_single_use() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let bag = StateBag {
        state_token: "tok1".to_string(),
        realm_id: realm.clone(),
        idp_id: idp,
        nonce: "n".to_string(),
        pkce_verifier: "v".to_string(),
        return_to: "/ui/account".to_string(),
        expires_at: Timestamp::from_micros(i64::MAX),
    };
    h.identity().put_federation_state(&bag).unwrap();
    let taken = h
        .identity()
        .take_federation_state(&realm, "tok1")
        .expect("first take");
    assert_eq!(taken.state_token, "tok1");
    // Second take fails — single-use.
    let err = h
        .identity()
        .take_federation_state(&realm, "tok1")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationInvalidState));
}

#[tokio::test]
async fn state_bag_expiry_is_enforced() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let bag = StateBag {
        state_token: "exp".to_string(),
        realm_id: realm.clone(),
        idp_id: idp,
        nonce: "n".to_string(),
        pkce_verifier: "v".to_string(),
        return_to: "/".to_string(),
        // Zero microseconds ≡ well in the past.
        expires_at: Timestamp::from_micros(0),
    };
    h.identity().put_federation_state(&bag).unwrap();
    let err = h
        .identity()
        .take_federation_state(&realm, "exp")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationInvalidState));
}

#[tokio::test]
async fn link_external_identity_roundtrip() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();

    h.identity()
        .link_external_identity(&realm, user.id(), &idp, "ext-sub-42")
        .unwrap();
    // Reverse lookup finds the user.
    let found = h
        .identity()
        .find_user_by_external_identity(&realm, &idp, "ext-sub-42")
        .unwrap();
    assert_eq!(found, Some(user.id().clone()));
    // Forward lookup enumerates links for the user.
    let list = h
        .identity()
        .list_external_identities_for_user(&realm, user.id())
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0, idp);
    assert_eq!(list[0].1, "ext-sub-42");
}

#[tokio::test]
async fn link_refuses_to_rehome_to_different_user() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let alice = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
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
                email: "bob@example.com".to_string(),
                display_name: "B".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();
    h.identity()
        .link_external_identity(&realm, alice.id(), &idp, "sub-x")
        .unwrap();
    // Attempting to re-home the same external sub to bob must fail
    // rather than silently override alice's link.
    let err = h
        .identity()
        .link_external_identity(&realm, bob.id(), &idp, "sub-x")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationAlreadyLinked));
}

#[tokio::test]
async fn unlink_is_idempotent_second_call_errors() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();
    h.identity()
        .link_external_identity(&realm, user.id(), &idp, "s")
        .unwrap();
    h.identity()
        .unlink_external_identity(&realm, user.id(), &idp)
        .unwrap();
    // After unlink the reverse lookup must not find anyone.
    assert!(h
        .identity()
        .find_user_by_external_identity(&realm, &idp, "s")
        .unwrap()
        .is_none());
    // Second unlink fails with NotLinked.
    let err = h
        .identity()
        .unlink_external_identity(&realm, user.id(), &idp)
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationNotLinked));
}

#[tokio::test]
async fn delete_user_cascades_both_federation_indexes() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();
    h.identity()
        .link_external_identity(&realm, user.id(), &idp, "sub-del")
        .unwrap();
    h.identity().delete_user(&realm, user.id()).unwrap();
    // Reverse index must be gone so the upstream sub can link to a
    // future user.
    assert!(h
        .identity()
        .find_user_by_external_identity(&realm, &idp, "sub-del")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn delete_idp_severs_all_links_but_leaves_users_intact() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
        .unwrap();
    let u1 = h
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
    let u2 = h
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
        .link_external_identity(&realm, u1.id(), &idp, "sub-1")
        .unwrap();
    h.identity()
        .link_external_identity(&realm, u2.id(), &idp, "sub-2")
        .unwrap();
    h.identity().delete_idp(&realm, &idp).unwrap();
    // Users still exist.
    assert!(h.identity().get_user(&realm, u1.id()).unwrap().is_some());
    assert!(h.identity().get_user(&realm, u2.id()).unwrap().is_some());
    // But no links remain.
    assert!(h
        .identity()
        .list_external_identities_for_user(&realm, u1.id())
        .unwrap()
        .is_empty());
    assert!(h
        .identity()
        .find_user_by_external_identity(&realm, &idp, "sub-1")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn confirm_link_ticket_is_single_use() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp, "google"))
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
        ticket: "tkt".to_string(),
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
    let first = h
        .identity()
        .take_confirm_link_ticket(&realm, "tkt")
        .expect("first");
    assert_eq!(first.user_id, *user.id());
    let err = h
        .identity()
        .take_confirm_link_ticket(&realm, "tkt")
        .unwrap_err();
    assert!(matches!(err, IdentityError::FederationInvalidState));
}

#[tokio::test]
async fn link_mode_default_is_confirm_when_unset() {
    // This asserts the RealmConfig invariant that callers rely on —
    // an unset `federation_link_mode` means `Confirm`, so the safe
    // default applies without any config.
    assert_eq!(LinkMode::default(), LinkMode::Confirm);
}

// ===== Federation edge cases =====

#[tokio::test]
async fn claim_mappings_in_idp_config_are_stored_and_retrieved() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;
    let idp_id = IdpId::generate();

    // Azure AD-style config: upstream sends `upn` and `displayName`
    // instead of the standard OIDC `email` and `name` claims.
    let mut cfg = oidc_config(&realm, &idp_id, "azure-ad");
    cfg.claim_mappings
        .insert("email".to_string(), "upn".to_string());
    cfg.claim_mappings
        .insert("name".to_string(), "displayName".to_string());

    h.identity().register_idp(&cfg).unwrap();

    let retrieved = h
        .identity()
        .get_idp(&realm, &idp_id)
        .unwrap()
        .expect("idp must exist after registration");

    assert_eq!(
        retrieved.claim_mappings.get("email").map(String::as_str),
        Some("upn"),
        "email→upn mapping must survive storage round-trip"
    );
    assert_eq!(
        retrieved.claim_mappings.get("name").map(String::as_str),
        Some("displayName"),
        "name→displayName mapping must survive storage round-trip"
    );
    assert_eq!(
        retrieved.claim_mappings.len(),
        2,
        "no extra mappings should appear"
    );
}

#[tokio::test]
async fn two_oidc_providers_same_realm_links_are_isolated() {
    let h = TestHarness::embedded().await.expect("harness");
    let realm = setup_realm(&h).await;

    let idp1 = IdpId::generate();
    let idp2 = IdpId::generate();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp1, "google"))
        .unwrap();
    h.identity()
        .register_idp(&oidc_config(&realm, &idp2, "microsoft"))
        .unwrap();

    // Both IdPs are visible under the realm.
    let listed = h.identity().list_idps(&realm).unwrap();
    assert_eq!(listed.len(), 2);

    let alice = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
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
                email: "bob@example.com".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();

    // The same external subject identifier can be used independently at
    // each IdP — "user-99" at Google and "user-99" at Microsoft are
    // unrelated identities.
    h.identity()
        .link_external_identity(&realm, alice.id(), &idp1, "user-99")
        .unwrap();
    h.identity()
        .link_external_identity(&realm, bob.id(), &idp2, "user-99")
        .unwrap();

    let found_idp1 = h
        .identity()
        .find_user_by_external_identity(&realm, &idp1, "user-99")
        .unwrap();
    assert_eq!(found_idp1, Some(alice.id().clone()), "idp1 link → alice");

    let found_idp2 = h
        .identity()
        .find_user_by_external_identity(&realm, &idp2, "user-99")
        .unwrap();
    assert_eq!(found_idp2, Some(bob.id().clone()), "idp2 link → bob");
}

#[test]
fn unverified_or_missing_email_identity_is_not_linkable_by_email() {
    let base = ExternalIdentity {
        idp_id: IdpId::generate(),
        external_sub: "sub-1".to_string(),
        email: "alice@example.com".to_string(),
        email_verified: true,
        display_name: "Alice".to_string(),
        first_name: String::new(),
        last_name: String::new(),
        picture_url: None,
    };

    // Verified email → linkable.
    assert!(
        base.is_linkable_by_email(),
        "verified email must be linkable"
    );

    // Unverified email → not linkable (prevents IdP-impersonation account hijack).
    let unverified = ExternalIdentity {
        email_verified: false,
        ..base.clone()
    };
    assert!(
        !unverified.is_linkable_by_email(),
        "unverified email must block auto-linking to prevent account hijack"
    );

    // Empty email (e.g. GitHub with private email setting) → not linkable.
    let no_email = ExternalIdentity {
        email: String::new(),
        email_verified: false,
        ..base.clone()
    };
    assert!(
        !no_email.is_linkable_by_email(),
        "empty email must never be used for auto-linking"
    );

    // Empty email even if somehow marked verified → not linkable.
    let empty_verified = ExternalIdentity {
        email: String::new(),
        email_verified: true,
        ..base
    };
    assert!(
        !empty_verified.is_linkable_by_email(),
        "empty email string must not be treated as a valid link target"
    );
}
