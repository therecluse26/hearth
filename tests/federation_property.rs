//! Property tests for external IdP federation (gap #5).
//!
//! Focuses on invariants that hold for *any* input: encoding
//! round-trips, forward/reverse index symmetry, and idempotency of
//! link/unlink pairs. These complement the integration tests in
//! `tests/federation.rs`, which exercise specific scenarios.

mod common;

use std::collections::BTreeMap;

use hearth::core::{IdpId, RealmId, Timestamp, UserId};
use hearth::identity::federation::{FederationSecret, IdpConfig, IdpKind, LinkMode, StateBag};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, IdentityEngine, IdentityError};

use common::TestHarness;
use proptest::prelude::*;

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

// Strategy for an "ascii-ish" external sub — upstream providers commit
// to a stable opaque string; in practice it's a URL-safe id. Keep the
// alphabet narrow to avoid JSON-escaping surprises in the property.
fn external_sub_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_\\-]{1,64}"
}

proptest! {
    // State-bag encode ∘ decode ≡ identity over arbitrary-ish token
    // strings. Regression guard: if we add a field and forget to mark
    // it serde(default), round-trips through storage will mis-decode.
    #[test]
    fn state_bag_round_trip_preserves_fields(
        token in "[a-zA-Z0-9_\\-]{1,64}",
        nonce in "[a-zA-Z0-9_\\-]{1,64}",
        verifier in "[a-zA-Z0-9_\\-]{43,128}",
        return_to in "/[a-zA-Z0-9_\\-/]{0,128}",
        exp in 1i64..i64::MAX,
    ) {
        let bag = StateBag {
            state_token: token,
            realm_id: RealmId::generate(),
            idp_id: IdpId::generate(),
            nonce,
            pkce_verifier: verifier,
            return_to,
            expires_at: Timestamp::from_micros(exp),
        };
        let json = serde_json::to_string(&bag).unwrap();
        let back: StateBag = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(bag, back);
    }

    // For any (user, idp, sub) triple, linking produces a symmetric
    // forward/reverse index. If this ever fails, `/account/linked-accounts`
    // and login would disagree about whether a user is linked.
    #[test]
    fn link_produces_symmetric_indexes(
        sub in external_sub_strategy(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async {
            let h = TestHarness::embedded().await.unwrap();
            let realm = h.identity().create_realm(&CreateRealmRequest {
                name: "p".to_string(), config: Default::default(),
            }).unwrap().id().clone();
            let idp = IdpId::generate();
            h.identity().register_idp(&oidc_config(&realm, &idp, "x")).unwrap();
            let user = h.identity().create_user(&realm, &CreateUserRequest {
                email: format!("{}@x.c", sub),
                display_name: "A".to_string(),
            }).unwrap();

            h.identity().link_external_identity(&realm, user.id(), &idp, &sub).unwrap();

            // Reverse index resolves to the user.
            let found = h.identity().find_user_by_external_identity(&realm, &idp, &sub).unwrap();
            prop_assert_eq!(found.as_ref(), Some(user.id()));

            // Forward index lists exactly this pair.
            let pairs = h.identity().list_external_identities_for_user(&realm, user.id()).unwrap();
            prop_assert_eq!(pairs.len(), 1);
            prop_assert_eq!(&pairs[0].0, &idp);
            prop_assert_eq!(&pairs[0].1, &sub);
            Ok(())
        }).unwrap();
    }

    // link → unlink → find returns None. Regression guard against the
    // class of bug where we delete one index but not the other, leaving
    // a zombie link that blocks re-registration.
    #[test]
    fn unlink_is_complete_across_both_indexes(
        sub in external_sub_strategy(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async {
            let h = TestHarness::embedded().await.unwrap();
            let realm = h.identity().create_realm(&CreateRealmRequest {
                name: "p".to_string(), config: Default::default(),
            }).unwrap().id().clone();
            let idp = IdpId::generate();
            h.identity().register_idp(&oidc_config(&realm, &idp, "x")).unwrap();
            let user = h.identity().create_user(&realm, &CreateUserRequest {
                email: format!("{}@x.c", sub),
                display_name: "A".to_string(),
            }).unwrap();

            h.identity().link_external_identity(&realm, user.id(), &idp, &sub).unwrap();
            h.identity().unlink_external_identity(&realm, user.id(), &idp).unwrap();

            // Both directions clean.
            prop_assert!(h.identity()
                .find_user_by_external_identity(&realm, &idp, &sub).unwrap().is_none());
            prop_assert!(h.identity()
                .list_external_identities_for_user(&realm, user.id()).unwrap().is_empty());

            // A fresh user can now claim the same sub.
            let user2 = h.identity().create_user(&realm, &CreateUserRequest {
                email: format!("new-{}@x.c", sub),
                display_name: "B".to_string(),
            }).unwrap();
            h.identity().link_external_identity(&realm, user2.id(), &idp, &sub).unwrap();
            let found = h.identity().find_user_by_external_identity(&realm, &idp, &sub).unwrap();
            prop_assert_eq!(found.as_ref(), Some(user2.id()));
            Ok(())
        }).unwrap();
    }

    // Attempting to re-home a live external sub to a different user must
    // fail with FederationAlreadyLinked — invariant across any sub value.
    #[test]
    fn link_refuses_rehome_property(
        sub in external_sub_strategy(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async {
            let h = TestHarness::embedded().await.unwrap();
            let realm = h.identity().create_realm(&CreateRealmRequest {
                name: "p".to_string(), config: Default::default(),
            }).unwrap().id().clone();
            let idp = IdpId::generate();
            h.identity().register_idp(&oidc_config(&realm, &idp, "x")).unwrap();
            let alice = h.identity().create_user(&realm, &CreateUserRequest {
                email: format!("a-{}@x.c", sub),
                display_name: "A".to_string(),
            }).unwrap();
            let bob = h.identity().create_user(&realm, &CreateUserRequest {
                email: format!("b-{}@x.c", sub),
                display_name: "B".to_string(),
            }).unwrap();

            h.identity().link_external_identity(&realm, alice.id(), &idp, &sub).unwrap();
            let err = h.identity()
                .link_external_identity(&realm, bob.id(), &idp, &sub).unwrap_err();
            prop_assert!(matches!(err, IdentityError::FederationAlreadyLinked));
            // But linking alice again to the same sub is idempotent.
            h.identity().link_external_identity(&realm, alice.id(), &idp, &sub).unwrap();
            Ok(())
        }).unwrap();
    }
}

// Static (non-proptest) helper asserting LinkMode::default stays Confirm.
// This is the only LinkMode invariant callers rely on; a property test
// on a three-variant enum is overkill, but we guard it here so a future
// `#[derive(Default)]` on a different variant would fail CI.
#[test]
fn link_mode_default_is_confirm() {
    assert_eq!(LinkMode::default(), LinkMode::Confirm);
}

// Regression guard for an #[allow(unused)] on UserId in this file:
// force the type to be referenced via a trivially-true assertion.
#[test]
fn user_id_is_usable() {
    let _u = UserId::generate();
}
