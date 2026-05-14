//! Regression test: resource indicator survives token refresh.
//!
//! Verifies that an RFC 8707 resource indicator carried in the
//! authorization request is:
//! (a) embedded in the initial access token's `aud` claim, and
//! (b) preserved through a refresh token rotation.

mod common;

use hearth::core::RealmId;
use hearth::identity::tokens::{decode_claims_unverified, Audience};
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, OAuthClient,
    RegisterClientRequest, TokenExchangeRequest,
};

/// Sets up a harness with a realm, user, and client for resource-audience tests.
async fn setup() -> (
    common::TestHarness,
    RealmId,
    hearth::core::UserId,
    OAuthClient,
) {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "resource-aud-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Resource Aud App".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    (harness, realm_id, user.id().clone(), client)
}

/// Runs an authorization code flow and returns the token response.
fn authorize_and_exchange(
    harness: &common::TestHarness,
    realm_id: &RealmId,
    user_id: &hearth::core::UserId,
    client: &OAuthClient,
    resource: Option<&str>,
) -> hearth::identity::OidcTokenResponse {
    let auth_response = harness
        .identity()
        .authorize(
            realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "csrf".to_string(),
                response_type: "code".to_string(),
                user_id: user_id.clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                resource: resource.map(str::to_string),
            },
        )
        .expect("authorize");

    harness
        .identity()
        .exchange_authorization_code(
            realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                code_verifier: None,
            },
        )
        .expect("exchange code")
}

#[tokio::test]
async fn resource_aud_preserved_through_refresh() {
    let (harness, realm_id, user_id, client) = setup().await;

    // 1. Authorize with a resource indicator → get tokens
    let tokens = authorize_and_exchange(
        &harness,
        &realm_id,
        &user_id,
        &client,
        Some("https://api.example.com"),
    );

    // 2. Assert access token has Multi audience [hearth, https://api.example.com]
    let access_claims =
        decode_claims_unverified(tokens.access_token()).expect("decode access token");
    assert!(
        matches!(&access_claims.aud, Audience::Multi(list) if list.len() == 2),
        "initial access token aud should be Multi with 2 entries, got {:?}",
        access_claims.aud
    );
    let aud_list = match &access_claims.aud {
        Audience::Multi(list) => list.clone(),
        _ => unreachable!(),
    };
    assert_eq!(aud_list[0], "hearth");
    assert_eq!(aud_list[1], "https://api.example.com");

    // 3. Refresh tokens
    let refreshed = harness
        .identity()
        .refresh_tokens(&realm_id, tokens.refresh_token())
        .expect("refresh tokens");

    // 4. Assert refreshed access token still has Multi audience
    let refreshed_claims =
        decode_claims_unverified(refreshed.access_token()).expect("decode refreshed");
    assert!(
        matches!(&refreshed_claims.aud, Audience::Multi(list) if list.len() == 2),
        "refreshed access token aud should still be Multi with 2 entries, got {:?}",
        refreshed_claims.aud
    );
    let refreshed_list = match &refreshed_claims.aud {
        Audience::Multi(list) => list.clone(),
        _ => unreachable!(),
    };
    assert_eq!(refreshed_list[0], "hearth");
    assert_eq!(refreshed_list[1], "https://api.example.com");
}

#[tokio::test]
async fn no_resource_produces_single_audience() {
    let (harness, realm_id, user_id, client) = setup().await;

    // Authorize without a resource indicator
    let tokens = authorize_and_exchange(&harness, &realm_id, &user_id, &client, None);

    // Assert access token has Single audience
    let access_claims =
        decode_claims_unverified(tokens.access_token()).expect("decode access token");
    assert!(
        matches!(&access_claims.aud, Audience::Single(s) if s == "hearth"),
        "no-resource access token aud should be Single, got {:?}",
        access_claims.aud
    );
}
