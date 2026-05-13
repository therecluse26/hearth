#![allow(clippy::unwrap_used)]
//! HTTP-level integration tests for the `/ui/federation/*` handlers.
//!
//! Boots a full axum router with a real `EmbeddedIdentityEngine`, a
//! real `EmbeddedAuditEngine`, and a stubbed `FederationHttpTransport`
//! — issues HTTP requests through the router and asserts on redirect
//! targets, cookies, and audit rows.
//!
//! Complements the engine-level tests in `tests/federation.rs` and
//! the connector unit tests in `src/identity/federation/oidc.rs` by
//! exercising the Web adapter end-to-end.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hearth::audit::{AuditEngine, AuditQuery};
use hearth::core::{Clock, IdpId, SystemClock, Timestamp};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::federation::{
    FederationSecret, IdpConfig, IdpKind, LinkMode, StateBag, StubFederationTransport,
};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, UpdateRealmRequest,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [7u8; 32];

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    audit: Arc<dyn AuditEngine>,
    realm_id: hearth::core::RealmId,
    idp_id: IdpId,
}

fn build_rig(stub: Arc<StubFederationTransport>) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    // Create the demo realm with default LinkMode::Confirm (None ≡
    // Confirm in RealmConfig).
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "demo".to_string(),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    // Register a connector. URLs point at idp.example; the stub will
    // intercept `/token`, `/jwks`, etc.
    let idp_id = IdpId::generate();
    identity
        .register_idp(&IdpConfig {
            id: idp_id.clone(),
            realm_id: realm_id.clone(),
            name: "upstream".to_string(),
            kind: IdpKind::Oidc,
            display_name: "Upstream".to_string(),
            issuer: "https://idp.example".to_string(),
            authorization_endpoint: "https://idp.example/auth".to_string(),
            token_endpoint: "https://idp.example/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: Some("https://idp.example/jwks".to_string()),
            scopes: vec!["openid".to_string(), "email".to_string()],
            client_id: "demo-client".to_string(),
            client_secret: FederationSecret::new("demo-secret".to_string()),
            claim_mappings: BTreeMap::new(),
            created_at: hearth::core::Timestamp::from_micros(0),
            updated_at: hearth::core::Timestamp::from_micros(0),
        })
        .expect("register idp");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));

    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email_service()),
    )
    .with_federation_http(stub as Arc<dyn hearth::identity::federation::FederationHttpTransport>);

    let app = web::router(state);

    Rig {
        app,
        identity,
        audit,
        realm_id,
        idp_id,
    }
}

fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    let fut = app.clone().oneshot(req);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
        .expect("router response")
}

fn set_link_mode(rig: &Rig, mode: LinkMode) {
    rig.identity
        .update_realm(
            &rig.realm_id,
            &UpdateRealmRequest {
                name: None,
                status: None,
                config: Some(RealmConfig {
                    federation_link_mode: Some(mode),
                    ..RealmConfig::default()
                }),
            },
        )
        .expect("update realm");
}

fn seed_state(rig: &Rig, state_token: &str, nonce: &str) {
    rig.identity
        .put_federation_state(&StateBag {
            state_token: state_token.to_string(),
            realm_id: rig.realm_id.clone(),
            idp_id: rig.idp_id.clone(),
            nonce: nonce.to_string(),
            pkce_verifier: "verifier-123".to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: Timestamp::from_micros(i64::MAX),
        })
        .expect("seed federation state");
}

fn stub_successful_oidc_callback(
    transport: &StubFederationTransport,
    _code: &str,
    nonce: &str,
    sub: &str,
    email: &str,
    email_verified: bool,
) {
    let kid = "test-key-1";
    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate rsa key");
    let public_key = private_key.to_public_key();
    let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    });
    let payload = serde_json::json!({
        "iss": "https://idp.example",
        "sub": sub,
        "aud": "demo-client",
        "exp": 4_102_444_800i64,
        "iat": 4_102_444_200i64,
        "nonce": nonce,
        "email": email,
        "email_verified": email_verified,
        "name": "Alice Federated",
    });
    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize jwt header"));
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("serialize jwt payload"));
    let signing_input = format!("{header_b64}.{payload_b64}");

    let pkcs8_der = private_key.to_pkcs8_der().expect("pkcs8 encode");
    let key_pair =
        ring::signature::RsaKeyPair::from_pkcs8(pkcs8_der.as_bytes()).expect("load keypair");
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    let ring_rng = ring::rand::SystemRandom::new();
    key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring_rng,
            signing_input.as_bytes(),
            &mut signature,
        )
        .expect("sign jwt");
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));

    transport.stub(
        "POST",
        "https://idp.example/token",
        200,
        serde_json::json!({ "id_token": jwt }).to_string(),
    );
    transport.stub(
        "GET",
        "https://idp.example/jwks",
        200,
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "kid": kid,
                "n": n_b64,
                "e": e_b64,
            }]
        })
        .to_string(),
    );
}

#[test]
fn begin_unknown_connector_returns_404() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=does-not-exist")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn begin_known_connector_302s_to_upstream_and_persists_state() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/begin?idp=upstream")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .expect("redirect")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("https://idp.example/auth?"),
        "got: {location}"
    );
    assert!(location.contains("client_id=demo-client"));
    assert!(location.contains("state="));
    assert!(location.contains("code_challenge="));

    // Pull the state token out of the URL and confirm the engine has
    // a persisted bag for it.
    let state_tok = location
        .split('&')
        .find_map(|p| p.strip_prefix("state="))
        .expect("state param");
    // `take` consumes, so calling it here ends the bag — that's fine
    // for this test.
    rig.identity
        .take_federation_state(&rig.realm_id, state_tok)
        .expect("state persisted");

    // Audit: FederationLoginStarted emitted.
    let events = rig
        .audit
        .query(&AuditQuery {
            realm_id: rig.realm_id.clone(),
            actor: None,
            action: Some(hearth::audit::AuditAction::FederationLoginStarted),
            start_time: None,
            end_time: None,
            limit: Some(10),
        })
        .expect("audit query");
    assert!(!events.is_empty(), "expected audit event");
}

#[test]
fn callback_with_error_redirects_to_login_denied() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/callback?state=whatever&error=access_denied")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/ui/login?error=federation_denied");
}

#[test]
fn callback_with_unknown_state_redirects_to_login_failed() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/callback?state=unknown&code=xyz")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/ui/login?error=federation_failed");
}

#[test]
fn login_page_renders_federation_buttons_when_connectors_exist() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/login")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(to_bytes(resp.into_body(), 1024 * 1024))
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    // The button row is present.
    assert!(
        body.contains("data-testid=\"federation-button\""),
        "body missing federation button marker"
    );
    assert!(
        body.contains("Sign in with Upstream"),
        "body missing button label"
    );
    // The URL points at the scoped begin endpoint.
    assert!(
        body.contains("/ui/realms/demo/federation/begin?idp=upstream"),
        "button URL missing or unscoped"
    );
}

#[test]
fn login_page_omits_federation_section_when_no_connectors() {
    // Build a rig, then delete the connector so the login page has
    // no federation options to render. The section should disappear
    // entirely — no empty "or continue with" divider.
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(stub);
    rig.identity
        .delete_idp(&rig.realm_id, &rig.idp_id)
        .expect("delete idp");
    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/login")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(to_bytes(resp.into_body(), 1024 * 1024))
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(!body.contains("federation-button"));
    assert!(!body.contains("or continue with"));
}

#[test]
fn callback_auto_links_existing_user_on_verified_email() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Auto);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-auto", "nonce-auto");
    stub_successful_oidc_callback(
        &stub,
        "code-auto",
        "nonce-auto",
        "ext-auto-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/callback?state=state-auto&code=code-auto")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/ui/account"
    );
    assert_eq!(
        rig.identity
            .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-auto-1")
            .expect("lookup link"),
        Some(existing.id().clone())
    );
}

#[test]
fn callback_confirm_mode_redirects_to_confirm_link_for_existing_user() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Confirm);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-confirm", "nonce-confirm");
    stub_successful_oidc_callback(
        &stub,
        "code-confirm",
        "nonce-confirm",
        "ext-confirm-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/callback?state=state-confirm&code=code-confirm")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("/ui/federation/confirm-link?ticket="),
        "unexpected confirm redirect: {location}"
    );
    assert_eq!(
        rig.identity
            .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-confirm-1")
            .expect("link lookup"),
        None
    );
    let ticket = location
        .split("ticket=")
        .nth(1)
        .expect("confirm-link ticket");
    let pending = rig
        .identity
        .take_confirm_link_ticket(&rig.realm_id, ticket)
        .expect("load confirm-link ticket");
    assert_eq!(pending.user_id, *existing.id());
}

#[test]
fn callback_disabled_mode_creates_separate_user_on_email_collision() {
    let stub = Arc::new(StubFederationTransport::new());
    let rig = build_rig(Arc::clone(&stub));
    set_link_mode(&rig, LinkMode::Disabled);
    let existing = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Local".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create local user");
    seed_state(&rig, "state-disabled", "nonce-disabled");
    stub_successful_oidc_callback(
        &stub,
        "code-disabled",
        "nonce-disabled",
        "ext-disabled-1",
        "alice@example.com",
        true,
    );

    let resp = send(
        &rig.app,
        Request::builder()
            .uri("/ui/realms/demo/federation/callback?state=state-disabled&code=code-disabled")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/ui/account"
    );
    let linked_user = rig
        .identity
        .find_user_by_external_identity(&rig.realm_id, &rig.idp_id, "ext-disabled-1")
        .expect("lookup link")
        .expect("linked user");
    assert_ne!(linked_user, *existing.id());
    let created = rig
        .identity
        .get_user(&rig.realm_id, &linked_user)
        .expect("get linked user")
        .expect("linked user exists");
    assert_eq!(
        created.email(),
        format!("ext-disabled-1@fed.{}.local", rig.idp_id.as_uuid())
    );
}
