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
use hearth::audit::{AuditEngine, AuditQuery};
use hearth::core::{Clock, IdpId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::federation::{FederationSecret, IdpConfig, IdpKind, StubFederationTransport};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
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
