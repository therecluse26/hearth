//! HEA-550 regression: PKCE must be enforced for confidential OAuth clients.
//!
//! RFC 9700 §2.1.1 mandates PKCE for all clients. Before the fix, the check
//! `!client.is_confidential()` exempted confidential clients entirely.

mod common;

use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, OidcConfig, RegisterClientRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use std::sync::Arc;

/// Builds a minimal identity engine with the given OIDC config.
fn build_engine(oidc: OidcConfig) -> (tempfile::TempDir, EmbeddedIdentityEngine) {
    use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
    use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
            .expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        oidc,
        ..IdentityConfig::default()
    };
    let engine = EmbeddedIdentityEngine::with_rbac(Arc::clone(&storage), clock, config, rbac, audit)
        .expect("engine");
    (dir, engine)
}

fn setup(oidc: OidcConfig) -> (tempfile::TempDir, EmbeddedIdentityEngine, RealmId) {
    use hearth::identity::IdentityEngine;

    let (dir, engine) = build_engine(oidc);
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "pkce-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    (dir, engine, realm_id)
}

fn make_user(engine: &EmbeddedIdentityEngine, realm_id: &RealmId) -> hearth::identity::User {
    use hearth::identity::IdentityEngine;
    engine
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("pkce-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "PKCE Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

fn register_confidential(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
) -> hearth::identity::OAuthClient {
    use hearth::identity::IdentityEngine;
    let client = engine
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: "Confidential App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some("s3cr3t!".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    assert!(client.is_confidential(), "must be confidential for this test");
    client
}

// ── HEA-550: confidential client, no PKCE, default config → rejected ────────

/// Regression: confidential client without PKCE must be rejected by default.
///
/// Before HEA-550, `!client.is_confidential()` short-circuited the check and
/// allowed confidential clients to omit `code_challenge` entirely.
#[test]
fn confidential_client_without_pkce_rejected_by_default() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup(OidcConfig {
        require_pkce_for_confidential_clients: true, // default — explicit for clarity
        ..OidcConfig::default()
    });
    let user = make_user(&engine, &realm_id);
    let client = register_confidential(&engine, &realm_id);

    let result = engine.authorize(
        &realm_id,
        &AuthorizationRequest {
            client_id: client.client_id().clone(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            state: "csrf-token".to_string(),
            response_type: "code".to_string(),
            user_id: user.id().clone(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            resource: None,
        },
    );

    assert!(
        result.is_err(),
        "confidential client without PKCE must be rejected (RFC 9700 §2.1.1)"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("PKCE"), "error must mention PKCE, got: {err}");
}

// ── HEA-550: opt-out allows legacy confidential client without PKCE ──────────

/// Legacy opt-out: confidential client without PKCE accepted when
/// `require_pkce_for_confidential_clients: false`.
#[test]
fn confidential_client_without_pkce_allowed_with_opt_out() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup(OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    });
    let user = make_user(&engine, &realm_id);
    let client = register_confidential(&engine, &realm_id);

    engine
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                state: "csrf-token".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
                resource: None,
            },
        )
        .expect("confidential client without PKCE must succeed when opt-out is configured");
}

// ── Public clients remain rejected without PKCE (no regression) ─────────────

/// Public clients (no secret) still require PKCE regardless of the confidential flag.
#[test]
fn public_client_without_pkce_always_rejected() {
    use hearth::identity::IdentityEngine;

    // Even with the confidential opt-out, public clients are always held to PKCE.
    let (_dir, engine, realm_id) = setup(OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    });
    let user = make_user(&engine, &realm_id);

    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Public App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None, // public
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    assert!(!client.is_confidential());

    let result = engine.authorize(
        &realm_id,
        &AuthorizationRequest {
            client_id: client.client_id().clone(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            state: "csrf-token".to_string(),
            response_type: "code".to_string(),
            user_id: user.id().clone(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            resource: None,
        },
    );

    assert!(result.is_err(), "public client without PKCE must always be rejected");
}
