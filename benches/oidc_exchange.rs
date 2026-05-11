//! Criterion benchmarks for OIDC authorization code exchange.
//!
//! Covers `TEST_SCENARIOS.md` § OIDC — Benchmark:
//! Auth code exchange latency: p50 < 1ms, p99 < 5ms

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    AuthorizationRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig,
    IdentityEngine, RegisterClientRequest, TokenExchangeRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an engine with a registered client and user.
fn setup_oidc() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    RealmId,
    hearth::core::ClientId,
    hearth::core::UserId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("engine creation");
    let realm = RealmId::generate();

    let client = engine
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Bench App".to_string(),
                redirect_uris: vec!["https://bench.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench-oidc@example.com".to_string(),
                display_name: "Bench OIDC User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                        attributes: Default::default(),
            },
        )
        .expect("create user");

    (
        dir,
        engine,
        realm,
        client.client_id().clone(),
        user.id().clone(),
    )
}

/// Benchmarks the full authorize + exchange flow.
fn bench_auth_code_exchange(c: &mut Criterion) {
    let (_dir, engine, realm, client_id, user_id) = setup_oidc();

    c.bench_function("oidc_auth_code_exchange", |b| {
        b.iter(|| {
            // Authorize: generate code
            let auth = engine
                .authorize(
                    &realm,
                    &AuthorizationRequest {
                        client_id: client_id.clone(),
                        redirect_uri: "https://bench.example.com/callback".to_string(),
                        scope: "openid".to_string(),
                        state: "bench-state".to_string(),
                        resource: None,
                        response_type: "code".to_string(),
                        user_id: user_id.clone(),
                        code_challenge: None,
                        code_challenge_method: None,
                        nonce: None,
                    },
                )
                .expect("authorize");

            // Exchange: trade code for tokens
            let result = engine.exchange_authorization_code(
                &realm,
                &TokenExchangeRequest {
                    client_id: client_id.clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://bench.example.com/callback".to_string(),
                    code_verifier: None,
                },
            );
            assert!(result.is_ok());
        });
    });
}

criterion_group!(benches, bench_auth_code_exchange);
criterion_main!(benches);
