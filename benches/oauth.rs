//! Criterion benchmarks for OAuth 2.0 client credentials and token introspection.
//!
//! Covers `TEST_SCENARIOS.md` § OAuth — Benchmark:
//! - G1: Client credentials issuance: p50 < 500 μs, p99 < 2 ms
//! - G2: Token introspection: p50 < 50 μs, p99 < 500 μs

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    ClientCredentialsRequest, CreateRealmRequest, EmbeddedIdentityEngine, IdentityConfig,
    IdentityEngine, RegisterClientRequest, TokenIntrospectionRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an engine with a realm, a confidential client, and a pre-issued
/// access token for introspection benchmarks.
fn setup_oauth() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    RealmId,
    String, // client_secret
    String, // access_token from client_credentials
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

    // Create a real realm (required for per-realm signing keys).
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "bench-oauth-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let secret = "bench-client-secret-that-is-long-enough";
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Bench Confidential Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some(secret.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    // Pre-issue a token for introspection benchmarks.
    let cred_resp = engine
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: secret.to_string(),
                scope: Some("read write".to_string()),
            },
        )
        .expect("client_credentials_token");

    (
        dir,
        engine,
        realm_id,
        secret.to_string(),
        cred_resp.access_token().to_string(),
    )
}

/// Benchmarks client credentials token issuance.
///
/// Target: p50 < 500 μs, p99 < 2 ms.
fn bench_client_credentials(c: &mut Criterion) {
    let (_dir, engine, realm_id, secret, _token) = setup_oauth();

    // We need the client_id — re-register a second client for repeated issuance.
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Bench CC Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some(secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let client_id = client.client_id().clone();
    c.bench_function("oauth_client_credentials_issuance", |b| {
        b.iter(|| {
            let result = engine.client_credentials_token(
                &realm_id,
                &ClientCredentialsRequest {
                    client_id: client_id.clone(),
                    client_secret: secret.clone(),
                    scope: Some("read".to_string()),
                },
            );
            assert!(result.is_ok());
        });
    });
}

/// Benchmarks token introspection (hot path).
///
/// Target: p50 < 50 μs, p99 < 500 μs.
fn bench_token_introspection(c: &mut Criterion) {
    let (_dir, engine, realm_id, _secret, access_token) = setup_oauth();

    c.bench_function("oauth_token_introspection", |b| {
        b.iter(|| {
            let result = engine.introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: access_token.clone(),
                    token_type_hint: None,
                },
            );
            assert!(result.is_ok());
            assert!(result.expect("introspect").active);
        });
    });
}

criterion_group!(benches, bench_client_credentials, bench_token_introspection);
criterion_main!(benches);
