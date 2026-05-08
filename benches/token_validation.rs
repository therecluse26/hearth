//! Criterion benchmarks for JWT token operations.
//!
//! Covers `TEST_SCENARIOS.md` § JWT / Tokens — Benchmark:
//! 1. Token validation (JWT verify + session lookup): p50 < 50 μs, p99 < 500 μs
//! 2. Token issuance (full flow): p50 < 1 ms, p99 < 5 ms

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    verify_token_signature, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig,
    IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an engine with a user, session, and pre-issued tokens.
fn setup_tokens() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    RealmId,
    String, // access token
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

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench@example.com".to_string(),
                display_name: "Bench User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(
            &realm,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");

    let access_token = pair.access_token().to_string();

    (dir, engine, realm, access_token)
}

/// Benchmarks token validation via session lookup (internal hot path).
fn bench_token_validation_session_lookup(c: &mut Criterion) {
    let (_dir, engine, realm, token) = setup_tokens();

    c.bench_function("token_validation_session_lookup", |b| {
        b.iter(|| {
            let result = engine.validate_token(&realm, &token);
            assert!(result.is_ok());
        });
    });
}

/// Benchmarks token validation via full Ed25519 signature verification.
fn bench_token_validation_signature(c: &mut Criterion) {
    let (_dir, engine, _realm, token) = setup_tokens();
    let pub_key = engine.signing_key().public_key_bytes().to_vec();

    c.bench_function("token_validation_ed25519_verify", |b| {
        b.iter(|| {
            let result = verify_token_signature(&token, &pub_key);
            assert!(result.is_ok());
        });
    });
}

/// Benchmarks token issuance (create session + issue tokens).
fn bench_token_issuance(c: &mut Criterion) {
    let (_dir, engine, realm, _token) = setup_tokens();

    // Pre-create a user (reuse across iterations)
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench-issue@example.com".to_string(),
                display_name: "Issue Bench".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create user");

    c.bench_function("token_issuance_full_flow", |b| {
        b.iter(|| {
            let session = engine
                .create_session(
                    &realm,
                    user.id(),
                    &hearth::identity::SessionContext::default(),
                )
                .expect("create session");
            let result = engine.issue_tokens(&realm, user.id(), session.id());
            assert!(result.is_ok());
        });
    });
}

criterion_group!(
    benches,
    bench_token_validation_session_lookup,
    bench_token_validation_signature,
    bench_token_issuance
);
criterion_main!(benches);
