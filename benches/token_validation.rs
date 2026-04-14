//! Criterion benchmarks for JWT token operations.
//!
//! Covers `TEST_SCENARIOS.md` § JWT / Tokens — Benchmark:
//! 1. Token validation (JWT verify + session lookup): p50 < 50 μs, p99 < 500 μs
//! 2. Token issuance (full flow): p50 < 1 ms, p99 < 5 ms

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use hearth::core::{Clock, SystemClock, TenantId};
use hearth::identity::{
    verify_token_signature, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig,
    IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Sets up an engine with a user, session, and pre-issued tokens.
fn setup_tokens() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    TenantId,
    String, // access token
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = EmbeddedStorageEngine::open(config).expect("open");
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::new(storage) as Arc<dyn StorageEngine>,
        clock,
        IdentityConfig::default(),
    )
    .expect("engine creation");
    let tenant = TenantId::generate();

    let user = engine
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "bench@example.com".to_string(),
                display_name: "Bench User".to_string(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(&tenant, user.id())
        .expect("create session");

    let pair = engine
        .issue_tokens(&tenant, user.id(), session.id())
        .expect("issue tokens");

    let access_token = pair.access_token().to_string();

    (dir, engine, tenant, access_token)
}

/// Benchmarks token validation via session lookup (internal hot path).
fn bench_token_validation_session_lookup(c: &mut Criterion) {
    let (_dir, engine, tenant, token) = setup_tokens();

    c.bench_function("token_validation_session_lookup", |b| {
        b.iter(|| {
            let result = engine.validate_token(&tenant, &token);
            assert!(result.is_ok());
        });
    });
}

/// Benchmarks token validation via full Ed25519 signature verification.
fn bench_token_validation_signature(c: &mut Criterion) {
    let (_dir, engine, _tenant, token) = setup_tokens();
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
    let (_dir, engine, tenant, _token) = setup_tokens();

    // Pre-create a user (reuse across iterations)
    let user = engine
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "bench-issue@example.com".to_string(),
                display_name: "Issue Bench".to_string(),
            },
        )
        .expect("create user");

    c.bench_function("token_issuance_full_flow", |b| {
        b.iter(|| {
            let session = engine
                .create_session(&tenant, user.id())
                .expect("create session");
            let result = engine.issue_tokens(&tenant, user.id(), session.id());
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
