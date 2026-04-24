//! Criterion benchmarks for claims-based RBAC checks.
//!
//! Covers the hot-path authorization pattern after the Zanzibar → RBAC
//! migration: client and server authorization decisions are JWT claim
//! lookups, never network calls.
//!
//! Targets (from `docs/specs/AUTHORIZATION.md` § 10):
//! - JWT payload decode + permission lookup: p99 < 1 μs
//! - In-memory HashSet `contains` over the claim set: p99 < 100 ns

use std::collections::HashSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// Build a JWT payload segment containing `n` permissions plus a fixed
/// set of RBAC-relevant claims. The signature segment is arbitrary —
/// nothing in these benchmarks verifies it.
fn forge_token(permission_count: usize) -> String {
    let perms: Vec<String> = (0..permission_count)
        .map(|i| format!("namespace.resource.action_{i:04}"))
        .collect();
    let roles = vec!["admin".to_string(), "editor".to_string()];
    let groups = vec!["engineering".to_string(), "security".to_string()];
    let claims = serde_json::json!({
        "sub": "user_abc123",
        "iss": "https://hearth.example.com",
        "aud": "hearth",
        "exp": 2_000_000_000i64,
        "iat": 1_700_000_000i64,
        "sid": "sid_1",
        "tid": "tid_1",
        "oid": "org_42",
        "token_type": "access",
        "roles": roles,
        "groups": groups,
        "permissions": perms,
    });
    let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "k1"});
    let hb = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let cb = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let sig = URL_SAFE_NO_PAD.encode(b"not-a-real-signature");
    format!("{hb}.{cb}.{sig}")
}

/// Benchmarks the end-to-end "client-side claim lookup" pattern:
/// split the JWT, base64url-decode the payload segment, parse JSON,
/// then test membership.
///
/// This is what a web app does on every render when it calls
/// `hearth.hasPermission(...)`.
fn bench_jwt_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("rbac_jwt_lookup");
    for size in [10usize, 50, 100] {
        let token = forge_token(size);
        let target = format!("namespace.resource.action_{:04}", size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let t = black_box(token.as_str());
                let permission = black_box(target.as_str());
                let parts: Vec<&str> = t.split('.').collect();
                assert_eq!(parts.len(), 3);
                let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("base64 decode");
                let claims: serde_json::Value =
                    serde_json::from_slice(&payload).expect("json parse");
                let found = claims
                    .get("permissions")
                    .and_then(|p| p.as_array())
                    .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(permission)));
                black_box(found)
            });
        });
    }
    group.finish();
}

/// Benchmarks server-side authorization: given a pre-materialized
/// `HashSet<String>` of the claim set (as a middleware would build once
/// per request after verifying the token), check membership.
///
/// This is the steady-state hot path — after the per-request
/// verification cost has been amortized over however many permission
/// checks the handler performs.
fn bench_hashset_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("rbac_hashset_contains");
    for size in [10usize, 50, 100] {
        let set: HashSet<String> = (0..size)
            .map(|i| format!("namespace.resource.action_{i:04}"))
            .collect();
        let target = format!("namespace.resource.action_{:04}", size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let s = black_box(&set);
                let t = black_box(target.as_str());
                black_box(s.contains(t))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_jwt_lookup, bench_hashset_contains);
criterion_main!(benches);
