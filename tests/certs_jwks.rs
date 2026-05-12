//! Integration tests for the `/certs` JWKS endpoint (HEA-51 / OIDC M1).
//!
//! Verifies that:
//!
//! - `GET /certs` returns an RFC 7517 JWKS document.
//! - The response includes one entry per supported algorithm: `EdDSA`
//!   (the primary signer), `RS256`, and `ES256` (ecosystem-compat keys
//!   for OIDC clients like `jose` / `python-jose`).
//! - Each entry has the field set required by its key type
//!   (`OKP`/Ed25519 has `crv` + `x`; `RSA` has `n` + `e`; `EC` has
//!   `crv` + `x` + `y`).
//! - Aliases `/jwks` and `/.well-known/jwks.json` return identical
//!   documents.
//!
//! Acceptance for HEA-51 calls for the JWKS to be consumable by `jose`
//! / `python-jose`. Asserting field-level RFC 7517 conformance here is
//! the in-process Rust equivalent — anything that passes these checks
//! is parseable by spec-compliant JOSE libraries.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn fetch_jwks(app: &axum::Router, path: &str) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "GET {path}");
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body bytes");
    serde_json::from_slice(&body_bytes).expect("JWKS JSON")
}

#[tokio::test]
async fn certs_returns_rfc7517_jwks_with_all_three_algorithms() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h).await;

    let body = fetch_jwks(&app, "/certs").await;

    let keys = body["keys"].as_array().expect("keys array");
    let algs: Vec<&str> = keys
        .iter()
        .map(|k| k["alg"].as_str().unwrap_or_default())
        .collect();

    assert!(
        algs.contains(&"EdDSA"),
        "JWKS must include EdDSA (primary signer); got {algs:?}"
    );
    assert!(
        algs.contains(&"RS256"),
        "JWKS must include RS256 per HEA-51; got {algs:?}"
    );
    assert!(
        algs.contains(&"ES256"),
        "JWKS must include ES256 per HEA-51; got {algs:?}"
    );

    // RFC 7517 invariants: every entry has kty, kid, use="sig", alg.
    for entry in keys {
        assert!(entry["kty"].as_str().is_some(), "kty required");
        assert!(entry["kid"].as_str().is_some(), "kid required");
        assert_eq!(entry["use"].as_str(), Some("sig"), "use must be sig");
        assert!(entry["alg"].as_str().is_some(), "alg required");
    }

    // Per-algorithm field invariants.
    for entry in keys {
        match entry["alg"].as_str() {
            Some("EdDSA") => {
                assert_eq!(entry["kty"].as_str(), Some("OKP"));
                assert_eq!(entry["crv"].as_str(), Some("Ed25519"));
                let x = entry["x"].as_str().expect("OKP entry must include x");
                let decoded = URL_SAFE_NO_PAD.decode(x).expect("x is base64url");
                assert_eq!(decoded.len(), 32, "Ed25519 public key is 32 bytes");
                assert!(entry.get("y").map_or(true, |v| v.is_null()));
                assert!(entry.get("n").map_or(true, |v| v.is_null()));
                assert!(entry.get("e").map_or(true, |v| v.is_null()));
            }
            Some("RS256") => {
                assert_eq!(entry["kty"].as_str(), Some("RSA"));
                let n = entry["n"].as_str().expect("RSA entry must include n");
                let e = entry["e"].as_str().expect("RSA entry must include e");
                let n_bytes = URL_SAFE_NO_PAD.decode(n).expect("n is base64url");
                let e_bytes = URL_SAFE_NO_PAD.decode(e).expect("e is base64url");
                // RSA-2048 modulus is 256 bytes; allow shorter for leading
                // zero stripping but reject anything obviously off-spec.
                assert!(
                    (250..=257).contains(&n_bytes.len()),
                    "RSA-2048 modulus length looks wrong: {}",
                    n_bytes.len()
                );
                assert!(!e_bytes.is_empty(), "RSA exponent must be non-empty");
                assert!(entry.get("crv").map_or(true, |v| v.is_null()));
                assert!(entry.get("x").map_or(true, |v| v.is_null()));
                assert!(entry.get("y").map_or(true, |v| v.is_null()));
            }
            Some("ES256") => {
                assert_eq!(entry["kty"].as_str(), Some("EC"));
                assert_eq!(entry["crv"].as_str(), Some("P-256"));
                let x = entry["x"].as_str().expect("EC entry must include x");
                let y = entry["y"].as_str().expect("EC entry must include y");
                let x_bytes = URL_SAFE_NO_PAD.decode(x).expect("x is base64url");
                let y_bytes = URL_SAFE_NO_PAD.decode(y).expect("y is base64url");
                assert_eq!(x_bytes.len(), 32, "P-256 x coordinate is 32 bytes");
                assert_eq!(y_bytes.len(), 32, "P-256 y coordinate is 32 bytes");
                assert!(entry.get("n").map_or(true, |v| v.is_null()));
                assert!(entry.get("e").map_or(true, |v| v.is_null()));
            }
            other => panic!("unexpected alg in JWKS: {other:?}"),
        }
    }
}

#[tokio::test]
async fn jwks_aliases_return_same_document() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h).await;

    // Each route must return an identical JWKS document. Stable `kid`s
    // are critical so that an OIDC client landing on any of the three
    // mount points sees consistent verification material.
    let certs = fetch_jwks(&app, "/certs").await;
    let jwks = fetch_jwks(&app, "/jwks").await;
    let well_known = fetch_jwks(&app, "/.well-known/jwks.json").await;

    assert_eq!(certs, jwks, "/certs and /jwks must match");
    assert_eq!(
        certs, well_known,
        "/certs and /.well-known/jwks.json must match"
    );
}

#[tokio::test]
async fn jwt_kid_header_matches_a_jwks_entry() {
    use hearth::core::RealmId;
    use hearth::identity::{verify_token_signature, CreateUserRequest, SessionContext};

    let h = common::TestHarness::embedded().await.expect("harness");

    // A realm scope is required so the identity engine has a JWKS to
    // hand out. Using a fresh RealmId mirrors the other token tests
    // and avoids the create_realm setup overhead.
    let realm_id = RealmId::generate();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("kid-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Kid Match Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = h
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = h
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    // Pull the JWT header `kid` out of the access token.
    let header_b64 = pair
        .access_token()
        .split('.')
        .next()
        .expect("access token has header segment");
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("decode JWT header");
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("parse JWT header");
    let token_kid = header["kid"].as_str().expect("JWT must carry kid");

    let app = build_app(&h).await;
    let jwks = fetch_jwks(&app, "/certs").await;
    let keys = jwks["keys"].as_array().expect("keys array");

    let matched = keys
        .iter()
        .find(|j| j["kid"].as_str() == Some(token_kid))
        .unwrap_or_else(|| {
            panic!(
                "no JWKS entry with kid {token_kid}; JWKS kids = {:?}",
                keys.iter()
                    .map(|j| j["kid"].as_str())
                    .collect::<Vec<_>>()
            )
        });

    // Cross-check: the matched entry should be the EdDSA signer
    // (current primary; HEA-53 may add RS256/ES256 signers later).
    assert_eq!(matched["alg"].as_str(), Some("EdDSA"));

    // The matched key should successfully verify the access token.
    let x_b64 = matched["x"].as_str().expect("Ed25519 JWK x");
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .expect("decode Ed25519 pubkey");
    verify_token_signature(pair.access_token(), &pub_bytes)
        .expect("token must verify under matched JWKS entry");
}
