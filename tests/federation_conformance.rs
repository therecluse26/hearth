//! OIDC RP conformance tests for external IdP federation (gap #5).
//!
//! Per OIDC Core 1.0 §3.1.3.7 the relying party MUST validate:
//!
//! * `iss` matches the expected issuer
//! * `aud` contains the client_id
//! * `exp` is in the future (with reasonable skew)
//! * `nbf` (if present) is not in the future
//! * `nonce` matches what the RP sent
//! * The ID token signature is valid under a JWKS key
//!
//! Plus the happy-path RS256 signature verification that rounds out
//! the last coverage gap in the federation feature: we generate an
//! ephemeral RSA-2048 keypair at test time, sign a synthetic JWT, and
//! verify it through `verify_rs256`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hearth::core::{IdpId, RealmId, Timestamp};
use hearth::identity::federation::{
    verify_id_token_claims, verify_rs256, FederationSecret, IdTokenClaims, IdpConfig, IdpKind, Jwk,
    StateBag,
};
use hearth::identity::IdentityError;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

fn sample_cfg() -> IdpConfig {
    IdpConfig {
        id: IdpId::generate(),
        realm_id: RealmId::generate(),
        name: "upstream".to_string(),
        kind: IdpKind::Oidc,
        display_name: "Upstream".to_string(),
        issuer: "https://idp.example".to_string(),
        authorization_endpoint: "https://idp.example/auth".to_string(),
        token_endpoint: "https://idp.example/token".to_string(),
        userinfo_endpoint: None,
        jwks_uri: Some("https://idp.example/jwks".to_string()),
        scopes: vec!["openid".to_string()],
        client_id: "conformance-client".to_string(),
        client_secret: FederationSecret::new("s".to_string()),
        claim_mappings: BTreeMap::new(),
        created_at: Timestamp::from_micros(0),
        updated_at: Timestamp::from_micros(0),
    }
}

fn bag_with_nonce(nonce: &str) -> StateBag {
    StateBag {
        state_token: "st".to_string(),
        realm_id: RealmId::generate(),
        idp_id: IdpId::generate(),
        nonce: nonce.to_string(),
        pkce_verifier: "v".to_string(),
        return_to: "/".to_string(),
        expires_at: Timestamp::from_micros(i64::MAX),
    }
}

// ===== Claim validation per OIDC Core §3.1.3.7 =====

#[test]
fn rejects_mismatched_issuer() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: "https://wrong.example".to_string(),
        sub: "sub".into(),
        aud: Some(serde_json::Value::String(cfg.client_id.clone())),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    assert!(matches!(
        verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_000),
        Err(IdentityError::FederationTokenVerificationFailed)
    ));
}

#[test]
fn accepts_audience_as_string() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::Value::String(cfg.client_id.clone())),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_000).expect("aud=string");
}

#[test]
fn accepts_audience_as_array_containing_client() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::json!([
            "other",
            cfg.client_id.clone(),
            "still-other"
        ])),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_000).expect("aud=array");
}

#[test]
fn rejects_audience_array_without_client() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::json!(["a", "b"])),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    assert!(verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_000).is_err());
}

#[test]
fn rejects_missing_nonce_when_expected() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("expected");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::Value::String(cfg.client_id.clone())),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        // Provider dropped the nonce.
        nonce: None,
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    assert!(verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_000).is_err());
}

#[test]
fn rejects_exp_past_skew_tolerance() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::Value::String(cfg.client_id.clone())),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    // exp + 120s > 60s skew → reject.
    assert!(verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_120).is_err());
}

#[test]
fn accepts_exp_within_skew_tolerance() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::Value::String(cfg.client_id.clone())),
        nbf: None,
        exp: 2_000_000_000,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    // exp + 30s is within 60s skew.
    verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_030).expect("within skew");
}

#[test]
fn rejects_nbf_in_the_future_past_skew() {
    let cfg = sample_cfg();
    let bag = bag_with_nonce("n");
    let claims = IdTokenClaims {
        iss: cfg.issuer.clone(),
        sub: "sub".into(),
        aud: Some(serde_json::Value::String(cfg.client_id.clone())),
        // nbf 120s in the future → outside 60s skew.
        nbf: Some(2_000_000_120),
        exp: 2_000_000_600,
        iat: Some(2_000_000_000 - 60),
        nonce: Some("n".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    assert!(verify_id_token_claims(&claims, &cfg, &bag, 2_000_000_000).is_err());
}

// ===== RS256 happy-path signature verify =====
//
// Generates a fresh RSA-2048 keypair, signs a synthetic ID token with
// RS256 (via the `rsa` dev-dependency — ring 0.17 doesn't expose key
// generation), builds a matching JWK from the public modulus + exponent,
// and verifies through Hearth's `verify_rs256`. This is the one code
// path the sad-path tests can't cover by construction.

#[test]
fn rs256_signature_verify_round_trip() {
    // Generate a 2048-bit RSA keypair with the `rsa` crate (ring 0.17
    // doesn't expose key generation), export to PKCS#8 DER, then load
    // into ring for signing — same stack Hearth uses for verification.
    // This gives us a real RS256 signature end-to-end without extra
    // sha2 features or hand-rolled PKCS1v15 encoding.

    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate rsa key");
    let public_key = private_key.to_public_key();

    // Build the JWK from public components. `n` and `e` are base64url-
    // no-pad big-endian byte encodings.
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let jwk = Jwk {
        kty: "RSA".into(),
        alg: Some("RS256".into()),
        kid: Some("test-key-1".into()),
        n: Some(URL_SAFE_NO_PAD.encode(&n_bytes)),
        e: Some(URL_SAFE_NO_PAD.encode(&e_bytes)),
    };

    // Craft the synthetic JWT signing input.
    let header = r#"{"alg":"RS256","typ":"JWT","kid":"test-key-1"}"#;
    let payload =
        r#"{"iss":"https://idp.example","sub":"alice","aud":"c","exp":9999999999,"nonce":"n"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with ring (RSA_PKCS1_SHA256 — same algorithm Hearth verifies).
    let pkcs8_der = private_key.to_pkcs8_der().expect("pkcs8 encode");
    let key_pair =
        ring::signature::RsaKeyPair::from_pkcs8(pkcs8_der.as_bytes()).expect("load keypair");
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    let ring_rng = ring::rand::SystemRandom::new();
    key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring_rng,
            signing_input.as_bytes(),
            &mut signature,
        )
        .expect("sign");

    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
    let jwt = format!("{signing_input}.{sig_b64}");

    // 1. Happy path: verification passes.
    verify_rs256(&jwt, &jwk).expect("valid RS256 signature");

    // 2. Flip a bit in the signature; verification must now fail.
    let mut tampered = signature.clone();
    tampered[0] ^= 0x01;
    let bad_sig_b64 = URL_SAFE_NO_PAD.encode(&tampered);
    let bad_jwt = format!("{signing_input}.{bad_sig_b64}");
    assert!(matches!(
        verify_rs256(&bad_jwt, &jwk),
        Err(IdentityError::FederationTokenVerificationFailed)
    ));

    // 3. Wrong public key: verification must fail.
    let other = RsaPrivateKey::new(&mut rng, 2048)
        .expect("another key")
        .to_public_key();
    let other_jwk = Jwk {
        kty: "RSA".into(),
        alg: Some("RS256".into()),
        kid: Some("test-key-1".into()),
        n: Some(URL_SAFE_NO_PAD.encode(other.n().to_bytes_be())),
        e: Some(URL_SAFE_NO_PAD.encode(other.e().to_bytes_be())),
    };
    assert!(matches!(
        verify_rs256(&jwt, &other_jwk),
        Err(IdentityError::FederationTokenVerificationFailed)
    ));
}

#[test]
fn rs256_rejects_non_rsa_jwk() {
    let jwk = Jwk {
        kty: "EC".into(),
        alg: Some("ES256".into()),
        kid: Some("k".into()),
        n: None,
        e: None,
    };
    let dummy_jwt = "aGVhZGVy.cGF5bG9hZA.c2ln";
    assert!(matches!(
        verify_rs256(dummy_jwt, &jwk),
        Err(IdentityError::FederationTokenVerificationFailed)
    ));
}

#[test]
fn rs256_rejects_jwk_missing_components() {
    let jwk = Jwk {
        kty: "RSA".into(),
        alg: Some("RS256".into()),
        kid: Some("k".into()),
        n: None, // modulus missing
        e: Some("AQAB".into()),
    };
    let dummy_jwt = "aGVhZGVy.cGF5bG9hZA.c2ln";
    assert!(matches!(
        verify_rs256(dummy_jwt, &jwk),
        Err(IdentityError::FederationTokenVerificationFailed)
    ));
}
