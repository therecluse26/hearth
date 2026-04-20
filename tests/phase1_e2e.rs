//! End-to-end integration tests for Phase 1 features.
//!
//! These tests verify that Phase 1 features compose correctly end-to-end
//! through the public API. They cover:
//!
//! 1. MFA enrollment + login (password + TOTP → session → tokens)
//! 2. Passkey-only authentication (`WebAuthn` registration → auth → session → tokens)
//! 3. Multi-tenant isolation round-trip (two tenants stay fully isolated)
//!
//! Inline helpers for TOTP and `WebAuthn` mirror `tests/mfa.rs` and
//! `tests/webauthn.rs` respectively — duplicated rather than extracted
//! into `tests/common/` to avoid destabilising the existing test suites.

mod common;

use hearth::core::TenantId;
use hearth::identity::{
    AuthenticationOptions, CleartextPassword, CompleteAuthenticationParams, CreateTenantRequest,
    CreateUserRequest, RegistrationOptions,
};

// ============================================================================
// Local helpers (intentional duplication — see module docs).
// ============================================================================

/// Computes a TOTP code from a base32 secret at the given unix-seconds time.
///
/// Mirrors `tests/mfa.rs::compute_totp_code` — duplicated to keep this file
/// self-contained.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let msg = step.to_be_bytes();
    let tag = ring::hmac::sign(&key, &msg);
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let otp = binary % 1_000_000;
    format!("{otp:06}")
}

/// Minimal `WebAuthn` test authenticator.
///
/// Mirrors `tests/webauthn.rs::webauthn_helper::TestAuthenticator` — builds
/// bit-accurate mock authenticator responses using `ring` for P-256 signing
/// and `ciborium` for CBOR encoding.
mod wa {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    const COSE_ALG_ES256: i64 = -7;

    pub struct TestAuthenticator {
        key_pair_pkcs8: Vec<u8>,
        pub credential_id: Vec<u8>,
        rp_id: String,
    }

    impl TestAuthenticator {
        pub fn new(rp_id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate P-256 key");
            let mut cred_id = vec![0u8; 32];
            rng.fill(&mut cred_id).expect("random cred id");
            Self {
                key_pair_pkcs8: pkcs8.as_ref().to_vec(),
                credential_id: cred_id,
                rp_id: rp_id.to_string(),
            }
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let pub_bytes = key_pair.public_key().as_ref();
            let x = &pub_bytes[1..33];
            let y = &pub_bytes[33..65];

            let cose_map = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(2.into()),
                ),
                (
                    ciborium::Value::Integer(3.into()),
                    ciborium::Value::Integer(COSE_ALG_ES256.into()),
                ),
                (
                    ciborium::Value::Integer((-1).into()),
                    ciborium::Value::Integer(1.into()),
                ),
                (
                    ciborium::Value::Integer((-2).into()),
                    ciborium::Value::Bytes(x.to_vec()),
                ),
                (
                    ciborium::Value::Integer((-3).into()),
                    ciborium::Value::Bytes(y.to_vec()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&cose_map, &mut buf).expect("encode COSE key");
            buf
        }

        #[allow(clippy::cast_possible_truncation)]
        fn build_auth_data(&self, sign_count: u32, include_credential: bool) -> Vec<u8> {
            let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes());
            let mut data = Vec::new();
            data.extend_from_slice(rp_id_hash.as_ref());
            let flags: u8 = if include_credential { 0x41 } else { 0x01 };
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());

            if include_credential {
                data.extend_from_slice(&[0u8; 16]); // AAGUID
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        fn build_client_data_json(ceremony_type: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
            serde_json::to_vec(&serde_json::json!({
                "type": ceremony_type,
                "challenge": challenge_b64,
                "origin": origin,
            }))
            .expect("serialize clientDataJSON")
        }

        fn sign(&self, data: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let sig = key_pair.sign(&rng, data).expect("sign");
            sig.as_ref().to_vec()
        }

        pub fn build_registration_response(
            &self,
            challenge: &[u8],
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>) {
            let client_data_json =
                Self::build_client_data_json("webauthn.create", challenge, origin);
            let auth_data = self.build_auth_data(0, true);

            let att_obj = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("none".to_string()),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![]),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(auth_data),
                ),
            ]);
            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode attestation");

            (client_data_json, att_bytes)
        }

        pub fn build_authentication_response(
            &self,
            challenge: &[u8],
            origin: &str,
            sign_count: u32,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let client_data_json = Self::build_client_data_json("webauthn.get", challenge, origin);
            let auth_data = self.build_auth_data(sign_count, false);

            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
            let mut signed_data = auth_data.clone();
            signed_data.extend_from_slice(client_data_hash.as_ref());
            let sig = self.sign(&signed_data);

            (client_data_json, auth_data, sig)
        }
    }
}

// ============================================================================
// Scenario: MFA enrollment + login
// ============================================================================

/// Register → enable TOTP → authenticate (password + TOTP) → receive session.
///
/// Proves that Phase 1 MFA composes with the Phase 0 password + session + token
/// flow without regressing any step.
#[tokio::test]
async fn mfa_enrollment_plus_login() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    // 1. Create tenant with real signing key.
    let tenant_rec = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("e2e-mfa-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create tenant");
    let tenant = tenant_rec.id().clone();

    // 2. Create user with password.
    let user = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "e2e-mfa@example.com".to_string(),
                display_name: "E2E MFA User".to_string(),
            },
        )
        .expect("create user");

    let password = CleartextPassword::from_string("E2ePassw0rd!".to_string());
    harness
        .identity()
        .set_password(&tenant, user.id(), &password)
        .expect("set password");

    // 3. Enroll TOTP and activate via initial code.
    let enrollment = harness
        .identity()
        .enroll_totp(&tenant, user.id())
        .expect("enroll_totp");
    assert_eq!(enrollment.recovery_codes.len(), 8);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now);

    harness
        .identity()
        .verify_totp_enrollment(&tenant, user.id(), &code)
        .expect("verify_totp_enrollment");
    assert!(harness
        .identity()
        .mfa_enabled(&tenant, user.id())
        .expect("mfa_enabled"));

    // 4. Authenticate: password + TOTP.
    let pw_ok = harness
        .identity()
        .verify_password(&tenant, user.id(), &password)
        .expect("verify_password");
    assert!(pw_ok, "password must verify");

    // Fresh TOTP code (may be same step — replay protection handles that).
    let now2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code2 = compute_totp_code(&enrollment.secret_base32, now2);
    let verify = harness.identity().verify_totp(&tenant, user.id(), &code2);
    if verify.is_err() {
        // Step already used — advance one window.
        let code3 = compute_totp_code(&enrollment.secret_base32, now2 + 30);
        harness
            .identity()
            .verify_totp(&tenant, user.id(), &code3)
            .expect("verify_totp with next step");
    }

    // 5. Session + tokens.
    let session = harness
        .identity()
        .create_session(
            &tenant,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let tokens = harness
        .identity()
        .issue_tokens(&tenant, user.id(), session.id())
        .expect("issue tokens");

    // 6. Token validates and claims match user/session/tenant.
    let claims = harness
        .identity()
        .validate_token(&tenant, tokens.access_token())
        .expect("validate token");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.sid, session.id().to_string());
    assert_eq!(claims.tid, tenant.to_string());
}

// ============================================================================
// Scenario: Passkey-only authentication
// ============================================================================

/// Register passkey → passwordless login → receive session → validate token.
///
/// Proves the full `WebAuthn` ceremony composes with session issuance and
/// token validation without a password credential ever being set.
#[tokio::test]
async fn passkey_only_authentication() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let tenant_rec = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("e2e-passkey-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create tenant");
    let tenant = tenant_rec.id().clone();

    // User WITHOUT password — passkey-only.
    let user = harness
        .identity()
        .create_user(
            &tenant,
            &CreateUserRequest {
                email: "e2e-passkey@example.com".to_string(),
                display_name: "E2E Passkey User".to_string(),
            },
        )
        .expect("create user");

    let rp_id = "example.com";
    let origin = "https://example.com";
    let authenticator = wa::TestAuthenticator::new(rp_id);

    // Registration ceremony.
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &tenant,
            user.id(),
            &RegistrationOptions {
                rp_id: rp_id.to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");

    let (client_data_json, att_obj) =
        authenticator.build_registration_response(&reg_challenge, origin);

    let cred_info = harness
        .identity()
        .complete_webauthn_registration(
            &tenant,
            user.id(),
            &client_data_json,
            &att_obj,
            origin,
            false,
        )
        .expect("complete registration");
    assert_eq!(cred_info.credential_id(), authenticator.credential_id);

    // Authentication ceremony — no password ever set.
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &tenant,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: rp_id.to_string(),
            },
        )
        .expect("start authentication");

    let (auth_cdj, auth_data, sig) =
        authenticator.build_authentication_response(&auth_challenge, origin, 1);

    let auth_result = harness
        .identity()
        .complete_webauthn_authentication(
            &tenant,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &auth_cdj,
                authenticator_data: &auth_data,
                signature: &sig,
                user_handle: None,
                origin,
            },
        )
        .expect("complete authentication");
    assert_eq!(auth_result.user_id(), user.id());

    // Session + tokens flow off the passkey-authenticated user.
    let session = harness
        .identity()
        .create_session(
            &tenant,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let tokens = harness
        .identity()
        .issue_tokens(&tenant, user.id(), session.id())
        .expect("issue tokens");

    let claims = harness
        .identity()
        .validate_token(&tenant, tokens.access_token())
        .expect("validate token");
    assert_eq!(claims.sub, user.id().to_string());
    assert_eq!(claims.tid, tenant.to_string());
}

// ============================================================================
// Scenario: Multi-tenant isolation round-trip
// ============================================================================

/// Two tenants remain fully isolated: foreign tokens fail, foreign user
/// lookups return `None`, JWKS differ, and deleting tenant A leaves B intact.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn multi_tenant_isolation_roundtrip() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    // Create two independent tenants.
    let tenant_a = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("tenant-a-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("tenant A");
    let a = tenant_a.id().clone();

    let tenant_b = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("tenant-b-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("tenant B");
    let b = tenant_b.id().clone();

    // Users + tokens in each tenant.
    let user_a = harness
        .identity()
        .create_user(
            &a,
            &CreateUserRequest {
                email: "alice@tenant-a.example".to_string(),
                display_name: "Alice A".to_string(),
            },
        )
        .expect("create user A");

    let user_b = harness
        .identity()
        .create_user(
            &b,
            &CreateUserRequest {
                email: "bob@tenant-b.example".to_string(),
                display_name: "Bob B".to_string(),
            },
        )
        .expect("create user B");

    let session_a = harness
        .identity()
        .create_session(
            &a,
            user_a.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session A");
    let session_b = harness
        .identity()
        .create_session(
            &b,
            user_b.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session B");

    let tokens_a = harness
        .identity()
        .issue_tokens(&a, user_a.id(), session_a.id())
        .expect("tokens A");
    let tokens_b = harness
        .identity()
        .issue_tokens(&b, user_b.id(), session_b.id())
        .expect("tokens B");

    // --- Isolation assertion 1: token from A fails under tenant B context. ---
    let a_under_b = harness
        .identity()
        .validate_token(&b, tokens_a.access_token());
    assert!(
        a_under_b.is_err(),
        "tenant A token must not validate under tenant B"
    );

    // Same direction: B under A.
    let b_under_a = harness
        .identity()
        .validate_token(&a, tokens_b.access_token());
    assert!(
        b_under_a.is_err(),
        "tenant B token must not validate under tenant A"
    );

    // --- Isolation assertion 2: user A not visible in tenant B scope. ---
    let cross = harness
        .identity()
        .get_user(&b, user_a.id())
        .expect("get_user cross-tenant must not error");
    assert!(
        cross.is_none(),
        "user from tenant A must not be visible in tenant B"
    );

    // --- Isolation assertion 3: JWKS per tenant differ. ---
    let jwks_a = harness.identity().tenant_jwks(&a).expect("jwks A");
    let jwks_b = harness.identity().tenant_jwks(&b).expect("jwks B");
    assert!(!jwks_a.keys.is_empty(), "tenant A JWKS must have a key");
    assert!(!jwks_b.keys.is_empty(), "tenant B JWKS must have a key");
    let a_kids: Vec<&str> = jwks_a.keys.iter().map(|k| k.kid.as_str()).collect();
    let b_kids: Vec<&str> = jwks_b.keys.iter().map(|k| k.kid.as_str()).collect();
    for kid in &a_kids {
        assert!(
            !b_kids.contains(kid),
            "tenant JWKS kids must not overlap: {kid}"
        );
    }

    // --- Isolation assertion 4: deleting tenant A leaves tenant B intact. ---
    harness.identity().delete_tenant(&a).expect("delete A");

    // Tenant A data is gone.
    let a_tenant_gone = harness
        .identity()
        .get_tenant(&a)
        .expect("get_tenant A post-delete");
    assert!(a_tenant_gone.is_none(), "tenant A should be deleted");

    // Tenant B user still exists.
    let b_user_still_there = harness
        .identity()
        .get_user(&b, user_b.id())
        .expect("get user B post-delete");
    assert!(
        b_user_still_there.is_some(),
        "tenant B user must survive tenant A deletion"
    );

    // Tenant B session still valid.
    let b_session_still_there = harness
        .identity()
        .get_session(&b, session_b.id())
        .expect("get session B post-delete");
    assert!(
        b_session_still_there.is_some(),
        "tenant B session must survive tenant A deletion"
    );

    // Tenant B token still validates.
    let b_claims = harness
        .identity()
        .validate_token(&b, tokens_b.access_token())
        .expect("tenant B token must validate after tenant A deletion");
    assert_eq!(b_claims.sub, user_b.id().to_string());
    assert_eq!(b_claims.tid, b.to_string());

    // Silence unused warning for TenantId imports.
    let _ = TenantId::generate();
}
