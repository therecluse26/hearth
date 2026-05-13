//! Integration tests for `WebAuthn` / Passkeys (Step 24).
//!
//! Black box tests via `TestHarness` — exercises `WebAuthn` registration,
//! authentication, multi-credential management, and credential revocation
//! through the public `IdentityEngine` trait.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    AuthenticationOptions, CompleteAuthenticationParams, CreateRealmRequest, CreateUserRequest,
    IdentityError, RegistrationOptions, User,
};

/// Helper: creates a real realm with a signing key.
fn create_realm(harness: &common::TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("webauthn-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}

/// Helper: creates a user with a unique email.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("webauthn-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "WebAuthn Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ============================================================================
// Minimal WebAuthn test helper for integration tests.
//
// Builds bit-accurate mock authenticator responses (CBOR attestation objects,
// signed assertions) using ring for P-256 key generation/signing and ciborium
// for CBOR encoding. This mirrors the internal test_helper but is self-contained.
// ============================================================================

mod webauthn_helper {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// COSE algorithm identifier for ES256.
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

        /// Builds a registration response with "none" attestation.
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

        /// Builds an authentication response (assertion).
        pub fn build_authentication_response(
            &self,
            challenge: &[u8],
            origin: &str,
            sign_count: u32,
            user_handle: Option<&str>,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
            let client_data_json = Self::build_client_data_json("webauthn.get", challenge, origin);
            let auth_data = self.build_auth_data(sign_count, false);

            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
            let mut signed_data = auth_data.clone();
            signed_data.extend_from_slice(client_data_hash.as_ref());
            let sig = self.sign(&signed_data);

            let handle = user_handle.map(|h| h.as_bytes().to_vec());
            (client_data_json, auth_data, sig, handle)
        }
    }
}

// ===== Scenario D1: Full lifecycle via embedded API =====
//
// create realm → user → start registration → complete registration →
// start authentication → complete authentication → success

#[tokio::test]
async fn webauthn_full_lifecycle() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";

    let authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Start registration
    let challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");

    // Build mock authenticator response
    let (client_data_json, attestation_object) =
        authenticator.build_registration_response(&challenge, origin);

    // Complete registration
    let cred_info = harness
        .identity()
        .complete_webauthn_registration(
            &realm,
            user.id(),
            &client_data_json,
            &attestation_object,
            origin,
            false,
        )
        .expect("complete registration");

    assert_eq!(cred_info.credential_id(), authenticator.credential_id);

    // Verify credential is listed
    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list credentials");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential_id(), authenticator.credential_id);

    // Start authentication
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    // Build mock assertion
    let (auth_cdj, auth_data, sig, _handle) =
        authenticator.build_authentication_response(&auth_challenge, origin, 1, None);

    // Complete authentication
    let auth_result = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
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
    assert_eq!(auth_result.sign_count(), 1);
}

// ===== Scenario D2: Credential management =====
//
// register key1 → auth → register key2 → revoke key1 →
// list (only key2) → auth key2 ✓

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn webauthn_credential_management() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";

    let auth1 = webauthn_helper::TestAuthenticator::new("example.com");
    let auth2 = webauthn_helper::TestAuthenticator::new("example.com");

    // Register key1
    let challenge1 = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start reg1");

    let (cdj1, att1) = auth1.build_registration_response(&challenge1, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &cdj1, &att1, origin, false)
        .expect("complete reg1");

    // Authenticate with key1
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start auth1");

    let (acdj, aad, asig, _) =
        auth1.build_authentication_response(&auth_challenge, origin, 1, None);
    harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &auth1.credential_id,
                client_data_json: &acdj,
                authenticator_data: &aad,
                signature: &asig,
                user_handle: None,
                origin,
            },
        )
        .expect("auth with key1");

    // Register key2
    let challenge2 = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start reg2");

    let (cdj2, att2) = auth2.build_registration_response(&challenge2, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &cdj2, &att2, origin, false)
        .expect("complete reg2");

    // Two credentials now
    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list");
    assert_eq!(creds.len(), 2, "should have 2 credentials");

    // Revoke key1
    harness
        .identity()
        .revoke_webauthn_credential(&realm, user.id(), &auth1.credential_id)
        .expect("revoke key1");

    // Only key2 remains
    let creds_after = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list after revoke");
    assert_eq!(
        creds_after.len(),
        1,
        "should have 1 credential after revoke"
    );
    assert_eq!(
        creds_after[0].credential_id(),
        auth2.credential_id,
        "remaining credential should be key2"
    );

    // Authenticate with key2
    let auth_challenge2 = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start auth2");

    let (acdj2, aad2, asig2, _) =
        auth2.build_authentication_response(&auth_challenge2, origin, 1, None);
    let result = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &auth2.credential_id,
                client_data_json: &acdj2,
                authenticator_data: &aad2,
                signature: &asig2,
                user_handle: None,
                origin,
            },
        )
        .expect("auth with key2");

    assert_eq!(result.user_id(), user.id());
}

// ===== Scenario D3: Credential naming and rename =====
//
// register → list (name=None) → rename → list (name=Some("...")) →
// rename to empty → list (name=None) → rename unknown cred → NotFound

#[tokio::test]
async fn webauthn_credential_naming() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";

    let auth = webauthn_helper::TestAuthenticator::new("example.com");

    // Register
    let challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");

    let (cdj, att) = auth.build_registration_response(&challenge, origin);
    let cred = harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &cdj, &att, origin, false)
        .expect("complete registration");

    // Name is None after registration
    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].name(), None, "name should start as None");

    // Rename
    harness
        .identity()
        .rename_webauthn_credential(&realm, user.id(), cred.credential_id(), "MacBook Touch ID")
        .expect("rename");

    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list after rename");
    assert_eq!(creds[0].name(), Some("MacBook Touch ID"));

    // Rename to empty string clears the name
    harness
        .identity()
        .rename_webauthn_credential(&realm, user.id(), cred.credential_id(), "   ")
        .expect("rename to blank");

    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list after blank rename");
    assert_eq!(creds[0].name(), None, "blank rename should clear name");

    // Rename with unknown credential ID returns NotFound
    let fake_id = vec![0xde, 0xad, 0xbe, 0xef];
    let err = harness
        .identity()
        .rename_webauthn_credential(&realm, user.id(), &fake_id, "Ghost")
        .expect_err("unknown credential should return error");
    assert!(
        matches!(err, IdentityError::WebAuthnCredentialNotFound),
        "expected WebAuthnCredentialNotFound, got: {err}"
    );
}
