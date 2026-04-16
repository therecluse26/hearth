//! Convert Keycloak password credentials into Hearth's PHC string format.
//!
//! Keycloak stores password credentials as a pair of nested JSON strings:
//!
//! ```json
//! {
//!   "type": "password",
//!   "credentialData": "{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\"}",
//!   "secretData":     "{\"value\":\"base64-hash\",\"salt\":\"base64-salt\"}"
//! }
//! ```
//!
//! This module parses that shape and produces the standard PHC string
//! format `$pbkdf2-sha256$i=N$salt$hash`, which the existing
//! `credentials::verify_hash()` path can then verify natively.

use serde::Deserialize;

use crate::identity::credentials::PasswordAlgorithm;
use crate::identity::migration::error::MigrationError;

/// A Keycloak password credential as represented in a realm export.
///
/// Keycloak wraps two JSON payloads (`credentialData` and `secretData`)
/// as strings inside the outer credential object. Deserialize directly
/// from an element of the user's `credentials` array.
#[derive(Debug, Deserialize)]
pub struct KeycloakCredential {
    /// Credential kind. Only `password` is handled; other kinds (e.g.
    /// `otp`, `webauthn`) are ignored by the caller.
    #[serde(rename = "type")]
    pub kind: String,
    /// Stringified JSON describing the KDF parameters.
    #[serde(rename = "credentialData", default)]
    pub credential_data: Option<String>,
    /// Stringified JSON carrying the hash value and salt.
    #[serde(rename = "secretData", default)]
    pub secret_data: Option<String>,
    /// Unix-millis timestamp at which the credential was created.
    #[serde(rename = "createdDate", default)]
    pub created_date: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CredentialData {
    #[serde(rename = "hashIterations")]
    hash_iterations: u32,
    algorithm: String,
}

#[derive(Debug, Deserialize)]
struct SecretData {
    value: String,
    salt: String,
}

/// Parsed output of a Keycloak password credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKeycloakCredential {
    /// The resolved `PasswordAlgorithm` in Hearth's taxonomy.
    pub algorithm: PasswordAlgorithm,
    /// PHC-formatted hash string suitable for storage and for
    /// `credentials::verify_hash()`.
    pub phc_string: String,
}

/// Converts a Keycloak password credential into Hearth's PHC string form.
///
/// Currently supports `pbkdf2-sha256` (Keycloak's default since v15).
/// `pbkdf2-sha512` and other algorithms return
/// [`MigrationError::UnsupportedAlgorithm`]; callers typically surface
/// these as skipped-credential warnings in the migration report.
pub fn parse_keycloak_credential(
    cred: &KeycloakCredential,
) -> Result<ParsedKeycloakCredential, MigrationError> {
    if cred.kind != "password" {
        return Err(MigrationError::ParseError {
            reason: format!("expected credential type 'password', got '{}'", cred.kind),
        });
    }

    let credential_data_str =
        cred.credential_data
            .as_deref()
            .ok_or_else(|| MigrationError::ParseError {
                reason: "password credential missing credentialData".to_string(),
            })?;
    let secret_data_str =
        cred.secret_data
            .as_deref()
            .ok_or_else(|| MigrationError::ParseError {
                reason: "password credential missing secretData".to_string(),
            })?;

    let credential_data: CredentialData = serde_json::from_str(credential_data_str)?;
    let secret_data: SecretData = serde_json::from_str(secret_data_str)?;

    match credential_data.algorithm.as_str() {
        "pbkdf2-sha256" => {
            // Keycloak encodes salt and value as base64 with padding; the
            // PHC spec mandates base64 without padding. Strip `=` before
            // composing the string — decoders are tolerant of either.
            let salt = strip_b64_padding(&secret_data.salt);
            let hash = strip_b64_padding(&secret_data.value);
            let phc_string = format!(
                "$pbkdf2-sha256$i={}${}${}",
                credential_data.hash_iterations, salt, hash
            );
            Ok(ParsedKeycloakCredential {
                algorithm: PasswordAlgorithm::Pbkdf2Sha256,
                phc_string,
            })
        }
        other => Err(MigrationError::UnsupportedAlgorithm {
            algorithm: other.to_string(),
        }),
    }
}

fn strip_b64_padding(s: &str) -> &str {
    s.trim_end_matches('=')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credentials::{
        verify_password, CleartextPassword, PasswordAlgorithm, StoredCredential,
    };

    /// Builds a `KeycloakCredential` from a freshly derived PBKDF2-SHA256
    /// hash so tests remain deterministic without depending on captured
    /// Keycloak fixtures.
    fn make_keycloak_credential(
        password: &str,
        iterations: u32,
        salt: &[u8],
    ) -> KeycloakCredential {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use hmac::Hmac;
        use pbkdf2::pbkdf2;
        use sha2::Sha256;

        let mut out = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut out)
            .expect("pbkdf2 derivation");

        let credential_data = format!(
            "{{\"hashIterations\":{iterations},\"algorithm\":\"pbkdf2-sha256\",\
             \"additionalParameters\":{{}}}}"
        );
        let secret_data = format!(
            "{{\"value\":\"{}\",\"salt\":\"{}\",\"additionalParameters\":{{}}}}",
            STANDARD.encode(out),
            STANDARD.encode(salt),
        );

        KeycloakCredential {
            kind: "password".to_string(),
            credential_data: Some(credential_data),
            secret_data: Some(secret_data),
            created_date: Some(1_700_000_000_000),
        }
    }

    #[test]
    fn parses_pbkdf2_sha256_and_round_trips_through_verifier() {
        let cred = make_keycloak_credential("hunter2", 27_500, b"sixteen-byte-sal");

        let parsed = parse_keycloak_credential(&cred).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Pbkdf2Sha256);
        assert!(parsed.phc_string.starts_with("$pbkdf2-sha256$i=27500$"));

        let stored = StoredCredential {
            algorithm: PasswordAlgorithm::Pbkdf2Sha256,
            hash: parsed.phc_string,
            created_at: 0,
        };
        let ok = verify_password(
            &CleartextPassword::from_string("hunter2".to_string()),
            &stored,
        )
        .expect("verify");
        assert!(ok, "the PHC string produced by the parser must verify");
    }

    #[test]
    fn rejects_pbkdf2_sha512_as_unsupported() {
        let cred = KeycloakCredential {
            kind: "password".to_string(),
            credential_data: Some(
                "{\"hashIterations\":210000,\"algorithm\":\"pbkdf2-sha512\"}".to_string(),
            ),
            secret_data: Some("{\"value\":\"AAAA\",\"salt\":\"BBBB\"}".to_string()),
            created_date: None,
        };

        match parse_keycloak_credential(&cred) {
            Err(MigrationError::UnsupportedAlgorithm { algorithm }) => {
                assert_eq!(algorithm, "pbkdf2-sha512");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_password_credential_kind() {
        let cred = KeycloakCredential {
            kind: "otp".to_string(),
            credential_data: None,
            secret_data: None,
            created_date: None,
        };

        assert!(matches!(
            parse_keycloak_credential(&cred),
            Err(MigrationError::ParseError { .. })
        ));
    }

    #[test]
    fn rejects_missing_secret_data() {
        let cred = KeycloakCredential {
            kind: "password".to_string(),
            credential_data: Some(
                "{\"hashIterations\":1,\"algorithm\":\"pbkdf2-sha256\"}".to_string(),
            ),
            secret_data: None,
            created_date: None,
        };

        assert!(matches!(
            parse_keycloak_credential(&cred),
            Err(MigrationError::ParseError { .. })
        ));
    }

    #[test]
    fn strips_base64_padding_from_salt_and_value() {
        // Salt encodes a length that produces `=` padding in base64.
        let cred = make_keycloak_credential("correcthorse", 10_000, b"short");
        let parsed = parse_keycloak_credential(&cred).expect("parse");
        // The PHC string must not contain padding characters in the
        // salt/hash segments.
        let segments: Vec<&str> = parsed.phc_string.split('$').collect();
        assert_eq!(segments.len(), 5, "expected 4-segment PHC string");
        assert!(
            !segments[3].contains('='),
            "salt segment should have no padding: {}",
            segments[3]
        );
        assert!(
            !segments[4].contains('='),
            "hash segment should have no padding: {}",
            segments[4]
        );
    }
}
