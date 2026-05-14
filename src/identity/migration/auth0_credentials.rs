//! Convert Auth0 `custom_password_hash` records into Hearth PHC strings.
//!
//! Auth0's bulk user-import schema (used by `POST /api/v2/jobs/users-imports`
//! and, when available, the bulk-export pathway) represents a password hash
//! as:
//!
//! ```text
//! { "algorithm": "bcrypt", "hash": { "value": "$2a$10$..." } }
//! ```
//!
//! The interesting observation is that for the algorithms Hearth's
//! `verify_hash` already recognises — bcrypt, argon2, pbkdf2-sha256 —
//! Auth0's `hash.value` **is already** a PHC string. So this module is
//! mostly a prefix-check passthrough, with `UnsupportedAlgorithm` errors
//! for md5, sha1, plain non-PHC scrypt, etc.
//!
//! This keeps the anti-corruption layer narrow: we don't re-derive or
//! re-encode, we just validate the shape and hand the existing PHC string
//! to the engine.
//!
//! For PHC-shaped strings we ignore the Auth0 `algorithm` field when it
//! disagrees with the PHC prefix (real Auth0 exports sometimes set
//! `"algorithm": "argon2"` with a `$2b$`-prefixed value, for instance).
//! The PHC prefix is the source of truth.

use crate::identity::credentials::PasswordAlgorithm;
use crate::identity::migration::auth0::Auth0PasswordHash;
use crate::identity::migration::error::MigrationError;

/// Parsed output of an Auth0 `custom_password_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuth0Credential {
    /// Resolved `PasswordAlgorithm` in Hearth's taxonomy.
    pub algorithm: PasswordAlgorithm,
    /// PHC-formatted hash string accepted by `credentials::verify_hash`.
    pub phc_string: String,
}

/// Converts an Auth0 password-hash record into Hearth's PHC representation.
///
/// Recognised inputs:
/// - **bcrypt**: `hash.value` starts with `$2a$`, `$2b$`, or `$2y$`.
/// - **argon2**: `hash.value` starts with `$argon2` (any variant — Hearth's
///   verifier accepts `argon2id`; `argon2i`/`argon2d` will fail verification
///   at login time, which is fine for migration scenarios).
/// - **pbkdf2-sha256**: `hash.value` starts with `$pbkdf2-sha256$`.
/// - **scrypt (PHC)**: `hash.value` starts with `$scrypt$`.
///
/// Anything else — md5, sha1, plain non-PHC scrypt parameter dumps,
/// unknown algorithm names — returns [`MigrationError::UnsupportedAlgorithm`]
/// so the caller can surface a per-user warning and import the user with
/// `credential: None`.
///
/// The `hash.value` being empty or missing is a structural error and
/// returns [`MigrationError::ParseError`] so the caller can decide whether
/// to skip the user entirely or just the credential.
pub fn parse_auth0_credential(
    cred: &Auth0PasswordHash,
) -> Result<ParsedAuth0Credential, MigrationError> {
    let value = cred.hash.value.trim();
    if value.is_empty() {
        return Err(MigrationError::ParseError {
            reason: "custom_password_hash.hash.value is empty".to_string(),
        });
    }

    if value.starts_with("$2a$") || value.starts_with("$2b$") || value.starts_with("$2y$") {
        return Ok(ParsedAuth0Credential {
            algorithm: PasswordAlgorithm::Bcrypt,
            phc_string: value.to_string(),
        });
    }

    if value.starts_with("$argon2") {
        return Ok(ParsedAuth0Credential {
            algorithm: PasswordAlgorithm::Argon2id,
            phc_string: value.to_string(),
        });
    }

    if value.starts_with("$pbkdf2-sha256$") {
        return Ok(ParsedAuth0Credential {
            algorithm: PasswordAlgorithm::Pbkdf2Sha256,
            phc_string: value.to_string(),
        });
    }

    if value.starts_with("$scrypt$") {
        return Ok(ParsedAuth0Credential {
            algorithm: PasswordAlgorithm::Scrypt,
            phc_string: value.to_string(),
        });
    }

    // Not a PHC shape we recognise. Echo the operator-declared algorithm
    // in the error so the warning is actionable.
    Err(MigrationError::UnsupportedAlgorithm {
        algorithm: cred.algorithm.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::migration::auth0::Auth0PasswordHashValue;

    fn cred(algo: &str, value: &str) -> Auth0PasswordHash {
        Auth0PasswordHash {
            algorithm: algo.to_string(),
            hash: Auth0PasswordHashValue {
                value: value.to_string(),
            },
        }
    }

    #[test]
    fn bcrypt_2a_prefix_is_passthrough() {
        let c = cred(
            "bcrypt",
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        );
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Bcrypt);
        assert!(parsed.phc_string.starts_with("$2a$"));
    }

    #[test]
    fn bcrypt_2b_prefix_is_passthrough() {
        let c = cred(
            "bcrypt",
            "$2b$04$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
        );
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Bcrypt);
    }

    #[test]
    fn bcrypt_2y_prefix_is_passthrough() {
        let c = cred(
            "bcrypt",
            "$2y$10$somethingsomethingsomething.abcdefghijklmno",
        );
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Bcrypt);
    }

    #[test]
    fn argon2_prefix_is_passthrough() {
        let c = cred("argon2", "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash");
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Argon2id);
    }

    #[test]
    fn pbkdf2_sha256_prefix_is_passthrough() {
        let c = cred("pbkdf2", "$pbkdf2-sha256$i=27500$c2FsdA$aGFzaA");
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Pbkdf2Sha256);
    }

    #[test]
    fn scrypt_phc_prefix_is_passthrough() {
        let c = cred("scrypt", "$scrypt$ln=14,r=8,p=1$c2FsdA$aGFzaA");
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Scrypt);
    }

    #[test]
    fn md5_returns_unsupported() {
        // deepcode ignore HardcodedNonCryptoSecret: algorithm-rejection test fixture — MD5 hash of "password"
        let c = cred("md5", "5f4dcc3b5aa765d61d8327deb882cf99");
        match parse_auth0_credential(&c) {
            Err(MigrationError::UnsupportedAlgorithm { algorithm }) => {
                assert_eq!(algorithm, "md5");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn sha1_returns_unsupported() {
        // deepcode ignore HardcodedNonCryptoSecret: algorithm-rejection test fixture — SHA-1 hash
        let c = cred("sha1", "7c4a8d09ca3762af61e59520943dc26494f8941b");
        assert!(matches!(
            parse_auth0_credential(&c),
            Err(MigrationError::UnsupportedAlgorithm { .. })
        ));
    }

    #[test]
    fn pbkdf2_sha512_not_phc_shape_returns_unsupported() {
        // Auth0 sometimes sets algorithm=pbkdf2 with a non-PHC value.
        // We don't attempt to reassemble — PHC-shape is the gate.
        let c = cred("pbkdf2", "rawhashbytes_nopad");
        assert!(matches!(
            parse_auth0_credential(&c),
            Err(MigrationError::UnsupportedAlgorithm { .. })
        ));
    }

    #[test]
    fn empty_hash_value_is_parse_error() {
        let c = cred("bcrypt", "");
        assert!(matches!(
            parse_auth0_credential(&c),
            Err(MigrationError::ParseError { .. })
        ));
    }

    #[test]
    fn whitespace_only_hash_is_parse_error() {
        let c = cred("bcrypt", "   \t\n ");
        assert!(matches!(
            parse_auth0_credential(&c),
            Err(MigrationError::ParseError { .. })
        ));
    }

    #[test]
    fn phc_prefix_wins_over_declared_algorithm() {
        // Real Auth0 exports are inconsistent about the `algorithm` field.
        // As long as the PHC prefix is recognisable, we trust it.
        let c = cred(
            "argon2",
            "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNopqrstu",
        );
        let parsed = parse_auth0_credential(&c).expect("parse");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Bcrypt);
    }
}
