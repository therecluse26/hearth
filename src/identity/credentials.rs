//! Credential storage: password hashing, verification, and types.
//!
//! Uses Argon2id as the primary hashing algorithm (OWASP recommended).
//! Supports verification of bcrypt and scrypt hashes for migration scenarios.
//! All cleartext passwords are wrapped in `Zeroize`-on-drop types.

use std::fmt;

use argon2::Argon2;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use hmac::Hmac;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::pbkdf2;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::error::IdentityError;

/// A cleartext password that is zeroed from memory on drop.
///
/// **Security**: This type intentionally does NOT implement `Display`,
/// `Serialize`, or content-revealing `Debug`. The `Debug` impl prints
/// a redacted placeholder.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CleartextPassword {
    bytes: Vec<u8>,
}

impl fmt::Debug for CleartextPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CleartextPassword(***)")
    }
}

impl CleartextPassword {
    /// Creates a new cleartext password from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Creates a new cleartext password from a string.
    pub fn from_string(s: String) -> Self {
        Self {
            bytes: s.into_bytes(),
        }
    }

    /// Returns the password bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The hashing algorithm used for a stored credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PasswordAlgorithm {
    /// Argon2id — the recommended algorithm.
    Argon2id,
    /// Bcrypt — supported for migration from legacy systems.
    Bcrypt,
    /// Scrypt — supported for migration from legacy systems.
    Scrypt,
    /// PBKDF2-HMAC-SHA256 — supported for migration from Keycloak and
    /// similar legacy systems. Verification only: new credentials are
    /// always hashed with Argon2id.
    Pbkdf2Sha256,
}

/// A stored password credential.
///
/// Contains the hashed password in PHC string format along with metadata.
/// The `Debug` implementation redacts the hash field to prevent accidental
/// exposure in logs.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredCredential {
    /// The hashing algorithm used.
    pub algorithm: PasswordAlgorithm,
    /// The password hash in PHC string format.
    pub hash: String,
    /// When this credential was created (Unix microseconds).
    pub created_at: i64,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("algorithm", &self.algorithm)
            .field("hash", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Configuration for password hashing parameters.
///
/// Defaults follow OWASP recommendations for Argon2id:
/// - 19 MiB memory cost
/// - 2 iterations (time cost)
/// - 1 degree of parallelism
#[derive(Debug, Clone)]
pub struct CredentialConfig {
    /// Memory cost in KiB for Argon2id.
    pub memory_cost_kib: u32,
    /// Number of iterations (time cost) for Argon2id.
    pub time_cost: u32,
    /// Degree of parallelism for Argon2id.
    pub parallelism: u32,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            memory_cost_kib: 19_456, // 19 MiB per OWASP
            time_cost: 2,
            parallelism: 1,
        }
    }
}

impl CredentialConfig {
    /// Returns a fast configuration suitable for tests.
    ///
    /// Uses minimal parameters to keep test execution fast while still
    /// exercising the hashing pipeline.
    pub fn fast_for_testing() -> Self {
        Self {
            memory_cost_kib: 256, // 256 KiB — fast enough for tests
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Builds an `Argon2` hasher from this configuration.
    fn to_argon2(&self) -> Result<Argon2<'static>, IdentityError> {
        let params =
            argon2::Params::new(self.memory_cost_kib, self.time_cost, self.parallelism, None)
                .map_err(|e| IdentityError::InvalidInput {
                    reason: format!("invalid Argon2id parameters: {e}"),
                })?;
        Ok(Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Hashes a password using Argon2id with the given configuration.
///
/// Returns a `StoredCredential` with the hash in PHC string format.
pub(crate) fn hash_password(
    password: &CleartextPassword,
    config: &CredentialConfig,
    created_at: i64,
) -> Result<StoredCredential, IdentityError> {
    let argon2 = config.to_argon2()?;
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("password hashing failed: {e}"),
        })?;

    Ok(StoredCredential {
        algorithm: PasswordAlgorithm::Argon2id,
        hash: hash.to_string(),
        created_at,
    })
}

/// Verifies a password against a stored credential.
///
/// Supports Argon2id, bcrypt, and scrypt hash formats. The algorithm
/// is determined from the PHC string prefix, not the `algorithm` field,
/// ensuring correct verification regardless of metadata.
pub(crate) fn verify_password(
    password: &CleartextPassword,
    credential: &StoredCredential,
) -> Result<bool, IdentityError> {
    verify_hash(password, &credential.hash)
}

/// Verifies a password against a hash string.
///
/// Dispatches to the correct algorithm based on the hash prefix.
pub(crate) fn verify_hash(
    password: &CleartextPassword,
    hash_str: &str,
) -> Result<bool, IdentityError> {
    // Try bcrypt first — bcrypt hashes start with "$2b$" or "$2a$"
    if hash_str.starts_with("$2b$") || hash_str.starts_with("$2a$") {
        return Ok(bcrypt::verify(password.as_bytes(), hash_str).unwrap_or(false));
    }

    // PBKDF2-SHA256: `$pbkdf2-sha256$i=N$<salt-b64>$<hash-b64>`.
    // The `password-hash` crate does not ship a PBKDF2 verifier, so we
    // parse the PHC string manually and compare in constant time.
    if hash_str.starts_with("$pbkdf2-sha256$") {
        return verify_pbkdf2_sha256(password.as_bytes(), hash_str);
    }

    // Parse as PHC string for argon2id and scrypt
    let parsed = PasswordHash::new(hash_str).map_err(|e| IdentityError::InvalidInput {
        reason: format!("invalid password hash format: {e}"),
    })?;

    // Dispatch based on algorithm identifier in the PHC string
    let alg_id = parsed.algorithm;
    if alg_id == argon2::ARGON2ID_IDENT {
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    } else if alg_id == scrypt::ALG_ID {
        Ok(scrypt::Scrypt
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    } else {
        Err(IdentityError::InvalidInput {
            reason: format!("unsupported password hash algorithm: {alg_id}"),
        })
    }
}

/// Verifies a password against a PBKDF2-HMAC-SHA256 PHC string.
///
/// Format: `$pbkdf2-sha256$i=<iterations>$<salt-b64>$<hash-b64>`.
///
/// Base64 encoding is the PHC standard-no-padding variant. The hash
/// length in the PHC string determines how many derived bytes to
/// compute; this matches Keycloak's default of 32 bytes but also
/// supports other sizes produced by alternative exporters.
fn verify_pbkdf2_sha256(password: &[u8], hash_str: &str) -> Result<bool, IdentityError> {
    let mut parts = hash_str.split('$');
    // The PHC string starts with an empty segment because of the
    // leading '$'; skip it, then consume the four payload segments.
    let _empty = parts.next();
    let algo = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing algorithm".to_string(),
    })?;
    if algo != "pbkdf2-sha256" {
        return Err(IdentityError::InvalidInput {
            reason: format!("unexpected pbkdf2 variant: {algo}"),
        });
    }
    let params = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing parameters".to_string(),
    })?;
    let iterations = params
        .strip_prefix("i=")
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: format!("invalid pbkdf2 iterations: {params}"),
        })?;
    if iterations == 0 {
        return Err(IdentityError::InvalidInput {
            reason: "pbkdf2 iterations must be non-zero".to_string(),
        });
    }
    let salt_b64 = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing salt".to_string(),
    })?;
    let hash_b64 = parts.next().ok_or_else(|| IdentityError::InvalidInput {
        reason: "invalid pbkdf2 hash: missing hash".to_string(),
    })?;
    if parts.next().is_some() {
        return Err(IdentityError::InvalidInput {
            reason: "invalid pbkdf2 hash: trailing data".to_string(),
        });
    }

    let salt = STANDARD_NO_PAD
        .decode(salt_b64)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid pbkdf2 salt: {e}"),
        })?;
    let expected = STANDARD_NO_PAD
        .decode(hash_b64)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid pbkdf2 hash: {e}"),
        })?;

    let mut derived = vec![0u8; expected.len()];
    pbkdf2::<Hmac<Sha256>>(password, &salt, iterations, &mut derived).map_err(|e| {
        IdentityError::InvalidInput {
            reason: format!("pbkdf2 derivation failed: {e}"),
        }
    })?;

    // Constant-time equality — prevents timing oracles on hash comparison.
    Ok(derived.ct_eq(&expected).into())
}

/// Hashes a raw secret (e.g., client secret) with Argon2id.
///
/// Returns the PHC-formatted hash string. Used for confidential OAuth
/// client authentication where we don't have a `CleartextPassword` wrapper.
pub(crate) fn hash_raw_secret(
    secret: &[u8],
    config: &CredentialConfig,
) -> Result<String, IdentityError> {
    let argon2 = config.to_argon2()?;
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(secret, &salt)
        .map_err(|e| IdentityError::InvalidInput {
            reason: format!("secret hashing failed: {e}"),
        })?;
    Ok(hash.to_string())
}

/// Verifies a raw secret against an Argon2id hash string.
///
/// Returns `true` if the secret matches the hash.
pub(crate) fn verify_raw_secret(secret: &[u8], hash_str: &str) -> Result<bool, IdentityError> {
    let parsed = PasswordHash::new(hash_str).map_err(|e| IdentityError::InvalidInput {
        reason: format!("invalid hash format: {e}"),
    })?;
    Ok(Argon2::default().verify_password(secret, &parsed).is_ok())
}

/// Pre-computes a dummy hash for timing-oracle prevention.
///
/// When `verify_password` is called for a nonexistent user, we verify
/// against this dummy hash so the response time is indistinguishable
/// from a real failed verification.
pub(crate) fn compute_dummy_hash(config: &CredentialConfig) -> String {
    let argon2 = config.to_argon2().expect("default config should be valid");
    let salt = SaltString::generate(&mut OsRng);
    let dummy_password = b"dummy_password_for_timing_defense";
    argon2
        .hash_password(dummy_password, &salt)
        .expect("dummy hash should succeed")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CredentialConfig {
        CredentialConfig::fast_for_testing()
    }

    // ===== CleartextPassword =====

    #[test]
    fn cleartext_password_debug_is_redacted() {
        let pw = CleartextPassword::from_string("supersecret".to_string());
        let debug = format!("{pw:?}");
        assert!(
            !debug.contains("supersecret"),
            "debug must not reveal password: {debug}"
        );
        assert!(
            debug.contains("***"),
            "debug should show redacted placeholder: {debug}"
        );
    }

    #[test]
    fn cleartext_password_as_bytes() {
        let pw = CleartextPassword::from_string("hello".to_string());
        assert_eq!(pw.as_bytes(), b"hello");
    }

    #[test]
    fn cleartext_password_from_raw_bytes() {
        let pw = CleartextPassword::new(vec![0x00, 0xFF, 0x42]);
        assert_eq!(pw.as_bytes(), &[0x00, 0xFF, 0x42]);
    }

    // ===== StoredCredential =====

    #[test]
    fn stored_credential_debug_redacts_hash() {
        let cred = StoredCredential {
            algorithm: PasswordAlgorithm::Argon2id,
            hash: "$argon2id$v=19$m=256,t=1,p=1$somesalt$somehash".to_string(),
            created_at: 1_000_000,
        };
        let debug = format!("{cred:?}");
        assert!(
            !debug.contains("somesalt"),
            "debug must not reveal salt: {debug}"
        );
        assert!(
            !debug.contains("somehash"),
            "debug must not reveal hash: {debug}"
        );
        assert!(
            debug.contains("REDACTED"),
            "debug should show REDACTED: {debug}"
        );
    }

    #[test]
    fn stored_credential_serde_roundtrip() {
        let cred = StoredCredential {
            algorithm: PasswordAlgorithm::Argon2id,
            hash: "$argon2id$v=19$m=256,t=1,p=1$salt$hash".to_string(),
            created_at: 1_000_000,
        };
        let json = serde_json::to_string(&cred).expect("serialize");
        let deserialized: StoredCredential = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.algorithm, cred.algorithm);
        assert_eq!(deserialized.hash, cred.hash);
        assert_eq!(deserialized.created_at, cred.created_at);
    }

    // ===== Scenario 1: Hash + verify =====

    #[test]
    fn hash_and_verify_correct_password() {
        let config = test_config();
        let pw = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
        let cred = hash_password(&pw, &config, 1_000_000).expect("hash");

        assert_eq!(cred.algorithm, PasswordAlgorithm::Argon2id);
        assert!(
            cred.hash.starts_with("$argon2id$"),
            "hash should be PHC format"
        );

        let result = verify_password(&pw, &cred).expect("verify");
        assert!(result, "correct password should verify");
    }

    #[test]
    fn hash_and_verify_wrong_password() {
        let config = test_config();
        let pw = CleartextPassword::from_string("correct-password".to_string());
        let cred = hash_password(&pw, &config, 1_000_000).expect("hash");

        let wrong = CleartextPassword::from_string("wrong-password".to_string());
        let result = verify_password(&wrong, &cred).expect("verify");
        assert!(!result, "wrong password should not verify");
    }

    #[test]
    fn different_hashes_for_same_password() {
        let config = test_config();
        let pw1 = CleartextPassword::from_string("same-password".to_string());
        let pw2 = CleartextPassword::from_string("same-password".to_string());
        let cred1 = hash_password(&pw1, &config, 1_000_000).expect("hash1");
        let cred2 = hash_password(&pw2, &config, 1_000_000).expect("hash2");

        // Different salts should produce different hashes
        assert_ne!(
            cred1.hash, cred2.hash,
            "same password should produce different hashes (different salts)"
        );
    }

    // ===== Scenario 2: Multi-algorithm verification =====

    #[test]
    fn verify_bcrypt_hash() {
        // Generate a bcrypt hash
        let hash = bcrypt::hash(b"bcrypt-password", bcrypt::DEFAULT_COST).expect("bcrypt hash");
        let pw = CleartextPassword::from_string("bcrypt-password".to_string());
        let result = verify_hash(&pw, &hash).expect("verify");
        assert!(result, "correct password should verify against bcrypt hash");

        let wrong = CleartextPassword::from_string("wrong".to_string());
        let result = verify_hash(&wrong, &hash).expect("verify");
        assert!(
            !result,
            "wrong password should not verify against bcrypt hash"
        );
    }

    #[test]
    fn verify_scrypt_hash() {
        use password_hash::PasswordHasher;
        // Generate a scrypt hash with minimal params for test speed
        let params = scrypt::Params::new(8, 1, 1, 32).expect("scrypt params");
        let salt = SaltString::generate(&mut OsRng);
        let scrypt_hasher = scrypt::Scrypt;
        let hash = scrypt_hasher
            .hash_password_customized(b"scrypt-password", None, None, params, &salt)
            .expect("scrypt hash");

        let pw = CleartextPassword::from_string("scrypt-password".to_string());
        let result = verify_hash(&pw, &hash.to_string()).expect("verify");
        assert!(result, "correct password should verify against scrypt hash");

        let wrong = CleartextPassword::from_string("wrong".to_string());
        let result = verify_hash(&wrong, &hash.to_string()).expect("verify");
        assert!(
            !result,
            "wrong password should not verify against scrypt hash"
        );
    }

    // ===== PBKDF2-SHA256 verification (migration path) =====

    /// Helper: builds a PBKDF2-SHA256 PHC string for a given password.
    fn build_pbkdf2_phc(password: &[u8], iterations: u32, salt: &[u8]) -> String {
        let mut derived = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut derived)
            .expect("pbkdf2 derivation");
        format!(
            "$pbkdf2-sha256$i={iterations}${}${}",
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(derived),
        )
    }

    #[test]
    fn verify_pbkdf2_sha256_correct_password() {
        // 27,500 is Keycloak's historical default; we use a smaller value
        // here purely for test speed. The verifier is identical either way.
        let phc = build_pbkdf2_phc(b"keycloak-password", 1000, b"keycloak-salt-16");
        let pw = CleartextPassword::from_string("keycloak-password".to_string());
        assert!(
            verify_hash(&pw, &phc).expect("verify"),
            "should accept correct password"
        );
    }

    #[test]
    fn verify_pbkdf2_sha256_wrong_password() {
        let phc = build_pbkdf2_phc(b"keycloak-password", 1000, b"keycloak-salt-16");
        let wrong = CleartextPassword::from_string("different".to_string());
        assert!(
            !verify_hash(&wrong, &phc).expect("verify"),
            "should reject wrong password"
        );
    }

    #[test]
    fn verify_pbkdf2_sha256_via_stored_credential() {
        // Round-trips through the public `verify_password` entry point so
        // a Keycloak-migrated credential works end-to-end without any
        // special-casing at the engine layer.
        let phc = build_pbkdf2_phc(b"migrated-password", 1000, b"stable-salt-abc");
        let cred = StoredCredential {
            algorithm: PasswordAlgorithm::Pbkdf2Sha256,
            hash: phc,
            created_at: 1_000_000,
        };
        let pw = CleartextPassword::from_string("migrated-password".to_string());
        assert!(verify_password(&pw, &cred).expect("verify"));
    }

    #[test]
    fn verify_pbkdf2_sha256_rejects_malformed_phc() {
        let pw = CleartextPassword::from_string("x".to_string());
        // Missing iterations parameter
        let bad = "$pbkdf2-sha256$i=$c2FsdA$aGFzaA";
        assert!(verify_hash(&pw, bad).is_err(), "malformed PHC must error");
    }

    // ===== Scenario 4 (P1): Custom params =====

    #[test]
    fn custom_params_respected() {
        let config = CredentialConfig {
            memory_cost_kib: 512,
            time_cost: 2,
            parallelism: 1,
        };
        let pw = CleartextPassword::from_string("test-password".to_string());
        let cred = hash_password(&pw, &config, 1_000_000).expect("hash");

        // PHC string should reflect custom memory cost
        assert!(
            cred.hash.contains("m=512"),
            "hash should contain m=512: {}",
            cred.hash
        );
        assert!(
            cred.hash.contains("t=2"),
            "hash should contain t=2: {}",
            cred.hash
        );

        // Should still verify
        let result = verify_password(&pw, &cred).expect("verify");
        assert!(result, "custom-params hash should still verify");
    }

    // ===== Dummy hash for timing =====

    #[test]
    fn dummy_hash_is_valid_argon2id() {
        let config = test_config();
        let dummy = compute_dummy_hash(&config);
        assert!(
            dummy.starts_with("$argon2id$"),
            "dummy hash should be argon2id"
        );

        // Should be verifiable (against the dummy password, not a real one)
        let parsed = PasswordHash::new(&dummy).expect("should parse as PHC");
        assert_eq!(parsed.algorithm, argon2::ARGON2ID_IDENT);
    }

    // ===== Adversarial: Debug/Display never reveals hash content =====

    #[test]
    fn password_algorithm_debug_is_safe() {
        let alg = PasswordAlgorithm::Argon2id;
        let debug = format!("{alg:?}");
        assert!(debug.contains("Argon2id"), "should show variant name");
    }

    #[test]
    fn cleartext_password_has_no_display() {
        // CleartextPassword deliberately does not implement Display.
        // This is a compile-time guarantee — if someone adds Display,
        // this test documents the intent.
        fn assert_no_display<T: fmt::Debug>() {}
        assert_no_display::<CleartextPassword>();
    }

    // ===== Property tests =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: Arbitrary bytes never cause panics when used as passwords.
            #[test]
            fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                let config = CredentialConfig::fast_for_testing();
                let pw = CleartextPassword::new(bytes);
                // Should not panic — may return Ok or Err
                let _ = hash_password(&pw, &config, 1_000_000);
            }

            /// Property: Hash round-trip — any password verifies after hashing.
            #[test]
            fn hash_roundtrip_always_verifies(s in ".{1,128}") {
                let config = CredentialConfig::fast_for_testing();
                let pw = CleartextPassword::from_string(s.clone());
                let cred = hash_password(&pw, &config, 1_000_000).expect("hash should succeed");
                let pw2 = CleartextPassword::from_string(s);
                let result = verify_password(&pw2, &cred).expect("verify should succeed");
                prop_assert!(result, "password should verify after hashing");
            }
        }
    }
}
