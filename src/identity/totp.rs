//! TOTP (Time-based One-Time Password) implementation per RFC 6238.
//!
//! Provides TOTP secret generation, code computation/validation with ±1
//! window tolerance, provisioning URI generation (for authenticator apps),
//! and single-use recovery code generation with Argon2id hashing.

use std::fmt;

use ring::hmac;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::credentials::{self, CredentialConfig};
use crate::identity::error::IdentityError;

/// TOTP period in seconds (RFC 6238 default).
const TOTP_PERIOD: u64 = 30;

/// Number of digits in a TOTP code (RFC 6238 default).
const TOTP_DIGITS: u32 = 6;

/// Validation window: accept codes for T-1 and T+1 in addition to T.
const TOTP_WINDOW: u64 = 1;

/// Number of recovery codes generated during MFA enrollment.
const RECOVERY_CODE_COUNT: usize = 8;

/// Length of each recovery code (characters).
const RECOVERY_CODE_LENGTH: usize = 8;

/// Character set for recovery codes — excludes confusable characters (0, O, 1, I).
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A 20-byte TOTP secret that is zeroed from memory on drop.
///
/// **Security**: Intentionally does NOT implement `Display` or content-revealing
/// `Debug`. The `Debug` impl prints a redacted placeholder.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct TotpSecret {
    bytes: [u8; 20],
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(***)")
    }
}

impl TotpSecret {
    /// Generates a new random 20-byte TOTP secret.
    pub(crate) fn generate() -> Result<Self, IdentityError> {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate TOTP secret".to_string(),
            })?;
        Ok(Self { bytes })
    }

    /// Creates a `TotpSecret` from a base32-encoded string (for testing/restore).
    pub(crate) fn from_base32(encoded: &str) -> Result<Self, IdentityError> {
        let decoded = data_encoding::BASE32_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid base32 TOTP secret: {e}"),
            })?;
        if decoded.len() != 20 {
            return Err(IdentityError::InvalidInput {
                reason: format!("TOTP secret must be 20 bytes, got {}", decoded.len()),
            });
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }

    /// Returns the secret as a base32-encoded string (no padding).
    pub(crate) fn to_base32(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(&self.bytes)
    }

    /// Returns the raw secret bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Persisted MFA state for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredMfaState {
    /// Base32-encoded TOTP secret.
    pub secret_base32: String,
    /// Whether MFA has been verified and is active.
    pub enabled: bool,
    /// Argon2id hashes of recovery codes (empty slots = `None`).
    pub recovery_code_hashes: Vec<Option<String>>,
    /// The last TOTP time step that was successfully used (replay protection).
    pub last_used_step: Option<u64>,
    /// When MFA was enabled (Unix microseconds), if enabled.
    pub enabled_at: Option<i64>,
    /// Plaintext recovery codes held during the pending enrollment window.
    ///
    /// Present only while `enabled == false`. Hashed and moved to
    /// `recovery_code_hashes` when the user confirms enrollment via
    /// `verify_totp_enrollment()`, then cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_recovery_codes: Option<Vec<String>>,
}

/// Plaintext recovery codes returned once at enrollment.
///
/// **Security**: Each code's memory is zeroed on drop. Does NOT implement
/// `Debug`, `Display`, `Serialize`, or `Clone` — the only way to observe
/// the codes is to call `iter()` or `as_slice()`, which forces callers to
/// render them at a single, auditable site.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCodes {
    codes: Vec<String>,
}

impl RecoveryCodes {
    /// Wraps a vector of plaintext recovery codes.
    pub(crate) fn new(codes: Vec<String>) -> Self {
        Self { codes }
    }

    /// Returns the codes as a slice for iteration.
    pub fn as_slice(&self) -> &[String] {
        &self.codes
    }

    /// Returns the number of recovery codes.
    pub fn len(&self) -> usize {
        self.codes.len()
    }

    /// Returns `true` if there are no recovery codes.
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// Iterates over the plaintext recovery codes.
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.codes.iter()
    }
}

impl<'a> IntoIterator for &'a RecoveryCodes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.codes.iter()
    }
}

impl fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodes")
            .field("count", &self.codes.len())
            .field("codes", &"[REDACTED]")
            .finish()
    }
}

/// Returned once during MFA enrollment — contains the plaintext recovery codes.
///
/// **Security**: Recovery codes are shown exactly once. After enrollment,
/// only their Argon2id hashes are stored. The `recovery_codes` field is
/// wrapped in [`RecoveryCodes`] to zero the plaintext on drop.
pub struct TotpEnrollment {
    /// Base32-encoded TOTP secret for manual entry.
    pub secret_base32: String,
    /// `otpauth://` URI for QR code scanning.
    pub provisioning_uri: String,
    /// Plaintext recovery codes (shown once).
    pub recovery_codes: RecoveryCodes,
}

impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("secret_base32", &"[REDACTED]")
            .field("provisioning_uri", &"[REDACTED]")
            .field("recovery_codes", &"[REDACTED]")
            .finish()
    }
}

/// Generates a provisioning URI for authenticator apps.
///
/// Format: `otpauth://totp/{issuer}:{account}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30`
pub(crate) fn generate_provisioning_uri(
    secret_base32: &str,
    account: &str,
    issuer: &str,
) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )
}

/// Computes a TOTP code for the given secret and time step.
///
/// Implements RFC 4226 dynamic truncation on HMAC-SHA1 output.
pub(crate) fn compute_totp(secret: &[u8], time_step: u64) -> String {
    // HMAC-SHA1(secret, time_step as 8-byte big-endian)
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let msg = time_step.to_be_bytes();
    let tag = hmac::sign(&key, &msg);
    let hash = tag.as_ref();

    // Dynamic truncation (RFC 4226 §5.4)
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);

    let otp = binary % 10u32.pow(TOTP_DIGITS);
    format!("{otp:0>width$}", width = TOTP_DIGITS as usize)
}

/// Validates a TOTP code against a secret at the given Unix timestamp.
///
/// Checks the current time step and ±`TOTP_WINDOW` adjacent steps.
/// Returns `Some(matching_step)` if valid, `None` if no match.
pub(crate) fn validate_totp(
    secret: &[u8],
    code: &str,
    unix_secs: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let current_step = unix_secs / TOTP_PERIOD;

    // Check T-window through T+window
    let start = current_step.saturating_sub(TOTP_WINDOW);
    let end = current_step + TOTP_WINDOW;

    for step in start..=end {
        // Replay protection: reject steps already used
        if let Some(last) = last_used_step {
            if step <= last {
                continue;
            }
        }
        if compute_totp(secret, step) == code {
            return Some(step);
        }
    }
    None
}

/// Generates `RECOVERY_CODE_COUNT` unique recovery codes.
///
/// Each code is `RECOVERY_CODE_LENGTH` characters from `RECOVERY_ALPHABET`
/// (28 chars: A-Z minus I/O, 2-9 minus 0/1).
pub(crate) fn generate_recovery_codes() -> Result<Vec<String>, IdentityError> {
    let rng = ring::rand::SystemRandom::new();
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);

    for _ in 0..RECOVERY_CODE_COUNT {
        let mut buf = [0u8; RECOVERY_CODE_LENGTH];
        rng.fill(&mut buf)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate recovery code entropy".to_string(),
            })?;

        let code: String = buf
            .iter()
            .map(|&b| {
                let idx = (b as usize) % RECOVERY_ALPHABET.len();
                RECOVERY_ALPHABET[idx] as char
            })
            .collect();
        codes.push(code);
    }

    Ok(codes)
}

/// Hashes recovery codes using Argon2id in parallel.
///
/// Spawns one thread per code inside `std::thread::scope` so all hashes
/// run concurrently. Because each Argon2id invocation is memory-bound
/// (~19 MiB), parallel instances don't contend on CPU cores, reducing
/// wall-clock time from N × ~1s to ~1s regardless of code count.
///
/// # Panics
///
/// Propagates any panic from a spawned hashing thread.
pub(crate) fn hash_recovery_codes(
    codes: &[String],
    config: &CredentialConfig,
) -> Result<Vec<Option<String>>, IdentityError> {
    std::thread::scope(|s| {
        let handles: Vec<_> = codes
            .iter()
            .map(|code| {
                s.spawn(|| {
                    let hash = credentials::hash_raw_secret(code.as_bytes(), config)?;
                    Ok(Some(hash))
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().expect("recovery code hash thread panicked"))
            .collect()
    })
}

/// Verifies a recovery code against stored hashes, returning the index if found.
///
/// On success, the caller should set that index to `None` to mark it used.
pub(crate) fn verify_recovery_code(
    code: &str,
    hashes: &[Option<String>],
) -> Result<Option<usize>, IdentityError> {
    for (i, slot) in hashes.iter().enumerate() {
        if let Some(hash) = slot {
            if credentials::verify_raw_secret(code.as_bytes(), hash)? {
                return Ok(Some(i));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Scenario A1: Provisioning URI generation =====

    #[test]
    fn generate_totp_secret_with_correct_provisioning_uri() {
        let secret = TotpSecret::generate().expect("generate");
        let base32 = secret.to_base32();

        // Base32 of 20 bytes = 32 chars (no padding)
        assert_eq!(
            base32.len(),
            32,
            "base32 encoding of 20 bytes should be 32 chars"
        );

        // Roundtrip
        let restored = TotpSecret::from_base32(&base32).expect("from_base32");
        assert_eq!(restored.as_bytes(), secret.as_bytes());

        // Provisioning URI format
        let uri = generate_provisioning_uri(&base32, "user@example.com", "Hearth");
        assert!(
            uri.starts_with("otpauth://totp/Hearth:user@example.com?"),
            "URI should start with otpauth://totp/issuer:account, got: {uri}"
        );
        assert!(
            uri.contains(&format!("secret={base32}")),
            "URI must contain secret"
        );
        assert!(uri.contains("issuer=Hearth"), "URI must contain issuer");
        assert!(uri.contains("algorithm=SHA1"), "URI must specify SHA1");
        assert!(uri.contains("digits=6"), "URI must specify 6 digits");
        assert!(uri.contains("period=30"), "URI must specify 30s period");
    }

    // ===== Scenario A2: TOTP code validation (known test vector) =====

    #[test]
    fn validate_totp_code_for_current_time_window_succeeds() {
        // RFC 6238 test vector: secret = "12345678901234567890" (ASCII)
        // Time = 59 → step = 1
        let secret = b"12345678901234567890";
        let code = compute_totp(secret, 1); // step 1 = time 30..59

        // The code should be a 6-digit string
        assert_eq!(code.len(), 6, "TOTP code should be 6 digits");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "TOTP code should be all digits: {code}"
        );

        // Known value: RFC 6238 Appendix B, T=1 → 287082
        assert_eq!(code, "287082", "RFC 6238 test vector for step 1");

        // Validate at exact time (step=1 corresponds to 30..59)
        let matched = validate_totp(secret, &code, 59, None);
        assert_eq!(matched, Some(1), "should match step 1 at time=59");
    }

    // ===== Scenario A3: Time window tolerance =====

    #[test]
    fn totp_time_window_tolerance_t_minus1_and_t_plus1_accepted() {
        let secret = b"12345678901234567890";
        let current_time = 90; // step = 3

        // Code for step 3 (current)
        let code_current = compute_totp(secret, 3);
        let matched = validate_totp(secret, &code_current, current_time, None);
        assert!(matched.is_some(), "current step code should validate");

        // Code for step 2 (T-1) — should be accepted within window
        let code_prev = compute_totp(secret, 2);
        let matched = validate_totp(secret, &code_prev, current_time, None);
        assert_eq!(matched, Some(2), "T-1 code should be accepted");

        // Code for step 4 (T+1) — should be accepted within window
        let code_next = compute_totp(secret, 4);
        let matched = validate_totp(secret, &code_next, current_time, None);
        assert_eq!(matched, Some(4), "T+1 code should be accepted");

        // Code for step 1 (T-2) — should be rejected
        let code_old = compute_totp(secret, 1);
        let matched = validate_totp(secret, &code_old, current_time, None);
        assert!(matched.is_none(), "T-2 code should be rejected");

        // Code for step 5 (T+2) — should be rejected
        let code_far = compute_totp(secret, 5);
        let matched = validate_totp(secret, &code_far, current_time, None);
        assert!(matched.is_none(), "T+2 code should be rejected");
    }

    // ===== Scenario B1: Recovery code generation =====

    #[test]
    fn generate_recovery_codes_correct_count_entropy_uniqueness() {
        let codes = generate_recovery_codes().expect("generate");

        // 8 codes
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT, "should generate 8 codes");

        for code in &codes {
            // Each 8 chars
            assert_eq!(
                code.len(),
                RECOVERY_CODE_LENGTH,
                "each code should be {RECOVERY_CODE_LENGTH} chars"
            );

            // All chars from RECOVERY_ALPHABET (no confusable 0, O, 1, I)
            for ch in code.chars() {
                assert!(
                    RECOVERY_ALPHABET.contains(&(ch as u8)),
                    "char '{ch}' should be in recovery alphabet"
                );
            }

            // No confusable characters
            assert!(!code.contains('0'), "must not contain 0");
            assert!(!code.contains('O'), "must not contain O");
            assert!(!code.contains('1'), "must not contain 1");
            assert!(!code.contains('I'), "must not contain I");
        }

        // All unique
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "all recovery codes should be unique"
        );
    }

    // ===== Scenario B2: Recovery code redemption =====

    #[test]
    fn recovery_code_redemption_valid_succeeds_reused_rejected() {
        let codes = generate_recovery_codes().expect("generate");
        let config = CredentialConfig::fast_for_testing();

        // Hash all codes
        let mut hashes = hash_recovery_codes(&codes, &config).expect("hash");

        // Verify first code succeeds
        let idx = verify_recovery_code(&codes[0], &hashes).expect("verify");
        assert_eq!(idx, Some(0), "first code should match index 0");

        // Mark as used (set slot to None)
        hashes[0] = None;

        // Same code should now fail
        let idx = verify_recovery_code(&codes[0], &hashes).expect("verify");
        assert!(idx.is_none(), "used code should not match");

        // Different code still works
        let idx = verify_recovery_code(&codes[1], &hashes).expect("verify");
        assert_eq!(idx, Some(1), "second code should still match");
    }

    // ===== Scenario E: Property test — TOTP time tolerance =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: TOTP code computed within ±30s validates,
            /// code computed at |offset| > 60s does not.
            #[test]
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
            fn totp_time_window_property(
                // Use a reasonable time range (year 2020 to 2030)
                base_time in 1_577_836_800u64..1_893_456_000u64,
                // Offset within one period (should validate)
                near_offset in 0u64..30u64,
                // Offset beyond two periods (should NOT validate)
                far_offset in 61u64..120u64,
            ) {
                let secret = b"12345678901234567890";

                // Near: code at base_time + near_offset should validate at base_time
                let near_time = base_time + near_offset;
                let code = compute_totp(secret, near_time / TOTP_PERIOD);
                let result = validate_totp(secret, &code, base_time, None);
                prop_assert!(result.is_some(), "near code should validate: base={base_time}, offset={near_offset}");

                // Far: code at base_time + far_offset should NOT validate at base_time
                let far_time = base_time + far_offset;
                let far_code = compute_totp(secret, far_time / TOTP_PERIOD);
                // Only assert rejection if the far code is actually for a different step range
                let far_step = far_time / TOTP_PERIOD;
                let current_step = base_time / TOTP_PERIOD;
                if far_step > current_step + TOTP_WINDOW {
                    let result = validate_totp(secret, &far_code, base_time, None);
                    prop_assert!(result.is_none(), "far code should NOT validate: base={base_time}, offset={far_offset}");
                }
            }
        }
    }

    // ===== TotpSecret Debug is redacted =====

    #[test]
    fn totp_secret_debug_is_redacted() {
        let secret = TotpSecret::generate().expect("generate");
        let debug = format!("{secret:?}");
        assert!(debug.contains("***"), "debug should be redacted: {debug}");
        assert!(
            !debug.contains(&secret.to_base32()),
            "debug must not reveal secret"
        );
    }

    // ===== TotpEnrollment Debug is redacted =====

    #[test]
    fn totp_enrollment_debug_is_redacted() {
        let enrollment = TotpEnrollment {
            secret_base32: "JBSWY3DPEHPK3PXP".to_string(),
            provisioning_uri: "otpauth://totp/test".to_string(),
            recovery_codes: RecoveryCodes::new(vec!["ABC123XY".to_string()]),
        };
        let debug = format!("{enrollment:?}");
        assert!(
            debug.contains("REDACTED"),
            "debug should show REDACTED: {debug}"
        );
        assert!(
            !debug.contains("JBSWY3DPEHPK3PXP"),
            "must not reveal secret"
        );
        assert!(
            !debug.contains("ABC123XY"),
            "must not reveal recovery codes"
        );
    }
}
