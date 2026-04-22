//! Input validation and normalization for identity fields.
//!
//! All validation functions return `Result<String, IdentityError>` where
//! the `Ok` value is the normalized form of the input.

use unicode_normalization::UnicodeNormalization;

use crate::identity::error::IdentityError;
use crate::identity::types::PasswordPolicy;

/// Maximum length for an email address (RFC 5321).
const MAX_EMAIL_LENGTH: usize = 254;

/// Maximum length for a display name.
const MAX_DISPLAY_NAME_LENGTH: usize = 256;

/// Maximum length for a password in bytes.
///
/// Prevents CPU-based denial-of-service via extremely large inputs to Argon2id.
/// 1 KiB is generous for any reasonable password while capping cost.
const MAX_PASSWORD_LENGTH: usize = 1024;

/// Maximum length for an OAuth client name.
const MAX_CLIENT_NAME_LENGTH: usize = 256;

/// Maximum length for a redirect URI.
const MAX_REDIRECT_URI_LENGTH: usize = 2048;

/// Validates and normalizes an email address.
///
/// Normalization: trim whitespace, lowercase, NFC normalize.
///
/// Validation rules:
/// - Non-empty after trimming
/// - Contains exactly one `@` with non-empty local and domain parts
/// - Domain contains at least one `.`
/// - No null bytes or control characters
/// - Maximum 254 characters (after normalization)
pub(crate) fn validate_email(email: &str) -> Result<String, IdentityError> {
    let normalized: String = email.trim().nfc().collect::<String>().to_lowercase();

    if normalized.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "email must not be empty".to_string(),
        });
    }

    if contains_null_or_control(&normalized) {
        return Err(IdentityError::InvalidInput {
            reason: "email must not contain null bytes or control characters".to_string(),
        });
    }

    if normalized.len() > MAX_EMAIL_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!("email exceeds maximum length of {MAX_EMAIL_LENGTH} characters"),
        });
    }

    let at_pos = normalized
        .find('@')
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: "email must contain '@'".to_string(),
        })?;

    let local = &normalized[..at_pos];
    let domain = &normalized[at_pos + 1..];

    if local.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "email local part must not be empty".to_string(),
        });
    }

    if domain.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "email domain must not be empty".to_string(),
        });
    }

    if !domain.contains('.') {
        return Err(IdentityError::InvalidInput {
            reason: "email domain must contain '.'".to_string(),
        });
    }

    // Check for multiple @ signs
    if normalized.matches('@').count() > 1 {
        return Err(IdentityError::InvalidInput {
            reason: "email must contain exactly one '@'".to_string(),
        });
    }

    Ok(normalized)
}

/// Validates and normalizes a display name.
///
/// Normalization: trim whitespace, NFC normalize.
///
/// Validation rules:
/// - Non-empty after trimming
/// - No null bytes
/// - Maximum 256 characters (after normalization)
pub(crate) fn validate_display_name(name: &str) -> Result<String, IdentityError> {
    let normalized: String = name.trim().nfc().collect();

    if normalized.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "display name must not be empty".to_string(),
        });
    }

    if normalized.contains('\0') {
        return Err(IdentityError::InvalidInput {
            reason: "display name must not contain null bytes".to_string(),
        });
    }

    if normalized.len() > MAX_DISPLAY_NAME_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!(
                "display name exceeds maximum length of {MAX_DISPLAY_NAME_LENGTH} characters"
            ),
        });
    }

    Ok(normalized)
}

/// Enforces a realm's [`PasswordPolicy`] against a candidate password.
///
/// Complements `validate_password_length` (which only guards against the
/// hashing `DoS` bound). Used by self-service registration; admin-created
/// users bypass this check intentionally, because operators may set weak
/// interim passwords that the user must rotate on first login.
pub(crate) fn validate_password_against_policy(
    password_bytes: &[u8],
    policy: &PasswordPolicy,
) -> Result<(), IdentityError> {
    if let Some(min) = policy.min_length {
        if password_bytes.len() < min {
            return Err(IdentityError::InvalidInput {
                reason: format!("password must be at least {min} characters"),
            });
        }
    }
    let as_str = std::str::from_utf8(password_bytes).map_err(|_| IdentityError::InvalidInput {
        reason: "password must be valid UTF-8".to_string(),
    })?;
    if matches!(policy.require_uppercase, Some(true))
        && !as_str.chars().any(|c| c.is_ascii_uppercase())
    {
        return Err(IdentityError::InvalidInput {
            reason: "password must contain an uppercase letter".to_string(),
        });
    }
    if matches!(policy.require_number, Some(true)) && !as_str.chars().any(|c| c.is_ascii_digit()) {
        return Err(IdentityError::InvalidInput {
            reason: "password must contain a digit".to_string(),
        });
    }
    if matches!(policy.require_special, Some(true))
        && !as_str.chars().any(|c| !c.is_ascii_alphanumeric())
    {
        return Err(IdentityError::InvalidInput {
            reason: "password must contain a special character".to_string(),
        });
    }
    Ok(())
}

/// Validates a password length.
///
/// Passwords must be between 1 and 1024 bytes. The upper bound prevents
/// CPU-based denial-of-service via expensive Argon2id hashing on extremely large inputs.
pub(crate) fn validate_password_length(password_bytes: &[u8]) -> Result<(), IdentityError> {
    if password_bytes.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "password must not be empty".to_string(),
        });
    }
    if password_bytes.len() > MAX_PASSWORD_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!("password exceeds maximum length of {MAX_PASSWORD_LENGTH} bytes"),
        });
    }
    Ok(())
}

/// Validates an OAuth client name.
pub(crate) fn validate_client_name(name: &str) -> Result<String, IdentityError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "client name must not be empty".to_string(),
        });
    }
    if trimmed.len() > MAX_CLIENT_NAME_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!(
                "client name exceeds maximum length of {MAX_CLIENT_NAME_LENGTH} characters"
            ),
        });
    }
    Ok(trimmed.to_string())
}

/// Validates a redirect URI.
pub(crate) fn validate_redirect_uri(uri: &str) -> Result<(), IdentityError> {
    if uri.is_empty() {
        return Err(IdentityError::InvalidInput {
            reason: "redirect URI must not be empty".to_string(),
        });
    }
    if uri.len() > MAX_REDIRECT_URI_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!(
                "redirect URI exceeds maximum length of {MAX_REDIRECT_URI_LENGTH} characters"
            ),
        });
    }
    Ok(())
}

/// Minimum length for an organization slug.
const MIN_SLUG_LENGTH: usize = 3;

/// Maximum length for an organization slug.
const MAX_SLUG_LENGTH: usize = 63;

/// Validates an organization slug.
///
/// Slugs are URL-safe identifiers used in URLs and API paths.
///
/// Validation rules:
/// - 3-63 characters
/// - Lowercase ASCII alphanumeric and hyphens only
/// - Must start and end with an alphanumeric character
/// - No consecutive hyphens
pub(crate) fn validate_slug(slug: &str) -> Result<String, IdentityError> {
    if slug.len() < MIN_SLUG_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!("slug must be at least {MIN_SLUG_LENGTH} characters"),
        });
    }

    if slug.len() > MAX_SLUG_LENGTH {
        return Err(IdentityError::InvalidInput {
            reason: format!("slug must not exceed {MAX_SLUG_LENGTH} characters"),
        });
    }

    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(IdentityError::InvalidInput {
            reason: "slug must contain only lowercase letters, digits, and hyphens".to_string(),
        });
    }

    if slug.starts_with('-') || slug.ends_with('-') {
        return Err(IdentityError::InvalidInput {
            reason: "slug must not start or end with a hyphen".to_string(),
        });
    }

    if slug.contains("--") {
        return Err(IdentityError::InvalidInput {
            reason: "slug must not contain consecutive hyphens".to_string(),
        });
    }

    Ok(slug.to_string())
}

/// Returns `true` if the string contains null bytes or ASCII control characters.
fn contains_null_or_control(s: &str) -> bool {
    s.chars()
        .any(|c| c == '\0' || (c.is_control() && c != '\t'))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Email validation =====

    #[test]
    fn valid_email_passes() {
        let result = validate_email("Alice@Example.COM").expect("should be valid");
        assert_eq!(result, "alice@example.com");
    }

    #[test]
    fn email_trimmed() {
        let result = validate_email("  alice@example.com  ").expect("should be valid");
        assert_eq!(result, "alice@example.com");
    }

    #[test]
    fn empty_email_rejected() {
        let err = validate_email("").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn whitespace_only_email_rejected() {
        let err = validate_email("   ").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_missing_at_rejected() {
        let err = validate_email("aliceexample.com").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_empty_local_rejected() {
        let err = validate_email("@example.com").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_empty_domain_rejected() {
        let err = validate_email("alice@").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_domain_without_dot_rejected() {
        let err = validate_email("alice@localhost").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_multiple_at_rejected() {
        let err = validate_email("alice@bob@example.com").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_null_byte_rejected() {
        let err = validate_email("alice\0@example.com").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_control_char_rejected() {
        let err = validate_email("alice\x01@example.com").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_oversized_rejected() {
        let local = "a".repeat(250);
        let email = format!("{local}@example.com");
        let err = validate_email(&email).expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn email_unicode_normalized() {
        // é as decomposed (e + combining accent) vs composed
        let decomposed = "caf\u{0065}\u{0301}@example.com"; // e + combining acute
        let composed = "caf\u{00E9}@example.com"; // precomposed é
        let result1 = validate_email(decomposed).expect("valid");
        let result2 = validate_email(composed).expect("valid");
        assert_eq!(result1, result2, "NFC normalization should make them equal");
    }

    // ===== Display name validation =====

    #[test]
    fn valid_display_name_passes() {
        let result = validate_display_name("Alice Smith").expect("should be valid");
        assert_eq!(result, "Alice Smith");
    }

    #[test]
    fn display_name_trimmed() {
        let result = validate_display_name("  Alice  ").expect("should be valid");
        assert_eq!(result, "Alice");
    }

    #[test]
    fn empty_display_name_rejected() {
        let err = validate_display_name("").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn whitespace_only_display_name_rejected() {
        let err = validate_display_name("   ").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn display_name_null_byte_rejected() {
        let err = validate_display_name("Alice\0Bob").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn display_name_oversized_rejected() {
        let name = "A".repeat(257);
        let err = validate_display_name(&name).expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn display_name_max_length_accepted() {
        let name = "A".repeat(256);
        let result = validate_display_name(&name).expect("should be valid");
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn display_name_unicode_normalized() {
        let decomposed = "Caf\u{0065}\u{0301}";
        let composed = "Caf\u{00E9}";
        let result1 = validate_display_name(decomposed).expect("valid");
        let result2 = validate_display_name(composed).expect("valid");
        assert_eq!(result1, result2);
    }

    #[test]
    fn display_name_preserves_case() {
        let result = validate_display_name("Alice McSmith").expect("valid");
        assert_eq!(result, "Alice McSmith");
    }

    // ===== Slug validation =====

    #[test]
    fn valid_slug_passes() {
        let result = validate_slug("acme-corp").expect("should be valid");
        assert_eq!(result, "acme-corp");
    }

    #[test]
    fn slug_minimum_length() {
        let result = validate_slug("abc").expect("should be valid");
        assert_eq!(result, "abc");
    }

    #[test]
    fn slug_maximum_length() {
        let slug = "a".repeat(63);
        let result = validate_slug(&slug).expect("should be valid");
        assert_eq!(result.len(), 63);
    }

    #[test]
    fn slug_too_short_rejected() {
        let err = validate_slug("ab").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_too_long_rejected() {
        let slug = "a".repeat(64);
        let err = validate_slug(&slug).expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_uppercase_rejected() {
        let err = validate_slug("Acme-Corp").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_spaces_rejected() {
        let err = validate_slug("acme corp").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_leading_hyphen_rejected() {
        let err = validate_slug("-acme").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_trailing_hyphen_rejected() {
        let err = validate_slug("acme-").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_consecutive_hyphens_rejected() {
        let err = validate_slug("acme--corp").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn slug_with_digits_accepted() {
        let result = validate_slug("acme-123").expect("should be valid");
        assert_eq!(result, "acme-123");
    }

    #[test]
    fn slug_all_digits_accepted() {
        let result = validate_slug("123").expect("should be valid");
        assert_eq!(result, "123");
    }

    #[test]
    fn slug_special_chars_rejected() {
        let err = validate_slug("acme_corp").expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }
}
