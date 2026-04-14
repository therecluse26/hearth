//! Storage key encoding for user records.
//!
//! Two indexes are maintained, both tenant-scoped via `StorageEngine`:
//!
//! - **Primary**: `usr:id:{uuid}` → JSON-serialized `User`
//! - **Email index**: `usr:email:{normalized_email}` → `UserId` UUID string bytes
//!
//! Scan prefix `usr:id:` enables listing all users in a tenant.

use crate::core::UserId;

/// Prefix for user primary keys.
const USER_ID_PREFIX: &str = "usr:id:";

/// Prefix for user email index keys.
const USER_EMAIL_PREFIX: &str = "usr:email:";

/// Encodes the primary key for a user record.
///
/// Format: `usr:id:{uuid}`
pub(crate) fn encode_user_id(user_id: &UserId) -> Vec<u8> {
    format!("{USER_ID_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Encodes the email index key for a user.
///
/// Format: `usr:email:{normalized_email}`
///
/// The email must already be normalized (lowercase, trimmed, NFC)
/// before calling this function.
pub(crate) fn encode_user_email(email: &str) -> Vec<u8> {
    format!("{USER_EMAIL_PREFIX}{email}").into_bytes()
}

/// Returns the scan prefix for listing all user records.
///
/// Format: `usr:id:`
#[allow(dead_code)]
pub(crate) fn user_id_scan_prefix() -> Vec<u8> {
    USER_ID_PREFIX.as_bytes().to_vec()
}

/// Computes the exclusive end bound for a prefix scan.
///
/// Increments the last byte of the prefix.
#[allow(dead_code)]
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn encode_user_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_user_id(&user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "usr:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_user_email_format() {
        let key = encode_user_email("alice@example.com");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "usr:email:alice@example.com");
    }

    #[test]
    fn user_id_scan_prefix_format() {
        let prefix = user_id_scan_prefix();
        let prefix_str = std::str::from_utf8(&prefix).expect("utf8");
        assert_eq!(prefix_str, "usr:id:");
    }

    #[test]
    fn user_id_key_starts_with_scan_prefix() {
        let user_id = UserId::generate();
        let key = encode_user_id(&user_id);
        let prefix = user_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn prefix_end_increments_last_byte() {
        let prefix = user_id_scan_prefix();
        let end = prefix_end(&prefix);
        // ':' is 0x3A, incrementing gives ';' (0x3B)
        assert_eq!(end.last(), Some(&0x3B));
        assert!(end > prefix);
    }

    #[test]
    fn prefix_end_empty() {
        let end = prefix_end(b"");
        assert!(end.is_empty());
    }

    #[test]
    fn different_users_produce_different_keys() {
        let id1 = UserId::generate();
        let id2 = UserId::generate();
        let key1 = encode_user_id(&id1);
        let key2 = encode_user_id(&id2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn different_emails_produce_different_keys() {
        let key1 = encode_user_email("alice@example.com");
        let key2 = encode_user_email("bob@example.com");
        assert_ne!(key1, key2);
    }
}
