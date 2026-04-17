//! Storage key encoding for identity records.
//!
//! Indexes maintained, all tenant-scoped via `StorageEngine`:
//!
//! - **User primary**: `usr:id:{uuid}` → JSON-serialized `User`
//! - **User email index**: `usr:email:{normalized_email}` → `UserId` UUID bytes
//! - **Session primary**: `ses:id:{uuid}` → JSON-serialized `Session`
//! - **Session user index**: `ses:user:{user_uuid}:{session_uuid}` → empty
//! - **Credential**: `cred:user:{uuid}` → JSON-serialized `StoredCredential`
//! - **OAuth client**: `oauth:client:{uuid}` → JSON-serialized `OAuthClient`
//! - **OAuth code**: `oauth:code:{sha256_hex}` → JSON-serialized code
//! - **Tenant primary**: `tenant:id:{uuid}` → JSON-serialized `Tenant` (system tenant scope)
//! - **Tenant signing key**: `tenant:key:{uuid}` → PKCS#8 DER bytes (system tenant scope)
//!
//! Scan prefix `usr:id:` enables listing all users in a tenant.

use crate::core::{ClientId, SessionId, TenantId, UserId};

/// Prefix for user primary keys.
const USER_ID_PREFIX: &str = "usr:id:";

/// Prefix for user email index keys.
const USER_EMAIL_PREFIX: &str = "usr:email:";

/// Prefix for user credential keys.
const CREDENTIAL_PREFIX: &str = "cred:user:";

/// Prefix for OAuth client keys.
const OAUTH_CLIENT_PREFIX: &str = "oauth:client:";

/// Prefix for OAuth authorization code keys (stored by hash).
const OAUTH_CODE_PREFIX: &str = "oauth:code:";

/// Prefix for tenant primary keys (stored under system tenant).
const TENANT_ID_PREFIX: &str = "tenant:id:";

/// Prefix for tenant signing key storage (stored under system tenant).
const TENANT_KEY_PREFIX: &str = "tenant:key:";

/// Prefix for grant family storage (refresh token rotation).
const GRANT_FAMILY_PREFIX: &str = "oauth:family:";

/// Prefix for device authorization code storage.
const DEVICE_CODE_PREFIX: &str = "oauth:device:";

/// Prefix for user code to device code mapping.
const USER_CODE_PREFIX: &str = "oauth:ucode:";

/// Prefix for revoked token JTI storage (sessionless token revocation).
const REVOKED_JTI_PREFIX: &str = "oauth:revjti:";

/// Prefix for MFA TOTP state per user.
const MFA_TOTP_PREFIX: &str = "mfa:totp:";

/// Prefix for `WebAuthn` credential storage.
const WEBAUTHN_CRED_PREFIX: &str = "webauthn:cred:";

/// Prefix for `WebAuthn` discoverable credential index.
const WEBAUTHN_DISC_PREFIX: &str = "webauthn:disc:";

/// Prefix for magic link token storage (stored by SHA-256 hash of token).
const MAGIC_LINK_PREFIX: &str = "magic:link:";

/// Prefix for email verification token storage (stored by SHA-256 hash).
const EMAIL_VERIFY_PREFIX: &str = "email:verify:";

/// Prefix for session primary keys.
const SESSION_ID_PREFIX: &str = "ses:id:";

/// Prefix for user-to-sessions index keys.
const SESSION_USER_PREFIX: &str = "ses:user:";

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

/// Encodes the credential key for a user.
///
/// Format: `cred:user:{uuid}`
pub(crate) fn encode_credential_key(user_id: &UserId) -> Vec<u8> {
    format!("{CREDENTIAL_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Encodes the primary key for a session record.
///
/// Format: `ses:id:{uuid}`
pub(crate) fn encode_session_id(session_id: &SessionId) -> Vec<u8> {
    format!("{SESSION_ID_PREFIX}{}", session_id.as_uuid()).into_bytes()
}

/// Encodes the user-to-session index key.
///
/// Format: `ses:user:{user_uuid}:{session_uuid}`
///
/// This enables prefix-scanning all sessions for a user (e.g., for cascade delete).
pub(crate) fn encode_user_session(user_id: &UserId, session_id: &SessionId) -> Vec<u8> {
    format!(
        "{SESSION_USER_PREFIX}{}:{}",
        user_id.as_uuid(),
        session_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all sessions belonging to a user.
///
/// Format: `ses:user:{user_uuid}:`
pub(crate) fn encode_user_sessions_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{SESSION_USER_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all sessions in a tenant.
///
/// Format: `ses:id:`
pub(crate) fn session_id_scan_prefix() -> Vec<u8> {
    SESSION_ID_PREFIX.as_bytes().to_vec()
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

/// Returns the scan prefix for listing all OAuth clients.
///
/// Format: `oauth:client:`
pub(crate) fn oauth_client_scan_prefix() -> Vec<u8> {
    OAUTH_CLIENT_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for an OAuth client.
///
/// Format: `oauth:client:{client_id_uuid}`
pub(crate) fn encode_oauth_client(client_id: &ClientId) -> Vec<u8> {
    format!("{OAUTH_CLIENT_PREFIX}{}", client_id.as_uuid()).into_bytes()
}

/// Encodes the storage key for an OAuth authorization code.
///
/// The code is stored by its SHA-256 hex digest, not the raw code value.
/// Format: `oauth:code:{sha256_hex}`
pub(crate) fn encode_oauth_code(code_hash: &str) -> Vec<u8> {
    format!("{OAUTH_CODE_PREFIX}{code_hash}").into_bytes()
}

// ===== Tenant key encoding =====

/// The well-known system `TenantId` used for storing tenant metadata.
///
/// Uses the nil UUID (`00000000-0000-0000-0000-000000000000`) as a
/// reserved namespace. Real tenants use random v4 UUIDs and will
/// never collide with this.
pub(crate) fn system_tenant_id() -> TenantId {
    TenantId::new(uuid::Uuid::nil())
}

/// Encodes the primary key for a tenant record.
///
/// Format: `tenant:id:{uuid}`
///
/// Stored under the system tenant namespace.
pub(crate) fn encode_tenant_id(tenant_id: &TenantId) -> Vec<u8> {
    format!("{TENANT_ID_PREFIX}{}", tenant_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all tenant records.
///
/// Format: `tenant:id:`
#[allow(dead_code)]
pub(crate) fn tenant_id_scan_prefix() -> Vec<u8> {
    TENANT_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a tenant's signing key material.
///
/// Format: `tenant:key:{uuid}`
///
/// Stored under the system tenant namespace.
pub(crate) fn encode_tenant_signing_key(tenant_id: &TenantId) -> Vec<u8> {
    format!("{TENANT_KEY_PREFIX}{}", tenant_id.as_uuid()).into_bytes()
}

/// Encodes the storage key for a grant family (refresh token rotation).
///
/// Format: `oauth:family:{family_id}`
pub(crate) fn encode_grant_family(family_id: &str) -> Vec<u8> {
    format!("{GRANT_FAMILY_PREFIX}{family_id}").into_bytes()
}

/// Returns the scan prefix for all grant families.
///
/// Format: `oauth:family:`
#[allow(dead_code)]
pub(crate) fn grant_family_scan_prefix() -> Vec<u8> {
    GRANT_FAMILY_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a device authorization code.
///
/// Format: `oauth:device:{device_code_hash}`
pub(crate) fn encode_device_code(device_code_hash: &str) -> Vec<u8> {
    format!("{DEVICE_CODE_PREFIX}{device_code_hash}").into_bytes()
}

/// Returns the scan prefix for all device codes.
///
/// Format: `oauth:device:`
#[allow(dead_code)]
pub(crate) fn device_code_scan_prefix() -> Vec<u8> {
    DEVICE_CODE_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a user code to device code mapping.
///
/// Format: `oauth:ucode:{user_code}`
pub(crate) fn encode_user_code(user_code: &str) -> Vec<u8> {
    format!("{USER_CODE_PREFIX}{user_code}").into_bytes()
}

/// Returns the scan prefix for all user codes.
///
/// Format: `oauth:ucode:`
#[allow(dead_code)]
pub(crate) fn user_code_scan_prefix() -> Vec<u8> {
    USER_CODE_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a user's MFA TOTP state.
///
/// Format: `mfa:totp:{user_uuid}`
pub(crate) fn encode_mfa_totp_key(user_id: &UserId) -> Vec<u8> {
    format!("{MFA_TOTP_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Encodes the storage key for a `WebAuthn` credential.
///
/// Format: `webauthn:cred:{user_uuid}:{credential_id_b64url}`
///
/// Supports prefix scanning all credentials for a user.
pub(crate) fn encode_webauthn_credential(user_id: &UserId, credential_id_b64: &str) -> Vec<u8> {
    format!(
        "{WEBAUTHN_CRED_PREFIX}{}:{credential_id_b64}",
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all `WebAuthn` credentials for a user.
///
/// Format: `webauthn:cred:{user_uuid}:`
pub(crate) fn encode_webauthn_credentials_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{WEBAUTHN_CRED_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Encodes the discoverable credential index key.
///
/// Format: `webauthn:disc:{credential_id_b64url}`
///
/// Maps a credential ID to a user UUID for username-less authentication.
pub(crate) fn encode_webauthn_discoverable(credential_id_b64: &str) -> Vec<u8> {
    format!("{WEBAUTHN_DISC_PREFIX}{credential_id_b64}").into_bytes()
}

/// Encodes the storage key for a magic link token.
///
/// Format: `magic:link:{sha256_hex_of_token}`
///
/// The token hash is the SHA-256 hex digest of the plaintext token.
/// The plaintext is never stored.
pub(crate) fn encode_magic_link_token(token_hash: &str) -> Vec<u8> {
    format!("{MAGIC_LINK_PREFIX}{token_hash}").into_bytes()
}

/// Encodes the storage key for an email verification token.
///
/// Format: `email:verify:{sha256_hex_of_token}`
///
/// The token hash is the SHA-256 hex digest of the plaintext token.
/// The plaintext is never stored.
pub(crate) fn encode_email_verify_token(token_hash: &str) -> Vec<u8> {
    format!("{EMAIL_VERIFY_PREFIX}{token_hash}").into_bytes()
}

/// Encodes the storage key for a revoked token JTI.
///
/// Format: `oauth:revjti:{jti}`
///
/// Used for revoking sessionless tokens (e.g., `client_credentials` access tokens)
/// that cannot be revoked via session revocation.
pub(crate) fn encode_revoked_jti(jti: &str) -> Vec<u8> {
    format!("{REVOKED_JTI_PREFIX}{jti}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ClientId, SessionId, TenantId};
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
    fn encode_credential_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_credential_key(&user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "cred:user:550e8400-e29b-41d4-a716-446655440000");
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

    #[test]
    fn encode_session_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let session_id = SessionId::new(uuid);
        let key = encode_session_id(&session_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "ses:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_user_session_format() {
        let user_uuid =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let session_uuid =
            Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(user_uuid);
        let session_id = SessionId::new(session_uuid);
        let key = encode_user_session(&user_id, &session_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "ses:user:550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn user_sessions_prefix_enables_scan() {
        let user_id = UserId::generate();
        let session_id = SessionId::generate();
        let key = encode_user_session(&user_id, &session_id);
        let prefix = encode_user_sessions_prefix(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn different_sessions_produce_different_keys() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let key1 = encode_session_id(&id1);
        let key2 = encode_session_id(&id2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn encode_oauth_client_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let client_id = ClientId::new(uuid);
        let key = encode_oauth_client(&client_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "oauth:client:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_oauth_code_format() {
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key = encode_oauth_code(hash);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "oauth:code:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn different_clients_produce_different_keys() {
        let id1 = ClientId::generate();
        let id2 = ClientId::generate();
        let key1 = encode_oauth_client(&id1);
        let key2 = encode_oauth_client(&id2);
        assert_ne!(key1, key2);
    }

    // ===== Tenant key tests =====

    #[test]
    fn system_tenant_id_is_nil_uuid() {
        let sys = system_tenant_id();
        assert_eq!(*sys.as_uuid(), Uuid::nil());
    }

    #[test]
    fn system_tenant_id_is_stable() {
        assert_eq!(system_tenant_id(), system_tenant_id());
    }

    #[test]
    fn encode_tenant_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let tenant_id = TenantId::new(uuid);
        let key = encode_tenant_id(&tenant_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "tenant:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn tenant_id_key_starts_with_scan_prefix() {
        let tenant_id = TenantId::generate();
        let key = encode_tenant_id(&tenant_id);
        let prefix = tenant_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_tenant_signing_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let tenant_id = TenantId::new(uuid);
        let key = encode_tenant_signing_key(&tenant_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "tenant:key:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_mfa_totp_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_mfa_totp_key(&user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "mfa:totp:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn encode_webauthn_credential_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(uuid);
        let key = encode_webauthn_credential(&user_id, "cred123");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "webauthn:cred:550e8400-e29b-41d4-a716-446655440000:cred123"
        );
    }

    #[test]
    fn webauthn_credential_prefix_enables_scan() {
        let user_id = UserId::generate();
        let key = encode_webauthn_credential(&user_id, "credABC");
        let prefix = encode_webauthn_credentials_prefix(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_webauthn_discoverable_format() {
        let key = encode_webauthn_discoverable("abc123");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "webauthn:disc:abc123");
    }

    #[test]
    fn different_tenants_produce_different_keys() {
        let id1 = TenantId::generate();
        let id2 = TenantId::generate();
        assert_ne!(encode_tenant_id(&id1), encode_tenant_id(&id2));
        assert_ne!(
            encode_tenant_signing_key(&id1),
            encode_tenant_signing_key(&id2)
        );
    }
}
