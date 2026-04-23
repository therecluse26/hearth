//! Storage key encoding for identity records.
//!
//! Indexes maintained, all realm-scoped via `StorageEngine`:
//!
//! - **User primary**: `usr:id:{uuid}` → JSON-serialized `User`
//! - **User email index**: `usr:email:{normalized_email}` → `UserId` UUID bytes
//! - **Session primary**: `ses:id:{uuid}` → JSON-serialized `Session`
//! - **Session user index**: `ses:user:{user_uuid}:{session_uuid}` → empty
//! - **Credential**: `cred:user:{uuid}` → JSON-serialized `StoredCredential`
//! - **OAuth client**: `oauth:client:{uuid}` → JSON-serialized `OAuthClient`
//! - **OAuth code**: `oauth:code:{sha256_hex}` → JSON-serialized code
//! - **Realm primary**: `realm:id:{uuid}` → JSON-serialized `Realm` (system realm scope)
//! - **Realm signing key**: `realm:key:{uuid}` → PKCS#8 DER bytes (system realm scope)
//!
//! Scan prefix `usr:id:` enables listing all users in a realm.

use crate::core::{ClientId, InvitationId, OrganizationId, RealmId, SessionId, UserId};

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

/// Prefix for realm primary keys (stored under system realm).
const REALM_ID_PREFIX: &str = "realm:id:";

/// Prefix for realm signing key storage (stored under system realm).
const REALM_KEY_PREFIX: &str = "realm:key:";

/// Prefix for realm name index (stored under system realm).
const REALM_NAME_PREFIX: &str = "realm:name:";

/// Prefix for grant family storage (refresh token rotation).
const GRANT_FAMILY_PREFIX: &str = "oauth:family:";

/// Prefix for device authorization code storage.
const DEVICE_CODE_PREFIX: &str = "oauth:device:";

/// Prefix for user code to device code mapping.
const USER_CODE_PREFIX: &str = "oauth:ucode:";

/// Prefix for revoked token JTI storage (sessionless token revocation).
const REVOKED_JTI_PREFIX: &str = "oauth:revjti:";

/// Prefix for OAuth consent record storage.
const OAUTH_CONSENT_PREFIX: &str = "oauth:consent:";

/// Prefix for OAuth pending-authorization ticket storage.
///
/// Holds in-flight browser authorization requests awaiting consent, keyed
/// by an opaque ticket UUID. Short-TTL (10 minutes) and single-use — the
/// analog of `oauth:device:` for the browser flow.
const OAUTH_PENDING_AUTH_PREFIX: &str = "oauth:pending_auth:";

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

/// Prefix for password reset token storage (stored by SHA-256 hash).
const PASSWORD_RESET_PREFIX: &str = "rst:token:";

/// Prefix for organization primary keys.
const ORG_ID_PREFIX: &str = "org:id:";

/// Prefix for organization slug uniqueness index.
const ORG_SLUG_PREFIX: &str = "org:slug:";

/// Prefix for membership by org (org → user direction).
const ORGM_ORG_PREFIX: &str = "orgm:org:";

/// Prefix for membership by user (user → org direction).
const ORGM_USER_PREFIX: &str = "orgm:user:";

/// Prefix for invitation primary keys.
const ORGI_ID_PREFIX: &str = "orgi:id:";

/// Prefix for invitation token lookup (hashed).
const ORGI_TOKEN_PREFIX: &str = "orgi:token:";

/// Prefix for invitation dedup by org+email.
const ORGI_ORG_PREFIX: &str = "orgi:org:";

/// Prefix for listing invitations by org.
const ORGI_LIST_PREFIX: &str = "orgi:list:";

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

/// Returns the scan prefix for listing all sessions in a realm.
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

// ===== Realm key encoding =====

/// The well-known system `RealmId`.
///
/// Uses the nil UUID (`00000000-0000-0000-0000-000000000000`) as a
/// reserved namespace. Real realms use random v4 UUIDs and will never
/// collide with this.
///
/// Historically this realm held only Hearth-owned metadata (realm
/// records, per-realm signing keys). It is now **also the home of all
/// Hearth administrator users**: admins authenticate against this
/// realm, and the `hearth#admin` Zanzibar tuple lives here. Operators
/// administer application realms via a `TargetRealm` parameter (see
/// `src/protocol/web/auth.rs`) while their session always belongs to
/// the system realm.
///
/// The system realm is deliberately invisible on public surfaces:
/// [`EmbeddedIdentityEngine::list_realms`] filters it out,
/// [`EmbeddedIdentityEngine::get_realm_by_name`] returns `None` for
/// the reserved name, and YAML `realms:` blocks reject it at parse
/// time. Operators cannot target it via API; it is managed entirely
/// by the server.
pub(crate) fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Reserved name for the invisible system realm. YAML `realms:` may
/// not declare it; `get_realm_by_name` filters it; admin UI realm
/// switchers skip it.
pub(crate) const SYSTEM_REALM_NAME: &str = "system";

/// Returns `true` when the given `RealmId` is the reserved system
/// realm (nil UUID). Use this at every API boundary that accepts a
/// `RealmId` from operator input to guard against accidental writes
/// to Hearth's internal realm.
pub(crate) fn is_system_realm(realm_id: &RealmId) -> bool {
    *realm_id == system_realm_id()
}

/// Encodes the primary key for a realm record.
///
/// Format: `realm:id:{uuid}`
///
/// Stored under the system realm namespace.
pub(crate) fn encode_realm_id(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_ID_PREFIX}{}", realm_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all realm records.
///
/// Format: `realm:id:`
#[allow(dead_code)]
pub(crate) fn realm_id_scan_prefix() -> Vec<u8> {
    REALM_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the name index key for a realm.
///
/// Format: `realm:name:{name}`
///
/// Stored under the system realm namespace.
pub(crate) fn encode_realm_name(name: &str) -> Vec<u8> {
    format!("{REALM_NAME_PREFIX}{name}").into_bytes()
}

/// Encodes the storage key for a realm's signing key material.
///
/// Format: `realm:key:{uuid}`
///
/// Stored under the system realm namespace.
pub(crate) fn encode_realm_signing_key(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes()
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

/// Encodes the storage key for a password reset token.
///
/// Format: `rst:token:{sha256_hex_of_token}`
///
/// The token hash is the SHA-256 hex digest of the plaintext token.
/// The plaintext is never stored.
pub(crate) fn encode_password_reset_token(token_hash: &str) -> Vec<u8> {
    format!("{PASSWORD_RESET_PREFIX}{token_hash}").into_bytes()
}

/// Returns the scan prefix for password reset tokens (cascade deletion).
///
/// Format: `rst:token:`
#[allow(dead_code)]
pub(crate) fn password_reset_scan_prefix() -> Vec<u8> {
    PASSWORD_RESET_PREFIX.as_bytes().to_vec()
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

// ===== OAuth consent key encoding =====

/// Encodes the primary key for an OAuth consent record.
///
/// Format: `oauth:consent:{user_uuid}:{client_uuid}`
///
/// The compound key enables:
/// - O(1) lookup of a specific `(user, client)` consent.
/// - Prefix scan by user for "list my consents".
/// - Cascade delete of all consent records on user deletion.
pub(crate) fn encode_consent_key(user_id: &UserId, client_id: &ClientId) -> Vec<u8> {
    format!(
        "{OAUTH_CONSENT_PREFIX}{}:{}",
        user_id.as_uuid(),
        client_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all consents granted by a user.
///
/// Format: `oauth:consent:{user_uuid}:`
pub(crate) fn encode_consent_prefix_for_user(user_id: &UserId) -> Vec<u8> {
    format!("{OAUTH_CONSENT_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all consent records in a realm.
///
/// Format: `oauth:consent:`
///
/// Used by `delete_realm` cascade and by `delete_oauth_client` cascade
/// (which then filters by the trailing `:{client_uuid}` segment).
pub(crate) fn oauth_consent_scan_prefix() -> Vec<u8> {
    OAUTH_CONSENT_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a pending-authorization ticket.
///
/// Format: `oauth:pending_auth:{ticket_uuid}`
pub(crate) fn encode_pending_auth_key(ticket: &str) -> Vec<u8> {
    format!("{OAUTH_PENDING_AUTH_PREFIX}{ticket}").into_bytes()
}

/// Returns the scan prefix for all pending-authorization tickets.
///
/// Format: `oauth:pending_auth:`
pub(crate) fn oauth_pending_auth_scan_prefix() -> Vec<u8> {
    OAUTH_PENDING_AUTH_PREFIX.as_bytes().to_vec()
}

// ===== Organization key encoding =====

/// Encodes the primary key for an organization record.
///
/// Format: `org:id:{uuid}`
pub(crate) fn encode_org_id(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORG_ID_PREFIX}{}", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all organizations.
///
/// Format: `org:id:`
pub(crate) fn org_id_scan_prefix() -> Vec<u8> {
    ORG_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the slug uniqueness index key.
///
/// Format: `org:slug:{slug}`
pub(crate) fn encode_org_slug(slug: &str) -> Vec<u8> {
    format!("{ORG_SLUG_PREFIX}{slug}").into_bytes()
}

/// Returns the scan prefix for all organization slug entries.
///
/// Format: `org:slug:`
#[allow(dead_code)]
pub(crate) fn org_slug_scan_prefix() -> Vec<u8> {
    ORG_SLUG_PREFIX.as_bytes().to_vec()
}

/// Encodes the membership key (org → user direction).
///
/// Format: `orgm:org:{org_uuid}:user:{user_uuid}`
pub(crate) fn encode_membership_by_org(org_id: &OrganizationId, user_id: &UserId) -> Vec<u8> {
    format!(
        "{ORGM_ORG_PREFIX}{}:user:{}",
        org_id.as_uuid(),
        user_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all members of an organization.
///
/// Format: `orgm:org:{org_uuid}:`
pub(crate) fn membership_by_org_prefix(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORGM_ORG_PREFIX}{}:", org_id.as_uuid()).into_bytes()
}

/// Encodes the reverse membership key (user → org direction).
///
/// Format: `orgm:user:{user_uuid}:org:{org_uuid}`
pub(crate) fn encode_membership_by_user(user_id: &UserId, org_id: &OrganizationId) -> Vec<u8> {
    format!(
        "{ORGM_USER_PREFIX}{}:org:{}",
        user_id.as_uuid(),
        org_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all organizations a user belongs to.
///
/// Format: `orgm:user:{user_uuid}:`
pub(crate) fn membership_by_user_prefix(user_id: &UserId) -> Vec<u8> {
    format!("{ORGM_USER_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all membership-by-org entries (realm-wide).
///
/// Format: `orgm:org:`
#[allow(dead_code)]
pub(crate) fn membership_org_scan_prefix() -> Vec<u8> {
    ORGM_ORG_PREFIX.as_bytes().to_vec()
}

/// Returns the scan prefix for all membership-by-user entries (realm-wide).
///
/// Format: `orgm:user:`
#[allow(dead_code)]
pub(crate) fn membership_user_scan_prefix() -> Vec<u8> {
    ORGM_USER_PREFIX.as_bytes().to_vec()
}

/// Encodes the primary key for an invitation record.
///
/// Format: `orgi:id:{uuid}`
pub(crate) fn encode_invitation_id(invitation_id: &InvitationId) -> Vec<u8> {
    format!("{ORGI_ID_PREFIX}{}", invitation_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation records.
///
/// Format: `orgi:id:`
#[allow(dead_code)]
pub(crate) fn invitation_id_scan_prefix() -> Vec<u8> {
    ORGI_ID_PREFIX.as_bytes().to_vec()
}

/// Encodes the token lookup key for an invitation.
///
/// Format: `orgi:token:{sha256_hex}`
///
/// The token is stored as a SHA-256 hash, never as plaintext.
pub(crate) fn encode_invitation_token(token_hash: &str) -> Vec<u8> {
    format!("{ORGI_TOKEN_PREFIX}{token_hash}").into_bytes()
}

/// Returns the scan prefix for all invitation token entries.
///
/// Format: `orgi:token:`
#[allow(dead_code)]
pub(crate) fn invitation_token_scan_prefix() -> Vec<u8> {
    ORGI_TOKEN_PREFIX.as_bytes().to_vec()
}

/// Encodes the invitation dedup key (prevents duplicate invites per org+email).
///
/// Format: `orgi:org:{org_uuid}:email:{email}`
pub(crate) fn encode_invitation_org_email(org_id: &OrganizationId, email: &str) -> Vec<u8> {
    format!("{ORGI_ORG_PREFIX}{}:email:{email}", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation dedup entries for an org.
///
/// Format: `orgi:org:{org_uuid}:`
#[allow(dead_code)]
pub(crate) fn invitation_org_prefix(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORGI_ORG_PREFIX}{}:", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation org entries (realm-wide).
///
/// Format: `orgi:org:`
#[allow(dead_code)]
pub(crate) fn invitation_org_scan_prefix() -> Vec<u8> {
    ORGI_ORG_PREFIX.as_bytes().to_vec()
}

/// Encodes the invitation listing key (for paginated org-scoped listing).
///
/// Format: `orgi:list:{org_uuid}:{invitation_uuid}`
pub(crate) fn encode_invitation_list(
    org_id: &OrganizationId,
    invitation_id: &InvitationId,
) -> Vec<u8> {
    format!(
        "{ORGI_LIST_PREFIX}{}:{}",
        org_id.as_uuid(),
        invitation_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for listing all invitations for an org.
///
/// Format: `orgi:list:{org_uuid}:`
pub(crate) fn invitation_list_prefix(org_id: &OrganizationId) -> Vec<u8> {
    format!("{ORGI_LIST_PREFIX}{}:", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all invitation list entries (realm-wide).
///
/// Format: `orgi:list:`
#[allow(dead_code)]
pub(crate) fn invitation_list_scan_prefix() -> Vec<u8> {
    ORGI_LIST_PREFIX.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ClientId, InvitationId, OrganizationId, RealmId, SessionId};
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

    // ===== Realm key tests =====

    #[test]
    fn system_realm_id_is_nil_uuid() {
        let sys = system_realm_id();
        assert_eq!(*sys.as_uuid(), Uuid::nil());
    }

    #[test]
    fn system_realm_id_is_stable() {
        assert_eq!(system_realm_id(), system_realm_id());
    }

    #[test]
    fn encode_realm_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let realm_id = RealmId::new(uuid);
        let key = encode_realm_id(&realm_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "realm:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn realm_id_key_starts_with_scan_prefix() {
        let realm_id = RealmId::generate();
        let key = encode_realm_id(&realm_id);
        let prefix = realm_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_realm_signing_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let realm_id = RealmId::new(uuid);
        let key = encode_realm_signing_key(&realm_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "realm:key:550e8400-e29b-41d4-a716-446655440000");
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
    fn different_realms_produce_different_keys() {
        let id1 = RealmId::generate();
        let id2 = RealmId::generate();
        assert_ne!(encode_realm_id(&id1), encode_realm_id(&id2));
        assert_ne!(
            encode_realm_signing_key(&id1),
            encode_realm_signing_key(&id2)
        );
    }

    // ===== Organization key tests =====

    #[test]
    fn encode_org_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let org_id = OrganizationId::new(uuid);
        let key = encode_org_id(&org_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "org:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn org_id_key_starts_with_scan_prefix() {
        let org_id = OrganizationId::generate();
        let key = encode_org_id(&org_id);
        let prefix = org_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_org_slug_format() {
        let key = encode_org_slug("acme-corp");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "org:slug:acme-corp");
    }

    #[test]
    fn membership_by_org_format() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_org(&org_id, &user_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("orgm:org:"));
        assert!(key_str.contains(":user:"));
    }

    #[test]
    fn membership_by_org_starts_with_prefix() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_org(&org_id, &user_id);
        let prefix = membership_by_org_prefix(&org_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn membership_by_user_format() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_user(&user_id, &org_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("orgm:user:"));
        assert!(key_str.contains(":org:"));
    }

    #[test]
    fn membership_by_user_starts_with_prefix() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let key = encode_membership_by_user(&user_id, &org_id);
        let prefix = membership_by_user_prefix(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_invitation_id_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let inv_id = InvitationId::new(uuid);
        let key = encode_invitation_id(&inv_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "orgi:id:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn invitation_id_starts_with_scan_prefix() {
        let inv_id = InvitationId::generate();
        let key = encode_invitation_id(&inv_id);
        let prefix = invitation_id_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_invitation_token_format() {
        let key = encode_invitation_token("abc123def456");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "orgi:token:abc123def456");
    }

    #[test]
    fn encode_invitation_org_email_format() {
        let org_id = OrganizationId::generate();
        let key = encode_invitation_org_email(&org_id, "alice@example.com");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("orgi:org:"));
        assert!(key_str.ends_with(":email:alice@example.com"));
    }

    #[test]
    fn invitation_list_starts_with_prefix() {
        let org_id = OrganizationId::generate();
        let inv_id = InvitationId::generate();
        let key = encode_invitation_list(&org_id, &inv_id);
        let prefix = invitation_list_prefix(&org_id);
        assert!(key.starts_with(&prefix));
    }

    // ===== Consent key tests =====

    #[test]
    fn encode_consent_key_format() {
        let user_uuid =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let client_uuid =
            Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(user_uuid);
        let client_id = ClientId::new(client_uuid);
        let key = encode_consent_key(&user_id, &client_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "oauth:consent:550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn consent_key_starts_with_user_prefix() {
        let user_id = UserId::generate();
        let client_id = ClientId::generate();
        let key = encode_consent_key(&user_id, &client_id);
        let prefix = encode_consent_prefix_for_user(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn consent_key_starts_with_scan_prefix() {
        let user_id = UserId::generate();
        let client_id = ClientId::generate();
        let key = encode_consent_key(&user_id, &client_id);
        let prefix = oauth_consent_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn different_users_produce_different_consent_prefixes() {
        let u1 = UserId::generate();
        let u2 = UserId::generate();
        assert_ne!(
            encode_consent_prefix_for_user(&u1),
            encode_consent_prefix_for_user(&u2)
        );
    }

    #[test]
    fn encode_pending_auth_key_format() {
        let key = encode_pending_auth_key("ticket-abc-123");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "oauth:pending_auth:ticket-abc-123");
    }

    #[test]
    fn pending_auth_key_starts_with_scan_prefix() {
        let key = encode_pending_auth_key("t1");
        let prefix = oauth_pending_auth_scan_prefix();
        assert!(key.starts_with(&prefix));
    }
}
