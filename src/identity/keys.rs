//! Storage key encoding for identity records.
//!
//! Indexes maintained, all realm-scoped via `StorageEngine`:
//!
//! - **User primary**: `usr:id:{uuid}` → JSON-serialized `User`
//! - **User email index**: `usr:email:{normalized_email}` → `UserId` UUID bytes
//! - **Session primary**: `ses:id:{uuid}` → JSON-serialized `Session`
//! - **Session user index**: `ses:user:{user_uuid}:{session_uuid}` → empty
//! - **Credential**: `cred:user:{uuid}` → JSON-serialized `StoredCredential`
//! - **Credential history**: `cred:history:{uuid}` → JSON-serialized `Vec<StoredCredential>`
//! - **OAuth client**: `oauth:client:{uuid}` → JSON-serialized `OAuthClient`
//! - **OAuth code**: `oauth:code:{sha256_hex}` → JSON-serialized code
//! - **Realm primary**: `realm:id:{uuid}` → JSON-serialized `Realm` (system realm scope)
//! - **Realm signing key**: `realm:key:{uuid}` → PKCS#8 DER bytes (system realm scope)
//!
//! Scan prefix `usr:id:` enables listing all users in a realm.

use crate::core::{
    ClientId, IdpId, InvitationId, OrganizationId, RealmId, SessionId, UserId, WebhookId,
};

/// Prefix for user primary keys.
const USER_ID_PREFIX: &str = "usr:id:";

/// Prefix for user email index keys.
const USER_EMAIL_PREFIX: &str = "usr:email:";

/// Prefix for user credential keys.
const CREDENTIAL_PREFIX: &str = "cred:user:";

/// Prefix for credential history keys.
const CREDENTIAL_HISTORY_PREFIX: &str = "cred:history:";

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

/// Prefix for session → grant-family secondary index.
///
/// Format: `oauth:session_fam:{session_uuid}:{family_id}` — empty value.
/// Written at grant family creation; scanned during session revocation for
/// cascade refresh-token family invalidation.
const SESSION_GRANT_FAMILY_PREFIX: &str = "oauth:session_fam:";

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

/// Prefix for external Identity Provider connector records (per realm).
///
/// Holds `IdpConfig` JSON reconciled from YAML. Keyed by `IdpId` to
/// preserve connector identity across reconciliation cycles (so existing
/// `fed:ext:*` account links survive config edits).
const FED_IDP_PREFIX: &str = "fed:idp:";

/// Prefix for short-lived federation login state.
///
/// Holds the `StateBag` (nonce, PKCE verifier, return_to, realm, idp_id)
/// for an in-flight `begin` → `callback` round trip. 10-minute TTL;
/// single-use — `take_federation_state` removes the entry after read.
const FED_STATE_PREFIX: &str = "fed:state:";

/// Prefix for confirm-to-link tickets.
///
/// Holds the pending external identity awaiting local-account
/// re-authentication, in the `link_existing_accounts: confirm` flow.
/// HMAC-bound to the matched user; single-use; 10-minute TTL.
const FED_CONFIRM_PREFIX: &str = "fed:confirm:";

/// Prefix for the reverse external-identity → user index.
///
/// Keyed by `(realm, idp_id, external_sub)`. Primary lookup on every
/// federation login — O(1) resolution of "which Hearth user owns this
/// upstream identity?"
const FED_EXT_PREFIX: &str = "fed:ext:";

/// Prefix for the forward user → external-identity index.
///
/// Keyed by `(realm, user_id, idp_id)`. Used for `/ui/account/linked-accounts`
/// enumeration and for cascade cleanup in `delete_user`. Value is the
/// `external_sub` string.
const FED_EXT_FWD_PREFIX: &str = "fed:ext_fwd:";

/// Prefix for per-realm RSA signing key for SAML (stored under system realm).
///
/// Format: `realm:saml_key:{uuid}` — PKCS#8 DER bytes.
const REALM_SAML_KEY_PREFIX: &str = "realm:saml_key:";

/// Prefix for SAML registered Service Providers (per realm).
///
/// Format: `saml:sp:{sp_key}` — JSON-serialized `SamlServiceProvider`.
/// The SP key is a stable slug (from YAML) so reconciliation survives edits.
const SAML_SP_PREFIX: &str = "saml:sp:";

/// Prefix for SAML outbound-request state (SP side).
///
/// Format: `saml:state:{token}` — JSON-serialized `SamlStateBag`. 10-minute
/// TTL; single-use; HMAC-bound echo in `RelayState`.
const SAML_STATE_PREFIX: &str = "saml:state:";

/// Prefix for SAML assertion-ID replay sentinels (SP side).
///
/// Format: `saml:asn:{idp_uuid}:{assertion_id}` — empty value. TTL equals
/// the assertion's `NotOnOrAfter - now`; duplicates are replay attacks.
const SAML_ASSERTION_PREFIX: &str = "saml:asn:";

/// Prefix for SAML IdP-issued session → SP registration (IdP side).
///
/// Format: `saml:sp_session:{session_uuid}:{sp_key}` — JSON-serialized
/// `SamlSessionRegistration`. Used for SLO fan-out: when a user logs out
/// at Hearth (acting as IdP), we find all SPs that consumed an assertion
/// for that session and propagate `LogoutRequest`s.
const SAML_SP_SESSION_PREFIX: &str = "saml:sp_session:";

/// Prefix for SAML in-flight logout state.
///
/// Format: `saml:logout:{token}` — JSON-serialized `SamlLogoutStateBag`.
/// Matches the SP-side / IdP-side logout round-trip (LogoutRequest sent →
/// LogoutResponse received). 5-minute TTL; single-use.
#[allow(dead_code)]
const SAML_LOGOUT_STATE_PREFIX: &str = "saml:logout:";

/// Prefix for the SCIM `externalId` → Hearth `UserId` index.
///
/// Format: `scim:ext_user:{external_id}` — value is the stringified
/// `UserId` UUID. External IDs are supplied by the SCIM client (IdP) for
/// idempotent provisioning; enforced unique per realm.
const SCIM_EXT_USER_PREFIX: &str = "scim:ext_user:";

/// Prefix for the reverse Hearth `UserId` → SCIM `externalId` index.
///
/// Format: `scim:ext_user_fwd:{user_uuid}` — value is the external ID.
/// Maintained in lockstep with `scim:ext_user:*` so cascade cleanup on
/// `delete_user` doesn't require scanning the forward space.
const SCIM_EXT_USER_FWD_PREFIX: &str = "scim:ext_user_fwd:";

/// Prefix for the SCIM `externalId` → Hearth `OrganizationId` index.
///
/// Format: `scim:ext_group:{external_id}` — value is the stringified
/// `OrganizationId` UUID.
const SCIM_EXT_GROUP_PREFIX: &str = "scim:ext_group:";

/// Prefix for the reverse Hearth `OrganizationId` → SCIM `externalId` index.
///
/// Format: `scim:ext_group_fwd:{org_uuid}` — value is the external ID.
const SCIM_EXT_GROUP_FWD_PREFIX: &str = "scim:ext_group_fwd:";

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

/// Encodes the credential history key for a user.
///
/// Format: `cred:history:{uuid}`
pub(crate) fn encode_credential_history_key(user_id: &UserId) -> Vec<u8> {
    format!("{CREDENTIAL_HISTORY_PREFIX}{}", user_id.as_uuid()).into_bytes()
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

/// Returns the scan prefix for all OAuth authorization codes.
///
/// Format: `oauth:code:`
pub(crate) fn oauth_code_scan_prefix() -> Vec<u8> {
    OAUTH_CODE_PREFIX.as_bytes().to_vec()
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
/// realm, and RBAC role assignments (at the `rba:` key prefix) live
/// here as well. Operators
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

/// Encodes the extended consent key for a `(user, client, org_key, resource_key)` tuple.
///
/// Format: `oauth:consent:{user_uuid}:{client_uuid}:{org_key}:{resource_key}`
///
/// - `org_key` is the org UUID string, or `"_realm"` for realm-scoped consent.
/// - `resource_key` is the resource URI, or `"_default"` when no resource indicator.
///
/// This is the preferred key for consent records created under the expanded
/// authorization model. Legacy records keyed by `encode_consent_key` remain
/// readable during migration.
pub(crate) fn encode_consent_key_extended(
    user_id: &UserId,
    client_id: &ClientId,
    org_key: &str,
    resource_key: &str,
) -> Vec<u8> {
    format!(
        "{OAUTH_CONSENT_PREFIX}{}:{}:{}:{}",
        user_id.as_uuid(),
        client_id.as_uuid(),
        org_key,
        resource_key,
    )
    .into_bytes()
}

/// The sentinel `org_key` value meaning the consent applies at realm scope
/// (i.e. not tied to a specific organization).
pub(crate) const CONSENT_ORG_KEY_REALM: &str = "_realm";

/// The sentinel `resource_key` value meaning no resource indicator was
/// supplied by the client.
pub(crate) const CONSENT_RESOURCE_KEY_DEFAULT: &str = "_default";

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

// ===== Federation key encoding =====

/// Encodes the storage key for an external IdP connector record.
///
/// Format: `fed:idp:{idp_uuid}`
///
/// Connector records are realm-scoped via the underlying `StorageEngine`;
/// no realm segment is embedded in the key because every read goes through
/// the realm handle (same convention as `oauth:client:{client_uuid}`).
pub(crate) fn encode_idp_key(idp_id: &IdpId) -> Vec<u8> {
    format!("{FED_IDP_PREFIX}{}", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing every IdP connector in a realm.
///
/// Format: `fed:idp:`
pub(crate) fn fed_idp_scan_prefix() -> Vec<u8> {
    FED_IDP_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for an in-flight federation state record.
///
/// Format: `fed:state:{opaque_token}`
///
/// The token is an opaque random string that is echoed to the upstream
/// IdP via the OAuth `state` query parameter and verified on callback.
pub(crate) fn encode_federation_state_key(state_token: &str) -> Vec<u8> {
    format!("{FED_STATE_PREFIX}{state_token}").into_bytes()
}

/// Returns the scan prefix for federation state (for cascade cleanup).
///
/// Format: `fed:state:`
#[allow(dead_code)]
pub(crate) fn fed_state_scan_prefix() -> Vec<u8> {
    FED_STATE_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a confirm-to-link ticket.
///
/// Format: `fed:confirm:{ticket_uuid}`
///
/// Used in `link_existing_accounts: confirm` mode: after an external
/// login matches an existing local user by email, the external identity
/// is parked here while the user re-authenticates locally to prove
/// ownership of the matched account.
pub(crate) fn encode_federation_confirm_key(ticket: &str) -> Vec<u8> {
    format!("{FED_CONFIRM_PREFIX}{ticket}").into_bytes()
}

/// Returns the scan prefix for federation confirm-link tickets.
///
/// Format: `fed:confirm:`
#[allow(dead_code)]
pub(crate) fn fed_confirm_scan_prefix() -> Vec<u8> {
    FED_CONFIRM_PREFIX.as_bytes().to_vec()
}

/// Encodes the reverse external-identity → user index key.
///
/// Format: `fed:ext:{idp_uuid}:{external_sub}`
///
/// On every federation callback, Hearth asks "who owns this upstream
/// identity?" This key answers that in one lookup. The value is the
/// `UserId` UUID bytes.
///
/// The external sub is used verbatim; upstream providers commit to its
/// stability (Google: sub claim is the Google user ID; GitHub: numeric
/// user id as string; Apple: sub claim).
pub(crate) fn encode_federation_ext_key(idp_id: &IdpId, external_sub: &str) -> Vec<u8> {
    format!("{FED_EXT_PREFIX}{}:{external_sub}", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every external-identity record owned by
/// a given IdP connector.
///
/// Format: `fed:ext:{idp_uuid}:`
///
/// Used by `delete_idp` cascade to sever every link for the connector
/// without touching other connectors in the realm.
pub(crate) fn encode_federation_ext_prefix_for_idp(idp_id: &IdpId) -> Vec<u8> {
    format!("{FED_EXT_PREFIX}{}:", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every external-identity record in the realm.
///
/// Format: `fed:ext:`
///
/// Used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn fed_ext_scan_prefix() -> Vec<u8> {
    FED_EXT_PREFIX.as_bytes().to_vec()
}

/// Encodes the forward user → external-identity index key.
///
/// Format: `fed:ext_fwd:{user_uuid}:{idp_uuid}`
///
/// Lets `/ui/account/linked-accounts` enumerate a user's linked IdPs in
/// a single scan, and lets `delete_user` cascade severs every reverse
/// index entry without a full-realm scan. Value is the external sub
/// (the same string used as the trailing segment of `fed:ext:*`).
pub(crate) fn encode_federation_ext_fwd_key(user_id: &UserId, idp_id: &IdpId) -> Vec<u8> {
    format!(
        "{FED_EXT_FWD_PREFIX}{}:{}",
        user_id.as_uuid(),
        idp_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for every external identity linked to a user.
///
/// Format: `fed:ext_fwd:{user_uuid}:`
pub(crate) fn encode_federation_ext_fwd_prefix_for_user(user_id: &UserId) -> Vec<u8> {
    format!("{FED_EXT_FWD_PREFIX}{}:", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for the realm-wide forward index.
///
/// Format: `fed:ext_fwd:`
///
/// Used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn fed_ext_fwd_scan_prefix() -> Vec<u8> {
    FED_EXT_FWD_PREFIX.as_bytes().to_vec()
}

/// Encodes the SCIM `externalId` → `UserId` index key.
///
/// Format: `scim:ext_user:{external_id}` — value is the stringified
/// `UserId` UUID. Called by the SCIM layer to provide idempotent
/// provisioning: an IdP that sends the same `externalId` twice resolves
/// to the same Hearth user.
pub(crate) fn encode_scim_ext_user_key(external_id: &str) -> Vec<u8> {
    format!("{SCIM_EXT_USER_PREFIX}{external_id}").into_bytes()
}

/// Returns the scan prefix for every SCIM external-id-to-user mapping.
///
/// Format: `scim:ext_user:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_user_scan_prefix() -> Vec<u8> {
    SCIM_EXT_USER_PREFIX.as_bytes().to_vec()
}

/// Encodes the reverse `UserId` → SCIM `externalId` index key.
///
/// Format: `scim:ext_user_fwd:{user_uuid}` — value is the external id.
/// Lets `delete_user` cascade revoke the SCIM mapping in O(1) without
/// scanning the forward space.
pub(crate) fn encode_scim_ext_user_fwd_key(user_id: &UserId) -> Vec<u8> {
    format!("{SCIM_EXT_USER_FWD_PREFIX}{}", user_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every SCIM forward index entry in a realm.
///
/// Format: `scim:ext_user_fwd:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_user_fwd_scan_prefix() -> Vec<u8> {
    SCIM_EXT_USER_FWD_PREFIX.as_bytes().to_vec()
}

/// Encodes the SCIM `externalId` → `OrganizationId` (group) index key.
///
/// Format: `scim:ext_group:{external_id}` — value is the stringified
/// `OrganizationId` UUID.
pub(crate) fn encode_scim_ext_group_key(external_id: &str) -> Vec<u8> {
    format!("{SCIM_EXT_GROUP_PREFIX}{external_id}").into_bytes()
}

/// Returns the scan prefix for every SCIM group external-id mapping.
///
/// Format: `scim:ext_group:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_group_scan_prefix() -> Vec<u8> {
    SCIM_EXT_GROUP_PREFIX.as_bytes().to_vec()
}

/// Encodes the reverse `OrganizationId` → SCIM `externalId` index key.
///
/// Format: `scim:ext_group_fwd:{org_uuid}` — value is the external id.
pub(crate) fn encode_scim_ext_group_fwd_key(org_id: &OrganizationId) -> Vec<u8> {
    format!("{SCIM_EXT_GROUP_FWD_PREFIX}{}", org_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for every SCIM group forward index entry.
///
/// Format: `scim:ext_group_fwd:` — used by `delete_realm` cascade.
#[allow(dead_code)]
pub(crate) fn scim_ext_group_fwd_scan_prefix() -> Vec<u8> {
    SCIM_EXT_GROUP_FWD_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for a realm's SAML signing key (RSA-2048 PKCS#8).
///
/// Format: `realm:saml_key:{uuid}` — stored under the system realm scope,
/// parallel to the realm's Ed25519 JWT signing key at `realm:key:`.
pub(crate) fn encode_realm_saml_key(realm_id: &RealmId) -> Vec<u8> {
    format!("{REALM_SAML_KEY_PREFIX}{}", realm_id.as_uuid()).into_bytes()
}

/// Encodes the storage key for a SAML registered Service Provider.
///
/// Format: `saml:sp:{sp_key}` — the SP key is a stable slug from YAML.
pub(crate) fn encode_saml_sp_key(sp_key: &str) -> Vec<u8> {
    format!("{SAML_SP_PREFIX}{sp_key}").into_bytes()
}

/// Returns the scan prefix for every SAML SP registration in the realm.
///
/// Format: `saml:sp:` — used by reconcile and cascade cleanup.
pub(crate) fn saml_sp_scan_prefix() -> Vec<u8> {
    SAML_SP_PREFIX.as_bytes().to_vec()
}

/// Encodes the storage key for SAML SP-side outbound request state.
///
/// Format: `saml:state:{opaque_token}`.
pub(crate) fn encode_saml_state_key(state_token: &str) -> Vec<u8> {
    format!("{SAML_STATE_PREFIX}{state_token}").into_bytes()
}

/// Returns the scan prefix for SAML outbound request state.
#[allow(dead_code)]
pub(crate) fn saml_state_scan_prefix() -> Vec<u8> {
    SAML_STATE_PREFIX.as_bytes().to_vec()
}

/// Encodes the SAML assertion-ID replay sentinel key.
///
/// Format: `saml:asn:{idp_uuid}:{assertion_id}`.
pub(crate) fn encode_saml_assertion_id(idp_id: &IdpId, assertion_id: &str) -> Vec<u8> {
    format!("{SAML_ASSERTION_PREFIX}{}:{assertion_id}", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SAML assertion-ID sentinels owned by an IdP.
#[allow(dead_code)]
pub(crate) fn encode_saml_assertion_prefix_for_idp(idp_id: &IdpId) -> Vec<u8> {
    format!("{SAML_ASSERTION_PREFIX}{}:", idp_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SAML assertion sentinels in the realm.
#[allow(dead_code)]
pub(crate) fn saml_assertion_scan_prefix() -> Vec<u8> {
    SAML_ASSERTION_PREFIX.as_bytes().to_vec()
}

/// Encodes the SAML SP-session registration key (IdP side, for SLO fan-out).
///
/// Format: `saml:sp_session:{session_uuid}:{sp_key}`.
pub(crate) fn encode_saml_sp_session(session_id: &SessionId, sp_key: &str) -> Vec<u8> {
    format!("{SAML_SP_SESSION_PREFIX}{}:{sp_key}", session_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SP registrations on a session.
pub(crate) fn encode_saml_sp_session_prefix(session_id: &SessionId) -> Vec<u8> {
    format!("{SAML_SP_SESSION_PREFIX}{}:", session_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for all SP session registrations in the realm.
#[allow(dead_code)]
pub(crate) fn saml_sp_session_scan_prefix() -> Vec<u8> {
    SAML_SP_SESSION_PREFIX.as_bytes().to_vec()
}

/// Encodes the SAML logout state key.
///
/// Format: `saml:logout:{opaque_token}`.
#[allow(dead_code)]
pub(crate) fn encode_saml_logout_key(token: &str) -> Vec<u8> {
    format!("{SAML_LOGOUT_STATE_PREFIX}{token}").into_bytes()
}

/// Returns the scan prefix for SAML logout state.
#[allow(dead_code)]
pub(crate) fn saml_logout_scan_prefix() -> Vec<u8> {
    SAML_LOGOUT_STATE_PREFIX.as_bytes().to_vec()
}

/// Encodes the session → grant-family index key.
///
/// Format: `oauth:session_fam:{session_uuid}:{family_id}`.
pub(crate) fn encode_session_grant_family(session_id: &SessionId, family_id: &str) -> Vec<u8> {
    format!(
        "{SESSION_GRANT_FAMILY_PREFIX}{}:{family_id}",
        session_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all grant families on a session.
///
/// Format: `oauth:session_fam:{session_uuid}:`.
pub(crate) fn encode_session_grant_family_prefix(session_id: &SessionId) -> Vec<u8> {
    format!("{SESSION_GRANT_FAMILY_PREFIX}{}:", session_id.as_uuid()).into_bytes()
}

// ---------------------------------------------------------------------------
// Webhook keys
// ---------------------------------------------------------------------------

/// Prefix for webhook primary keys.
const WEBHOOK_ID_PREFIX: &str = "wh:id:";

/// Encodes the primary key for a webhook record.
///
/// Format: `wh:id:{uuid}`
pub(crate) fn encode_webhook_id(webhook_id: &WebhookId) -> Vec<u8> {
    format!("{WEBHOOK_ID_PREFIX}{}", webhook_id.as_uuid()).into_bytes()
}

/// Returns the scan prefix for listing all webhooks in a realm.
///
/// Format: `wh:id:`
pub(crate) fn webhook_id_scan_prefix() -> Vec<u8> {
    WEBHOOK_ID_PREFIX.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ClientId, IdpId, InvitationId, OrganizationId, RealmId, SessionId};
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
        // deepcode ignore HardcodedNonCryptoSecret: storage key format fixture — verifies encode_oauth_code prefix
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

    // ===== Federation key tests =====

    #[test]
    fn encode_idp_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let idp_id = IdpId::new(uuid);
        let key = encode_idp_key(&idp_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fed:idp:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn idp_key_starts_with_scan_prefix() {
        let key = encode_idp_key(&IdpId::generate());
        assert!(key.starts_with(&fed_idp_scan_prefix()));
    }

    #[test]
    fn encode_federation_state_key_format() {
        let key = encode_federation_state_key("state-token-abc");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fed:state:state-token-abc");
    }

    #[test]
    fn federation_state_key_starts_with_scan_prefix() {
        let key = encode_federation_state_key("xyz");
        assert!(key.starts_with(&fed_state_scan_prefix()));
    }

    #[test]
    fn encode_federation_confirm_key_format() {
        let key = encode_federation_confirm_key("ticket-uuid-1");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fed:confirm:ticket-uuid-1");
    }

    #[test]
    fn federation_confirm_key_starts_with_scan_prefix() {
        let key = encode_federation_confirm_key("t");
        assert!(key.starts_with(&fed_confirm_scan_prefix()));
    }

    #[test]
    fn encode_federation_ext_key_format() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let idp_id = IdpId::new(uuid);
        let key = encode_federation_ext_key(&idp_id, "google-sub-12345");
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "fed:ext:550e8400-e29b-41d4-a716-446655440000:google-sub-12345"
        );
    }

    #[test]
    fn federation_ext_key_starts_with_idp_prefix() {
        let idp_id = IdpId::generate();
        let key = encode_federation_ext_key(&idp_id, "sub-abc");
        let prefix = encode_federation_ext_prefix_for_idp(&idp_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn federation_ext_key_starts_with_realm_scan_prefix() {
        let key = encode_federation_ext_key(&IdpId::generate(), "sub");
        assert!(key.starts_with(&fed_ext_scan_prefix()));
    }

    #[test]
    fn different_idps_produce_disjoint_ext_prefixes() {
        let p1 = encode_federation_ext_prefix_for_idp(&IdpId::generate());
        let p2 = encode_federation_ext_prefix_for_idp(&IdpId::generate());
        assert_ne!(p1, p2);
        // Critical: one prefix must not be a prefix of the other, or a
        // cascade scan for IdP-A would delete IdP-B's records.
        assert!(!p1.starts_with(&p2));
        assert!(!p2.starts_with(&p1));
    }

    #[test]
    fn encode_federation_ext_fwd_key_format() {
        let user_uuid =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let idp_uuid = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let user_id = UserId::new(user_uuid);
        let idp_id = IdpId::new(idp_uuid);
        let key = encode_federation_ext_fwd_key(&user_id, &idp_id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(
            key_str,
            "fed:ext_fwd:550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn federation_ext_fwd_key_starts_with_user_prefix() {
        let user_id = UserId::generate();
        let idp_id = IdpId::generate();
        let key = encode_federation_ext_fwd_key(&user_id, &idp_id);
        let prefix = encode_federation_ext_fwd_prefix_for_user(&user_id);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn federation_ext_fwd_key_starts_with_realm_scan_prefix() {
        let key = encode_federation_ext_fwd_key(&UserId::generate(), &IdpId::generate());
        assert!(key.starts_with(&fed_ext_fwd_scan_prefix()));
    }

    #[test]
    fn different_users_produce_disjoint_ext_fwd_prefixes() {
        let p1 = encode_federation_ext_fwd_prefix_for_user(&UserId::generate());
        let p2 = encode_federation_ext_fwd_prefix_for_user(&UserId::generate());
        assert_ne!(p1, p2);
        // Critical: cross-user cascade deletes must not leak.
        assert!(!p1.starts_with(&p2));
        assert!(!p2.starts_with(&p1));
    }

    #[test]
    fn federation_prefixes_do_not_overlap_with_legacy_prefixes() {
        // Regression guard: a future rename of legacy prefixes that
        // happened to begin with "fed" would cascade-delete federation
        // data. All legacy prefixes used by hearth today.
        let fed = fed_idp_scan_prefix();
        let legacy_prefixes = [
            user_id_scan_prefix(),
            session_id_scan_prefix(),
            oauth_client_scan_prefix(),
            oauth_consent_scan_prefix(),
            oauth_pending_auth_scan_prefix(),
            org_id_scan_prefix(),
        ];
        for p in &legacy_prefixes {
            assert!(!fed.starts_with(p));
            assert!(!p.starts_with(&fed));
        }
    }
}
