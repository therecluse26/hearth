//! Identity domain types: users, tenants, requests, and status.

use serde::{Deserialize, Serialize};

use crate::core::{InvitationId, OrganizationId, SessionId, TenantId, Timestamp, UserId};
use crate::identity::email::EmailBranding;

/// A cursor-based page of results.
///
/// The `next_cursor` is an opaque token that the client passes back to
/// fetch the next page. When `next_cursor` is `None`, there are no more
/// results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// Cursor for the next page, or `None` if this is the last page.
    pub next_cursor: Option<String>,
}

impl<T> Default for Page<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }
}

/// Result of a single item within a bulk operation.
///
/// The `index` field identifies which item in the original request
/// this result corresponds to.
#[derive(Clone, Debug)]
pub struct BulkResult<T> {
    /// Zero-based index into the original request array.
    pub index: usize,
    /// Success value or error description.
    pub result: Result<T, String>,
}

/// The lifecycle status of a user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserStatus {
    /// Account is active and can authenticate.
    Active,
    /// Account is disabled by an administrator.
    Disabled,
    /// Account is awaiting email verification.
    PendingVerification,
}

/// A user record within a tenant.
///
/// Fields are private; access via accessor methods. Email is always stored
/// normalized (lowercase, trimmed, NFC).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    id: UserId,
    email: String,
    display_name: String,
    status: UserStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl User {
    /// Creates a new user. Used internally by the identity engine.
    pub(crate) fn new(
        id: UserId,
        email: String,
        display_name: String,
        status: UserStatus,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            email,
            display_name,
            status,
            created_at,
            updated_at,
        }
    }

    /// Returns the user's unique identifier.
    pub fn id(&self) -> &UserId {
        &self.id
    }

    /// Returns the user's normalized email address.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the user's display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the user's account status.
    pub fn status(&self) -> UserStatus {
        self.status
    }

    /// Returns when the user was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the user was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the email. Used internally during user updates.
    pub(crate) fn set_email(&mut self, email: String) {
        self.email = email;
    }

    /// Updates the display name. Used internally during user updates.
    pub(crate) fn set_display_name(&mut self, display_name: String) {
        self.display_name = display_name;
    }

    /// Updates the status. Used internally during user updates.
    pub(crate) fn set_status(&mut self, status: UserStatus) {
        self.status = status;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// Device and network context captured at session creation time.
///
/// All fields are optional — API-originated sessions (no browser) or
/// sessions created before this feature was added will have `None` values.
#[derive(Clone, Debug, Default)]
pub struct SessionContext {
    /// Client IP address (peer or extracted from `X-Forwarded-For`).
    pub ip_address: Option<String>,
    /// Raw `User-Agent` header value (stored for future re-parsing).
    pub user_agent_raw: Option<String>,
    /// Pre-parsed device label, e.g. `"Chrome, Mac OSX"`.
    pub device_label: Option<String>,
}

/// An authentication session bound to a user.
///
/// Sessions have a configurable TTL and can be refreshed or revoked.
/// Fields are private; access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    created_at: Timestamp,
    expires_at: Timestamp,
    last_refreshed_at: Timestamp,
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_agent_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_label: Option<String>,
}

impl Session {
    /// Creates a new session. Used internally by the identity engine.
    pub(crate) fn new(
        id: SessionId,
        user_id: UserId,
        created_at: Timestamp,
        expires_at: Timestamp,
        context: &SessionContext,
    ) -> Self {
        Self {
            id,
            user_id,
            created_at,
            expires_at,
            last_refreshed_at: created_at,
            revoked: false,
            ip_address: context.ip_address.clone(),
            user_agent_raw: context.user_agent_raw.clone(),
            device_label: context.device_label.clone(),
        }
    }

    /// Returns the session's unique identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the ID of the user this session belongs to.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns when the session was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the session expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns when the session was last refreshed (UTC microseconds).
    pub fn last_refreshed_at(&self) -> Timestamp {
        self.last_refreshed_at
    }

    /// Returns whether the session has been revoked.
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Returns whether the session is valid (not expired and not revoked).
    pub(crate) fn is_valid(&self, now: Timestamp) -> bool {
        !self.revoked && now < self.expires_at
    }

    /// Marks the session as revoked.
    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Refreshes the session by extending the TTL.
    pub(crate) fn refresh(&mut self, now: Timestamp, ttl_micros: i64) {
        self.expires_at = now.add_micros(ttl_micros);
        self.last_refreshed_at = now;
    }

    /// Returns the client IP address captured at session creation, if available.
    pub fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    /// Returns the raw User-Agent header captured at session creation, if available.
    pub fn user_agent_raw(&self) -> Option<&str> {
        self.user_agent_raw.as_deref()
    }

    /// Returns the pre-parsed device label (e.g. "Chrome, Mac OSX"), if available.
    pub fn device_label(&self) -> Option<&str> {
        self.device_label.as_deref()
    }
}

/// Request to create a new user.
#[derive(Clone, Debug)]
pub struct CreateUserRequest {
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized).
    pub display_name: String,
}

/// Request to update an existing user.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateUserRequest {
    /// New email address (will be normalized).
    pub email: Option<String>,
    /// New display name (will be trimmed and NFC-normalized).
    pub display_name: Option<String>,
    /// New account status.
    pub status: Option<UserStatus>,
}

// ===== Tenant types =====

/// The lifecycle status of a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TenantStatus {
    /// Tenant is active; all operations proceed normally.
    Active,
    /// Tenant is suspended; authentication and authorization are denied.
    Suspended,
    /// Tenant was removed from YAML config and soft-deleted.
    ///
    /// Behaves like `Suspended` (auth denied) but additionally signals
    /// that the tenant can be permanently deleted from the admin UI.
    Archived,
}

/// Password complexity policy stored in a tenant's configuration.
///
/// These are *declarations* — enforcement is a separate concern in the identity
/// engine. When all fields are `None`, no additional complexity requirements
/// are imposed beyond the default minimum.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length. Must be >= 1 when set.
    pub min_length: Option<usize>,
    /// Require at least one uppercase letter.
    pub require_uppercase: Option<bool>,
    /// Require at least one digit.
    pub require_number: Option<bool>,
    /// Require at least one special character.
    pub require_special: Option<bool>,
}

/// Per-tenant configuration overrides.
///
/// Fields are optional — when `None`, the engine-level default is used.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Session time-to-live in microseconds. Overrides engine default.
    pub session_ttl_micros: Option<i64>,
    /// Argon2id memory cost in KiB. Overrides engine default.
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost (iterations). Overrides engine default.
    pub password_time_cost: Option<u32>,
    /// Per-tenant email branding overrides.
    pub email_branding: Option<EmailBranding>,
    /// Composed CSS block (named theme + optional custom file contents) served
    /// as the tenant-specific theme stylesheet. `None` means no per-tenant
    /// theme is configured — the global theme applies.
    pub web_theme_css: Option<String>,
    /// Whether MFA is required for all users in this tenant.
    pub mfa_required: Option<bool>,
    /// Allowed MFA methods (e.g. `["totp", "webauthn"]`).
    pub mfa_methods: Option<Vec<String>>,
    /// Allowed authentication methods (e.g. `["password", "magic_link", "passkey"]`).
    pub allowed_auth_methods: Option<Vec<String>>,
    /// Password complexity policy.
    pub password_policy: Option<PasswordPolicy>,
    /// Per-tenant access token TTL in microseconds.
    pub access_token_ttl_micros: Option<i64>,
    /// Per-tenant refresh token TTL in microseconds.
    pub refresh_token_ttl_micros: Option<i64>,
    /// Maximum failed login attempts before lockout.
    pub max_failed_logins: Option<u32>,
    /// Lockout duration in microseconds after max failed logins.
    pub lockout_duration_micros: Option<i64>,
    /// Whether passkey login still requires a TOTP challenge.
    /// When `Some(true)`, passkey auth is treated like password auth
    /// with respect to MFA gating.
    pub passkey_requires_mfa: Option<bool>,
}

/// A tenant record.
///
/// Each tenant is an isolated namespace for users, sessions, credentials,
/// tokens, and authorization tuples. Fields are private; access via
/// accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    id: TenantId,
    name: String,
    status: TenantStatus,
    config: TenantConfig,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Tenant {
    /// Creates a new tenant. Used internally by the identity engine.
    pub(crate) fn new(
        id: TenantId,
        name: String,
        status: TenantStatus,
        config: TenantConfig,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            name,
            status,
            config,
            created_at,
            updated_at,
        }
    }

    /// Returns the tenant's unique identifier.
    pub fn id(&self) -> &TenantId {
        &self.id
    }

    /// Returns the tenant's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the tenant's lifecycle status.
    pub fn status(&self) -> TenantStatus {
        self.status
    }

    /// Returns the tenant's configuration overrides.
    pub fn config(&self) -> &TenantConfig {
        &self.config
    }

    /// Returns when the tenant was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the tenant was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the tenant name. Used internally during updates.
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Updates the tenant status. Used internally during updates.
    pub(crate) fn set_status(&mut self, status: TenantStatus) {
        self.status = status;
    }

    /// Updates the tenant configuration. Used internally during updates.
    pub(crate) fn set_config(&mut self, config: TenantConfig) {
        self.config = config;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// Request to create a new tenant.
#[derive(Clone, Debug)]
pub struct CreateTenantRequest {
    /// The tenant's display name.
    pub name: String,
    /// Optional per-tenant configuration. Defaults applied if omitted.
    pub config: Option<TenantConfig>,
}

/// Request to update an existing tenant.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateTenantRequest {
    /// New display name.
    pub name: Option<String>,
    /// New tenant status.
    pub status: Option<TenantStatus>,
    /// New configuration overrides.
    pub config: Option<TenantConfig>,
}

// ===== Organization types =====

/// The lifecycle status of an organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationStatus {
    /// Organization is active; members can operate normally.
    Active,
    /// Organization is suspended by an administrator.
    Suspended,
}

/// Per-organization configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationConfig {
    /// Maximum number of members allowed. `None` means unlimited.
    pub max_members: Option<u32>,
}

/// An organization within a tenant.
///
/// Organizations represent B2B customer groups. Users can be members of
/// multiple organizations within the same tenant. Fields are private;
/// access via accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    id: OrganizationId,
    name: String,
    slug: String,
    description: String,
    status: OrganizationStatus,
    config: OrganizationConfig,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl Organization {
    /// Creates a new organization. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: OrganizationId,
        name: String,
        slug: String,
        description: String,
        status: OrganizationStatus,
        config: OrganizationConfig,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            id,
            name,
            slug,
            description,
            status,
            config,
            created_at,
            updated_at,
        }
    }

    /// Returns the organization's unique identifier.
    pub fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// Returns the organization's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the organization's URL-safe slug.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Returns the organization's description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the organization's lifecycle status.
    pub fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// Returns the organization's configuration.
    pub fn config(&self) -> &OrganizationConfig {
        &self.config
    }

    /// Returns when the organization was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns when the organization was last updated (UTC microseconds).
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Updates the name. Used internally during organization updates.
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Updates the description. Used internally during organization updates.
    pub(crate) fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Updates the status. Used internally during organization updates.
    pub(crate) fn set_status(&mut self, status: OrganizationStatus) {
        self.status = status;
    }

    /// Updates the configuration. Used internally during organization updates.
    pub(crate) fn set_config(&mut self, config: OrganizationConfig) {
        self.config = config;
    }

    /// Updates the `updated_at` timestamp.
    pub(crate) fn set_updated_at(&mut self, ts: Timestamp) {
        self.updated_at = ts;
    }
}

/// A role within an organization.
///
/// Roles form a hierarchy: Owner > Admin > Member. Higher roles
/// inherit the capabilities of lower roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRole {
    /// Full control including delete, role management, and billing.
    Owner,
    /// Can manage members and settings but not delete the org.
    Admin,
    /// Basic membership with access to org resources.
    Member,
}

/// A membership record linking a user to an organization.
///
/// Stored as bidirectional indexes (org→user and user→org) for
/// efficient lookups in both directions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMembership {
    org_id: OrganizationId,
    user_id: UserId,
    role: OrganizationRole,
    joined_at: Timestamp,
    invited_by: Option<UserId>,
}

impl OrganizationMembership {
    /// Creates a new membership. Used internally by the identity engine.
    pub(crate) fn new(
        org_id: OrganizationId,
        user_id: UserId,
        role: OrganizationRole,
        joined_at: Timestamp,
        invited_by: Option<UserId>,
    ) -> Self {
        Self {
            org_id,
            user_id,
            role,
            joined_at,
            invited_by,
        }
    }

    /// Returns the organization this membership belongs to.
    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    /// Returns the user who is a member.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the member's role within the organization.
    pub fn role(&self) -> OrganizationRole {
        self.role
    }

    /// Returns when the user joined the organization (UTC microseconds).
    pub fn joined_at(&self) -> Timestamp {
        self.joined_at
    }

    /// Returns who invited this member, if applicable.
    pub fn invited_by(&self) -> Option<&UserId> {
        self.invited_by.as_ref()
    }

    /// Updates the role. Used internally during role changes.
    pub(crate) fn set_role(&mut self, role: OrganizationRole) {
        self.role = role;
    }
}

/// The status of an organization invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    /// Invitation has been sent but not yet acted upon.
    Pending,
    /// Invitation was accepted; the user is now a member.
    Accepted,
    /// Invitation was revoked by an admin before acceptance.
    Revoked,
    /// Invitation expired before the recipient acted.
    Expired,
}

/// An invitation to join an organization.
///
/// The token is stored as a SHA-256 hash. The plaintext token is returned
/// only once at creation time and never persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    id: InvitationId,
    org_id: OrganizationId,
    email: String,
    role: OrganizationRole,
    token_hash: String,
    status: InvitationStatus,
    expires_at: Timestamp,
    invited_by: UserId,
    created_at: Timestamp,
}

impl OrganizationInvitation {
    /// Creates a new invitation. Used internally by the identity engine.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: InvitationId,
        org_id: OrganizationId,
        email: String,
        role: OrganizationRole,
        token_hash: String,
        status: InvitationStatus,
        expires_at: Timestamp,
        invited_by: UserId,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            org_id,
            email,
            role,
            token_hash,
            status,
            expires_at,
            invited_by,
            created_at,
        }
    }

    /// Returns the invitation's unique identifier.
    pub fn id(&self) -> &InvitationId {
        &self.id
    }

    /// Returns which organization this invitation is for.
    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    /// Returns the email address the invitation was sent to.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the role the invitee will receive upon acceptance.
    pub fn role(&self) -> OrganizationRole {
        self.role
    }

    /// Returns the SHA-256 hash of the invitation token.
    pub(crate) fn token_hash(&self) -> &str {
        &self.token_hash
    }

    /// Returns the invitation's current status.
    pub fn status(&self) -> InvitationStatus {
        self.status
    }

    /// Returns when the invitation expires (UTC microseconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Returns who created this invitation.
    pub fn invited_by(&self) -> &UserId {
        &self.invited_by
    }

    /// Returns when the invitation was created (UTC microseconds).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Marks the invitation as accepted.
    pub(crate) fn set_accepted(&mut self) {
        self.status = InvitationStatus::Accepted;
    }

    /// Marks the invitation as revoked.
    pub(crate) fn set_revoked(&mut self) {
        self.status = InvitationStatus::Revoked;
    }
}

/// Request to create a new organization.
#[derive(Clone, Debug)]
pub struct CreateOrganizationRequest {
    /// Display name for the organization.
    pub name: String,
    /// URL-safe slug (lowercase alphanumeric + hyphens, 3-63 chars).
    pub slug: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional configuration overrides.
    pub config: Option<OrganizationConfig>,
}

/// Request to update an existing organization.
///
/// Only `Some` fields are applied; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateOrganizationRequest {
    /// New display name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// New lifecycle status.
    pub status: Option<OrganizationStatus>,
    /// New configuration overrides.
    pub config: Option<OrganizationConfig>,
}

/// Request to create an invitation to join an organization.
#[derive(Clone, Debug)]
pub struct CreateInvitationRequest {
    /// Organization to invite the user to.
    pub org_id: OrganizationId,
    /// Email address of the invitee.
    pub email: String,
    /// Role to assign upon acceptance.
    pub role: OrganizationRole,
    /// User who is creating the invitation.
    pub invited_by: UserId,
}

// ===== Migration / import request types (Phase 1 Step 30) =====

/// A pre-hashed credential to attach to an imported user.
///
/// Unlike `CreateUserRequest` + `set_password`, imports preserve the
/// source system's hash verbatim so users can authenticate with their
/// existing passwords. New hashes (via `change_password` or `set_password`)
/// are always Argon2id; successful verification against a legacy hash
/// auto-upgrades it in place.
#[derive(Clone, Debug)]
pub struct RawCredential {
    /// The PHC-formatted hash string (e.g. `$pbkdf2-sha256$i=27500$salt$hash`).
    pub phc_string: String,
    /// Unix-microseconds timestamp of original credential creation, if known.
    pub created_at_micros: Option<i64>,
}

/// Request to import a user from an external identity provider.
///
/// `id` allows preserving the source system's user ID so that in-flight
/// tokens and application-level references remain valid; leave `None`
/// to let the engine generate a fresh `UserId`. `credential` may be
/// `None` — e.g. for users whose source hash used an unsupported KDF.
#[derive(Clone, Debug)]
pub struct ImportUserRequest {
    /// Preserved source-system UUID, or `None` to generate a new one.
    pub id: Option<UserId>,
    /// Email address (will be normalized).
    pub email: String,
    /// Display name (will be trimmed and NFC-normalized).
    pub display_name: String,
    /// Account status.
    pub status: UserStatus,
    /// Pre-hashed credential. `None` imports the user with no password.
    pub credential: Option<RawCredential>,
}

/// Request to import an OAuth 2.0 client from an external provider.
///
/// Unlike `RegisterClientRequest`, this allows preserving the client's
/// source-system identifier. The secret (if any) is hashed with Argon2id
/// at import time — the source system's hashed secret is not reusable
/// because Hearth's storage format requires Argon2id.
#[derive(Clone, Debug)]
pub struct ImportClientRequest {
    /// Preserved source-system client UUID, or `None` to generate.
    pub id: Option<crate::core::ClientId>,
    /// Display name.
    pub client_name: String,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Plaintext client secret — hashed with Argon2id before storage.
    /// `None` creates a public client.
    pub client_secret: Option<String>,
    /// Allowed OAuth 2.0 grant types (defaults to `authorization_code`).
    pub grant_types: Vec<String>,
}

/// Summary returned by a successful migration.
///
/// Counts reflect what was actually written. `warnings` contains
/// human-readable notes about partial imports (e.g. users whose credential
/// used an unsupported KDF and was skipped).
#[derive(Clone, Debug, Default)]
pub struct MigrationReport {
    /// ID of the tenant the migrated realm was imported into.
    pub tenant_id: Option<TenantId>,
    /// Number of users written.
    pub users_imported: usize,
    /// Number of users whose credentials could not be imported
    /// (the user record itself was still created).
    pub users_with_skipped_credentials: usize,
    /// Number of OAuth clients written.
    pub clients_imported: usize,
    /// Number of authorization tuples written.
    pub tuples_written: usize,
    /// Non-fatal issues encountered during the import.
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;

    #[test]
    fn user_accessors() {
        let id = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            id.clone(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            UserStatus::Active,
            now,
            now,
        );

        assert_eq!(user.id(), &id);
        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), now);
        assert_eq!(user.updated_at(), now);
    }

    #[test]
    fn user_serde_round_trip() {
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            UserStatus::PendingVerification,
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&user).expect("serialize");
        let deserialized: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(user, deserialized);
    }

    #[test]
    fn user_status_serde_round_trip() {
        for status in [
            UserStatus::Active,
            UserStatus::Disabled,
            UserStatus::PendingVerification,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: UserStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn user_mutators() {
        let mut user = User::new(
            UserId::generate(),
            "old@example.com".to_string(),
            "Old Name".to_string(),
            UserStatus::Active,
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        user.set_email("new@example.com".to_string());
        user.set_display_name("New Name".to_string());
        user.set_status(UserStatus::Disabled);
        user.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(user.email(), "new@example.com");
        assert_eq!(user.display_name(), "New Name");
        assert_eq!(user.status(), UserStatus::Disabled);
        assert_eq!(user.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn update_request_default_is_all_none() {
        let req = UpdateUserRequest::default();
        assert!(req.email.is_none());
        assert!(req.display_name.is_none());
        assert!(req.status.is_none());
    }

    // ===== Tenant type tests =====

    #[test]
    fn tenant_accessors() {
        let id = TenantId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let config = TenantConfig {
            session_ttl_micros: Some(3_600_000_000),
            ..TenantConfig::default()
        };
        let tenant = Tenant::new(
            id.clone(),
            "Acme Corp".to_string(),
            TenantStatus::Active,
            config.clone(),
            now,
            now,
        );

        assert_eq!(tenant.id(), &id);
        assert_eq!(tenant.name(), "Acme Corp");
        assert_eq!(tenant.status(), TenantStatus::Active);
        assert_eq!(tenant.config(), &config);
        assert_eq!(tenant.created_at(), now);
        assert_eq!(tenant.updated_at(), now);

        // Verify new auth policy fields default to None
        assert!(config.mfa_required.is_none());
        assert!(config.mfa_methods.is_none());
        assert!(config.allowed_auth_methods.is_none());
        assert!(config.password_policy.is_none());
        assert!(config.access_token_ttl_micros.is_none());
        assert!(config.refresh_token_ttl_micros.is_none());
        assert!(config.max_failed_logins.is_none());
        assert!(config.lockout_duration_micros.is_none());
    }

    #[test]
    fn tenant_serde_round_trip() {
        let tenant = Tenant::new(
            TenantId::generate(),
            "Test Tenant".to_string(),
            TenantStatus::Active,
            TenantConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&tenant).expect("serialize");
        let deserialized: Tenant = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tenant, deserialized);
    }

    #[test]
    fn tenant_status_serde_round_trip() {
        for status in [TenantStatus::Active, TenantStatus::Suspended] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: TenantStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn tenant_mutators() {
        let mut tenant = Tenant::new(
            TenantId::generate(),
            "Old Name".to_string(),
            TenantStatus::Active,
            TenantConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        tenant.set_name("New Name".to_string());
        tenant.set_status(TenantStatus::Suspended);
        let new_config = TenantConfig {
            session_ttl_micros: Some(7_200_000_000),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            ..TenantConfig::default()
        };
        tenant.set_config(new_config.clone());
        tenant.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(tenant.name(), "New Name");
        assert_eq!(tenant.status(), TenantStatus::Suspended);
        assert_eq!(tenant.config(), &new_config);
        assert_eq!(tenant.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn tenant_config_default_is_all_none() {
        let config = TenantConfig::default();
        assert!(config.session_ttl_micros.is_none());
        assert!(config.password_memory_cost.is_none());
        assert!(config.password_time_cost.is_none());
    }

    #[test]
    fn update_tenant_request_default_is_all_none() {
        let req = UpdateTenantRequest::default();
        assert!(req.name.is_none());
        assert!(req.status.is_none());
        assert!(req.config.is_none());
    }

    // ===== Organization type tests =====

    #[test]
    fn organization_accessors() {
        let id = OrganizationId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let config = OrganizationConfig {
            max_members: Some(100),
        };
        let org = Organization::new(
            id.clone(),
            "Acme Corp".to_string(),
            "acme-corp".to_string(),
            "A test org".to_string(),
            OrganizationStatus::Active,
            config.clone(),
            now,
            now,
        );

        assert_eq!(org.id(), &id);
        assert_eq!(org.name(), "Acme Corp");
        assert_eq!(org.slug(), "acme-corp");
        assert_eq!(org.description(), "A test org");
        assert_eq!(org.status(), OrganizationStatus::Active);
        assert_eq!(org.config(), &config);
        assert_eq!(org.created_at(), now);
        assert_eq!(org.updated_at(), now);
    }

    #[test]
    fn organization_serde_round_trip() {
        let org = Organization::new(
            OrganizationId::generate(),
            "Test Org".to_string(),
            "test-org".to_string(),
            String::new(),
            OrganizationStatus::Active,
            OrganizationConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&org).expect("serialize");
        let deserialized: Organization = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(org, deserialized);
    }

    #[test]
    fn organization_mutators() {
        let mut org = Organization::new(
            OrganizationId::generate(),
            "Old Name".to_string(),
            "old-name".to_string(),
            "Old desc".to_string(),
            OrganizationStatus::Active,
            OrganizationConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        org.set_name("New Name".to_string());
        org.set_description("New desc".to_string());
        org.set_status(OrganizationStatus::Suspended);
        org.set_config(OrganizationConfig {
            max_members: Some(50),
        });
        org.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(org.name(), "New Name");
        assert_eq!(org.description(), "New desc");
        assert_eq!(org.status(), OrganizationStatus::Suspended);
        assert_eq!(org.config().max_members, Some(50));
        assert_eq!(org.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn membership_accessors() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let inviter = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);

        let membership = OrganizationMembership::new(
            org_id.clone(),
            user_id.clone(),
            OrganizationRole::Admin,
            now,
            Some(inviter.clone()),
        );

        assert_eq!(membership.org_id(), &org_id);
        assert_eq!(membership.user_id(), &user_id);
        assert_eq!(membership.role(), OrganizationRole::Admin);
        assert_eq!(membership.joined_at(), now);
        assert_eq!(membership.invited_by(), Some(&inviter));
    }

    #[test]
    fn membership_serde_round_trip() {
        let membership = OrganizationMembership::new(
            OrganizationId::generate(),
            UserId::generate(),
            OrganizationRole::Member,
            Timestamp::from_micros(1_000),
            None,
        );

        let json = serde_json::to_string(&membership).expect("serialize");
        let deserialized: OrganizationMembership =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(membership, deserialized);
    }

    #[test]
    fn invitation_accessors() {
        let inv_id = InvitationId::generate();
        let org_id = OrganizationId::generate();
        let inviter = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let expires = Timestamp::from_micros(2_000_000);

        let invitation = OrganizationInvitation::new(
            inv_id.clone(),
            org_id.clone(),
            "alice@example.com".to_string(),
            OrganizationRole::Member,
            "abc123hash".to_string(),
            InvitationStatus::Pending,
            expires,
            inviter.clone(),
            now,
        );

        assert_eq!(invitation.id(), &inv_id);
        assert_eq!(invitation.org_id(), &org_id);
        assert_eq!(invitation.email(), "alice@example.com");
        assert_eq!(invitation.role(), OrganizationRole::Member);
        assert_eq!(invitation.token_hash(), "abc123hash");
        assert_eq!(invitation.status(), InvitationStatus::Pending);
        assert_eq!(invitation.expires_at(), expires);
        assert_eq!(invitation.invited_by(), &inviter);
        assert_eq!(invitation.created_at(), now);
    }

    #[test]
    fn invitation_status_transitions() {
        let mut invitation = OrganizationInvitation::new(
            InvitationId::generate(),
            OrganizationId::generate(),
            "bob@example.com".to_string(),
            OrganizationRole::Admin,
            "hash".to_string(),
            InvitationStatus::Pending,
            Timestamp::from_micros(2_000_000),
            UserId::generate(),
            Timestamp::from_micros(1_000_000),
        );

        assert_eq!(invitation.status(), InvitationStatus::Pending);

        invitation.set_accepted();
        assert_eq!(invitation.status(), InvitationStatus::Accepted);

        // Test revoke on a fresh invitation
        let mut invitation2 = OrganizationInvitation::new(
            InvitationId::generate(),
            OrganizationId::generate(),
            "carol@example.com".to_string(),
            OrganizationRole::Member,
            "hash2".to_string(),
            InvitationStatus::Pending,
            Timestamp::from_micros(2_000_000),
            UserId::generate(),
            Timestamp::from_micros(1_000_000),
        );

        invitation2.set_revoked();
        assert_eq!(invitation2.status(), InvitationStatus::Revoked);
    }

    #[test]
    fn update_organization_request_default_is_all_none() {
        let req = UpdateOrganizationRequest::default();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.status.is_none());
        assert!(req.config.is_none());
    }
}
