//! Identity domain types: users, tenants, requests, and status.

use serde::{Deserialize, Serialize};

use crate::core::{SessionId, TenantId, Timestamp, UserId};
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
}

impl Session {
    /// Creates a new session. Used internally by the identity engine.
    pub(crate) fn new(
        id: SessionId,
        user_id: UserId,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            id,
            user_id,
            created_at,
            expires_at,
            last_refreshed_at: created_at,
            revoked: false,
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
pub enum TenantStatus {
    /// Tenant is active; all operations proceed normally.
    Active,
    /// Tenant is suspended; authentication and authorization are denied.
    Suspended,
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
            email_branding: None,
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
}
